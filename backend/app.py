from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify, request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from neon_db import get_db_connection
from flask_cors import CORS

import pandas as pd
import io
from pathlib import Path
import os
import ipaddress
import platform
import subprocess
import shutil
import json
import smtplib
import secrets
import hashlib
import hmac
import re
from functools import wraps
import sqlite3
from email.message import EmailMessage
from threading import Lock
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import numpy as np
import joblib
import shap

from shap_risk_model import extract_features


app = Flask(__name__)
CORS(app)


# =========================================================
# NEON USER AUTHENTICATION AND EMAIL VERIFICATION
# =========================================================

# Set a long, random SECRET_KEY in backend/.env before deployment.
# Do not reuse the Neon database password as the Flask secret.
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "").strip()

AUTH_TOKEN_MAX_AGE = 12 * 60 * 60
VERIFICATION_TOKEN_MAX_AGE = 30 * 60
AUTH_TOKEN_SALT = "cowrie-dashboard-auth-v1"
VERIFICATION_TOKEN_SALT = "cowrie-email-verification-v1"
PASSWORD_RESET_TOKEN_MAX_AGE = 30 * 60


def _auth_serializer(salt):
    secret = app.config.get("SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError(
            "SECRET_KEY is missing or too short. Set a random value of at least 32 characters in backend/.env."
        )
    return URLSafeTimedSerializer(secret, salt=salt)


def _send_account_email(recipient, subject, body):
    if not ALERT_EMAIL_SENDER or not ALERT_EMAIL_PASSWORD:
        raise RuntimeError(
            "SMTP sender credentials are not configured. Set ALERT_EMAIL_SENDER and ALERT_EMAIL_PASSWORD."
        )

    message = EmailMessage()
    message["From"] = ALERT_EMAIL_SENDER
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
        smtp.starttls()
        smtp.login(ALERT_EMAIL_SENDER, ALERT_EMAIL_PASSWORD)
        smtp.send_message(message)


def _verification_url(token):
    public_url = os.getenv("BACKEND_PUBLIC_URL", "").strip().rstrip("/")
    if not public_url:
        public_url = request.url_root.rstrip("/")
    return f"{public_url}/api/auth/verify?token={token}"


def _create_verification_token(email):
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = datetime.now(timezone.utc).replace(microsecond=0)
    return raw_token, token_hash, expires_at


def _send_verification_email(email, token):
    link = _verification_url(token)
    body = (
        "Cowrie Cyber Threat Detection System\n\n"
        "Thank you for registering.\n"
        "Verify your email address by opening this link:\n\n"
        f"{link}\n\n"
        "This verification link expires in 30 minutes.\n"
        "If you did not create this account, you can ignore this email.\n"
    )
    _send_account_email(
        email,
        "[Cowrie Security] Verify your email address",
        body
    )


def _send_password_reset_email(email, token):
    frontend_url = os.getenv("FRONTEND_PUBLIC_URL", "http://localhost:5173").strip().rstrip("/")
    reset_link = f"{frontend_url}/?reset_token={token}"
    body = (
        "Cowrie Cyber Threat Detection System\n\n"
        "A password reset was requested for your account.\n"
        "Choose a new password by opening this one-time link:\n\n"
        f"{reset_link}\n\n"
        "This link expires in 30 minutes and can only be used once.\n"
        "If you did not request this change, ignore this email. Your current password will remain unchanged.\n"
    )
    _send_account_email(email, "[Cowrie Security] Password reset", body)


def _get_bearer_user():
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    token = header.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        data = _auth_serializer(AUTH_TOKEN_SALT).loads(
            token, max_age=AUTH_TOKEN_MAX_AGE
        )
        user_id = data.get("user_id")
        if not isinstance(user_id, int):
            return None

        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, email, email_verified, notification_enabled
                    FROM users
                    WHERE id = %s
                    LIMIT 1
                    """,
                    (user_id,)
                )
                return cursor.fetchone()
        finally:
            connection.close()
    except (BadSignature, SignatureExpired, RuntimeError):
        return None
    except Exception:
        app.logger.exception("Could not validate authenticated user")
        return None


def require_auth(route_function):
    @wraps(route_function)
    def wrapped(*args, **kwargs):
        user = _get_bearer_user()
        if not user:
            return jsonify({
                "status": "error",
                "message": "Authentication is required. Please log in again."
            }), 401
        if not user.get("email_verified"):
            return jsonify({
                "status": "error",
                "message": "Please verify your email address before continuing."
            }), 403
        request.authenticated_user = user
        return route_function(*args, **kwargs)
    return wrapped


@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "A valid JSON request is required."}), 400

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"status": "error", "message": "Enter a valid email address."}), 400
    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return jsonify({"status": "error", "message": "Password must contain 8 to 128 characters."}), 400

    connection = None
    try:
        password_hash = generate_password_hash(password)
        raw_token, token_hash, _ = _create_verification_token(email)
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users
                    (email, password_hash, notification_enabled, email_verified,
                     verification_token_hash, verification_expires_at)
                VALUES (%s, %s, TRUE, FALSE, %s, NOW() + INTERVAL '30 minutes')
                RETURNING id, email, email_verified
                """,
                (email, password_hash, token_hash)
            )
            user = cursor.fetchone()
        connection.commit()

        try:
            _send_verification_email(email, raw_token)
        except Exception:
            app.logger.exception("Verification email could not be sent for newly registered account")
            return jsonify({
                "status": "pending",
                "message": "Your account was created, but the verification email could not be sent. Use the resend verification option after SMTP settings are corrected.",
                "user": {
                    "id": user["id"],
                    "email": user["email"],
                    "email_verified": False
                }
            }), 202

        return jsonify({
            "status": "success",
            "message": "Registration successful. Check your email and verify your account before logging in.",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "email_verified": False
            }
        }), 201

    except Exception as error:
        if connection:
            connection.rollback()
        if getattr(error, "pgcode", None) == "23505":
            return jsonify({"status": "error", "message": "This email address is already registered."}), 409
        app.logger.exception("User registration failed")
        return jsonify({"status": "error", "message": "Registration could not be completed."}), 500
    finally:
        if connection:
            connection.close()


@app.route("/api/auth/resend-verification", methods=["POST"])
def auth_resend_verification():
    data = request.get_json(silent=True)
    email = str((data or {}).get("email", "")).strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"status": "error", "message": "Enter a valid email address."}), 400

    connection = None
    try:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                SET verification_token_hash = %s,
                    verification_expires_at = NOW() + INTERVAL '30 minutes'
                WHERE email = %s AND email_verified = FALSE
                RETURNING email
                """,
                (token_hash, email)
            )
            user = cursor.fetchone()
        connection.commit()

        # Use a generic response to avoid disclosing whether an account exists.
        if user:
            try:
                _send_verification_email(user["email"], raw_token)
            except Exception:
                app.logger.exception("Resend verification email failed")
                return jsonify({
                    "status": "error",
                    "message": "The verification email could not be sent. Check SMTP configuration and try again."
                }), 503

        return jsonify({
            "status": "success",
            "message": "If the account exists and is not verified, a new verification email has been sent."
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Resend verification request failed")
        return jsonify({"status": "error", "message": "The request could not be completed."}), 500
    finally:
        if connection:
            connection.close()


@app.route("/api/auth/verify", methods=["GET"])
def auth_verify_email():
    raw_token = request.args.get("token", "").strip()
    if not raw_token:
        return jsonify({"status": "error", "message": "Verification token is missing."}), 400

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                SET email_verified = TRUE,
                    verification_token_hash = NULL,
                    verification_expires_at = NULL
                WHERE verification_token_hash = %s
                  AND verification_expires_at > NOW()
                  AND email_verified = FALSE
                RETURNING email
                """,
                (token_hash,)
            )
            user = cursor.fetchone()
        connection.commit()

        if not user:
            return jsonify({
                "status": "error",
                "message": "This verification link is invalid, expired, or has already been used. Request a new verification email."
            }), 400

        return jsonify({
            "status": "success",
            "message": "Email verified successfully. You can now log in."
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Email verification failed")
        return jsonify({"status": "error", "message": "Email verification could not be completed."}), 500
    finally:
        if connection:
            connection.close()


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "A valid JSON request is required."}), 400

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")
    if not email or not isinstance(password, str):
        return jsonify({"status": "error", "message": "Email and password are required."}), 400

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, email, password_hash, email_verified, notification_enabled
                FROM users
                WHERE email = %s
                LIMIT 1
                """,
                (email,)
            )
            user = cursor.fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify({"status": "error", "message": "Invalid email or password."}), 401

        if not user["email_verified"]:
            return jsonify({
                "status": "error",
                "code": "EMAIL_NOT_VERIFIED",
                "message": "Please verify your email address before logging in."
            }), 403

        token = _auth_serializer(AUTH_TOKEN_SALT).dumps({
            "user_id": int(user["id"]),
            "email": user["email"]
        })

        return jsonify({
            "status": "success",
            "message": "Login successful.",
            "token": token,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "email_verified": user["email_verified"],
                "notification_enabled": user["notification_enabled"]
            }
        }), 200
    except Exception:
        app.logger.exception("User login failed")
        return jsonify({"status": "error", "message": "Login could not be completed."}), 500
    finally:
        if connection:
            connection.close()


@app.route("/api/auth/request-password-reset", methods=["POST"])
def auth_request_password_reset():
    data = request.get_json(silent=True)
    email = str((data or {}).get("email", "")).strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"status": "error", "message": "Enter a valid email address."}), 400

    connection = None
    try:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                SET password_reset_token_hash = %s,
                    password_reset_expires_at = NOW() + INTERVAL '30 minutes'
                WHERE email = %s AND email_verified = TRUE
                RETURNING email
                """,
                (token_hash, email)
            )
            user = cursor.fetchone()
        connection.commit()

        # Keep the response identical whether or not the email is registered.
        if user:
            try:
                _send_password_reset_email(user["email"], raw_token)
            except Exception:
                app.logger.exception("Password reset email could not be sent")

        return jsonify({
            "status": "success",
            "message": "If a verified account exists for that email, a password reset link has been sent. Check your inbox and spam folder."
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Password reset request failed")
        return jsonify({"status": "error", "message": "The password reset request could not be completed."}), 500
    finally:
        if connection:
            connection.close()


@app.route("/api/auth/reset-password", methods=["POST"])
def auth_reset_password():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "A valid JSON request is required."}), 400

    raw_token = str(data.get("token", "")).strip()
    new_password = data.get("password", "")
    if not raw_token:
        return jsonify({"status": "error", "message": "The password reset token is missing."}), 400
    if not isinstance(new_password, str) or len(new_password) < 8 or len(new_password) > 128:
        return jsonify({"status": "error", "message": "Password must contain 8 to 128 characters."}), 400

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    connection = None
    try:
        new_password_hash = generate_password_hash(new_password)
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                SET password_hash = %s,
                    password_reset_token_hash = NULL,
                    password_reset_expires_at = NULL
                WHERE password_reset_token_hash = %s
                  AND password_reset_expires_at > NOW()
                  AND email_verified = TRUE
                RETURNING id
                """,
                (new_password_hash, token_hash)
            )
            user = cursor.fetchone()
        connection.commit()

        if not user:
            return jsonify({
                "status": "error",
                "message": "This password reset link is invalid, expired, or already used. Request a new link."
            }), 400

        return jsonify({
            "status": "success",
            "message": "Password updated successfully. You can now log in using your new password."
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Password reset could not be completed")
        return jsonify({"status": "error", "message": "The password could not be updated."}), 500
    finally:
        if connection:
            connection.close()


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def auth_me():
    user = request.authenticated_user
    return jsonify({
        "status": "success",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "email_verified": user["email_verified"],
            "notification_enabled": user["notification_enabled"]
        }
    }), 200


@app.route("/api/auth/notification-preference", methods=["GET"])
@require_auth
def get_notification_preference():
    user = request.authenticated_user
    return jsonify({
        "status": "success",
        "notification_enabled": bool(user["notification_enabled"])
    }), 200


@app.route("/api/auth/notification-preference", methods=["PUT"])
@require_auth
def update_notification_preference():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("notification_enabled"), bool):
        return jsonify({
            "status": "error",
            "message": "notification_enabled must be true or false."
        }), 400

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                SET notification_enabled = %s
                WHERE id = %s
                RETURNING notification_enabled
                """,
                (data["notification_enabled"], request.authenticated_user["id"])
            )
            result = cursor.fetchone()
        connection.commit()
        return jsonify({
            "status": "success",
            "message": "Notification preference updated.",
            "notification_enabled": bool(result["notification_enabled"])
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Notification preference update failed")
        return jsonify({"status": "error", "message": "Notification preference could not be updated."}), 500
    finally:
        if connection:
            connection.close()



BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = (
    BASE_DIR
    / "data"
    / "cowrie_refined_dataset_enriched_ips.csv"
)

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "models"
    / "cowrie_risk_model.joblib"
)


# =========================================================
# EMAIL NOTIFICATION CONFIGURATION
# =========================================================

ALERT_EMAIL_SENDER = os.getenv(
    "ALERT_EMAIL_SENDER",
    ""
).strip()

ALERT_EMAIL_PASSWORD = os.getenv(
    "ALERT_EMAIL_PASSWORD",
    ""
).strip()

ALERT_EMAIL_RECIPIENT = os.getenv(
    "ALERT_EMAIL_RECIPIENT",
    ""
).strip()

SMTP_HOST = os.getenv(
    "ALERT_SMTP_HOST",
    "smtp.gmail.com"
).strip()

SMTP_PORT = int(
    os.getenv(
        "ALERT_SMTP_PORT",
        "587"
    )
)

alert_lock = Lock()
INDIA_TZ = ZoneInfo("Asia/Kolkata")


# =========================================================
# SHAP MODEL
# =========================================================

shap_model_bundle = None
shap_explainer = None
shap_model_lock = Lock()


def load_shap_model():

    global shap_model_bundle
    global shap_explainer

    with shap_model_lock:

        if (
            shap_model_bundle is not None
            and shap_explainer is not None
        ):
            return (
                shap_model_bundle,
                shap_explainer
            )

        if not MODEL_PATH.exists():

            raise FileNotFoundError(
                "SHAP model not found. Run "
                "py backend\\shap_risk_model.py first."
            )

        shap_model_bundle = joblib.load(
            MODEL_PATH
        )

        if not isinstance(
            shap_model_bundle,
            dict
        ):

            raise ValueError(
                "Saved SHAP model file has an invalid format."
            )

        if "model" not in shap_model_bundle:

            raise ValueError(
                "Saved SHAP model does not contain a 'model' entry."
            )

        if "feature_names" not in shap_model_bundle:

            raise ValueError(
                "Saved SHAP model does not contain feature names."
            )

        shap_explainer = shap.TreeExplainer(
            shap_model_bundle["model"]
        )

        return (
            shap_model_bundle,
            shap_explainer
        )


def get_shap_values_for_row(
    explainer,
    model,
    X_row
):

    shap_values = explainer.shap_values(
        X_row
    )

    predicted_label = model.predict(
        X_row
    )[0]

    classes = list(
        model.classes_
    )

    try:

        predicted_class_index = classes.index(
            predicted_label
        )

    except ValueError:

        predicted_class_index = 0

    if isinstance(
        shap_values,
        list
    ):

        values = np.asarray(
            shap_values[
                predicted_class_index
            ]
        )[0]

    else:

        values_array = np.asarray(
            shap_values
        )

        if values_array.ndim == 3:

            if values_array.shape[1] == len(classes):

                values = values_array[
                    0,
                    predicted_class_index,
                    :
                ]

            else:

                values = values_array[
                    0,
                    :,
                    predicted_class_index
                ]

        elif values_array.ndim == 2:

            values = values_array[0]

        else:

            values = values_array.reshape(-1)

    return (
        np.asarray(
            values,
            dtype=float
        ),
        predicted_label
    )


def build_shap_explanation(
    df,
    row_index
):

    if (
        row_index < 0
        or row_index >= len(df)
    ):

        raise IndexError(
            f"Dataset index must be between 0 and {len(df) - 1}."
        )

    model_bundle, explainer = (
        load_shap_model()
    )

    model = model_bundle["model"]

    feature_names = list(
        model_bundle["feature_names"]
    )

    X_all = extract_features(
        df
    )

    missing_features = [
        feature
        for feature in feature_names
        if feature not in X_all.columns
    ]

    if missing_features:

        raise ValueError(
            "The current feature extractor is missing model "
            "features: "
            + ", ".join(missing_features)
        )

    X_all = X_all[
        feature_names
    ]

    X_row = X_all.iloc[
        [row_index]
    ]

    shap_values, predicted_label = (
        get_shap_values_for_row(
            explainer,
            model,
            X_row
        )
    )

    if len(shap_values) != len(
        feature_names
    ):

        raise ValueError(
            "SHAP output size does not match the model feature count."
        )

    contribution_df = pd.DataFrame({

        "feature":
            feature_names,

        "shap_value":
            shap_values,

        "absolute_value":
            np.abs(shap_values),

        "feature_value":
            X_row.iloc[0].values

    })

    contribution_df = (
        contribution_df
        .sort_values(
            "absolute_value",
            ascending=False
        )
    )

    top_contributions = []

    for _, contribution in (
        contribution_df.head(10).iterrows()
    ):

        shap_value = float(
            contribution["shap_value"]
        )

        if shap_value > 0:

            effect = (
                "increases predicted risk"
            )

        elif shap_value < 0:

            effect = (
                "decreases predicted risk"
            )

        else:

            effect = (
                "no measurable effect"
            )

        top_contributions.append({

            "feature":
                str(
                    contribution["feature"]
                ),

            "value":
                make_json_safe(
                    contribution[
                        "feature_value"
                    ]
                ),

            "shap_value":
                round(
                    shap_value,
                    6
                ),

            "absolute_shap_value":
                round(
                    float(
                        contribution[
                            "absolute_value"
                        ]
                    ),
                    6
                ),

            "effect":
                effect

        })

    original_record = (
        df.iloc[row_index].to_dict()
    )

    return {

        "dataset_index":
            row_index,

        "actual_risk_level":
            str(
                original_record.get(
                    "risk_level",
                    ""
                )
            ),

        "predicted_risk_level":
            str(
                predicted_label
            ),

        "model_type":
            "Random Forest",

        "explanation_method":
            "SHAP TreeExplainer",

        "shap_values":
            top_contributions

    }


# =========================================================
# LIVE COWRIE STORAGE
# =========================================================
#
# Genuine Cowrie events received through /api/live-event
# are stored persistently in SQLite.
#
# This keeps previous live records available after Flask
# restarts or system reboots. The existing CSV dataset is
# kept separate.
# =========================================================

LIVE_DB_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "live_events.db"
)

MAX_LIVE_EVENTS = 500

live_db_lock = Lock()

live_session_context = {}
live_session_lock = Lock()


def initialize_live_database():

    LIVE_DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with sqlite3.connect(
        LIVE_DB_PATH
    ) as connection:

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS live_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT UNIQUE,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS email_notifications (
                event_key TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                sent_at TEXT
            )
            """
        )

        connection.commit()


def build_live_event_key(record):

    return "|".join([
        str(record.get("timestamp", "")),
        str(record.get("event_id", "")),
        str(record.get("session", "")),
        str(record.get("src_ip", "")),
        str(record.get("src_port", "")),
        str(record.get("destination_port", "")),
        str(record.get("command_input", "")),
    ])


def store_live_event(record):

    safe_record = make_json_safe(record)
    event_key = build_live_event_key(safe_record)

    with live_db_lock:

        with sqlite3.connect(
            LIVE_DB_PATH
        ) as connection:

            connection.execute(
                """
                INSERT OR IGNORE INTO live_events
                (
                    event_key,
                    event_json,
                    created_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    event_key,
                    json.dumps(
                        safe_record
                    ),
                    datetime.now().isoformat()
                )
            )

            # Keep the newest MAX_LIVE_EVENTS records.
            connection.execute(
                """
                DELETE FROM live_events
                WHERE id NOT IN (
                    SELECT id
                    FROM live_events
                    ORDER BY id DESC
                    LIMIT ?
                )
                """,
                (MAX_LIVE_EVENTS,)
            )

            connection.commit()


def load_live_events(limit=50):

    with live_db_lock:

        with sqlite3.connect(
            LIVE_DB_PATH
        ) as connection:

            rows = connection.execute(
                """
                SELECT event_json
                FROM live_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

    events = []

    for row in rows:

        try:
            events.append(
                json.loads(
                    row[0]
                )
            )

        except Exception:
            continue

    return events


def get_live_event_count():

    with live_db_lock:

        with sqlite3.connect(
            LIVE_DB_PATH
        ) as connection:

            row = connection.execute(
                "SELECT COUNT(*) FROM live_events"
            ).fetchone()

    return int(row[0])


initialize_live_database()


# =========================================================
# JSON SAFETY
# =========================================================

def make_json_safe(value):

    if isinstance(
        value,
        dict
    ):

        return {
            key: make_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        list
    ):

        return [
            make_json_safe(item)
            for item in value
        ]

    try:

        if pd.isna(value):

            return None

    except (
        TypeError,
        ValueError
    ):

        pass

    if hasattr(
        value,
        "item"
    ):

        try:

            return make_json_safe(
                value.item()
            )

        except (
            ValueError,
            TypeError
        ):

            pass

    return value


def records_to_json_safe(df):

    records = df.to_dict(
        orient="records"
    )

    return make_json_safe(
        records
    )


# =========================================================
# EMAIL HELPERS
# =========================================================

def format_timestamp_ist(value):

    if not value:
        return value

    try:
        text = str(value).strip()
        if text.endswith("Z"):
            dt = datetime.fromisoformat(
                text[:-1] + "+00:00"
            )
        else:
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(INDIA_TZ).strftime(
            "%d %b %Y, %I:%M:%S %p IST"
        )
    except (ValueError, TypeError):
        return str(value)


def claim_email_notification(event_key):

    with live_db_lock:
        with sqlite3.connect(LIVE_DB_PATH) as connection:
            connection.execute("PRAGMA busy_timeout = 5000")

            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO email_notifications
                (event_key, status, sent_at)
                VALUES (?, 'sending', NULL)
                """,
                (event_key,)
            )

            connection.commit()

            if cursor.rowcount == 1:
                return "claimed"

            row = connection.execute(
                """
                SELECT status
                FROM email_notifications
                WHERE event_key = ?
                LIMIT 1
                """,
                (event_key,)
            ).fetchone()

    if row and row[0] == "sent":
        return "already_sent"

    return "already_processing"


def mark_email_notification_sent(event_key):

    with live_db_lock:
        with sqlite3.connect(LIVE_DB_PATH) as connection:
            connection.execute(
                """
                UPDATE email_notifications
                SET status = 'sent',
                    sent_at = ?
                WHERE event_key = ?
                """,
                (datetime.now(timezone.utc).isoformat(), event_key)
            )
            connection.commit()


def release_email_notification_claim(event_key):

    with live_db_lock:
        with sqlite3.connect(LIVE_DB_PATH) as connection:
            connection.execute(
                "DELETE FROM email_notifications WHERE event_key = ?",
                (event_key,)
            )
            connection.commit()


def email_alerts_configured():

    return bool(
        ALERT_EMAIL_SENDER
        and ALERT_EMAIL_PASSWORD
    )


def build_event_key(record):

    return "|".join([

        str(
            record.get(
                "timestamp",
                ""
            )
        ),

        str(
            record.get(
                "event_id",
                ""
            )
        ),

        str(
            record.get(
                "event_type",
                ""
            )
        ),

        str(
            record.get(
                "src_ip",
                ""
            )
        ),

        str(
            record.get(
                "destination_port",
                ""
            )
        ),

        str(
            record.get(
                "command_input",
                ""
            )
        ),

        str(
            record.get(
                "calculated_risk_score",
                ""
            )
        ),

        str(
            record.get(
                "calculated_risk_level",
                ""
            )
        ),

    ])


def get_verified_notification_recipients():
    """Return only verified users who opted in to security notifications."""
    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT email
                FROM users
                WHERE email_verified = TRUE
                  AND notification_enabled = TRUE
                ORDER BY id
                """
            )
            rows = cursor.fetchall()
        return [row["email"] for row in rows if row.get("email")]
    finally:
        if connection:
            connection.close()


def send_email_notification(record):
    risk_level = str(
        record.get("calculated_risk_level", "")
    ).strip()

    if risk_level not in {"High", "Critical"}:
        return {
            "sent": False,
            "status": "not_required",
            "message": "Email notification is only required for High or Critical risk."
        }

    if not email_alerts_configured():
        return {
            "sent": False,
            "status": "not_configured",
            "message": "SMTP sender credentials are not configured."
        }

    event_key = build_event_key(record)
    claim_status = claim_email_notification(event_key)

    if claim_status == "already_sent":
        return {
            "sent": False,
            "status": "already_notified",
            "message": "This event has already generated an email notification."
        }

    if claim_status == "already_processing":
        return {
            "sent": False,
            "status": "already_processing",
            "message": "Email notification is already being processed for this event."
        }

    try:
        recipients = get_verified_notification_recipients()
        if not recipients:
            release_email_notification_claim(event_key)
            return {
                "sent": False,
                "status": "no_subscribers",
                "message": "No verified users have enabled email notifications."
            }

        src_ip = record.get("src_ip", "Unknown")
        timestamp = format_timestamp_ist(record.get("timestamp", "Unknown"))
        event_id = record.get("event_id", "Unknown")
        event_type = record.get("event_type", "Unknown")
        score = record.get("calculated_risk_score", "Unknown")
        reasons = record.get("risk_reasons", [])
        explanation = record.get("explanation", "")
        command = record.get("command_input", "")

        action = (
            "Email notification generated. Automatic IP blocking is not enabled "
            "in the current implementation."
            if risk_level == "Critical"
            else "Email notification generated."
        )

        reason_text = "\n".join(f"- {reason}" for reason in reasons)
        subject = f"[Cowrie Security Alert] {risk_level} Risk Activity Detected"
        body = f"""Cowrie Cyber Threat Detection System

A {risk_level.lower()}-risk activity was detected.

Risk level: {risk_level}
Risk score: {score}/100
Source IP: {src_ip}
Timestamp: {timestamp}
Event ID: {event_id}
Event type: {event_type}
Command: {command or "N/A"}

Reason:
{reason_text}

Explanation:
{explanation}

System response:
{action}

This notification was generated automatically by the
Cowrie Cyber Threat Detection application.
"""

        delivered = []
        failed = []
        for recipient in recipients:
            try:
                message = EmailMessage()
                message["From"] = ALERT_EMAIL_SENDER
                message["To"] = recipient
                message["Subject"] = subject
                message.set_content(body)

                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
                    smtp.starttls()
                    smtp.login(ALERT_EMAIL_SENDER, ALERT_EMAIL_PASSWORD)
                    smtp.send_message(message)
                delivered.append(recipient)
            except Exception:
                app.logger.exception("Security alert email delivery failed for one recipient")
                failed.append(recipient)

        if delivered:
            mark_email_notification_sent(event_key)
            return {
                "sent": True,
                "status": "sent" if not failed else "partially_sent",
                "message": f"Security alert delivered to {len(delivered)} verified user(s).",
                "recipient_count": len(delivered),
                "failed_count": len(failed)
            }

        release_email_notification_claim(event_key)
        return {
            "sent": False,
            "status": "error",
            "message": "Email delivery failed for all opted-in users."
        }

    except Exception:
        release_email_notification_claim(event_key)
        app.logger.exception("Multi-user email notification failed")
        return {
            "sent": False,
            "status": "error",
            "message": "Email notification could not be completed."
        }


# =========================================================
# DATASET
# =========================================================

def load_dataset():

    return pd.read_csv(
        DATASET_PATH
    )


def clean_records(df):

    df = df.astype(object)

    df = df.where(
        pd.notna(df),
        None
    )

    return df


# =========================================================
# EXISTING RISK ANALYSIS
# =========================================================

RECON_COMMANDS = {

    "whoami",
    "id",
    "uname",
    "hostname",
    "pwd",
    "ifconfig",
    "ip",
    "ip addr",
    "ip a",
    "netstat",
    "ss",
    "ps",
    "w",
    "who",
    "last",
    "env",

}


SUSPICIOUS_FILE_COMMANDS = {

    "cat /etc/passwd",
    "cat /etc/shadow",
    "wget",
    "curl",
    "nc",
    "netcat",

}


def get_command_value(row):

    command_value = row.get(
        "command_input"
    )

    if pd.isna(
        command_value
    ):

        command_value = row.get(
            "input"
        )

    if pd.isna(
        command_value
    ):

        command_value = row.get(
            "command"
        )

    if pd.isna(
        command_value
    ):

        command_value = ""

    return str(
        command_value
    ).strip().lower()


def calculate_risk(row):

    score = 0

    reasons = []

    event_id = str(
        row.get(
            "event_id",
            ""
        ) or ""
    ).lower()

    event_type = str(
        row.get(
            "event_type",
            ""
        ) or ""
    ).lower()

    command = get_command_value(
        row
    )

    # -----------------------------------------------------
    # 1. CONNECTION
    # -----------------------------------------------------

    if (
        "connect" in event_id
        or "connection" in event_type
        or "session.connect" in event_id
    ):

        score += 5

        reasons.append(
            "New SSH connection observed"
        )

    # -----------------------------------------------------
    # 2. RECONNAISSANCE
    # -----------------------------------------------------

    if any(
        keyword in event_id
        for keyword in [

            "client.version",
            "client.kex",
            "client.size",
            "session.params",
            "recon",

        ]
    ):

        score += 10

        reasons.append(
            "SSH reconnaissance or session information observed"
        )

    # -----------------------------------------------------
    # 3. FAILED LOGIN
    # -----------------------------------------------------

    if (
        "login.failed" in event_id
        or "login.failed" in event_type
        or "failed" in event_id
    ):

        score += 30

        reasons.append(
            "Failed SSH authentication attempt detected"
        )

    # -----------------------------------------------------
    # 4. SUCCESSFUL LOGIN
    # -----------------------------------------------------

    if (
        "login.success" in event_id
        or "login.success" in event_type
        or "success" in event_id
    ):

        score += 60

        reasons.append(
            "Successful SSH authentication observed"
        )

    # -----------------------------------------------------
    # 5. COMMAND
    # -----------------------------------------------------

    is_command_event = (
        "command" in event_id
        or "input" in event_id
    )

    if command or is_command_event:

        score += 20

        reasons.append(
            "Command executed after SSH access"
        )

        if command:

            command_name = (
                command.split(" ")[0]
            )

            if (
                command in RECON_COMMANDS
                or command_name in RECON_COMMANDS
            ):

                score += 35

                reasons.append(
                    "Post-login reconnaissance command "
                    f"detected: {command}"
                )

            elif any(
                suspicious in command
                for suspicious in SUSPICIOUS_FILE_COMMANDS
            ):

                score += 55

                reasons.append(
                    "Suspicious command detected: "
                    f"{command}"
                )

    # -----------------------------------------------------
    # 6. SUSPICIOUS COMMAND FALLBACK
    # -----------------------------------------------------

    if command:

        suspicious_keywords = [

            "wget",
            "curl",
            "chmod",
            "passwd",
            "shadow",
            "bash -c",
            "nc ",
            "netcat",

        ]

        if any(
            keyword in command
            for keyword in suspicious_keywords
        ):

            already_detected = any(
                "Suspicious command detected"
                in reason
                for reason in reasons
            )

            if not already_detected:

                score += 35

                reasons.append(
                    "Suspicious command detected: "
                    f"{command}"
                )

    # -----------------------------------------------------
    # 7. LIMIT
    # -----------------------------------------------------

    score = min(
        score,
        100
    )

    # -----------------------------------------------------
    # 8. RISK LEVEL
    # -----------------------------------------------------

    if score >= 75:

        risk_level = "Critical"

        recommended_action = (
            "Immediate attention required; "
            "automatic IP blocking is not enabled"
        )

    elif score >= 50:

        risk_level = "High"

        recommended_action = (
            "High-risk activity detected; "
            "email notification required"
        )

    elif score >= 25:

        risk_level = "Medium"

        recommended_action = (
            "Continue monitoring"
        )

    else:

        risk_level = "Low"

        recommended_action = (
            "Continue monitoring"
        )

    # -----------------------------------------------------
    # 9. EXPLANATION
    # -----------------------------------------------------

    if risk_level == "Critical":

        explanation = (
            "The observed activity contains multiple "
            "high-risk indicators and requires immediate "
            "attention."
        )

    elif risk_level == "High":

        explanation = (
            "The activity indicates potentially harmful "
            "attacker behaviour after or during SSH "
            "interaction."
        )

    elif risk_level == "Medium":

        explanation = (
            "The activity shows suspicious behaviour "
            "that should be monitored for further "
            "escalation."
        )

    else:

        explanation = (
            "The observed activity is currently low risk "
            "based on the defined detection rules."
        )

    if not reasons:

        reasons.append(
            "No major suspicious indicator detected"
        )

    return {

        "calculated_risk_score":
            score,

        "calculated_risk_level":
            risk_level,

        "risk_reasons":
            reasons,

        "recommended_action":
            recommended_action,

        "explanation":
            explanation

    }


def analyse_dataframe(df):

    analysed_records = []

    for row_index, row in df.iterrows():

        original_record = (
            row.to_dict()
        )

        original_record[
            "dataset_index"
        ] = int(
            row_index
        )

        risk_result = (
            calculate_risk(row)
        )

        original_record.update(
            risk_result
        )

        analysed_records.append(
            original_record
        )

    return pd.DataFrame(
        analysed_records
    )


def get_alert_records(
    df,
    limit=100
):

    analysed_df = (
        analyse_dataframe(df)
    )

    alert_df = analysed_df[
        analysed_df[
            "calculated_risk_level"
        ].isin(
            [
                "High",
                "Critical"
            ]
        )
    ].copy()

    timestamp_column = None

    for column in [

        "timestamp",
        "time",
        "datetime",
        "date",
        "event_time",

    ]:

        if column in alert_df.columns:

            timestamp_column = column

            break

    if timestamp_column:

        parsed_time = pd.to_datetime(
            alert_df[
                timestamp_column
            ],
            errors="coerce"
        )

        alert_df[
            "_sort_time"
        ] = parsed_time

        alert_df = (
            alert_df
            .sort_values(
                "_sort_time",
                ascending=False,
                na_position="last"
            )
            .drop(
                columns=[
                    "_sort_time"
                ]
            )
        )

    return alert_df.head(
        limit
    ).copy()


# =========================================================
# LIVE COWRIE ADAPTER
# =========================================================

def infer_attack_type(
    event_id,
    command
):

    event_id = str(
        event_id or ""
    ).lower()

    command = str(
        command or ""
    ).lower().strip()

    if (
        "login.failed" in event_id
        or "failed" in event_id
        or "authentication" in event_id
    ):

        return "bruteforce"

    if any(
        keyword in command
        for keyword in [

            "wget",
            "curl",
            "ftp",
            "tftp",
            "nc ",
            "netcat",
            "download",
            "base64",

        ]
    ):

        return "malware"

    if any(
        keyword in command
        for keyword in [

            "whoami",
            "uname",
            "id",
            "pwd",
            "hostname",
            "ifconfig",
            "ip addr",
            "ip a",
            "netstat",
            "ss",
            "ps",
            "last",
            "env",

        ]
    ):

        return "recon"

    if (
        "login.success" in event_id
        or "session.open" in event_id
    ):

        return "authentication"

    if "command" in event_id:

        return "command_activity"

    if "session.connect" in event_id:

        return "connection"

    return "unknown"


def infer_is_attack(
    event_id,
    command
):

    event_id = str(
        event_id or ""
    ).lower()

    command = str(
        command or ""
    ).lower().strip()

    if (
        "login.failed" in event_id
        or "login.success" in event_id
        or "command.input" in event_id
    ):

        return 1

    if any(
        keyword in command
        for keyword in [

            "whoami",
            "uname",
            "id",
            "pwd",
            "hostname",
            "ifconfig",
            "ip ",
            "netstat",
            "ss ",
            "ps ",
            "wget",
            "curl",
            "nc ",
            "netcat",
            "chmod",
            "passwd",
            "/etc/passwd",
            "/etc/shadow",

        ]
    ):

        return 1

    return 0


def normalize_cowrie_event(
    payload
):

    if not isinstance(
        payload,
        dict
    ):

        raise ValueError(
            "Cowrie event must be a JSON object."
        )

    event_id = (
        payload.get(
            "eventid"
        )
        or payload.get(
            "event_id"
        )
        or ""
    )

    event_type = (
        payload.get(
            "event_type"
        )
        or event_id
        or ""
    )

    session_id = str(
        payload.get(
            "session"
        )
        or ""
    )

    timestamp = (
        payload.get(
            "timestamp"
        )
        or datetime.now().isoformat()
    )

    src_ip = (
        payload.get(
            "src_ip"
        )
        or ""
    )

    src_port = (
        payload.get(
            "src_port"
        )
        or 0
    )

    destination_port = (
        payload.get(
            "dst_port"
        )
        or payload.get(
            "destination_port"
        )
        or 2222
    )

    command_input = (
        payload.get(
            "input"
        )
        or payload.get(
            "command_input"
        )
        or payload.get(
            "command"
        )
        or ""
    )

    username = (
        payload.get(
            "username"
        )
        or ""
    )

    # The trained feature extractor requires the password column.
    # Cowrie includes this value on authentication events; other event
    # types legitimately omit it, so use an empty string. The model
    # derives only password_present/password_length from this value.
    password = (
        payload.get(
            "password"
        )
        or ""
    )

    client_version = (
        payload.get(
            "version"
        )
        or payload.get(
            "client_version"
        )
        or ""
    )

    message = (
        payload.get(
            "message"
        )
        or ""
    )

    # -----------------------------------------------------
    # Recover session information from earlier Cowrie
    # events.
    # -----------------------------------------------------

    with live_session_lock:

        previous = (
            live_session_context.get(
                session_id,
                {}
            )
        )

        if username:

            previous[
                "username"
            ] = username

        elif previous.get(
            "username"
        ):

            username = previous[
                "username"
            ]


        if client_version:

            previous[
                "client_version"
            ] = client_version

        elif previous.get(
            "client_version"
        ):

            client_version = previous[
                "client_version"
            ]

        if src_ip:

            previous[
                "src_ip"
            ] = src_ip

        elif previous.get(
            "src_ip"
        ):

            src_ip = previous[
                "src_ip"
            ]

        if src_port:

            previous[
                "src_port"
            ] = src_port

        elif previous.get(
            "src_port"
        ):

            src_port = previous[
                "src_port"
            ]

        live_session_context[
            session_id
        ] = previous

    attack_type = infer_attack_type(
        event_id,
        command_input
    )

    is_attack = infer_is_attack(
        event_id,
        command_input
    )

    # -----------------------------------------------------
    # risk_level is required by the current feature
    # extractor, but it is NOT used as a model feature.
    #
    # We deliberately use a neutral placeholder here so
    # the live model does not receive the answer it is
    # supposed to predict.
    # -----------------------------------------------------

    record = {

        "timestamp":
            timestamp,

        "src_ip":
            src_ip,

        "src_port":
            src_port,

        "username":
            username,

        "password":
            password,

        "client_version":
            client_version,

        "command_input":
            command_input,

        "message":
            message,

        "event_id":
            event_id,

        "event_type":
            event_type,

        "session":
            session_id,

        "attack_type":
            attack_type,

        "destination_port":
            destination_port,

        "is_attack":
            is_attack,

        "risk_level":
            "Low",

        "data_origin":
            "live_cowrie",

    }

    return record


# =========================================================
# LIVE RANDOM FOREST + SHAP
# =========================================================

def analyse_live_with_model(
    record
):

    model_bundle, explainer = (
        load_shap_model()
    )

    model = (
        model_bundle["model"]
    )

    feature_names = list(
        model_bundle[
            "feature_names"
        ]
    )

    live_df = pd.DataFrame(
        [record]
    )

    X_live = extract_features(
        live_df
    )

    missing_features = [
        feature
        for feature in feature_names
        if feature not in X_live.columns
    ]

    if missing_features:

        raise ValueError(
            "Live feature extraction is missing model features: "
            + ", ".join(
                missing_features
            )
        )

    X_live = X_live[
        feature_names
    ]

    predicted_label = (
        model.predict(
            X_live
        )[0]
    )

    probabilities = {}

    if hasattr(
        model,
        "predict_proba"
    ):

        probability_values = (
            model.predict_proba(
                X_live
            )[0]
        )

        for label, probability in zip(
            model.classes_,
            probability_values
        ):

            probabilities[
                str(label)
            ] = round(
                float(probability),
                6
            )

    shap_values, _ = (
        get_shap_values_for_row(
            explainer,
            model,
            X_live
        )
    )

    contributions = []

    for feature_name, shap_value, feature_value in zip(
        feature_names,
        shap_values,
        X_live.iloc[0].values
    ):

        shap_value = float(
            shap_value
        )

        if shap_value > 0:

            effect = (
                "increases predicted risk"
            )

        elif shap_value < 0:

            effect = (
                "decreases predicted risk"
            )

        else:

            effect = (
                "no measurable effect"
            )

        contributions.append({

            "feature":
                feature_name,

            "value":
                make_json_safe(
                    feature_value
                ),

            "shap_value":
                round(
                    shap_value,
                    6
                ),

            "absolute_shap_value":
                round(
                    abs(shap_value),
                    6
                ),

            "effect":
                effect

        })

    contributions.sort(
        key=lambda item:
            item[
                "absolute_shap_value"
            ],
        reverse=True
    )

    return {

        "predicted_risk_level":
            str(
                predicted_label
            ),

        "model_type":
            "Random Forest",

        "explanation_method":
            "SHAP TreeExplainer",

        "class_probabilities":
            probabilities,

        "shap_values":
            contributions[:10]

    }


# =========================================================
# LIVE EVENT ENDPOINT
# =========================================================

@app.route(
    "/api/live-event",
    methods=["POST"]
)
def live_event():

    try:

        payload = request.get_json(
            silent=True
        )

        if not payload:

            return jsonify({

                "status":
                    "error",

                "message":
                    "No JSON Cowrie event was received."

            }), 400

        # -------------------------------------------------
        # Convert genuine Cowrie JSON into the same record
        # structure used by the existing ML feature extractor.
        # -------------------------------------------------

        record = normalize_cowrie_event(
            payload
        )

        # -------------------------------------------------
        # Existing explainable risk rules
        # -------------------------------------------------

        risk_result = calculate_risk(
            record
        )

        record.update(
            risk_result
        )

        # The feature extractor requires a risk_level field as a
        # neutral model-input placeholder. After rule analysis,
        # expose the actual calculated live risk level consistently.
        record[
            "risk_level"
        ] = risk_result[
            "calculated_risk_level"
        ]

        # -------------------------------------------------
        # Random Forest + SHAP
        # -------------------------------------------------

        model_result = (
            analyse_live_with_model(
                record
            )
        )

        record[
            "ml_predicted_risk_level"
        ] = model_result[
            "predicted_risk_level"
        ]

        record[
            "ml_class_probabilities"
        ] = model_result[
            "class_probabilities"
        ]

        record[
            "shap_explanation"
        ] = model_result[
            "shap_values"
        ]

        # The password is used only to derive the model's numeric
        # password_present/password_length features. Do not retain the
        # captured plaintext credential in stored events or notifications.
        record.pop("password", None)

        record[
            "processed_at"
        ] = datetime.now(timezone.utc).isoformat()

        record[
            "timestamp_ist"
        ] = format_timestamp_ist(
            record.get("timestamp", "")
        )

        # -------------------------------------------------
        # Email notification
        #
        # Existing project threshold is preserved:
        # High/Critical calculated risk generates email.
        # -------------------------------------------------

        email_result = (
            send_email_notification(
                record
            )
        )

        record[
            "email_notification"
        ] = email_result

        # Keep the live recommended action consistent with the
        # actual notification result.
        calculated_level = str(
            record.get(
                "calculated_risk_level",
                ""
            )
        )

        if calculated_level in {
            "High",
            "Critical"
        }:

            if email_result.get("status") == "sent":

                record[
                    "recommended_action"
                ] = "Email notification sent"

            elif email_result.get("status") == "not_configured":

                record[
                    "recommended_action"
                ] = (
                    "High/Critical risk detected; "
                    "email notification is not configured"
                )

            elif email_result.get("status") == "error":

                record[
                    "recommended_action"
                ] = (
                    "High/Critical risk detected; "
                    "email notification failed"
                )

            else:

                record[
                    "recommended_action"
                ] = "High/Critical risk detected; review immediately"

        else:

            record[
                "recommended_action"
            ] = "Continue monitoring"

        # -------------------------------------------------
        # Store live event persistently in SQLite.
        # -------------------------------------------------

        safe_record = make_json_safe(
            record
        )

        store_live_event(
            safe_record
        )

        return jsonify({

            "status":
                "success",

            "message":
                "Live Cowrie event analysed successfully.",

            "data":
                safe_record

        })

    except Exception as error:

        # Log the complete traceback so the exact failing stage
        # in live Cowrie event processing can be diagnosed.
        app.logger.exception(
            "Failed to process incoming Cowrie live event"
        )

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# LIVE EVENTS
# =========================================================

@app.route(
    "/api/live-logs"
)
def live_logs():

    try:

        limit = request.args.get(
            "limit",
            default=50,
            type=int
        )

        limit = max(
            1,
            min(
                limit,
                MAX_LIVE_EVENTS
            )
        )

        records = load_live_events(
            limit
        )

        return jsonify({

            "status":
                "success",

            "source":
                "live_cowrie",

            "total_live_events":
                get_live_event_count(),

            "returned_events":
                len(records),

            "data":
                make_json_safe(
                    records
                )

        })

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# LIVE STATUS
# =========================================================

@app.route(
    "/api/live-status"
)
def live_status():

    count = get_live_event_count()

    return jsonify({

        "status":
            "success",

        "live_integration":
            True,

        "source":
            "Cowrie JSON events",

        "events_received":
            count,

        "endpoint":
            "/api/live-event",

        "logs_endpoint":
            "/api/live-logs",

        "model":
            "Random Forest",

        "explainability":
            "SHAP TreeExplainer",

        "email_enabled":
            email_alerts_configured()

    })


# =========================================================
# SHAP STATUS
# =========================================================

@app.route(
    "/api/shap-status"
)
def shap_status():

    try:

        model_exists = (
            MODEL_PATH.exists()
        )

        if not model_exists:

            return jsonify({

                "status":
                    "success",

                "available":
                    False,

                "model_path":
                    str(
                        MODEL_PATH
                    ),

                "message":
                    "SHAP model has not been trained yet."

            })

        model_bundle, _ = (
            load_shap_model()
        )

        model = (
            model_bundle["model"]
        )

        return jsonify({

            "status":
                "success",

            "available":
                True,

            "model_type":
                "Random Forest",

            "explanation_method":
                "SHAP TreeExplainer",

            "feature_count":
                len(
                    model_bundle[
                        "feature_names"
                    ]
                ),

            "classes":
                [
                    str(label)
                    for label in model.classes_
                ]

        })

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "available":
                False,

            "message":
                str(error)

        }), 500


# =========================================================
# SHAP EXPLANATION
# =========================================================

@app.route(
    "/api/shap-explanation"
)
def shap_explanation():

    try:

        df = load_dataset()

        row_index = request.args.get(
            "index",
            default=0,
            type=int
        )

        result = (
            build_shap_explanation(
                df,
                row_index
            )
        )

        return jsonify({

            "status":
                "success",

            "data":
                result

        })

    except IndexError as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 400

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return jsonify({

        "message":
            "Cowrie Cyber Threat Detection API is running",

        "live_endpoint":
            "/api/live-event",

        "live_logs":
            "/api/live-logs",

        "live_status":
            "/api/live-status"

    })


# =========================================================
# TEST DATA
# =========================================================

@app.route(
    "/api/test-data"
)
def test_data():

    try:

        df = load_dataset()

        return jsonify({

            "status":
                "success",

            "total_records":
                len(df),

            "total_columns":
                len(df.columns),

            "columns":
                df.columns.tolist()

        })

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# ATTACK LOGS
# =========================================================

@app.route(
    "/api/logs"
)
def logs():

    try:

        df = load_dataset()

        limit = request.args.get(
            "limit",
            default=50,
            type=int
        )

        limit = max(
            1,
            min(
                limit,
                500
            )
        )

        records = clean_records(
            df.head(limit)
        )

        return jsonify({

            "status":
                "success",

            "total_records":
                len(df),

            "returned_records":
                len(records),

            "data":
                records_to_json_safe(
                    records
                )

        })

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# BASIC DATASET SUMMARY
# =========================================================

@app.route(
    "/api/summary"
)
def summary():

    try:

        df = load_dataset()

        total_events = len(
            df
        )

        if "is_attack" in df.columns:

            attack_events = int(
                df["is_attack"]
                .fillna(False)
                .astype(bool)
                .sum()
            )

        else:

            attack_events = 0

        if "risk_level" in df.columns:

            risk_counts = (
                df["risk_level"]
                .fillna("Unknown")
                .astype(str)
                .str.lower()
                .value_counts()
            )

            low_risk = int(
                risk_counts.get(
                    "low",
                    0
                )
            )

            medium_risk = int(
                risk_counts.get(
                    "medium",
                    0
                )
            )

            high_risk = int(
                risk_counts.get(
                    "high",
                    0
                )
            )

            critical_risk = int(
                risk_counts.get(
                    "critical",
                    0
                )
            )

        else:

            low_risk = 0
            medium_risk = 0
            high_risk = 0
            critical_risk = 0

        return jsonify({

            "status":
                "success",

            "total_events":
                total_events,

            "attack_events":
                attack_events,

            "risk_summary": {

                "low":
                    low_risk,

                "medium":
                    medium_risk,

                "high":
                    high_risk,

                "critical":
                    critical_risk

            }

        })

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# HOURLY ATTACK ACTIVITY
# =========================================================

@app.route(
    "/api/activity"
)
def activity():

    try:

        df = load_dataset()

        timestamp_column = None

        possible_columns = [

            "timestamp",
            "time",
            "datetime",
            "date",
            "event_time"

        ]

        for column in possible_columns:

            if column in df.columns:

                timestamp_column = column

                break

        if timestamp_column is None:

            return jsonify({

                "status":
                    "error",

                "message":
                    "No timestamp column found in dataset"

            }), 400

        timestamps = pd.to_datetime(
            df[
                timestamp_column
            ],
            errors="coerce"
        )

        timestamps = timestamps.dropna()

        if timestamps.empty:

            return jsonify({

                "status":
                    "error",

                "message":
                    "No valid timestamp values found"

            }), 400

        timestamps = (
            timestamps.sort_values()
        )

        hourly_activity = (
            timestamps
            .dt.floor("h")
            .value_counts()
            .sort_index()
        )

        activity_data = []

        for timestamp, count in (
            hourly_activity.items()
        ):

            activity_data.append({

                "time":
                    timestamp.strftime(
                        "%Y-%m-%d %H:%M"
                    ),

                "events":
                    int(count)

            })

        return jsonify({

            "status":
                "success",

            "timestamp_column":
                timestamp_column,

            "total_time_buckets":
                len(activity_data),

            "data":
                activity_data

        })

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# UPLOADED CSV DATASET ANALYSIS (ISOLATED FROM LIVE EVENTS)
# =========================================================

@app.route(
    "/api/analyse-dataset",
    methods=["POST"]
)
def analyse_uploaded_dataset():

    """Analyse a user-uploaded CSV with existing rule-based risk logic.

    The upload is processed in memory only. It is not saved, added to the
    training dataset, inserted into the live-event database, or emailed.
    """

    MAX_UPLOAD_BYTES = 5 * 1024 * 1024
    MAX_DATASET_ROWS = 5000
    MAX_DATASET_COLUMNS = 100

    uploaded_file = request.files.get("file")

    if uploaded_file is None or not uploaded_file.filename:
        return jsonify({
            "status": "error",
            "message": "Choose a CSV file before starting the analysis."
        }), 400

    if not uploaded_file.filename.lower().endswith(".csv"):
        return jsonify({
            "status": "error",
            "message": "Only .csv files are supported."
        }), 400

    try:
        file_bytes = uploaded_file.stream.read(MAX_UPLOAD_BYTES + 1)

        if not file_bytes:
            return jsonify({
                "status": "error",
                "message": "The uploaded CSV file is empty."
            }), 400

        if len(file_bytes) > MAX_UPLOAD_BYTES:
            return jsonify({
                "status": "error",
                "message": "The CSV file is too large. Maximum supported size is 5 MB."
            }), 413

        uploaded_df = pd.read_csv(
            io.BytesIO(file_bytes),
            low_memory=False
        )

        if uploaded_df.empty:
            return jsonify({
                "status": "error",
                "message": "The CSV contains no data rows."
            }), 400

        if len(uploaded_df.columns) > MAX_DATASET_COLUMNS:
            return jsonify({
                "status": "error",
                "message": f"The CSV has too many columns. Maximum supported columns: {MAX_DATASET_COLUMNS}."
            }), 400

        if len(uploaded_df) > MAX_DATASET_ROWS:
            return jsonify({
                "status": "error",
                "message": f"The CSV has too many rows. Maximum supported rows: {MAX_DATASET_ROWS}."
            }), 400

        uploaded_df.columns = [
            str(column).strip() for column in uploaded_df.columns
        ]

        if any(not column for column in uploaded_df.columns):
            return jsonify({
                "status": "error",
                "message": "Every CSV column must have a non-empty header."
            }), 400

        # Keep the existing calculate_risk/analyse_dataframe logic unchanged.
        # A useful event-related field must be present for these rules to assess.
        recognized_fields = {
            "event_id", "event_type", "command_input", "command", "input"
        }
        if not any(column in recognized_fields for column in uploaded_df.columns):
            return jsonify({
                "status": "error",
                "message": (
                    "The CSV must include at least one supported analysis column: "
                    "event_id, event_type, command_input, command, or input."
                )
            }), 400

        analysed_df = analyse_dataframe(uploaded_df)
        risk_counts = analysed_df["calculated_risk_level"].value_counts()
        records = records_to_json_safe(analysed_df)

        return jsonify({
            "status": "success",
            "message": "Uploaded CSV analysed successfully using the existing rule-based risk assessment.",
            "analysis_method": "Explainable rule-based risk assessment",
            "source": "Uploaded CSV (temporary in-memory analysis)",
            "total_records": int(len(analysed_df)),
            "risk_thresholds": {
                "low": "0-24",
                "medium": "25-49",
                "high": "50-74",
                "critical": "75-100"
            },
            "risk_summary": {
                "low": int(risk_counts.get("Low", 0)),
                "medium": int(risk_counts.get("Medium", 0)),
                "high": int(risk_counts.get("High", 0)),
                "critical": int(risk_counts.get("Critical", 0))
            },
            "data": records
        })

    except pd.errors.EmptyDataError:
        return jsonify({
            "status": "error",
            "message": "The uploaded file does not contain a readable CSV table."
        }), 400

    except (UnicodeDecodeError, pd.errors.ParserError, ValueError) as error:
        return jsonify({
            "status": "error",
            "message": f"Unable to read this CSV file: {str(error)}"
        }), 400

    except Exception:
        app.logger.exception("Uploaded dataset analysis failed")
        return jsonify({
            "status": "error",
            "message": "The dataset could not be analysed due to an unexpected server error."
        }), 500


# =========================================================
# EXPLAINABLE RISK ANALYSIS
# =========================================================

@app.route(
    "/api/risk-analysis"
)
def risk_analysis():

    try:

        df = load_dataset()

        limit = request.args.get(
            "limit",
            default=10,
            type=int
        )

        limit = max(
            1,
            min(
                limit,
                500
            )
        )

        analysed_df = (
            analyse_dataframe(
                df.head(limit)
            )
        )

        records = clean_records(
            analysed_df
        )

        risk_counts = (
            analysed_df[
                "calculated_risk_level"
            ]
            .value_counts()
        )

        return jsonify({

            "status":
                "success",

            "risk_method":
                "Explainable rule-based risk assessment",

            "analysed_records":
                len(records),

            "total_dataset_records":
                len(df),

            "risk_thresholds": {

                "low":
                    "0-24",

                "medium":
                    "25-49",

                "high":
                    "50-74",

                "critical":
                    "75-100"

            },

            "risk_summary": {

                "low":
                    int(
                        risk_counts.get(
                            "Low",
                            0
                        )
                    ),

                "medium":
                    int(
                        risk_counts.get(
                            "Medium",
                            0
                        )
                    ),

                "high":
                    int(
                        risk_counts.get(
                            "High",
                            0
                        )
                    ),

                "critical":
                    int(
                        risk_counts.get(
                            "Critical",
                            0
                        )
                    )

            },

            "data":
                records_to_json_safe(
                    records
                )

        })

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# COMPLETE DATASET RISK SUMMARY
# =========================================================

@app.route(
    "/api/risk-summary"
)
def risk_summary():

    try:

        df = load_dataset()

        analysed_df = (
            analyse_dataframe(
                df
            )
        )

        risk_counts = (
            analysed_df[
                "calculated_risk_level"
            ]
            .value_counts()
        )

        return jsonify({

            "status":
                "success",

            "risk_method":
                "Explainable rule-based risk assessment",

            "total_records":
                len(analysed_df),

            "risk_thresholds": {

                "low":
                    "0-24",

                "medium":
                    "25-49",

                "high":
                    "50-74",

                "critical":
                    "75-100"

            },

            "risk_summary": {

                "low":
                    int(
                        risk_counts.get(
                            "Low",
                            0
                        )
                    ),

                "medium":
                    int(
                        risk_counts.get(
                            "Medium",
                            0
                        )
                    ),

                "high":
                    int(
                        risk_counts.get(
                            "High",
                            0
                        )
                    ),

                "critical":
                    int(
                        risk_counts.get(
                            "Critical",
                            0
                        )
                    )

            }

        })

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# ALERTS
# =========================================================

@app.route(
    "/api/alerts"
)
def alerts():

    try:

        df = load_dataset()

        limit = request.args.get(
            "limit",
            default=100,
            type=int
        )

        limit = max(
            1,
            min(
                limit,
                500
            )
        )

        alert_df = (
            get_alert_records(
                df,
                limit
            )
        )

        records = clean_records(
            alert_df
        )

        # Alerts are read-only. Email notifications are generated
        # only when a genuine live Cowrie event is received through
        # /api/live-event. This prevents dashboard polling from
        # sending emails for the same alert records repeatedly.
        notification_results = []
        sent_count = 0

        return jsonify({

            "status":
                "success",

            "alert_method":
                "Calculated risk threshold",

            "email_configured":
                email_alerts_configured(),

            "total_alerts_returned":
                len(records),

            "email_notifications_sent":
                sent_count,

            "risk_thresholds": {

                "high":
                    "50-74",

                "critical":
                    "75-100"

            },

            "data":
                records_to_json_safe(
                    records
                ),

            "notification_results":
                notification_results

        })

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# NOTIFY LATEST ALERT
# =========================================================

@app.route(
    "/api/notify-latest-alert",
    methods=["POST"]
)
def notify_latest_alert():

    try:

        df = load_dataset()

        alert_df = (
            get_alert_records(
                df,
                1
            )
        )

        if alert_df.empty:

            return jsonify({

                "status":
                    "error",

                "message":
                    (
                        "No High or Critical alert "
                        "is available to notify."
                    )

            }), 404

        records = (
            records_to_json_safe(
                alert_df
            )
        )

        record = records[0]

        result = (
            send_email_notification(
                record
            )
        )

        response = {

            "status":
                (
                    "success"
                    if result["sent"]
                    else "error"
                ),

            "sent":
                result["sent"],

            "notification_status":
                result["status"],

            "message":
                result["message"],

            "risk_level":
                record.get(
                    "calculated_risk_level"
                ),

            "risk_score":
                record.get(
                    "calculated_risk_score"
                ),

            "event_id":
                record.get(
                    "event_id"
                ),

            "src_ip":
                record.get(
                    "src_ip"
                ),

            "timestamp":
                record.get(
                    "timestamp"
                )

        }

        return jsonify(
            response
        ), (
            200
            if result["sent"]
            else 400
        )

    except Exception as error:

        return jsonify({

            "status":
                "error",

            "message":
                str(error)

        }), 500


# =========================================================
# EMAIL CONFIGURATION STATUS
# =========================================================

@app.route(
    "/api/email-status"
)
def email_status():

    return jsonify({

        "status":
            "success",

        "configured":
            email_alerts_configured(),

        "smtp_host":
            SMTP_HOST,

        "smtp_port":
            SMTP_PORT,

        "sender_configured":
            bool(
                ALERT_EMAIL_SENDER
            ),

        "delivery_mode": "Verified Neon users with notifications enabled",

        "message":
            (
                "Email notification is ready."
                if email_alerts_configured()
                else
                "Email notification requires SMTP sender credentials and at least one verified user who enabled notifications."
            )

    })


# =========================================================
# TEST EMAIL
# =========================================================

@app.route(
    "/api/test-email",
    methods=["POST"]
)
def test_email():

    if not email_alerts_configured():

        return jsonify({

            "status":
                "error",

            "message":
                (
                    "Email is not configured. "
                    "Set ALERT_EMAIL_SENDER, "
                    "ALERT_EMAIL_PASSWORD and "
                    "at least one verified user with notifications enabled."
                )

        }), 400

    test_record = {

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "event_id":
            "test.email",

        "event_type":
            "system.email.test",

        "src_ip":
            "127.0.0.1",

        "destination_port":
            "2222",

        "command_input":
            "",

        "calculated_risk_score":
            60,

        "calculated_risk_level":
            "High",

        "risk_reasons": [

            "Test High-risk event generated "
            "by the administrator"

        ],

        "explanation":
            (
                "This is a test notification to verify "
                "the configured email system."
            )

    }

    test_record[
        "timestamp"
    ] = datetime.now(timezone.utc).isoformat()

    result = (
        send_email_notification(
            test_record
        )
    )

    if result["sent"]:

        return jsonify({

            "status":
                "success",

            "message":
                (
                    "Test email notification "
                    "sent successfully."
                )

        })

    return jsonify({

        "status":
            "error",

        "message":
            result["message"],

        "email_status":
            result["status"]

    }), 500


# =========================================================
# MANUAL IP BLOCKING (LINUX HOST ONLY)
# =========================================================

# Serialize check-and-insert so two dashboard requests for the same address
# cannot both add a duplicate rule at the same time.
ip_block_lock = Lock()


def _ip_block_response(message, http_status, status="error", **extra):
    """Return a consistent response shape for the dashboard."""
    return jsonify({"status": status, "message": message, **extra}), http_status



@app.route("/api/block-ip", methods=["POST"])
def block_ip():
    """Apply a manual IPv4 DROP rule on the Ubuntu Cowrie VM through SSH."""
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return _ip_block_response(
            "Send a JSON object containing src_ip.", 400
        )

    raw_ip = payload.get("src_ip", payload.get("ip", ""))

    if not isinstance(raw_ip, str) or not raw_ip.strip():
        return _ip_block_response(
            "A source IP address is required.", 400
        )

    try:
        address = ipaddress.ip_address(raw_ip.strip())
    except ValueError:
        return _ip_block_response(
            "A valid IPv4 address is required.", 400
        )
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_global
    ):
        return _ip_block_response(
            "Only valid public IPv4 source addresses can be blocked.",
            400
        )

    ssh_host = os.getenv("COWRIE_SSH_HOST", "127.0.0.1")
    ssh_port = os.getenv("COWRIE_SSH_PORT", "2222")
    ssh_user = os.getenv("COWRIE_SSH_USER", "dharsh")
    ssh_key = os.getenv("COWRIE_SSH_KEY", "")

    if not ssh_key or not os.path.isfile(ssh_key):
        return _ip_block_response(
            "SSH private key is missing or unavailable. No firewall rule was applied.",
            503,
            blocked=False,
            ip=str(address),
        )

    if not ssh_port.isdigit() or not 1 <= int(ssh_port) <= 65535:
        return _ip_block_response(
            "Invalid SSH port configuration.", 500,
            blocked=False,
            ip=str(address),
        )

    ssh_command = [
        "ssh",
        "-i", ssh_key,
        "-p", ssh_port,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8",
        "-o", "StrictHostKeyChecking=yes",
        f"{ssh_user}@{ssh_host}",
        f"sudo -n /usr/local/sbin/cowrie-block-ip add {address}",
    ]

    try:
        with ip_block_lock:
            result = subprocess.run(
                ssh_command,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )

        if result.returncode != 0:
            detail = (
                result.stderr or result.stdout or "SSH firewall command failed"
            ).strip()

            return _ip_block_response(
                f"Ubuntu firewall operation failed: {detail}",
                502,
                blocked=False,
                ip=str(address),
            )

        return _ip_block_response(
            f"Successfully applied an INPUT DROP rule for {address} on the Ubuntu Cowrie VM.",
            200,
            status="success",
            blocked=True,
            already_blocked=False,
            ip=str(address),
            platform="ubuntu-via-ssh",
        )

    except subprocess.TimeoutExpired:
        return _ip_block_response(
            "SSH firewall operation timed out. Verify the Ubuntu firewall before retrying.",
            504,
            blocked=False,
            ip=str(address),
        )

    except OSError as exc:
        return _ip_block_response(
            f"Could not start SSH: {exc}",
            503,
            blocked=False,
            ip=str(address),
        )




# =========================================================
# RUN FLASK
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        port=5000,
        host="0.0.0.0"
    )