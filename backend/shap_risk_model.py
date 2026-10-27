import os
import re
import warnings

import numpy as np
import pandas as pd
import shap

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")

DATASET_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "cowrie_refined_dataset_enriched_ips.csv",
)

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_PATH = os.path.join(MODEL_DIR, "cowrie_risk_model.joblib")


# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------

def safe_text(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def contains_any(text, keywords):
    text = safe_text(text).lower()
    return int(any(keyword in text for keyword in keywords))


def extract_features(df):
    """
    Convert Cowrie records into numeric features suitable for
    Random Forest classification and SHAP explanation.

    Existing risk_score/risk_level/explanation/recommended_action
    fields are deliberately NOT used as model inputs.
    """

    work = df.copy()

    required_columns = [
        "timestamp",
        "src_port",
        "username",
        "password",
        "client_version",
        "command_input",
        "message",
        "event_id",
        "attack_type",
        "destination_port",
        "is_attack",
        "risk_level",
    ]

    missing = [column for column in required_columns if column not in work.columns]
    if missing:
        raise ValueError(
            "Dataset is missing required columns: " + ", ".join(missing)
        )

    timestamp = pd.to_datetime(work["timestamp"], errors="coerce")

    command = work["command_input"].fillna("").astype(str).str.lower()
    message = work["message"].fillna("").astype(str).str.lower()
    event_id = work["event_id"].fillna("").astype(str).str.lower()
    attack_type = work["attack_type"].fillna("").astype(str).str.lower()
    client_version = work["client_version"].fillna("").astype(str).str.lower()
    username = work["username"].fillna("").astype(str)
    password = work["password"].fillna("").astype(str)

    features = pd.DataFrame(index=work.index)

    # Time-related features
    features["hour"] = timestamp.dt.hour.fillna(-1).astype(float)
    features["day_of_week"] = timestamp.dt.dayofweek.fillna(-1).astype(float)

    # Network-related features
    features["src_port"] = pd.to_numeric(
        work["src_port"], errors="coerce"
    ).fillna(0)
    features["destination_port"] = pd.to_numeric(
        work["destination_port"], errors="coerce"
    ).fillna(0)

    # Authentication / session characteristics
    features["username_present"] = (username.str.len() > 0).astype(int)
    features["password_present"] = (password.str.len() > 0).astype(int)
    features["username_length"] = username.str.len().astype(int)
    features["password_length"] = password.str.len().astype(int)

    # Command/message characteristics
    features["command_present"] = (command.str.len() > 0).astype(int)
    features["command_length"] = command.str.len().astype(int)
    features["message_length"] = message.str.len().astype(int)

    # Event characteristics
    features["is_attack"] = pd.to_numeric(
        work["is_attack"], errors="coerce"
    ).fillna(0).astype(int)

    # Authentication indicators
    features["failed_login_event"] = (
        event_id.str.contains(
            r"login|auth|failed|login.failed|password", regex=True
        )
        | message.str.contains(
            r"failed|authentication|invalid|incorrect|password", regex=True
        )
    ).astype(int)

    features["successful_login_event"] = (
        event_id.str.contains(
            r"login.success|auth.success|session.open|login", regex=True
        )
        & ~message.str.contains(r"failed|invalid|incorrect", regex=True)
    ).astype(int)

    # Reconnaissance indicators
    recon_keywords = [
        "whoami",
        "uname",
        "id",
        "pwd",
        "hostname",
        "ifconfig",
        "ip addr",
        "ip a",
        "netstat",
        "ss ",
        "ps ",
        "w ",
        "last",
        "ls",
        "cat /etc/os-release",
    ]

    features["recon_indicator"] = command.apply(
        lambda value: contains_any(value, recon_keywords)
    )

    # Download / malware related indicators
    download_keywords = [
        "wget",
        "curl",
        "ftp",
        "tftp",
        "nc ",
        "netcat",
        "download",
        "chmod +x",
        "base64",
    ]

    features["download_indicator"] = command.apply(
        lambda value: contains_any(value, download_keywords)
    )

    # Destructive / suspicious command indicators
    suspicious_keywords = [
        "rm -rf",
        "mkfs",
        "dd if=",
        "shutdown",
        "reboot",
        "passwd",
        "useradd",
        "usermod",
        "chmod",
        "chown",
        "crontab",
        "/etc/passwd",
        "/etc/shadow",
        "bash -i",
        "python -c",
        "perl -e",
    ]

    features["suspicious_command_indicator"] = command.apply(
        lambda value: contains_any(value, suspicious_keywords)
    )

    # Shell / privilege indicators
    privilege_keywords = [
        "sudo",
        "su ",
        "root",
        "setuid",
        "setgid",
    ]

    features["privilege_indicator"] = command.apply(
        lambda value: contains_any(value, privilege_keywords)
    )

    # Attack type flags
    features["bruteforce_attack_type"] = attack_type.str.contains(
        r"brute|credential|password", regex=True
    ).astype(int)

    features["recon_attack_type"] = attack_type.str.contains(
        r"recon|scan|discovery", regex=True
    ).astype(int)

    features["malware_attack_type"] = attack_type.str.contains(
        r"malware|download|payload|file", regex=True
    ).astype(int)

    # Common SSH client indicator
    features["ssh_client_indicator"] = client_version.str.contains(
        r"ssh|putty|paramiko", regex=True
    ).astype(int)

    return features.astype(float)


def print_shap_explanation(explainer, model, X_row, feature_names):
    """
    Print the SHAP contribution of one sample.
    """

    shap_values = explainer.shap_values(X_row)

    # SHAP API differs slightly between versions and multiclass models.
    predicted_label = model.predict(X_row)[0]
    predicted_class_index = list(model.classes_).index(predicted_label)

    if isinstance(shap_values, list):
        values = np.asarray(shap_values[predicted_class_index])[0]
    else:
        values_array = np.asarray(shap_values)

        if values_array.ndim == 3:
            values = values_array[0, :, predicted_class_index]
        elif values_array.ndim == 2:
            # SHAP may return (samples, features) for some tree models.
            values = values_array[0]
        else:
            values = values_array.reshape(-1)

    contributions = pd.DataFrame(
        {
            "feature": feature_names,
            "shap_value": values,
            "absolute_value": np.abs(values),
        }
    ).sort_values("absolute_value", ascending=False)

    print("\nTop SHAP feature contributions:")
    print(
        contributions[
            ["feature", "shap_value"]
        ].head(10).to_string(index=False)
    )


# ------------------------------------------------------------
# Main training and SHAP test
# ------------------------------------------------------------

def main():
    print("==============================================")
    print(" Cowrie Risk Classification + SHAP")
    print("==============================================")

    print(f"\nDataset: {DATASET_PATH}")

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found:\n{DATASET_PATH}"
        )

    df = pd.read_csv(DATASET_PATH)

    print(f"Rows loaded: {len(df)}")
    print(f"Columns loaded: {len(df.columns)}")

    target = df["risk_level"].fillna("Low").astype(str).str.strip()

    valid_mask = target.ne("") & target.ne("nan")
    df = df.loc[valid_mask].copy()
    target = target.loc[valid_mask]

    X = extract_features(df)
    y = target

    print("\nRisk label distribution:")
    print(y.value_counts().to_string())

    print("\nModel input features:")
    for feature in X.columns:
        print(f" - {feature}")

    # Stratified split keeps all available risk classes represented
    # in train/test when possible.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(
        n_estimators=250,
        random_state=42,
        class_weight="balanced",
        min_samples_leaf=2,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\n==============================================")
    print(" Model Evaluation")
    print("==============================================")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    # Save model for later Flask integration.
    import joblib

    joblib.dump(
        {
            "model": model,
            "feature_names": list(X.columns),
        },
        MODEL_PATH,
    )

    print(f"Model saved to: {MODEL_PATH}")

    # --------------------------------------------------------
    # SHAP
    # --------------------------------------------------------

    print("\n==============================================")
    print(" SHAP Explanation Test")
    print("==============================================")

    print("Creating SHAP TreeExplainer...")

    explainer = shap.TreeExplainer(model)

    # Explain one real test record.
    sample = X_test.iloc[[0]]
    actual_label = y_test.iloc[0]
    predicted_label = model.predict(sample)[0]

    print(f"Actual risk level:    {actual_label}")
    print(f"Predicted risk level: {predicted_label}")

    print_shap_explanation(
        explainer,
        model,
        sample,
        list(X.columns),
    )

    print("\nSHAP test completed successfully.")
    print("The next step is connecting this model to Flask.")


if __name__ == "__main__":
    main()
