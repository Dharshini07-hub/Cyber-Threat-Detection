import os
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def get_db_connection():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is missing from .env")
    return psycopg2.connect(
        database_url, sslmode="require", connect_timeout=10,
        cursor_factory=RealDictCursor
    )


def test_db_connection():
    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database() AS database, current_user AS username;")
            result = cursor.fetchone()
        return {"status": "success", "database": result["database"], "username": result["username"]}
    finally:
        if connection:
            connection.close()
