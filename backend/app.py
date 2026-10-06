import os
import json
import hmac
import hashlib
import time
from urllib.parse import parse_qsl

from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg

app = Flask(__name__)
CORS(app)

BOT_TOKEN = os.environ.get("BOT_TOKEN")
DATABASE_URL = os.environ.get("DATABASE_URL")


def verify_telegram_init_data(init_data):
    if not BOT_TOKEN:
        raise Exception("BOT_TOKEN is not configured")

    data = dict(parse_qsl(init_data, keep_blank_values=True))

    received_hash = data.pop("hash", None)

    if not received_hash:
        return None

    data_check_string = "\n".join(
        f"{key}={data[key]}" for key in sorted(data)
    )

    secret_key = hmac.new(
        b"WebAppData",
        BOT_TOKEN.encode(),
        hashlib.sha256
    ).digest()

    calculated_hash = hmac.new(
        secret_key,
        data_check_string.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        return None

    # رفض البيانات القديمة جدًا
    auth_date = int(data.get("auth_date", 0))

    if time.time() - auth_date > 86400:
        return None

    user_data = data.get("user")

    if not user_data:
        return None

    return json.loads(user_data)


def get_db():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL is not configured")

    return psycopg.connect(DATABASE_URL)


@app.get("/")
def home():
    return jsonify({
        "status": "online",
        "service": "BAC Mini App API"
    })


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/auth/telegram")
def telegram_login():
    body = request.get_json(silent=True) or {}
    init_data = body.get("initData")

    if not init_data:
        return jsonify({
            "error": "initData is required"
        }), 400

    try:
        telegram_user = verify_telegram_init_data(init_data)
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

    if not telegram_user:
        return jsonify({
            "error": "Invalid Telegram authentication"
        }), 401

    telegram_id = telegram_user["id"]

    first_name = telegram_user.get("first_name", "")
    last_name = telegram_user.get("last_name", "")
    username = telegram_user.get("username")
    photo_url = telegram_user.get("photo_url")

    with get_db() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    telegram_id BIGINT PRIMARY KEY,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    photo_url TEXT,
                    points INTEGER DEFAULT 0,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            cur.execute("""
                INSERT INTO users (
                    telegram_id,
                    username,
                    first_name,
                    last_name,
                    photo_url
                )
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (telegram_id)
                DO UPDATE SET
                    username = EXCLUDED.username,
                    first_name = EXCLUDED.first_name,
                    last_name = EXCLUDED.last_name,
                    photo_url = EXCLUDED.photo_url,
                    updated_at = NOW()
                RETURNING
                    telegram_id,
                    username,
                    first_name,
                    last_name,
                    photo_url,
                    points
            """, (
                telegram_id,
                username,
                first_name,
                last_name,
                photo_url
            ))

            user = cur.fetchone()

    return jsonify({
        "success": True,
        "user": {
            "telegram_id": user[0],
            "username": user[1],
            "first_name": user[2],
            "last_name": user[3],
            "photo_url": user[4],
            "points": user[5]
        }
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
