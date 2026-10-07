import os
import json
import hmac
import hashlib
import time

from urllib.parse import parse_qsl

from flask import Flask, request, jsonify
from flask_cors import CORS

import psycopg


# =========================================================
# APP
# =========================================================

app = Flask(__name__)
CORS(app)


# =========================================================
# ENVIRONMENT VARIABLES
# =========================================================

BOT_TOKEN = os.environ.get("BOT_TOKEN")
DATABASE_URL = os.environ.get("DATABASE_URL")


# =========================================================
# DATABASE
# =========================================================

def get_db():

    if not DATABASE_URL:
        raise Exception("DATABASE_URL is not configured")

    return psycopg.connect(DATABASE_URL)


# =========================================================
# CREATE DATABASE TABLES
# =========================================================

def init_database():

    with get_db() as conn:

        with conn.cursor() as cur:

            # ---------------------------------------------
            # USERS
            # ---------------------------------------------

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


            # ---------------------------------------------
            # BRANCHES
            # الشعب
            # ---------------------------------------------

            cur.execute("""
                CREATE TABLE IF NOT EXISTS branches (

                    id SERIAL PRIMARY KEY,

                    name TEXT NOT NULL,

                    description TEXT,

                    icon TEXT,

                    active BOOLEAN DEFAULT TRUE,

                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)


            # ---------------------------------------------
            # SUBJECTS
            # المواد
            # ---------------------------------------------

            cur.execute("""
                CREATE TABLE IF NOT EXISTS subjects (

                    id SERIAL PRIMARY KEY,

                    branch_id INTEGER
                        REFERENCES branches(id)
                        ON DELETE CASCADE,

                    name TEXT NOT NULL,

                    description TEXT,

                    icon TEXT,

                    active BOOLEAN DEFAULT TRUE,

                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)


            # ---------------------------------------------
            # LESSONS
            # الدروس
            # ---------------------------------------------

            cur.execute("""
                CREATE TABLE IF NOT EXISTS lessons (

                    id SERIAL PRIMARY KEY,

                    subject_id INTEGER
                        REFERENCES subjects(id)
                        ON DELETE CASCADE,

                    title TEXT NOT NULL,

                    description TEXT,

                    content TEXT,

                    lesson_order INTEGER DEFAULT 0,

                    active BOOLEAN DEFAULT TRUE,

                    created_at TIMESTAMPTZ DEFAULT NOW(),

                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)


            # ---------------------------------------------
            # LESSON FILES
            # ملفات PDF وغيرها
            # ---------------------------------------------

            cur.execute("""
                CREATE TABLE IF NOT EXISTS lesson_files (

                    id SERIAL PRIMARY KEY,

                    lesson_id INTEGER
                        REFERENCES lessons(id)
                        ON DELETE CASCADE,

                    title TEXT,

                    file_url TEXT NOT NULL,

                    file_type TEXT DEFAULT 'pdf',

                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)


            # ---------------------------------------------
            # VIDEOS
            # فيديوهات الدروس
            # ---------------------------------------------

            cur.execute("""
                CREATE TABLE IF NOT EXISTS lesson_videos (

                    id SERIAL PRIMARY KEY,

                    lesson_id INTEGER
                        REFERENCES lessons(id)
                        ON DELETE CASCADE,

                    title TEXT,

                    video_url TEXT NOT NULL,

                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)


            # ---------------------------------------------
            # INDEXES
            # ---------------------------------------------

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_subjects_branch
                ON subjects(branch_id)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_lessons_subject
                ON lessons(subject_id)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_files_lesson
                ON lesson_files(lesson_id)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_videos_lesson
                ON lesson_videos(lesson_id)
            """)


        conn.commit()


# =========================================================
# TELEGRAM AUTHENTICATION
# =========================================================

def verify_telegram_init_data(init_data):

    if not BOT_TOKEN:
        raise Exception("BOT_TOKEN is not configured")


    data = dict(
        parse_qsl(
            init_data,
            keep_blank_values=True
        )
    )


    received_hash = data.pop("hash", None)


    if not received_hash:
        return None


    data_check_string = "\n".join(
        f"{key}={data[key]}"
        for key in sorted(data)
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


    if not hmac.compare_digest(
        calculated_hash,
        received_hash
    ):
        return None


    # -----------------------------------------------------
    # Check auth date
    # -----------------------------------------------------

    try:

        auth_date = int(
            data.get("auth_date", 0)
        )

    except Exception:

        return None


    if auth_date <= 0:
        return None


    # البيانات صالحة لمدة 24 ساعة

    if time.time() - auth_date > 86400:
        return None


    # -----------------------------------------------------
    # Telegram user
    # -----------------------------------------------------

    user_data = data.get("user")


    if not user_data:
        return None


    try:

        return json.loads(user_data)

    except Exception:

        return None


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return jsonify({

        "status": "online",

        "service": "BAC PLUS API",

        "version": "2.0"

    })


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():

    try:

        with get_db() as conn:

            with conn.cursor() as cur:

                cur.execute("SELECT 1")

                cur.fetchone()


        return jsonify({

            "status": "ok",

            "database": "connected"

        })


    except Exception as e:

        return jsonify({

            "status": "error",

            "database": str(e)

        }), 500


# =========================================================
# TELEGRAM LOGIN
# =========================================================

@app.post("/api/auth/telegram")
def telegram_login():

    body = request.get_json(
        silent=True
    ) or {}


    init_data = body.get(
        "initData"
    )


    if not init_data:

        return jsonify({

            "success": False,

            "error": "initData is required"

        }), 400


    try:

        telegram_user = (
            verify_telegram_init_data(
                init_data
            )
        )


    except Exception as e:

        return jsonify({

            "success": False,

            "error": str(e)

        }), 500


    if not telegram_user:

        return jsonify({

            "success": False,

            "error":
                "Invalid Telegram authentication"

        }), 401


    telegram_id = telegram_user["id"]


    first_name = (
        telegram_user.get(
            "first_name",
            ""
        )
    )


    last_name = (
        telegram_user.get(
            "last_name",
            ""
        )
    )


    username = (
        telegram_user.get(
            "username"
        )
    )


    photo_url = (
        telegram_user.get(
            "photo_url"
        )
    )


    try:

        with get_db() as conn:

            with conn.cursor() as cur:

                cur.execute("""
                    INSERT INTO users (
                        telegram_id,
                        username,
                        first_name,
                        last_name,
                        photo_url
                    )

                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )

                    ON CONFLICT (telegram_id)

                    DO UPDATE SET

                        username =
                            EXCLUDED.username,

                        first_name =
                            EXCLUDED.first_name,

                        last_name =
                            EXCLUDED.last_name,

                        photo_url =
                            EXCLUDED.photo_url,

                        updated_at =
                            NOW()

                    RETURNING

                        telegram_id,
                        username,
                        first_name,
                        last_name,
                        photo_url,
                        points
                """, (

                    telegram_id,

                   
