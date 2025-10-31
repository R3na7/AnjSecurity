import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URL")
        or f"sqlite:///{BASE_DIR.parent / 'app.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False


def get_config():
    env = os.environ.get("FLASK_ENV", "development").lower()
    return Config()
