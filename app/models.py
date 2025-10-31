from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class PasswordRestriction(Enum):
    REQUIRE_LETTER = "require_letter"
    REQUIRE_DIGIT = "require_digit"
    REQUIRE_ARITHMETIC = "require_arithmetic"
    DISALLOW_USERNAME_MATCH = "disallow_username"
    MIN_LENGTH_TEN = "min_length_ten"

    @property
    def description(self) -> str:
        descriptions = {
            self.REQUIRE_LETTER: {
                "en": "Password must include at least one letter.",
                "ru": "Пароль должен содержать хотя бы одну букву.",
            },
            self.REQUIRE_DIGIT: {
                "en": "Password must include at least one digit.",
                "ru": "Пароль должен содержать хотя бы одну цифру.",
            },
            self.REQUIRE_ARITHMETIC: {
                "en": "Password must include +, -, * or /.",
                "ru": "Пароль должен содержать +, -, * или /.",
            },
            self.DISALLOW_USERNAME_MATCH: {
                "en": "Password must not match the username.",
                "ru": "Пароль не должен совпадать с именем пользователя.",
            },
            self.MIN_LENGTH_TEN: {
                "en": "Password must be at least 10 characters long.",
                "ru": "Пароль должен быть длиной не менее 10 символов.",
            },
        }
        return descriptions[self]


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_encrypted = db.Column(db.Text, nullable=False)
    encryption_algorithm = db.Column(db.String(50), nullable=False)
    encryption_key = db.Column(db.Text, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    must_reset_password = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def can_login(self) -> bool:
        return not self.is_blocked


class TheoryArticle(db.Model):
    __tablename__ = "theory_articles"

    id = db.Column(db.Integer, primary_key=True)
    title_en = db.Column(db.String(255), nullable=False)
    title_ru = db.Column(db.String(255), nullable=False)
    content_en = db.Column(db.Text, nullable=False)
    content_ru = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Test(db.Model):
    __tablename__ = "tests"

    id = db.Column(db.Integer, primary_key=True)
    title_en = db.Column(db.String(255), nullable=False)
    title_ru = db.Column(db.String(255), nullable=False)
    description_en = db.Column(db.Text, nullable=False)
    description_ru = db.Column(db.Text, nullable=False)
    questions = db.relationship("Question", backref="test", cascade="all, delete-orphan")


class Question(db.Model):
    __tablename__ = "questions"

    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey("tests.id"), nullable=False)
    text_en = db.Column(db.Text, nullable=False)
    text_ru = db.Column(db.Text, nullable=False)
    choices_en = db.Column(db.Text, nullable=False)
    choices_ru = db.Column(db.Text, nullable=False)
    correct_index = db.Column(db.Integer, nullable=False)

    def get_choices(self, language: str) -> List[str]:
        raw = self.choices_en if language == "en" else self.choices_ru
        return [choice.strip() for choice in raw.split("\n") if choice.strip()]

    def get_text(self, language: str) -> str:
        return self.text_en if language == "en" else self.text_ru


class PasswordPolicy(db.Model):
    __tablename__ = "password_policy"

    id = db.Column(db.Integer, primary_key=True)
    active_restriction = db.Column(db.String(64), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def restriction(self) -> PasswordRestriction | None:
        if self.active_restriction:
            return PasswordRestriction(self.active_restriction)
        return None

    @restriction.setter
    def restriction(self, restriction: PasswordRestriction | None) -> None:
        self.active_restriction = restriction.value if restriction else None
