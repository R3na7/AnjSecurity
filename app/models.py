from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

import json

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
    can_access_theory = db.Column(db.Boolean, default=True)
    can_access_tests = db.Column(db.Boolean, default=True)
    must_reset_password = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def can_login(self) -> bool:
        return not self.is_blocked

    def can_view_theory(self) -> bool:
        return self.can_access_theory

    def can_take_tests(self) -> bool:
        return self.can_access_tests


class TheoryArticle(db.Model):
    __tablename__ = "theory_articles"

    id = db.Column(db.Integer, primary_key=True)
    algorithm_slug = db.Column(db.String(50), nullable=False)
    title_en = db.Column(db.String(255), nullable=False)
    title_ru = db.Column(db.String(255), nullable=False)
    content_en = db.Column(db.Text, nullable=False)
    content_ru = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Test(db.Model):
    __tablename__ = "tests"

    id = db.Column(db.Integer, primary_key=True)
    algorithm_slug = db.Column(db.String(50), nullable=False)
    title_en = db.Column(db.String(255), nullable=True)
    title_ru = db.Column(db.String(255), nullable=True)
    description_en = db.Column(db.Text, nullable=True)
    description_ru = db.Column(db.Text, nullable=True)
    total_points = db.Column(db.Integer, nullable=False, default=0)
    time_limit_seconds = db.Column(db.Integer, nullable=False, default=60)
    questions = db.relationship("Question", backref="test", cascade="all, delete-orphan")
    results = db.relationship("TestResult", backref="test", cascade="all, delete-orphan")

    def display_title(self, lang: str) -> str:
        if lang == "ru":
            return self.title_ru or (self.questions[0].text_ru if self.questions else "")
        return self.title_en or (self.questions[0].text_en if self.questions else "")

    def display_description(self, lang: str) -> str:
        if lang == "ru":
            return self.description_ru or ""
        return self.description_en or ""


class Question(db.Model):
    __tablename__ = "questions"

    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey("tests.id"), nullable=False)
    text_en = db.Column(db.Text, nullable=True)
    text_ru = db.Column(db.Text, nullable=True)
    choices_en = db.Column(db.Text, nullable=True)
    choices_ru = db.Column(db.Text, nullable=True)
    correct_index = db.Column(db.Integer, nullable=False)

    def get_choices(self, language: str) -> List[str]:
        raw = self.choices_en if language == "en" else self.choices_ru
        if not raw:
            return []
        return [choice.strip() for choice in raw.split("\n") if choice.strip()]

    def get_text(self, language: str) -> str:
        if language == "en":
            return self.text_en or ""
        return self.text_ru or ""

    def get_correct_choice(self, language: str) -> Optional[str]:
        choices = self.get_choices(language)
        if 0 <= self.correct_index < len(choices):
            return choices[self.correct_index]
        return None


class TestResult(db.Model):
    __tablename__ = "test_results"

    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey("tests.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    score_points = db.Column(db.Integer, nullable=False)
    max_points = db.Column(db.Integer, nullable=False)
    correct_answers = db.Column(db.Integer, nullable=False)
    incorrect_answers = db.Column(db.Integer, nullable=False)
    attempt_number = db.Column(db.Integer, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    answers_payload = db.Column(db.Text, nullable=True)

    user = db.relationship("User", backref=db.backref("test_results", cascade="all, delete-orphan"))

    def save_answers(self, answers: List[dict]) -> None:
        self.answers_payload = json.dumps(answers)

    def load_answers(self) -> List[dict]:
        if not self.answers_payload:
            return []
        try:
            return json.loads(self.answers_payload)
        except json.JSONDecodeError:
            return []


class PasswordPolicy(db.Model):
    __tablename__ = "password_policy"

    id = db.Column(db.Integer, primary_key=True)
    active_restriction = db.Column(db.String(64), nullable=True)
    admin_require_letter = db.Column(db.Boolean, default=False)
    admin_require_digit = db.Column(db.Boolean, default=False)
    admin_require_arithmetic = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def restriction(self) -> PasswordRestriction | None:
        if self.active_restriction:
            return PasswordRestriction(self.active_restriction)
        return None

    @restriction.setter
    def restriction(self, restriction: PasswordRestriction | None) -> None:
        self.active_restriction = restriction.value if restriction else None

    def admin_requirements(self) -> dict[str, bool]:
        return {
            "letter": bool(self.admin_require_letter),
            "digit": bool(self.admin_require_digit),
            "arithmetic": bool(self.admin_require_arithmetic),
        }
