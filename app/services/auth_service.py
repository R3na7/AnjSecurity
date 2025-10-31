from __future__ import annotations

import re
from typing import Optional

from flask_login import LoginManager

from app.models import PasswordPolicy, PasswordRestriction, User, db
from app.services.encryption_service import EncryptionService


class AuthService:
    def __init__(self, encryption_service: EncryptionService) -> None:
        self.encryption_service = encryption_service

    def register_user(
        self,
        username: str,
        password: str,
        algorithm_slug: str,
        is_admin: bool = False,
        encryption_key: Optional[str] = None,
    ) -> User:
        encrypted_password = self.encryption_service.encrypt(
            algorithm_slug, password, encryption_key
        )
        user = User(
            username=username,
            password_encrypted=encrypted_password,
            encryption_algorithm=algorithm_slug,
            is_admin=is_admin,
            encryption_key=encryption_key,
        )
        db.session.add(user)
        db.session.commit()
        return user

    def authenticate(self, username: str, password: str) -> Optional[User]:
        user = User.query.filter_by(username=username).first()
        if not user:
            return None
        if not user.can_login():
            return None
        if not self.encryption_service.verify(
            user.encryption_algorithm,
            password,
            user.password_encrypted,
            user.encryption_key,
        ):
            return None
        return user

    def change_password(
        self, user: User, new_password: str, encryption_key: Optional[str] = None
    ) -> None:
        key_to_use = encryption_key if encryption_key is not None else user.encryption_key
        encrypted = self.encryption_service.encrypt(
            user.encryption_algorithm, new_password, key_to_use
        )
        user.password_encrypted = encrypted
        if encryption_key is not None:
            user.encryption_key = encryption_key
        user.must_reset_password = False
        db.session.commit()

    def ensure_policy(self) -> PasswordPolicy:
        policy = PasswordPolicy.query.get(1)
        if not policy:
            policy = PasswordPolicy(id=1)
            db.session.add(policy)
            db.session.commit()
        return policy

    def set_policy(self, restriction: Optional[PasswordRestriction]) -> PasswordPolicy:
        policy = self.ensure_policy()
        policy.restriction = restriction
        db.session.commit()
        if restriction is not None:
            for user in User.query.filter_by(is_admin=False).all():
                user.must_reset_password = True
            db.session.commit()
        return policy

    def _meets_baseline(self, user: User, plaintext: str) -> bool:
        if user.is_admin:
            return True
        has_letter = bool(re.search(r"[A-Za-zА-Яа-я]", plaintext))
        has_digit = any(ch.isdigit() for ch in plaintext)
        has_arithmetic = any(ch in "+-*/" for ch in plaintext)
        return has_letter and has_digit and has_arithmetic

    def plaintext_meets_restriction(self, user: User, plaintext: str) -> bool:
        if not self._meets_baseline(user, plaintext):
            return False
        restriction = self.ensure_policy().restriction
        if restriction is None:
            return True
        if restriction == PasswordRestriction.REQUIRE_LETTER:
            return bool(re.search(r"[A-Za-zА-Яа-я]", plaintext))
        if restriction == PasswordRestriction.REQUIRE_DIGIT:
            return any(ch.isdigit() for ch in plaintext)
        if restriction == PasswordRestriction.REQUIRE_ARITHMETIC:
            return any(ch in "+-*/" for ch in plaintext)
        if restriction == PasswordRestriction.DISALLOW_USERNAME_MATCH:
            return plaintext.lower() != user.username.lower()
        if restriction == PasswordRestriction.MIN_LENGTH_TEN:
            return len(plaintext) >= 10
        return True


login_manager = LoginManager()
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return User.query.get(int(user_id))
