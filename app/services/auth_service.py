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
    ) -> User:
        encrypted_password = self.encryption_service.encrypt(algorithm_slug, password)
        user = User(
            username=username,
            password_encrypted=encrypted_password,
            encryption_algorithm=algorithm_slug,
            is_admin=is_admin,
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
            user.encryption_algorithm, password, user.password_encrypted
        ):
            return None
        return user

    def change_password(self, user: User, new_password: str) -> None:
        encrypted = self.encryption_service.encrypt(
            user.encryption_algorithm, new_password
        )
        user.password_encrypted = encrypted
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

    def plaintext_meets_restriction(self, user: User, plaintext: str) -> bool:
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
