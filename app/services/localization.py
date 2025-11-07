from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass
class Localization:
    translations: Dict[str, Dict[str, str]]

    def gettext(self, key: str, lang: str) -> str:
        default_lang = "en"
        lang = lang if lang in {"en", "ru"} else default_lang
        if key in self.translations and lang in self.translations[key]:
            return self.translations[key][lang]
        return self.translations.get(key, {}).get(default_lang, key)


TRANSLATIONS = Localization(
    translations={
        "app_title": {"en": "Crypto Academy", "ru": "Академия Криптографии"},
        "login": {"en": "Login", "ru": "Вход"},
        "register": {"en": "Register", "ru": "Регистрация"},
        "logout": {"en": "Logout", "ru": "Выход"},
        "dashboard": {"en": "Dashboard", "ru": "Главная"},
        "theory": {"en": "Theory", "ru": "Теория"},
        "tests": {"en": "Tests", "ru": "Тесты"},
        "admin_panel": {"en": "Administration", "ru": "Администрирование"},
        "change_password": {"en": "Change password", "ru": "Сменить пароль"},
        "blocked_message": {
            "en": "Your account is blocked.",
            "ru": "Ваш аккаунт заблокирован.",
        },
        "password_reset_required": {
            "en": "You must change your password to meet the new policy.",
            "ru": "Вам необходимо сменить пароль согласно новым требованиям.",
        },
        "password_policy_failed": {
            "en": "Password must include letters, digits, arithmetic signs (+-*/), and satisfy the active policy.",
            "ru": "Пароль должен содержать буквы, цифры, знаки операций (+-*/), и соответствовать активной политике.",
        },
        "password_policy_updated": {
            "en": "Password policy updated.",
            "ru": "Политика паролей обновлена.",
        },
        "encryption_key_required": {
            "en": "Encryption key is required for the selected algorithm.",
            "ru": "Для выбранного алгоритма требуется ключ шифрования.",
        },
        "theory_access_revoked": {
            "en": "Theory materials are not available for your account.",
            "ru": "Доступ к теории для вашего аккаунта закрыт.",
        },
        "tests_access_revoked": {
            "en": "Tests are not available for your account.",
            "ru": "Доступ к тестам для вашего аккаунта закрыт.",
        },
        "permission_theory_revoked": {
            "en": "Theory access disabled.",
            "ru": "Доступ к теории отключён.",
        },
        "permission_theory_restored": {
            "en": "Theory access enabled.",
            "ru": "Доступ к теории включён.",
        },
        "permission_tests_revoked": {
            "en": "Test access disabled.",
            "ru": "Доступ к тестам отключён.",
        },
        "permission_tests_restored": {
            "en": "Test access enabled.",
            "ru": "Доступ к тестам включён.",
        },
        "test_unavailable_language": {
            "en": "This test is not available in the selected language yet.",
            "ru": "Этот тест ещё не доступен на выбранном языке.",
        },
        "test_attempts_exhausted": {
            "en": "You have used all attempts for this test.",
            "ru": "Все попытки для этого теста исчерпаны.",
        },
    }
)
