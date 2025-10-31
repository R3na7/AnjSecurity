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
        "blocked_message": {
            "en": "Your account is blocked.",
            "ru": "Ваш аккаунт заблокирован.",
        },
        "password_reset_required": {
            "en": "You must change your password to meet the new policy.",
            "ru": "Вам необходимо сменить пароль согласно новым требованиям.",
        },
    }
)
