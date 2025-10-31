from __future__ import annotations

import base64
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class CipherInfo:
    slug: str
    name: str
    category: str


class CipherAlgorithm(ABC):
    info: CipherInfo
    requires_key: bool = False
    key_input_type: str = "text"
    key_label_en: str = "Key"
    key_label_ru: str = "Ключ"
    key_hint_en: str = ""
    key_hint_ru: str = ""

    def get_key_label(self, lang: str) -> str:
        return self.key_label_ru if lang == "ru" else self.key_label_en

    def get_key_hint(self, lang: str) -> str:
        return self.key_hint_ru if lang == "ru" else self.key_hint_en

    @abstractmethod
    def encrypt(self, plaintext: str, key: Optional[str] = None) -> str:
        raise NotImplementedError

    @abstractmethod
    def matches(self, plaintext: str, encrypted: str, key: Optional[str] = None) -> bool:
        raise NotImplementedError


class CaesarCipher(CipherAlgorithm):
    info = CipherInfo("caesar", "Caesar Shift (Symmetric)", "symmetric")
    requires_key = True
    key_input_type = "number"
    key_label_en = "Shift value"
    key_label_ru = "Сдвиг"
    key_hint_en = "Use an integer shift, e.g. 3"
    key_hint_ru = "Введите целое число, например 3"

    def _parse_key(self, key: Optional[str]) -> int:
        if key is None or key.strip() == "":
            raise ValueError("Shift key is required for Caesar cipher")
        try:
            return int(key)
        except ValueError as exc:
            raise ValueError("Shift key must be an integer") from exc

    def encrypt(self, plaintext: str, key: Optional[str] = None) -> str:
        shift = self._parse_key(key)
        encrypted = []
        for ch in plaintext:
            code = ord(ch)
            encrypted.append(chr((code + shift) % 65536))
        return "".join(encrypted)

    def matches(self, plaintext: str, encrypted: str, key: Optional[str] = None) -> bool:
        return self.encrypt(plaintext, key) == encrypted


class VigenereCipher(CipherAlgorithm):
    info = CipherInfo("vigenere", "Vigenere (Symmetric)", "symmetric")
    requires_key = True
    key_label_en = "Keyword"
    key_label_ru = "Ключевое слово"
    key_hint_en = "Letters only, e.g. SECURITY"
    key_hint_ru = "Только буквы, например SECURITY"

    def _parse_key(self, key: Optional[str]) -> str:
        if key is None or not key.strip():
            raise ValueError("Keyword is required for Vigenere cipher")
        keyword = key.strip()
        if not any(ch.isalpha() for ch in keyword):
            raise ValueError("Keyword must contain letters")
        return keyword

    def encrypt(self, plaintext: str, key: Optional[str] = None) -> str:
        keyword = self._parse_key(key)
        key_cycle = (keyword * ((len(plaintext) // len(keyword)) + 1))[: len(plaintext)]
        encrypted_chars: List[str] = []
        for p, k in zip(plaintext, key_cycle):
            encrypted_chars.append(chr((ord(p) + ord(k)) % 65536))
        return "".join(encrypted_chars)

    def matches(self, plaintext: str, encrypted: str, key: Optional[str] = None) -> bool:
        return self.encrypt(plaintext, key) == encrypted


class XorCipher(CipherAlgorithm):
    info = CipherInfo("xor", "XOR Stream (Symmetric)", "symmetric")
    requires_key = True
    key_label_en = "Key phrase"
    key_label_ru = "Ключевая фраза"
    key_hint_en = "Will be converted to bytes"
    key_hint_ru = "Будет преобразован в байты"

    def _parse_key(self, key: Optional[str]) -> bytes:
        if key is None or not key.strip():
            raise ValueError("Key phrase is required for XOR cipher")
        return key.encode("utf-8")

    def encrypt(self, plaintext: str, key: Optional[str] = None) -> str:
        data = plaintext.encode("utf-8")
        key_bytes = self._parse_key(key)
        key_cycle = (key_bytes * ((len(data) // len(key_bytes)) + 1))[: len(data)]
        encrypted = bytes([b ^ k for b, k in zip(data, key_cycle)])
        return base64.b64encode(encrypted).decode("utf-8")

    def matches(self, plaintext: str, encrypted: str, key: Optional[str] = None) -> bool:
        return self.encrypt(plaintext, key) == encrypted


class ReverseCipher(CipherAlgorithm):
    info = CipherInfo("reverse", "Reversed Base64 (Symmetric)", "symmetric")

    def encrypt(self, plaintext: str, key: Optional[str] = None) -> str:
        reversed_text = plaintext[::-1]
        return base64.b64encode(reversed_text.encode("utf-8")).decode("utf-8")

    def matches(self, plaintext: str, encrypted: str, key: Optional[str] = None) -> bool:
        return self.encrypt(plaintext, key) == encrypted


class HashCipher(CipherAlgorithm):
    info = CipherInfo("hash", "SHA-256 Digest (Symmetric)", "symmetric")

    def encrypt(self, plaintext: str, key: Optional[str] = None) -> str:
        return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    def matches(self, plaintext: str, encrypted: str, key: Optional[str] = None) -> bool:
        return self.encrypt(plaintext, key) == encrypted


class SimpleRsaCipher(CipherAlgorithm):
    info = CipherInfo("rsa", "RSA Mini (Asymmetric)", "asymmetric")

    def __init__(self) -> None:
        self.n = 3233
        self.e = 17
        self.d = 2753

    def encrypt(self, plaintext: str, key: Optional[str] = None) -> str:
        encrypted_numbers = [str(pow(ord(ch), self.e, self.n)) for ch in plaintext]
        return "-".join(encrypted_numbers)

    def decrypt(self, encrypted: str) -> str:
        numbers = [int(part) for part in encrypted.split("-") if part]
        decrypted_chars = [chr(pow(num, self.d, self.n)) for num in numbers]
        return "".join(decrypted_chars)

    def matches(self, plaintext: str, encrypted: str, key: Optional[str] = None) -> bool:
        return plaintext == self.decrypt(encrypted)


class SimpleElGamalCipher(CipherAlgorithm):
    info = CipherInfo("elgamal", "ElGamal Mini (Asymmetric)", "asymmetric")

    def __init__(self) -> None:
        self.p = 467
        self.g = 2
        self.x = 127
        self.h = pow(self.g, self.x, self.p)
        self.k = 53

    def encrypt(self, plaintext: str, key: Optional[str] = None) -> str:
        encrypted_pairs = []
        for ch in plaintext.encode("utf-8"):
            r = pow(self.g, self.k, self.p)
            t = (pow(self.h, self.k, self.p) * ch) % self.p
            encrypted_pairs.append(f"{r}:{t}")
        return "|".join(encrypted_pairs)

    def decrypt(self, encrypted: str) -> str:
        pairs = [pair for pair in encrypted.split("|") if pair]
        decoded_bytes = []
        for pair in pairs:
            r_str, t_str = pair.split(":")
            r = int(r_str)
            t = int(t_str)
            s = pow(r, self.x, self.p)
            s_inv = pow(s, -1, self.p)
            decoded_bytes.append((t * s_inv) % self.p)
        return bytes(decoded_bytes).decode("utf-8")

    def matches(self, plaintext: str, encrypted: str, key: Optional[str] = None) -> bool:
        return plaintext == self.decrypt(encrypted)


class AffineCipher(CipherAlgorithm):
    info = CipherInfo("affine", "Affine Map (Symmetric)", "symmetric")

    def encrypt(self, plaintext: str, key: Optional[str] = None) -> str:
        a = 5
        b = 8
        encrypted_chars = []
        for ch in plaintext:
            encrypted_chars.append(chr(((a * ord(ch) + b) % 65536)))
        return "".join(encrypted_chars)

    def matches(self, plaintext: str, encrypted: str, key: Optional[str] = None) -> bool:
        return self.encrypt(plaintext, key) == encrypted


def get_algorithms() -> Dict[str, CipherAlgorithm]:
    algorithms: List[CipherAlgorithm] = [
        CaesarCipher(),
        VigenereCipher(),
        XorCipher(),
        ReverseCipher(),
        HashCipher(),
        AffineCipher(),
        SimpleRsaCipher(),
        SimpleElGamalCipher(),
    ]
    return {algo.info.slug: algo for algo in algorithms}


ALGORITHMS = get_algorithms()
