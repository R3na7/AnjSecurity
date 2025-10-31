from __future__ import annotations

import base64
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class CipherInfo:
    slug: str
    name: str
    category: str


class CipherAlgorithm(ABC):
    info: CipherInfo

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def matches(self, plaintext: str, encrypted: str) -> bool:
        raise NotImplementedError


class CaesarCipher(CipherAlgorithm):
    info = CipherInfo("caesar", "Caesar Shift (Symmetric)", "symmetric")

    def encrypt(self, plaintext: str) -> str:
        shift = 3
        encrypted = []
        for ch in plaintext:
            code = ord(ch)
            encrypted.append(chr((code + shift) % 65536))
        return "".join(encrypted)

    def matches(self, plaintext: str, encrypted: str) -> bool:
        return self.encrypt(plaintext) == encrypted


class VigenereCipher(CipherAlgorithm):
    info = CipherInfo("vigenere", "Vigenere (Symmetric)", "symmetric")
    key = "SECURE"

    def encrypt(self, plaintext: str) -> str:
        key_cycle = (self.key * ((len(plaintext) // len(self.key)) + 1))[: len(plaintext)]
        encrypted_chars: List[str] = []
        for p, k in zip(plaintext, key_cycle):
            encrypted_chars.append(chr((ord(p) + ord(k)) % 65536))
        return "".join(encrypted_chars)

    def matches(self, plaintext: str, encrypted: str) -> bool:
        return self.encrypt(plaintext) == encrypted


class XorCipher(CipherAlgorithm):
    info = CipherInfo("xor", "XOR Stream (Symmetric)", "symmetric")
    key = b"encryption-key"

    def encrypt(self, plaintext: str) -> str:
        data = plaintext.encode("utf-8")
        key_cycle = (self.key * ((len(data) // len(self.key)) + 1))[: len(data)]
        encrypted = bytes([b ^ k for b, k in zip(data, key_cycle)])
        return base64.b64encode(encrypted).decode("utf-8")

    def matches(self, plaintext: str, encrypted: str) -> bool:
        return self.encrypt(plaintext) == encrypted


class ReverseCipher(CipherAlgorithm):
    info = CipherInfo("reverse", "Reversed Base64 (Symmetric)", "symmetric")

    def encrypt(self, plaintext: str) -> str:
        reversed_text = plaintext[::-1]
        return base64.b64encode(reversed_text.encode("utf-8")).decode("utf-8")

    def matches(self, plaintext: str, encrypted: str) -> bool:
        return self.encrypt(plaintext) == encrypted


class HashCipher(CipherAlgorithm):
    info = CipherInfo("hash", "SHA-256 Digest (Symmetric)", "symmetric")

    def encrypt(self, plaintext: str) -> str:
        return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    def matches(self, plaintext: str, encrypted: str) -> bool:
        return self.encrypt(plaintext) == encrypted


class SimpleRsaCipher(CipherAlgorithm):
    info = CipherInfo("rsa", "RSA Mini (Asymmetric)", "asymmetric")

    def __init__(self) -> None:
        self.n = 3233
        self.e = 17
        self.d = 2753

    def encrypt(self, plaintext: str) -> str:
        encrypted_numbers = [str(pow(ord(ch), self.e, self.n)) for ch in plaintext]
        return "-".join(encrypted_numbers)

    def decrypt(self, encrypted: str) -> str:
        numbers = [int(part) for part in encrypted.split("-") if part]
        decrypted_chars = [chr(pow(num, self.d, self.n)) for num in numbers]
        return "".join(decrypted_chars)

    def matches(self, plaintext: str, encrypted: str) -> bool:
        return plaintext == self.decrypt(encrypted)


class SimpleElGamalCipher(CipherAlgorithm):
    info = CipherInfo("elgamal", "ElGamal Mini (Asymmetric)", "asymmetric")

    def __init__(self) -> None:
        self.p = 467
        self.g = 2
        self.x = 127
        self.h = pow(self.g, self.x, self.p)
        self.k = 53

    def encrypt(self, plaintext: str) -> str:
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

    def matches(self, plaintext: str, encrypted: str) -> bool:
        return plaintext == self.decrypt(encrypted)


class AffineCipher(CipherAlgorithm):
    info = CipherInfo("affine", "Affine Map (Symmetric)", "symmetric")

    def encrypt(self, plaintext: str) -> str:
        a = 5
        b = 8
        encrypted_chars = []
        for ch in plaintext:
            encrypted_chars.append(chr(((a * ord(ch) + b) % 65536)))
        return "".join(encrypted_chars)

    def matches(self, plaintext: str, encrypted: str) -> bool:
        return self.encrypt(plaintext) == encrypted


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
