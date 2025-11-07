"""Practical implementation notes for each supported cipher."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class PracticeMaterial:
    title_en: str
    title_ru: str
    description_en: str
    description_ru: str
    code_en: str
    code_ru: str


PRACTICE_MATERIALS: Dict[str, PracticeMaterial] = {
    "caesar": PracticeMaterial(
        title_en="Shift characters with modular arithmetic",
        title_ru="Сдвиг символов по модулю",
        description_en=(
            "The Caesar cipher replaces every character with another one that is"
            " shifted by a fixed value. The example below keeps the full"
            " Unicode range intact and demonstrates both encryption and"
            " decryption functions."
        ),
        description_ru=(
            "Шифр Цезаря заменяет каждый символ другим, сдвинутым на постоянное"
            " значение. Пример ниже работает со всем диапазоном Unicode и"
            " показывает функции шифрования и расшифрования."
        ),
        code_en="""def caesar_encrypt(text: str, shift: int) -> str:\n    result = []\n    for ch in text:\n        result.append(chr((ord(ch) + shift) % 65536))\n    return ''.join(result)\n\n\ndef caesar_decrypt(ciphertext: str, shift: int) -> str:\n    return caesar_encrypt(ciphertext, -shift)\n\n\nmessage = "SECURITY"\nencoded = caesar_encrypt(message, 3)\ndecoded = caesar_decrypt(encoded, 3)\nprint(encoded)\nprint(decoded)""",
        code_ru="""def caesar_encrypt(text: str, shift: int) -> str:\n    result = []\n    for ch in text:\n        result.append(chr((ord(ch) + shift) % 65536))\n    return ''.join(result)\n\n\ndef caesar_decrypt(ciphertext: str, shift: int) -> str:\n    return caesar_encrypt(ciphertext, -shift)\n\n\nmessage = "БЕЗОПАСНОСТЬ"\nencoded = caesar_encrypt(message, 5)\ndecoded = caesar_decrypt(encoded, 5)\nprint(encoded)\nprint(decoded)""",
    ),
    "vigenere": PracticeMaterial(
        title_en="Combine key letters with message letters",
        title_ru="Комбинирование букв ключа и сообщения",
        description_en=(
            "The Vigenere cipher cycles through a keyword and adds each key"
            " character to the original text. Subtracting the same characters"
            " returns the plaintext."
        ),
        description_ru=(
            "Шифр Виженера перебирает ключевое слово и добавляет символы ключа"
            " к исходному тексту. Обратная операция вычитает те же символы и"
            " возвращает открытый текст."
        ),
        code_en="""def vigenere_encrypt(text: str, keyword: str) -> str:\n    keyword = (keyword * ((len(text) // len(keyword)) + 1))[: len(text)]\n    result = []\n    for ch, key_ch in zip(text, keyword):\n        result.append(chr((ord(ch) + ord(key_ch)) % 65536))\n    return ''.join(result)\n\n\ndef vigenere_decrypt(ciphertext: str, keyword: str) -> str:\n    keyword = (keyword * ((len(ciphertext) // len(keyword)) + 1))[: len(ciphertext)]\n    result = []\n    for ch, key_ch in zip(ciphertext, keyword):\n        result.append(chr((ord(ch) - ord(key_ch)) % 65536))\n    return ''.join(result)\n\n\nmessage = "HELLO WORLD"\nencoded = vigenere_encrypt(message, "KEY")\ndecoded = vigenere_decrypt(encoded, "KEY")\nprint(encoded)\nprint(decoded)""",
        code_ru="""def vigenere_encrypt(text: str, keyword: str) -> str:\n    keyword = (keyword * ((len(text) // len(keyword)) + 1))[: len(text)]\n    result = []\n    for ch, key_ch in zip(text, keyword):\n        result.append(chr((ord(ch) + ord(key_ch)) % 65536))\n    return ''.join(result)\n\n\ndef vigenere_decrypt(ciphertext: str, keyword: str) -> str:\n    keyword = (keyword * ((len(ciphertext) // len(keyword)) + 1))[: len(ciphertext)]\n    result = []\n    for ch, key_ch in zip(ciphertext, keyword):\n        result.append(chr((ord(ch) - ord(key_ch)) % 65536))\n    return ''.join(result)\n\n\nmessage = "ПРИВЕТ МИР"\nencoded = vigenere_encrypt(message, "КЛЮЧ")\ndecoded = vigenere_decrypt(encoded, "КЛЮЧ")\nprint(encoded)\nprint(decoded)""",
    ),
    "xor": PracticeMaterial(
        title_en="XOR bytes with a repeating key",
        title_ru="XOR байтов с повторяющимся ключом",
        description_en=(
            "A stream XOR cipher transforms text into bytes and combines them"
            " with a repeating key. Applying the same routine twice restores"
            " the original message."
        ),
        description_ru=(
            "Потоковый XOR переводит текст в байты и комбинирует их с"
            " повторяющимся ключом. Повторное применение операции возвращает"
            " исходное сообщение."
        ),
        code_en="""import base64\n\n\ndef xor_cipher(text: str, key: str) -> str:\n    data = text.encode('utf-8')\n    key_bytes = key.encode('utf-8')\n    expanded_key = (key_bytes * ((len(data) // len(key_bytes)) + 1))[: len(data)]\n    encrypted = bytes([b ^ k for b, k in zip(data, expanded_key)])\n    return base64.b64encode(encrypted).decode('utf-8')\n\n\ndef xor_decipher(payload: str, key: str) -> str:\n    encrypted = base64.b64decode(payload.encode('utf-8'))\n    key_bytes = key.encode('utf-8')\n    expanded_key = (key_bytes * ((len(encrypted) // len(key_bytes)) + 1))[: len(encrypted)]\n    decrypted = bytes([b ^ k for b, k in zip(encrypted, expanded_key)])\n    return decrypted.decode('utf-8')\n\n\nmessage = "stream demo"\nencoded = xor_cipher(message, "secret")\ndecoded = xor_decipher(encoded, "secret")\nprint(encoded)\nprint(decoded)""",
        code_ru="""import base64\n\n\ndef xor_cipher(text: str, key: str) -> str:\n    data = text.encode('utf-8')\n    key_bytes = key.encode('utf-8')\n    expanded_key = (key_bytes * ((len(data) // len(key_bytes)) + 1))[: len(data)]\n    encrypted = bytes([b ^ k for b, k in zip(data, expanded_key)])\n    return base64.b64encode(encrypted).decode('utf-8')\n\n\ndef xor_decipher(payload: str, key: str) -> str:\n    encrypted = base64.b64decode(payload.encode('utf-8'))\n    key_bytes = key.encode('utf-8')\n    expanded_key = (key_bytes * ((len(encrypted) // len(key_bytes)) + 1))[: len(encrypted)]\n    decrypted = bytes([b ^ k for b, k in zip(encrypted, expanded_key)])\n    return decrypted.decode('utf-8')\n\n\nmessage = "пример потока"\nencoded = xor_cipher(message, "ключ")\ndecoded = xor_decipher(encoded, "ключ")\nprint(encoded)\nprint(decoded)""",
    ),
    "hash": PracticeMaterial(
        title_en="Produce irreversible SHA-256 digests",
        title_ru="Необратимое хеширование SHA-256",
        description_en=(
            "Hash functions map arbitrary input to a fixed-length digest. The"
            " snippet shows how to calculate SHA-256 and verify that the same"
            " input always produces the same hash."
        ),
        description_ru=(
            "Хеш-функции отображают произвольный ввод в значение фиксированной"
            " длины. Ниже показано вычисление SHA-256 и проверка, что одинаковый"
            " ввод даёт одинаковый результат."
        ),
        code_en="""import hashlib\n\ndef sha256_digest(text: str) -> str:\n    return hashlib.sha256(text.encode('utf-8')).hexdigest()\n\n\nmessage = "hash me"\ndigest = sha256_digest(message)\nprint(digest)\nprint(digest == sha256_digest(message))""",
        code_ru="""import hashlib\n\ndef sha256_digest(text: str) -> str:\n    return hashlib.sha256(text.encode('utf-8')).hexdigest()\n\n\nmessage = "захешируй меня"\ndigest = sha256_digest(message)\nprint(digest)\nprint(digest == sha256_digest(message))""",
    ),
    "affine": PracticeMaterial(
        title_en="Affine transformation over the Unicode range",
        title_ru="Аффинное преобразование по всему диапазону Unicode",
        description_en=(
            "The affine cipher multiplies each code point by a constant and"
            " adds an offset. The multiplicative constant must have a modular"
            " inverse for the alphabet size to enable decryption."
        ),
        description_ru=(
            "Аффинный шифр умножает код символа на константу и добавляет"
            " смещение. Константа должна иметь обратный элемент по модулю"
            " размера алфавита, чтобы было возможно расшифрование."
        ),
        code_en="""MODULUS = 65536\nA = 5\nB = 8\nINV_A = pow(A, -1, MODULUS)\n\n\ndef affine_encrypt(text: str) -> str:\n    return ''.join(chr((A * ord(ch) + B) % MODULUS) for ch in text)\n\n\ndef affine_decrypt(ciphertext: str) -> str:\n    return ''.join(chr(((ord(ch) - B) * INV_A) % MODULUS) for ch in ciphertext)\n\n\nmessage = "affine"\nencoded = affine_encrypt(message)\ndecoded = affine_decrypt(encoded)\nprint(encoded)\nprint(decoded)""",
        code_ru="""MODULUS = 65536\nA = 5\nB = 8\nINV_A = pow(A, -1, MODULUS)\n\ndef affine_encrypt(text: str) -> str:\n    return ''.join(chr((A * ord(ch) + B) % MODULUS) for ch in text)\n\n\ndef affine_decrypt(ciphertext: str) -> str:\n    return ''.join(chr(((ord(ch) - B) * INV_A) % MODULUS) for ch in ciphertext)\n\n\nmessage = "аффинный"\nencoded = affine_encrypt(message)\ndecoded = affine_decrypt(encoded)\nprint(encoded)\nprint(decoded)""",
    ),
    "rsa": PracticeMaterial(
        title_en="Toy RSA with fixed parameters",
        title_ru="Игрушечный RSA с фиксированными параметрами",
        description_en=(
            "This miniature RSA example uses hardcoded public and private"
            " keys. It is insecure for real applications but highlights the"
            " modular exponentiation workflow."
        ),
        description_ru=(
            "Этот упрощённый пример RSA использует фиксированные ключи. Он"
            " небезопасен для практики, но демонстрирует работу с модульными"
            " степенями."
        ),
        code_en="""N = 3233\nE = 17\nD = 2753\n\ndef rsa_encrypt(text: str) -> str:\n    return '-'.join(str(pow(ord(ch), E, N)) for ch in text)\n\ndef rsa_decrypt(ciphertext: str) -> str:\n    numbers = [int(part) for part in ciphertext.split('-') if part]\n    return ''.join(chr(pow(num, D, N)) for num in numbers)\n\n\nmessage = "rsa"\nencoded = rsa_encrypt(message)\ndecoded = rsa_decrypt(encoded)\nprint(encoded)\nprint(decoded)""",
        code_ru="""N = 3233\nE = 17\nD = 2753\n\ndef rsa_encrypt(text: str) -> str:\n    return '-'.join(str(pow(ord(ch), E, N)) for ch in text)\n\ndef rsa_decrypt(ciphertext: str) -> str:\n    numbers = [int(part) for part in ciphertext.split('-') if part]\n    return ''.join(chr(pow(num, D, N)) for num in numbers)\n\n\nmessage = "пример"\nencoded = rsa_encrypt(message)\ndecoded = rsa_decrypt(encoded)\nprint(encoded)\nprint(decoded)""",
    ),
    "elgamal": PracticeMaterial(
        title_en="Small primes for ElGamal",
        title_ru="Малые простые числа для Эль-Гамаля",
        description_en=(
            "ElGamal encrypts every byte as a pair of integers. The helper"
            " functions below use small primes to keep the math readable and"
            " demonstrate both directions of the algorithm."
        ),
        description_ru=(
            "Эль-Гамаль шифрует каждый байт как пару чисел. Вспомогательные"
            " функции ниже используют маленькие простые числа, чтобы упростить"
            " математику и показать оба направления алгоритма."
        ),
        code_en="""P = 467\nG = 2\nX = 127  # private key\nH = pow(G, X, P)\nK = 53     # ephemeral key\n\ndef elgamal_encrypt(text: str) -> str:\n    result = []\n    for ch in text.encode('utf-8'):\n        r = pow(G, K, P)\n        t = (pow(H, K, P) * ch) % P\n        result.append(f"{r}:{t}")\n    return '|'.join(result)\n\ndef elgamal_decrypt(ciphertext: str) -> str:\n    parts = [part for part in ciphertext.split('|') if part]\n    decoded = []\n    for part in parts:\n        r_str, t_str = part.split(':')\n        r = int(r_str)\n        t = int(t_str)\n        s = pow(r, X, P)\n        s_inv = pow(s, -1, P)\n        decoded.append((t * s_inv) % P)\n    return bytes(decoded).decode('utf-8')\n\n\nmessage = "elgamal"\nencoded = elgamal_encrypt(message)\ndecoded = elgamal_decrypt(encoded)\nprint(encoded)\nprint(decoded)""",
        code_ru="""P = 467\nG = 2\nX = 127  # закрытый ключ\nH = pow(G, X, P)\nK = 53     # одноразовый ключ\n\ndef elgamal_encrypt(text: str) -> str:\n    result = []\n    for ch in text.encode('utf-8'):\n        r = pow(G, K, P)\n        t = (pow(H, K, P) * ch) % P\n        result.append(f"{r}:{t}")\n    return '|'.join(result)\n\ndef elgamal_decrypt(ciphertext: str) -> str:\n    parts = [part for part in ciphertext.split('|') if part]\n    decoded = []\n    for part in parts:\n        r_str, t_str = part.split(':')\n        r = int(r_str)\n        t = int(t_str)\n        s = pow(r, X, P)\n        s_inv = pow(s, -1, P)\n        decoded.append((t * s_inv) % P)\n    return bytes(decoded).decode('utf-8')\n\n\nmessage = "пример"\nencoded = elgamal_encrypt(message)\ndecoded = elgamal_decrypt(encoded)\nprint(encoded)\nprint(decoded)""",
    ),
}
