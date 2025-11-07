from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from app.encryption.algorithms import ALGORITHMS, CipherAlgorithm, CipherInfo
from app.encryption.practice import PRACTICE_MATERIALS, PracticeMaterial


class EncryptionService:
    def __init__(self, algorithms: Dict[str, CipherAlgorithm] | None = None) -> None:
        self._algorithms = algorithms or ALGORITHMS

    def get_algorithm(self, slug: str) -> CipherAlgorithm:
        if slug not in self._algorithms:
            raise KeyError(f"Unknown algorithm: {slug}")
        return self._algorithms[slug]

    def all_algorithms(self) -> Iterable[CipherAlgorithm]:
        return self._algorithms.values()

    def algorithms_by_category(self, category: str) -> List[CipherAlgorithm]:
        return [
            algorithm
            for algorithm in self._algorithms.values()
            if algorithm.info.category == category
        ]

    def categories(self) -> Dict[str, List[CipherAlgorithm]]:
        categories: Dict[str, List[CipherAlgorithm]] = {}
        for algorithm in self._algorithms.values():
            categories.setdefault(algorithm.info.category, []).append(algorithm)
        return categories

    def get_practice_material(self, slug: str) -> PracticeMaterial | None:
        return PRACTICE_MATERIALS.get(slug)

    def encrypt(self, slug: str, plaintext: str, key: Optional[str] = None) -> str:
        algorithm = self.get_algorithm(slug)
        return algorithm.encrypt(plaintext, key)

    def verify(
        self, slug: str, plaintext: str, encrypted: str, key: Optional[str] = None
    ) -> bool:
        algorithm = self.get_algorithm(slug)
        return algorithm.matches(plaintext, encrypted, key)

    def describe(self) -> Dict[str, CipherInfo]:
        return {slug: algo.info for slug, algo in self._algorithms.items()}
