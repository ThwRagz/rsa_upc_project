from __future__ import annotations
from dataclasses import dataclass
from .math_utils import mod_pow, generate_rsa_keys


TABLA = {
    "A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5, "G": 6,
    "H": 7, "I": 8, "J": 9, "K": 10, "L": 11, "M": 12,
    "N": 13, "Ñ": 14, "O": 15, "P": 16, "Q": 17, "R": 18,
    "S": 19, "T": 20, "U": 21, "V": 22, "W": 23, "X": 24,
    "Y": 25, "Z": 26, " ": 27
}

TABLA_INVERSA = {valor: letra for letra, valor in TABLA.items()}


@dataclass
class RSAKeys:
    p: int
    q: int
    n: int
    phi: int
    e: int
    d: int

    @property
    def public_key(self) -> tuple[int, int]:
        return (self.e, self.n)

    @property
    def private_key(self) -> tuple[int, int]:
        return (self.d, self.n)


@dataclass
class EncryptionResult:
    original_text: str
    chunks: list[str]
    numeric_blocks: list[int]
    cipher_blocks: list[int]
    public_key: tuple[int, int]

    def cipher_string(self, separator: str = " ") -> str:
        return separator.join(str(c) for c in self.cipher_blocks)


@dataclass
class DecryptionResult:
    cipher_blocks: list[int]
    numeric_blocks: list[int]
    chunks: list[str]
    recovered_text: str
    private_key: tuple[int, int]


class RSAEngine:
    def __init__(self, p: int, q: int) -> None:
        params = generate_rsa_keys(p, q)

        self.keys = RSAKeys(
            p=params["p"],
            q=params["q"],
            n=params["n"],
            phi=params["phi"],
            e=params["e"],
            d=params["d"],
        )

    @staticmethod
    def text_to_blocks(text: str) -> tuple[list[str], list[int]]:
        text = text.upper()
        chunks = []
        numeric_blocks = []

        for caracter in text:
            if caracter not in TABLA:
                raise ValueError(
                    f"Caracter inválido: '{caracter}'. "
                    "Solo se permiten letras, Ñ y espacios."
                )

            chunks.append(caracter)
            numeric_blocks.append(TABLA[caracter])

        return chunks, numeric_blocks

    @staticmethod
    def blocks_to_text(numeric_blocks: list[int]) -> str:
        texto = ""

        for block in numeric_blocks:
            if block not in TABLA_INVERSA:
                raise ValueError(
                    f"El valor {block} no existe en la tabla de equivalencia."
                )

            texto += TABLA_INVERSA[block]

        return texto

    def _validate_blocks(self, numeric_blocks: list[int]) -> None:
        n = self.keys.n

        for block in numeric_blocks:
            if block >= n:
                raise ValueError(
                    f"El valor M={block} no puede cifrarse porque debe cumplirse M < n. "
                    f"Actualmente n={n}. Usa primos más grandes."
                )

    def encrypt(self, plaintext: str) -> EncryptionResult:
        if not plaintext.strip():
            raise ValueError("El texto a cifrar no puede estar vacío.")

        e, n = self.keys.public_key

        chunks, numeric_blocks = self.text_to_blocks(plaintext)
        self._validate_blocks(numeric_blocks)

        cipher_blocks = [mod_pow(m, e, n) for m in numeric_blocks]

        return EncryptionResult(
            original_text=plaintext.upper(),
            chunks=chunks,
            numeric_blocks=numeric_blocks,
            cipher_blocks=cipher_blocks,
            public_key=(e, n),
        )

    def decrypt(self, cipher_blocks: list[int]) -> DecryptionResult:
        if not cipher_blocks:
            raise ValueError("La lista de bloques cifrados no puede estar vacía.")

        d, n = self.keys.private_key

        numeric_blocks = [mod_pow(c, d, n) for c in cipher_blocks]
        recovered_text = self.blocks_to_text(numeric_blocks)
        chunks = list(recovered_text)

        return DecryptionResult(
            cipher_blocks=cipher_blocks,
            numeric_blocks=numeric_blocks,
            chunks=chunks,
            recovered_text=recovered_text,
            private_key=(d, n),
        )

    def full_cycle(self, plaintext: str) -> dict:
        enc = self.encrypt(plaintext)
        dec = self.decrypt(enc.cipher_blocks)

        return {
            "p": self.keys.p,
            "q": self.keys.q,
            "n": self.keys.n,
            "phi": self.keys.phi,
            "e": self.keys.e,
            "d": self.keys.d,
            "public_key": self.keys.public_key,
            "private_key": self.keys.private_key,
            "original_text": enc.original_text,
            "text_chunks": enc.chunks,
            "numeric_blocks_plain": enc.numeric_blocks,
            "cipher_blocks": enc.cipher_blocks,
            "numeric_blocks_recovered": dec.numeric_blocks,
            "text_chunks_recovered": dec.chunks,
            "recovered_text": dec.recovered_text,
            "integrity_ok": enc.original_text == dec.recovered_text,
        }

    def __repr__(self) -> str:
        return (
            f"RSAEngine(p={self.keys.p}, q={self.keys.q}, "
            f"n={self.keys.n}, e={self.keys.e}, d={self.keys.d})"
        )