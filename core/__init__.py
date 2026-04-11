"""
core/__init__.py
Expone la API pública del módulo de backend RSA.
"""
from .rsa_engine import RSAEngine, EncryptionResult, DecryptionResult
from .math_utils import (
    is_prime,
    get_primes_in_range,
    gcd,
    mod_inverse,
    mod_pow,
    generate_rsa_keys,
)

__all__ = [
    "RSAEngine",
    "EncryptionResult",
    "DecryptionResult",
    "is_prime",
    "get_primes_in_range",
    "gcd",
    "mod_inverse",
    "mod_pow",
    "generate_rsa_keys",
]