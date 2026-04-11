"""
math_utils.py
=============
Operaciones matemáticas de bajo nivel para el motor RSA.
Incluye: verificación de primalidad, algoritmo de Euclides extendido,
exponenciación modular y generación de claves.
"""


# ---------------------------------------------------------------------------
# 1. PRIMALIDAD
# ---------------------------------------------------------------------------

def is_prime(n: int) -> bool:
    """
    Verifica si un número entero positivo es primo.

    Utiliza el método de división por prueba con optimización √n.
    Válido y eficiente para números de 1-2 cifras requeridos por el proyecto.

    Args:
        n: Entero a verificar.

    Returns:
        True si n es primo, False en caso contrario.
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    # Solo verificamos divisores impares hasta √n
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def get_primes_in_range(low: int = 2, high: int = 99) -> list[int]:
    """
    Retorna todos los primos en el rango [low, high].
    Útil para poblar selectores de UI.

    Args:
        low:  Límite inferior (incluido).
        high: Límite superior (incluido).

    Returns:
        Lista de enteros primos en el rango dado.
    """
    return [n for n in range(low, high + 1) if is_prime(n)]


# ---------------------------------------------------------------------------
# 2. ALGORITMO DE EUCLIDES EXTENDIDO
# ---------------------------------------------------------------------------

def gcd(a: int, b: int) -> int:
    """
    Calcula el máximo común divisor usando el algoritmo de Euclides.

    Args:
        a, b: Enteros no negativos.

    Returns:
        mcd(a, b)
    """
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Algoritmo de Euclides Extendido.
    Encuentra (g, x, y) tal que  a*x + b*y = g = mcd(a, b).

    Aplicación en RSA: calcular el inverso modular de e respecto a φ(n).

    Args:
        a, b: Enteros.

    Returns:
        Tupla (g, x, y) donde g = mcd(a, b) y a*x + b*y = g.
    """
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def mod_inverse(e: int, phi: int) -> int:
    """
    Calcula el inverso modular de e módulo phi.
    Es decir, encuentra d tal que (e * d) ≡ 1 (mod phi).

    Usado para obtener la clave privada d a partir de e y φ(n).

    Args:
        e:   Exponente público.
        phi: φ(n) = (p-1)(q-1).

    Returns:
        d: Clave privada (inverso modular de e).

    Raises:
        ValueError: Si e y phi no son coprimos (mcd ≠ 1), es decir,
                    no existe inverso modular.
    """
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError(
            f"No existe inverso modular: mcd({e}, {phi}) = {g} ≠ 1. "
            "Elige un exponente público 'e' coprimo con φ(n)."
        )
    return x % phi


# ---------------------------------------------------------------------------
# 3. EXPONENCIACIÓN MODULAR
# ---------------------------------------------------------------------------

def mod_pow(base: int, exp: int, mod: int) -> int:
    """
    Calcula (base ^ exp) % mod de forma eficiente.

    Usa el algoritmo de exponenciación rápida (square-and-multiply),
    con complejidad O(log exp) en lugar de O(exp).

    NOTA: Python tiene `pow(base, exp, mod)` nativo que hace exactamente
    esto, pero lo implementamos explícitamente para transparencia didáctica.

    Args:
        base: Base de la potencia.
        exp:  Exponente (≥ 0).
        mod:  Módulo (> 1).

    Returns:
        (base ** exp) % mod

    Raises:
        ValueError: Si mod ≤ 1 o exp < 0.
    """
    if mod <= 1:
        raise ValueError(f"El módulo debe ser > 1, se recibió: {mod}")
    if exp < 0:
        raise ValueError(f"El exponente debe ser ≥ 0, se recibió: {exp}")

    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:          # bit actual es 1
            result = (result * base) % mod
        exp //= 2                  # desplazamiento de bit
        base = (base * base) % mod
    return result


# ---------------------------------------------------------------------------
# 4. GENERACIÓN DE EXPONENTE PÚBLICO
# ---------------------------------------------------------------------------

def find_public_exponent(phi: int) -> int:
    """
    Encuentra el exponente público 'e' más pequeño válido para RSA.

    Condiciones requeridas:
      - 1 < e < φ(n)
      - mcd(e, φ(n)) = 1  (coprimos)

    Empieza desde e=3 (el mínimo seguro) e incrementa de 2 en 2
    para buscar solo impares y acelerar la búsqueda.

    Args:
        phi: φ(n) = (p-1)(q-1).

    Returns:
        e: Exponente público válido.

    Raises:
        ValueError: Si no se encuentra e válido en el rango (caso teóricamente
                    imposible para φ(n) > 2).
    """
    # e=65537 es el estándar de la industria, pero puede ser mayor que φ(n)
    # para primos pequeños, así que buscamos desde el mínimo.
    e = 3
    while e < phi:
        if gcd(e, phi) == 1:
            return e
        e += 2
    raise ValueError(
        f"No se encontró exponente público válido para φ(n) = {phi}. "
        "Verifica que los primos p y q sean distintos y válidos."
    )


# ---------------------------------------------------------------------------
# 5. GENERACIÓN COMPLETA DE CLAVES RSA
# ---------------------------------------------------------------------------

def generate_rsa_keys(p: int, q: int) -> dict:
    """
    Genera el par completo de claves RSA a partir de dos primos p y q.

    Flujo:
      1. Valida que p y q sean primos distintos.
      2. Calcula n = p * q  (módulo público).
      3. Calcula φ(n) = (p-1)(q-1)  (función de Euler).
      4. Elige e: coprimo con φ(n)  (exponente público).
      5. Calcula d = e⁻¹ mod φ(n)  (clave privada).

    Args:
        p: Primer número primo (1-2 cifras).
        q: Segundo número primo (1-2 cifras), distinto de p.

    Returns:
        Diccionario con las claves y parámetros del sistema:
        {
            'p': int,            # Primo p
            'q': int,            # Primo q
            'n': int,            # Módulo n = p*q
            'phi': int,          # φ(n) = (p-1)(q-1)
            'e': int,            # Exponente público
            'd': int,            # Clave privada
            'public_key': (e, n),
            'private_key': (d, n),
            'max_block_value': int,   # Valor máximo permitido por bloque (= n-1)
        }

    Raises:
        ValueError: Si p o q no son primos, o si p == q.
    """
    # --- Validaciones ---
    if not is_prime(p):
        raise ValueError(f"p = {p} no es un número primo.")
    if not is_prime(q):
        raise ValueError(f"q = {q} no es un número primo.")
    if p == q:
        raise ValueError(
            f"p y q deben ser distintos. Se recibió p = q = {p}."
        )

    # --- Parámetros RSA ---
    n = p * q
    phi = (p - 1) * (q - 1)
    e = find_public_exponent(phi)
    d = mod_inverse(e, phi)

    return {
        'p': p,
        'q': q,
        'n': n,
        'phi': phi,
        'e': e,
        'd': d,
        'public_key': (e, n),
        'private_key': (d, n),
        'max_block_value': n - 1,
    }