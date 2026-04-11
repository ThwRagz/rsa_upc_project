"""
rsa_engine.py
=============
Controlador RSA: transforma texto ↔ números, gestiona la segmentación
dinámica (chunking) y expone las operaciones de cifrado/descifrado.

Arquitectura de chunking (Bloques Dinámicos)
-------------------------------------------------------
El módulo n determina el tamaño máximo de valor numérico permitido.
En lugar de cifrar carácter a carácter (ineficiente y vulnerable a
análisis de frecuencia), el motor calcula dinámicamente cuántos bytes
pueden agruparse en un solo bloque sin superar n.

Ejemplo con p=89, q=97  →  n=8633:
  - "UP" = 0x55_50 = 21840  > 8633  ✗  (2 bytes no caben)
  - "U"  = 0x55   = 85     < 8633  ✓  (1 byte sí cabe)
  → chunk_size = 1 byte

Ejemplo con p=89, q=97  →  n=8633, texto "UPC":
  Bloques: [85, 80, 67]  →  cifrados: [c1, c2, c3]

Para n ≥ 65536 (p,q suficientemente grandes):
  - "UP" = 21840 < 65536  ✓  → chunk_size = 2 bytes
  - Bloques de 2 caracteres maximizan eficiencia.
"""

from __future__ import annotations
from dataclasses import dataclass
from .math_utils import mod_pow, generate_rsa_keys


# ---------------------------------------------------------------------------
# 1. ESTRUCTURAS DE DATOS
# ---------------------------------------------------------------------------

@dataclass
class RSAKeys:
    """Contenedor inmutable para las claves y parámetros RSA."""
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
    """Resultado completo de una operación de cifrado."""
    original_text: str
    chunks: list[str]          # Fragmentos de texto originales
    numeric_blocks: list[int]  # Bloques numéricos antes de cifrar
    cipher_blocks: list[int]   # Bloques cifrados
    chunk_size: int            # Bytes por bloque usados
    public_key: tuple[int, int]

    def cipher_string(self, separator: str = " ") -> str:
        """Retorna los bloques cifrados como string separado."""
        return separator.join(str(c) for c in self.cipher_blocks)


@dataclass
class DecryptionResult:
    """Resultado completo de una operación de descifrado."""
    cipher_blocks: list[int]
    numeric_blocks: list[int]  # Bloques numéricos recuperados
    chunks: list[str]          # Fragmentos de texto recuperados
    recovered_text: str
    chunk_size: int
    private_key: tuple[int, int]


# ---------------------------------------------------------------------------
# 2. MOTOR RSA
# ---------------------------------------------------------------------------

class RSAEngine:
    """
    Motor RSA completo: generación de claves, cifrado y descifrado de texto.

    Uso básico:
        engine = RSAEngine(p=89, q=97)
        result = engine.encrypt("UPC")
        recovered = engine.decrypt(result.cipher_blocks)
        print(recovered.recovered_text)  # → "UPC"
    """

    def __init__(self, p: int, q: int) -> None:
        """
        Inicializa el motor generando todas las claves RSA.

        Args:
            p: Primer primo (1-2 cifras).
            q: Segundo primo (1-2 cifras), distinto de p.

        Raises:
            ValueError: Si p o q son inválidos.
        """
        params = generate_rsa_keys(p, q)
        self.keys = RSAKeys(
            p=params['p'], q=params['q'],
            n=params['n'], phi=params['phi'],
            e=params['e'], d=params['d'],
        )
        self._chunk_size: int = self._compute_chunk_size()

    # -----------------------------------------------------------------------
    # 2a. CHUNKING DINÁMICO
    # -----------------------------------------------------------------------

    def _compute_chunk_size(self) -> int:
        """
        Calcula el tamaño óptimo de bloque en bytes según n.

        Estrategia:
          Prueba bloques de tamaño creciente (1, 2, 3, …).
          El bloque de k bytes tiene el mayor valor posible cuando todos
          sus bytes son 0xFF (255). Ese valor es:
              max_val(k) = 256^k - 1
          Si max_val(k) < n, k bytes caben con seguridad.
          Si max_val(k) >= n, usamos k-1 bytes.

        Returns:
            Tamaño de bloque en bytes (mínimo 1).
        """
        n = self.keys.n
        chunk_size = 1
        while True:
            next_size = chunk_size + 1
            max_val = 256 ** next_size - 1   # Peor caso: todos bytes = 0xFF
            if max_val < n:
                chunk_size = next_size
            else:
                break
        return chunk_size

    @property
    def chunk_size(self) -> int:
        """Bytes por bloque calculados para este n."""
        return self._chunk_size

    # -----------------------------------------------------------------------
    # 2b. CONVERSIÓN TEXTO ↔ NÚMERO
    # -----------------------------------------------------------------------

    @staticmethod
    def text_to_blocks(text: str, chunk_size: int) -> tuple[list[str], list[int]]:
        """
        Divide el texto en fragmentos y convierte cada uno a entero.

        Conversión: interpreta los bytes del fragmento como un entero
        big-endian (el primer byte es el más significativo).

        Ejemplo (chunk_size=1):
          "UPC" → chunks=["U","P","C"] → blocks=[85, 80, 67]

        Ejemplo (chunk_size=2, si n lo permite):
          "UPCA" → chunks=["UP","CA"] → blocks=[21840, 16961]

        Args:
            text:       Texto a convertir (UTF-8).
            chunk_size: Bytes por fragmento.

        Returns:
            Tupla (chunks_text, numeric_blocks).
        """
        encoded = text.encode('utf-8')
        chunks_text: list[str] = []
        numeric_blocks: list[int] = []

        for i in range(0, len(encoded), chunk_size):
            byte_chunk = encoded[i: i + chunk_size]
            # Interpreta los bytes como entero big-endian
            numeric_val = int.from_bytes(byte_chunk, byteorder='big')
            # Decodifica solo para mostrar el fragmento de texto (best-effort)
            try:
                chunk_str = byte_chunk.decode('utf-8')
            except UnicodeDecodeError:
                chunk_str = repr(byte_chunk)
            chunks_text.append(chunk_str)
            numeric_blocks.append(numeric_val)

        return chunks_text, numeric_blocks

    @staticmethod
    def blocks_to_text(numeric_blocks: list[int], chunk_size: int) -> str:
        """
        Convierte una lista de enteros de vuelta al texto original.

        Inverso exacto de text_to_blocks.

        Args:
            numeric_blocks: Lista de enteros recuperados tras descifrar.
            chunk_size:     Bytes por bloque (el mismo usado al cifrar).

        Returns:
            Texto reconstruido.

        Raises:
            ValueError: Si algún bloque produce bytes inválidos UTF-8.
        """
        recovered_bytes = bytearray()
        for block in numeric_blocks:
            # Calcula el mínimo de bytes necesarios para representar el valor,
            # pero respeta chunk_size para bloques intermedios.
            # El bloque final puede ser más corto que chunk_size.
            byte_length = max(1, (block.bit_length() + 7) // 8)
            byte_length = min(byte_length, chunk_size)  # no exceder chunk_size
            recovered_bytes.extend(
                block.to_bytes(byte_length, byteorder='big')
            )
        try:
            return recovered_bytes.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Error al reconstruir el texto: los bytes descifrados no son "
                f"UTF-8 válido. Detalle: {exc}"
            ) from exc

    # -----------------------------------------------------------------------
    # 2c. VALIDACIÓN DE BLOQUES
    # -----------------------------------------------------------------------

    def _validate_blocks(self, numeric_blocks: list[int]) -> None:
        """
        Verifica que ningún bloque supere n-1 antes de cifrar.

        Si alguno lo supera, lanza ValueError con diagnóstico detallado
        en lugar de silenciosamente corromper los datos.

        Args:
            numeric_blocks: Bloques numéricos a validar.

        Raises:
            ValueError: Si algún bloque >= n.
        """
        n = self.keys.n
        for i, block in enumerate(numeric_blocks):
            if block >= n:
                raise ValueError(
                    f"Bloque #{i} tiene valor {block}, que es ≥ n={n}. "
                    "Esto causaría pérdida de datos irrecuperable. "
                    "El chunking dinámico debería haber prevenido esto; "
                    "verifica que chunk_size sea correcto."
                )

    # -----------------------------------------------------------------------
    # 2d. CIFRADO
    # -----------------------------------------------------------------------

    def encrypt(self, plaintext: str) -> EncryptionResult:
        """
        Cifra un texto plano usando la clave pública (e, n).

        Operación por bloque:  c = m^e mod n

        Flujo completo:
          1. Divide el texto en bloques de `chunk_size` bytes.
          2. Convierte cada bloque a entero m.
          3. Valida m < n (falla fuerte si no se cumple).
          4. Calcula c = m^e mod n para cada bloque.

        Args:
            plaintext: Texto a cifrar (no vacío).

        Returns:
            EncryptionResult con todos los bloques y metadatos.

        Raises:
            ValueError: Si el texto está vacío o contiene caracteres
                        que generan bloques >= n.
        """
        if not plaintext:
            raise ValueError("El texto a cifrar no puede estar vacío.")

        e, n = self.keys.e, self.keys.n

        # 1 & 2: Fragmentar y convertir
        chunks, numeric_blocks = self.text_to_blocks(plaintext, self._chunk_size)

        # 3: Validar ANTES de cifrar
        self._validate_blocks(numeric_blocks)

        # 4: Cifrar cada bloque
        cipher_blocks = [mod_pow(m, e, n) for m in numeric_blocks]

        return EncryptionResult(
            original_text=plaintext,
            chunks=chunks,
            numeric_blocks=numeric_blocks,
            cipher_blocks=cipher_blocks,
            chunk_size=self._chunk_size,
            public_key=(e, n),
        )

    # -----------------------------------------------------------------------
    # 2e. DESCIFRADO
    # -----------------------------------------------------------------------

    def decrypt(self, cipher_blocks: list[int]) -> DecryptionResult:
        """
        Descifra una lista de bloques cifrados usando la clave privada (d, n).

        Operación por bloque:  m = c^d mod n

        Args:
            cipher_blocks: Lista de enteros cifrados (salida de encrypt).

        Returns:
            DecryptionResult con el texto recuperado y metadatos.

        Raises:
            ValueError: Si la lista está vacía o el descifrado produce
                        bytes inválidos.
        """
        if not cipher_blocks:
            raise ValueError("La lista de bloques cifrados no puede estar vacía.")

        d, n = self.keys.d, self.keys.n

        # Descifrar cada bloque: m = c^d mod n
        numeric_blocks = [mod_pow(c, d, n) for c in cipher_blocks]

        # Convertir de vuelta a texto
        chunks = []
        for block in numeric_blocks:
            byte_length = max(1, (block.bit_length() + 7) // 8)
            byte_length = min(byte_length, self._chunk_size)
            try:
                chunk_str = block.to_bytes(byte_length, 'big').decode('utf-8')
            except (UnicodeDecodeError, OverflowError):
                chunk_str = repr(block)
            chunks.append(chunk_str)

        recovered_text = self.blocks_to_text(numeric_blocks, self._chunk_size)

        return DecryptionResult(
            cipher_blocks=cipher_blocks,
            numeric_blocks=numeric_blocks,
            chunks=chunks,
            recovered_text=recovered_text,
            chunk_size=self._chunk_size,
            private_key=(d, n),
        )

    # -----------------------------------------------------------------------
    # 2f. CICLO COMPLETO (útil para tests y demo)
    # -----------------------------------------------------------------------

    def full_cycle(self, plaintext: str) -> dict:
        """
        Ejecuta cifrado + descifrado y retorna un reporte completo.
        Ideal para verificar integridad y para mostrar en la UI de demostración.

        Args:
            plaintext: Texto a cifrar y luego descifrar.

        Returns:
            Diccionario con parámetros, pasos intermedios y verificación.
        """
        enc = self.encrypt(plaintext)
        dec = self.decrypt(enc.cipher_blocks)

        return {
            # Parámetros del sistema
            'p': self.keys.p,
            'q': self.keys.q,
            'n': self.keys.n,
            'phi': self.keys.phi,
            'e': self.keys.e,
            'd': self.keys.d,
            'public_key': self.keys.public_key,
            'private_key': self.keys.private_key,
            'chunk_size': self._chunk_size,

            # Cifrado
            'original_text': enc.original_text,
            'text_chunks': enc.chunks,
            'numeric_blocks_plain': enc.numeric_blocks,
            'cipher_blocks': enc.cipher_blocks,

            # Descifrado
            'numeric_blocks_recovered': dec.numeric_blocks,
            'text_chunks_recovered': dec.chunks,
            'recovered_text': dec.recovered_text,

            # Verificación
            'integrity_ok': plaintext == dec.recovered_text,
        }

    # -----------------------------------------------------------------------
    # 2g. REPRESENTACIÓN
    # -----------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"RSAEngine(p={self.keys.p}, q={self.keys.q}, "
            f"n={self.keys.n}, e={self.keys.e}, d={self.keys.d}, "
            f"chunk_size={self._chunk_size})"
        )