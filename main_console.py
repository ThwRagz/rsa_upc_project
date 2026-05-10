from core.math_utils import is_prime, gcd, mod_inverse, mod_pow
from core.rsa_engine import TABLA, TABLA_INVERSA
import random


def separador(titulo=""):
    print("\n" + "=" * 70)
    if titulo:
        print(titulo)
        print("=" * 70)


def pausar():
    input("\nPresiona Enter para continuar...")


def pedir_primo(nombre):
    while True:
        try:
            valor = int(input(f"Ingrese el número primo {nombre} de 1 o 2 cifras: "))

            if valor < 2 or valor > 99:
                print("Debe ingresar un número primo de 1 o 2 cifras.")
                continue

            if not is_prime(valor):
                print(f"{valor} no es primo. Corrija el valor.")
                continue

            return valor

        except ValueError:
            print("Entrada inválida. Ingrese un número entero.")


def validar_texto(texto):
    if not texto.strip():
        return False

    texto = texto.upper()

    for caracter in texto:
        if caracter not in TABLA:
            return False

    return True


def obtener_posibles_d(phi):
    return [d for d in range(2, phi) if gcd(d, phi) == 1]


def guardar_txt(contenido):
    nombre = input("Nombre del archivo TXT: ").strip()

    if not nombre:
        nombre = "mensaje_encriptado"

    if not nombre.endswith(".txt"):
        nombre += ".txt"

    with open(nombre, "w", encoding="utf-8") as archivo:
        archivo.write(contenido)

    print(f"\nArchivo guardado correctamente como: {nombre}")


def texto_a_numeros(texto):
    return [TABLA[caracter] for caracter in texto.upper()]


def numeros_a_texto(numeros):
    return "".join(TABLA_INVERSA.get(numero, "?") for numero in numeros)


def proceso_encriptacion():
    separador("PROCESO DE ENCRIPTACIÓN RSA")

    texto = input("Ingrese el texto a encriptar: ").upper()

    if not validar_texto(texto):
        print("\nError:")
        print("Solo se permiten letras, Ñ y espacios.")
        print("No se permiten números, emojis ni símbolos.")
        return

    p = pedir_primo("p")
    q = pedir_primo("q")

    while p == q:
        print("p y q deben ser primos diferentes.")
        q = pedir_primo("q")

    n = p * q
    phi = (p - 1) * (q - 1)

    mensaje_numerico = texto_a_numeros(texto)

    for m in mensaje_numerico:
        if m >= n:
            print("\nError:")
            print(f"El valor M = {m} no puede cifrarse porque debe cumplirse M < n.")
            print(f"Actualmente n = {n}. Usa primos más grandes.")
            return

    separador("1. CÁLCULO DE n Y φ(n)")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = p × q = {p} × {q} = {n}")
    print(f"φ(n) = ({p} - 1)({q} - 1) = {phi}")

    separador("2. POSIBLES VALORES DE d")
    posibles_d = obtener_posibles_d(phi)
    print("Condición: 1 < d < φ(n) y MCD(d, φ(n)) = 1")
    print(posibles_d)

    d = random.choice(posibles_d)
    print(f"\nSe selecciona d = {d}")

    separador("3. CÁLCULO DE e")
    e = mod_inverse(d, phi)
    print(f"e × {d} ≡ 1 mod {phi}")
    print(f"e = {e}")

    separador("4. GENERACIÓN DE CLAVES")
    print(f"Clave pública = (n, e) = ({n}, {e})")
    print(f"Clave privada = (n, d) = ({n}, {d})")

    separador("5. PROCESO DE ENCRIPTACIÓN")

    bloques_cifrados = []
    letras_cifradas = []

    print(f"Texto original: {texto}")
    print("\nMensaje original | Descripción                                      | Mensaje encriptado")
    print("-" * 115)

    for i, caracter in enumerate(texto, start=1):
        m = TABLA[caracter]
        c = mod_pow(m, e, n)
        letra_cifrada = TABLA_INVERSA.get(c, "?")

        bloques_cifrados.append(c)
        letras_cifradas.append(letra_cifrada)

        descripcion = f"Encripta con clave pública ({n}, {e})"

        print(
            f"{caracter} = {m:<3}         | "
            f"{descripcion:<44} | "
            f"C{i} ≡ {m}^{e} mod {n} = {c:<3} → {letra_cifrada}"
        )

    mensaje_cifrado_letras = "".join(letras_cifradas)

    print("\nMensaje encriptado en números:")
    print(bloques_cifrados)

    print("\nMensaje encriptado en letras:")
    print(mensaje_cifrado_letras)

    separador("6. GUARDAR MENSAJE ENCRIPTADO")

    contenido_txt = (
        "MENSAJE ENCRIPTADO RSA\n\n"
        f"Mensaje cifrado en letras:\n{mensaje_cifrado_letras}\n\n"
        f"Mensaje cifrado en números:\n{bloques_cifrados}\n\n"
        f"Clave privada para desencriptar:\n(n, d) = ({n}, {d})\n\n"
        "Instrucción:\n"
        "Para desencriptar, ingrese el mensaje cifrado y use la clave privada indicada.\n"
    )

    guardar = input("¿Desea guardar el mensaje encriptado en TXT? (s/n): ").lower()

    if guardar == "s":
        guardar_txt(contenido_txt)


def proceso_desencriptacion():
    separador("PROCESO DE DESENCRIPTACIÓN RSA")

    texto_cifrado = input("Ingrese el mensaje cifrado en letras: ").upper()

    if not validar_texto(texto_cifrado):
        print("\nError:")
        print("Solo se permiten letras, Ñ y espacios.")
        print("No se permiten números, emojis ni símbolos.")
        return

    p = pedir_primo("p")
    q = pedir_primo("q")

    while p == q:
        print("p y q deben ser primos diferentes.")
        q = pedir_primo("q")

    n = p * q
    phi = (p - 1) * (q - 1)

    mensaje_cifrado_numerico = texto_a_numeros(texto_cifrado)

    for c in mensaje_cifrado_numerico:
        if c >= n:
            print("\nError:")
            print(f"El valor C = {c} no puede desencriptarse porque debe cumplirse C < n.")
            print(f"Actualmente n = {n}. Usa primos más grandes.")
            return

    separador("1. CÁLCULO DE n Y φ(n)")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = p × q = {p} × {q} = {n}")
    print(f"φ(n) = ({p} - 1)({q} - 1) = {phi}")

    separador("2. POSIBLES VALORES DE d")
    posibles_d = obtener_posibles_d(phi)

    print("Condición: 1 < d < φ(n) y MCD(d, φ(n)) = 1")
    print(posibles_d)

    d = random.choice(posibles_d)
    print(f"\nSe selecciona d = {d}")

    separador("3. CÁLCULO DE e")
    e = mod_inverse(d, phi)

    print(f"e × {d} ≡ 1 mod {phi}")
    print(f"e = {e}")

    separador("4. GENERACIÓN DE CLAVES")
    print(f"Clave pública = (n, e) = ({n}, {e})")
    print(f"Clave privada = (n, d) = ({n}, {d})")

    separador("5. PROCESO DE DESENCRIPTACIÓN")

    bloques_descifrados = []
    letras_descifradas = []

    print(f"Mensaje cifrado: {texto_cifrado}")
    print("\nMensaje recibido | Descripción                                      | Mensaje desencriptado")
    print("-" * 115)

    for i, caracter in enumerate(texto_cifrado, start=1):
        c = TABLA[caracter]
        m = mod_pow(c, d, n)
        letra = TABLA_INVERSA.get(m, "?")

        bloques_descifrados.append(m)
        letras_descifradas.append(letra)

        descripcion = f"Desencripta con clave privada ({n}, {d})"

        print(
            f"{caracter} = {c:<3}        | "
            f"{descripcion:<44} | "
            f"M{i} ≡ {c}^{d} mod {n} = {m:<3} → {letra}"
        )

    mensaje_desencriptado = "".join(letras_descifradas)

    print("\nMensaje recibido en números:")
    print(mensaje_cifrado_numerico)

    print("\nMensaje desencriptado en números:")
    print(bloques_descifrados)

    print("\nMensaje desencriptado en letras:")
    print(mensaje_desencriptado)

    separador("6. GUARDAR MENSAJE DESENCRIPTADO")

    contenido_txt = (
        "MENSAJE DESENCRIPTADO RSA\n\n"
        f"Mensaje cifrado recibido:\n{texto_cifrado}\n\n"
        f"Mensaje cifrado en números:\n{mensaje_cifrado_numerico}\n\n"
        f"Clave privada utilizada:\n(n, d) = ({n}, {d})\n\n"
        f"Mensaje desencriptado:\n{mensaje_desencriptado}\n"
    )

    guardar = input("¿Desea guardar el mensaje desencriptado en TXT? (s/n): ").lower()

    if guardar == "s":
        guardar_txt(contenido_txt)

def menu():
    while True:
        separador("MENÚ PRINCIPAL - CRIPTOGRAFÍA RSA")
        print("[1] Encriptación")
        print("[2] Desencriptación")
        print("[0] Salir")

        opcion = input("\nSeleccione una opción: ").strip()

        if opcion == "1":
            proceso_encriptacion()
            pausar()
        elif opcion == "2":
            proceso_desencriptacion()
            pausar()
        elif opcion == "0":
            print("\nPrograma finalizado.")
            break
        else:
            print("Opción inválida.")
            pausar()


if __name__ == "__main__":
    menu()