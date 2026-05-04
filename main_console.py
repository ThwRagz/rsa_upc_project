# !!!ESTE ARCHIVO CONTIENE SOLO UI!!!
# (menu, input, output)

from core.rsa_engine import RSAEngine
from core.math_utils import is_prime
import os

# ----------------
# output formating
# ----------------

def limpiar_pantalla():
    os.system('cls' if os.name == 'nt' else 'clear')

def separador(titulo=""):
    linea = "=" * 50
    if titulo:
        print(f"\n{linea}")
        print(f"  {titulo}")
        print(f"{linea}")
    else:
        print(linea)

def pausar():
    input("\n  Presiona Enter para continuar...")


def pedir_primo(nombre):
    # try/catch para input
    while True:
        try:
            valor = int(input(f"  Ingresa el primo {nombre}: "))

            if not is_prime(valor):
                print(f"  {valor} no es primo, intenta con otro")
                continue

            return valor

        except ValueError:
            print("  eso no es un numero, intentalo de nuevo")

# -------------
# menu opciones
# -------------

def opcion_generar_claves(estado):
    separador("GENERAR CLAVES RSA")
    print("\n  necesitamos dos primos distintos, p y q\n")
    p = pedir_primo("p")
    q = pedir_primo("q")
    if p == q:
        print("\n  p y q tienen que ser distintos, no funciona con el mismo")
        pausar()
        return
    try:
        engine = RSAEngine(p, q)
    except ValueError as err:
        print(f"\n  error: {err}")
        pausar()
        return
    k = engine.keys
    print(f"\n  Primos          : p={k.p}, q={k.q}")
    print(f"  Modulo          : n = {k.p} x {k.q} = {k.n}")
    print(f"  Euler fi(n)     : ({k.p}-1)({k.q}-1) = {k.phi}")
    print(f"  Exp. publico    : e = {k.e}")
    print(f"  Exp. privado    : d = {k.d}")
    print(f"  chunk size      : {engine.chunk_size} byte(s) por bloque")
    print(f"\n  clave publica  ->  (n={k.n}, e={k.e})")
    print(f"  clave privada  ->  (n={k.n}, d={k.d})")
    # guardar estado
    estado['engine'] = engine
    estado['claves_listas'] = True
    print("\n  listo, claves guardadas en sesion")
    pausar()


def opcion_cifrar(estado):
    separador("CIFRAR MENSAJE")

    if not estado.get('claves_listas'):
        print("\n  primero genera las claves con la opcion 1")
        pausar()
        return

    engine = estado['engine']
    e, n = engine.keys.public_key
    print(f"\n  usando clave publica (n={n}, e={e})")
    print(f"  chunk size: {engine.chunk_size} byte(s)\n")

    texto = input("  texto a cifrar: ")
    if not texto.strip():
        print("\n  el texto no puede estar vacio")
        pausar()
        return
    try:
        resultado = engine.encrypt(texto)
    except ValueError as err:
        print(f"\n  error al cifrar: {err}")
        pausar()
        return

    # print bloque por bloque
    print(f"\n  {'fragmento':<12} {'M (numero)':<14} {'C (cifrado)'}")
    print("  " + "-" * 40)
    for chunk, m, c in zip(resultado.chunks, resultado.numeric_blocks, resultado.cipher_blocks):
        print(f"  {repr(chunk):<12} {m:<14} {c}")
    estado['ultimo_cifrado'] = resultado.cipher_blocks
    print(f"\n  resultado: {resultado.cipher_blocks}")
    pausar()


def opcion_descifrar(estado):
    separador("DESCIFRAR MENSAJE")

    if not estado.get('claves_listas'):
        print("\n  genera las claves primero (opcion 1)")
        pausar()
        return

    engine = estado['engine']
    d, n = engine.keys.private_key
    print(f"\n  usando clave privada (n={n}, d={d})\n")

    if estado.get('ultimo_cifrado'):
        usar = input("  usar el ultimo mensaje cifrado? (s/n): ").lower()
        cifrados = estado['ultimo_cifrado'] if usar == 's' else pedir_lista_cifrados()
    else:
        cifrados = pedir_lista_cifrados()
    if cifrados is None:
        pausar()
        return
    try:
        resultado = engine.decrypt(cifrados)
    except ValueError as err:
        print(f"\n  error al descifrar: {err}")
        pausar()
        return

    # print bloque por bloque
    print(f"\n  {'C (cifrado)':<14} {'M (numero)':<14} {'fragmento'}")
    print("  " + "-" * 40)
    for c, m, chunk in zip(resultado.cipher_blocks, resultado.numeric_blocks, resultado.chunks):
        print(f"  {c:<14} {m:<14} {repr(chunk)}")
    print(f"\n  mensaje original: {resultado.recovered_text}")
    pausar()


def pedir_lista_cifrados():
    try:
        raw = input("  ingresa los numeros cifrados separados por comas: ")
        return [int(x.strip()) for x in raw.split(',')]
    except ValueError:
        print("\n  formato invalido, ejemplo: 9, 14, 11")
        return None


def opcion_ciclo_completo(estado):
    # cifra y descifra en un paso, util para demo
    separador("CICLO COMPLETO")

    if not estado.get('claves_listas'):
        print("\n  genera las claves primero (opcion 1)")
        pausar()
        return
    texto = input("\n  texto a usar: ")
    if not texto.strip():
        print("\n  el texto no puede estar vacio")
        pausar()
        return
    try:
        reporte = estado['engine'].full_cycle(texto)
    except ValueError as err:
        print(f"\n  error: {err}")
        pausar()
        return

    print(f"\n  original   : {reporte['original_text']}")
    print(f"  cifrado    : {reporte['cipher_blocks']}")
    print(f"  recuperado : {reporte['recovered_text']}")
    print(f"  integridad : {'OK' if reporte['integrity_ok'] else 'FALLO'}")
    pausar()


def opcion_ver_estado(estado):
    separador("ESTADO DE LA SESION")
    if not estado.get('claves_listas'):
        print("\n  todavia no hay claves generadas")
    else:
        k = estado['engine'].keys
        print(f"\n  n  (modulo)       = {k.n}")
        print(f"  e  (pub)          = {k.e}")
        print(f"  d  (priv)         = {k.d}")
        print(f"  chunk size        = {estado['engine'].chunk_size}")
        if estado.get('ultimo_cifrado'):
            print(f"  ultimo cifrado    = {estado['ultimo_cifrado']}")

    pausar()


def opcion_limpiar(estado):
    estado.clear()
    print("\n  sesion limpia, como nuevo")
    pausar()


# ----------------------
# menu principal y loop
# ----------------------

def mostrar_menu():
    separador("SISTEMA RSA  -  MA475 UPC")
    print("""
  [1] Generar claves RSA
  [2] Cifrar mensaje
  [3] Descifrar mensaje
  [4] Ciclo completo (cifrar + descifrar)
  [5] Ver estado de sesion
  [6] Limpiar sesion
  [0] Salir
""")
    separador()


def main():
    estado = {}  # ultimo cifrado + engine de la sesion

    while True:
        limpiar_pantalla()
        mostrar_menu()
        opcion = input("  opcion: ").strip()
        if opcion == '1':
            opcion_generar_claves(estado)
        elif opcion == '2':
            opcion_cifrar(estado)
        elif opcion == '3':
            opcion_descifrar(estado)
        elif opcion == '4':
            opcion_ciclo_completo(estado)
        elif opcion == '5':
            opcion_ver_estado(estado)
        elif opcion == '6':
            opcion_limpiar(estado)
        elif opcion == '0':
            print("\n  chau!\n")
            break
        else:
            print("\n  esa opcion no existe")
            pausar()


if __name__ == "__main__":
    main()
