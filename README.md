# Subsistema de Criptografía RSA: Implementación Core y Renderizado Reactivo

**Curso:** Matemática Computacional (MA475)  
**Institución:** Universidad Peruana de Ciencias Aplicadas (UPC)  
**Periodo:** 2026-10  

## 1. Resumen Ejecutivo

Este repositorio contiene el código fuente para la implementación de un motor criptográfico basado en el algoritmo asimétrico RSA. La arquitectura del sistema está fundamentada en la separación estricta entre la capa de dominio matemático (backend algorítmico sin dependencias criptográficas externas) y la capa de presentación (interfaz web reactiva construida sobre Streamlit). El proyecto garantiza la trazabilidad computacional del proceso de generación de claves, la validación de coprimos y la exponenciación modular para el cifrado y descifrado de datos.

## 2. Objetivos Técnicos

* **Desarrollar** la lógica criptográfica RSA a nivel base mediante Python, asegurando la exclusión estricta de bibliotecas de terceros para el cálculo de claves y el encriptado de mensajes.
* **Implementar** algoritmos matemáticos fundamentales desde cero, incluyendo la evaluación de primalidad, el cálculo del Máximo Común Divisor (MCD) y el Algoritmo de Euclides Extendido para la obtención del inverso multiplicativo modular ($d$).
* **Orquestar** una interfaz gráfica web que exponga las variables de estado ($n$, $\varphi(n)$, $e$, $d$) mediante renderizado matemático iterativo, sin bloquear el hilo de ejecución principal.
* **Asegurar** la exportación segura de las cadenas cifradas mediante la generación dinámica de archivos `.txt` en la memoria del navegador.

## 3. Arquitectura del Sistema

El proyecto adopta un patrón de diseño modular que aísla el núcleo matemático de los componentes de la interfaz de usuario, previniendo recálculos innecesarios en el ciclo de vida de la aplicación:

```text
rsa_upc_project/
├── .venv/                  # Entorno virtual aislado (Excluido del control de versiones)
├── .gitignore              # Reglas de exclusión del repositorio
├── requirements.txt        # Especificación de dependencias de UI (Streamlit)
├── README.md               # Documentación técnica y especificaciones
├── app.py                  # FRONTEND: Interfaz de usuario, callbacks y gestión de estado
└── core/                   # BACKEND: Módulo de procesamiento matemático
    ├── __init__.py         
    ├── math_utils.py       # Operaciones de bajo nivel (Primalidad, Euclides, Exponenciación)
    └── rsa_engine.py       # Controlador RSA (Transformación ASCII, segmentación y cifrado)