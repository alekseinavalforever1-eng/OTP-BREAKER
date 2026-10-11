# Guía Rápida de Ejecución: Scripts del Módulo Rompedor / Predictor

Esta carpeta contiene los scripts en Python que componen el núcleo de pruebas y ataque del **Módulo 2 (Julián Narváez)**.

---

## ⚡ 1. Tabla Rápida: Qué Hace Cada Archivo y Cómo Correrlo

| Archivo | ¿Qué hace en pocas palabras? | Comando para Correr en PowerShell |
| :--- | :--- | :--- |
| **`demostracion_ruptura_en_vivo.py`** ⭐ *(El más importante)* | **Ejecuta la predicción real:**<br>1. Deduce la clave secreta $K$ en 3 ms y predice el 100% de los OTPs futuros.<br>2. Demuestra el acierto masivo sobre los 256 códigos del estándar coreano. | `python Modulo_Rompedor_Predictor\codigo\demostracion_ruptura_en_vivo.py` |
| **`simulador_dataset_interfaz.py`** | **Genera los datos de prueba:**<br>Crea los archivos CSV con las 11 columnas formales acordadas con Jahir (Módulo 1) para los escenarios de Corea y Google RFC Seguro. | `python Modulo_Rompedor_Predictor\codigo\simulador_dataset_interfaz.py` |
| **`modelo_lstm_pytorch.py`** | **Analizador Neuronal y Posicional:**<br>Define la Red LSTM multi-cabezal (`d1` a `d6`) y mide la caída de entropía de Shannon en cada dígito (delata el dígito `d3` defectuoso). | `python Modulo_Rompedor_Predictor\codigo\modelo_lstm_pytorch.py` |
| **`predictor_secuencias.py`** | **Motor Estadístico de Markov:**<br>Calcula la reducción del espacio de búsqueda (de 1.000.000 a 256 candidatos) y mide el tiempo de respuesta (0.29 ms). | `python Modulo_Rompedor_Predictor\codigo\predictor_secuencias.py` |

---

## 🔄 2. ¿Cómo se Relacionan Entre Ellos? (Flujo de Ejecución)

Los cuatro scripts se encadenan de forma lógica:

```text
[1. simulador_dataset_interfaz.py]
Genera los datasets sintéticos en la carpeta datos/
  ├── dataset_otps_ejemplo.csv (Escenario vulnerable de Corea)
  └── dataset_rfc_control.csv  (Escenario seguro de Google)
                |
                +---------------------------------------+
                |                                       |
                v                                       v
[2. modelo_lstm_pytorch.py]              [3. predictor_secuencias.py]
Analiza los dígitos d1..d6.               Modela las transiciones de Markov.
Detecta la baja entropía en d3.           Reduce el espacio a 256 candidatos.
                |                                       |
                +-------------------+-------------------+
                                    |
                                    v
                 [4. demostracion_ruptura_en_vivo.py]
                 Ejecuta la prueba de fuego final:
                 - Recupera la semilla real de una víctima en 3 ms.
                 - Predice los 5 OTPs futuros con 100% de éxito.
```

---

## 🎯 3. ¿Qué Archivo Hizo la Predicción y Cómo Funciona?

El archivo que logró la predicción exitosa es:  
**`demostracion_ruptura_en_vivo.py`**

Implementa los dos enfoques metodológicos de tu tesis:

### A. La Predicción al 100% (Enfoque de Caja Blanca - Patrón Estrategia)
* **¿Cómo lo hizo?**
  1. Asume la regla de diseño vulnerable: el programador creó la semilla usando el reloj del sistema (`CWE-337: seed = SHA1(timestamp)`).
  2. La víctima emite dos códigos en vivo: `OTP_0 = 470449` y `OTP_1 = 049155`.
  3. El script prueba concurrentemente las marcas de tiempo de esa ventana. En **3.51 milisegundos**, encuentra la única clave que genera ambos códigos.
  4. Con esa clave recuperada, el atacante calcula las siguientes 5 contraseñas de la víctima:
     ```text
     - Futuro T+60s:  Real = 901823 | Predicho = 901823 -> ACIERTO [100%]
     - Futuro T+90s:  Real = 071067 | Predicho = 071067 -> ACIERTO [100%]
     - Futuro T+120s: Real = 230230 | Predicho = 230230 -> ACIERTO [100%]
     ```
* **Relación con el Patrón Estrategia:**  
  Este código es exactamente el núcleo matemático que conforma la estrategia **`TimestampSeedSolver`** dentro de tu arquitectura de Caja Blanca.

---

### B. La Predicción sobre Corea (Enfoque de Caja Negra - 256 Códigos)
* **¿Cómo lo hizo?**
  1. Aquí el atacante **NO conoce la semilla** (es una clave AES aleatoria de 128 bits).
  2. Pero conoce que el algoritmo de extracción tiene un bucle que colapsa la salida a solo **256 números específicos** en el 6.25% de las llamadas.
  3. El atacante solo prueba esa lista de 256 números.
  4. En 10.000 logins simulados:
     * Google Authenticator acertó solo 1 vez (0.01% - azar puro).
     * El estándar de Corea acertó **727 veces (7.27%)**.
     * El atacante tiene una ventaja de **más de 700 veces superior** frente a Google Authenticator.
