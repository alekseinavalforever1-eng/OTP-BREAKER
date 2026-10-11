# Especificación de Interfaz Intermódulos, Modelo Neuronal LSTM y Arquitectura de Caja Blanca

**Proyecto de Trabajo de Integración Curricular (TIC) — EPN**  
**Documento de Entrega Formal:** Especificación de Datos y Arquitectura de Predicción  
**Módulo:** Módulo 2 — Predictor / Rompedor de OTPs  
**Tesista:** Julián Aleksei Narváez Vinueza  
**Director:** Ing. Jhonattan Barriga, Ph.D.  

---

## 1. Flujo de Información Formal Entre Módulos (Pipeline del Proyecto)

Para la sustentación y entrega de hoy, el flujo de datos entre los tres módulos del TIC se define con la siguiente arquitectura de interfaces:

```text
+-----------------------+              CSV / JSON                +-----------------------+
|       MÓDULO 1        | -------------------------------------> |       MÓDULO 2        |
| (Jahir Rocha)         |   - Dataset de OTPs                    | (Julián Narváez)      |
| Evaluador Estadístico |   - Marcas temporales                  | Predictor / Rompedor  |
| y Diagnóstico NIST    |   - Alertas de aleatoriedad (NIST)     | (Caja Blanca y Negra) |
+-----------------------+                                        +-----------------------+
                                                                             |
                                                                             | Reporte de Métricas
                                                                             | JSON / CSV
                                                                             v
                                                                 +-----------------------+
                                                                 |       MÓDULO 3        |
                                                                 | (Esteban Gómez)       |
                                                                 | Validador y Análisis  |
                                                                 | Comparativo Final     |
                                                                 +-----------------------+
```

---

## 2. Especificación del Contrato de Datos (Módulo 1 -> Módulo 2)

El archivo de intercambio oficial entre Jahir (Módulo 1) y tu Módulo 2 será un archivo **`dataset_otps.csv`** (o flujo JSON equivalente). Cada fila representa una contraseña generada en una ventana de tiempo específica.

### Esquema de Columnas y Tipos de Datos:

| Nombre de Columna | Tipo de Dato | Ejemplo | Justificación Técnica para el Módulo 2 |
| :--- | :--- | :--- | :--- |
| **`id`** | Entero (`int`) | `1042` | Índice secuencial de la muestra para ordenar cronológicamente la serie de tiempo. |
| **`timestamp`** | Entero largo (`int64`) | `1758844830` | Segundos Unix en que se emitió el OTP. **Vital para el Solver de Semillas** (acota la ventana de búsqueda en tiempo). |
| **`counter`** | Entero largo (`int64`) | `58628161` | Factor de movimiento (`timestamp // 30` en TOTP o evento en HOTP). Permite simular la entrada exacta del hash. |
| **`otp_decimal`** | Cadena (`varchar(8)`) | `"482910"` | El código completo de 6 u 8 dígitos. Se usa para verificar coincidencias exactas en fuerza bruta y para la matriz de transición de Markov. |
| **`d1`** | Entero (`int`) [0-9] | `4` | Primer dígito del OTP. **Insumo directo de la Red LSTM**. |
| **`d2`** | Entero (`int`) [0-9] | `8` | Segundo dígito del OTP. |
| **`d3`** | Entero (`int`) [0-9] | `2` | Tercer dígito del OTP. |
| **`d4`** | Entero (`int`) [0-9] | `9` | Cuarto dígito del OTP. |
| **`d5`** | Entero (`int`) [0-9] | `1` | Quinto dígito del OTP. |
| **`d6`** | Entero (`int`) [0-9] | `0` | Sexto dígito del OTP. |
| **`alertas_nist`** | Cadena (`varchar(64)`) | `"FAIL_FFT;FAIL_RUNS"` | Diagnóstico emitido por el Módulo 1 tras pasar el generador por `assess.exe`. Si está vacío o dice `"PASS"`, el generador es seguro. Si tiene fallas, tu módulo activa las estrategias correspondientes. |

### Ejemplo de Archivo `dataset_otps.csv`:
```csv
id,timestamp,counter,otp_decimal,d1,d2,d3,d4,d5,d6,alertas_nist
1,1758844800,58628160,394812,3,9,4,8,1,2,FAIL_BLOCK_FREQ;FAIL_FFT
2,1758844830,58628161,394812,3,9,4,8,1,2,FAIL_BLOCK_FREQ;FAIL_FFT
3,1758844860,58628162,104829,1,0,4,8,2,9,FAIL_BLOCK_FREQ;FAIL_FFT
4,1758844890,58628163,829103,8,2,9,1,0,3,FAIL_BLOCK_FREQ;FAIL_FFT
```

---

## 3. ¿Por Qué se Separan los Dígitos (`d1` a `d6`) para la Red LSTM?

En una serie de tiempo normal, se suele predecir un solo número continuo. Sin embargo, en contraseñas de un solo uso (OTPs):
1. **El Problema del Espacio Gigante de Clases:**  
   Si tratamos el OTP como un único entero (de `000000` a `999999`), la red neuronal tendría que clasificar entre **1.000.000 de clases de salida**. Entrenar una red con 1 millón de neuronas en la capa softmax saturaría la memoria RAM y requeriría millones de datos.
2. **La Solución: Clasificador Multi-Cabezal (Multi-Head Classifier):**  
   Al descomponer el OTP en sus 6 columnas `d1` a `d6`, la arquitectura de la red LSTM tiene **6 cabezas de salida independientes**, cada una clasificando entre solo 10 clases (los dígitos del `0` al `9`):
   * Cabeza 1: Distribución de probabilidad para el dígito 1 (`P(d1 = 0..9)`).
   * Cabeza 2: Distribución de probabilidad para el dígito 2 (`P(d2 = 0..9)`).
   * ...
   * Cabeza 6: Distribución de probabilidad para el dígito 6 (`P(d6 = 0..9)`).
3. **Detección de Sesgos Ocultos Posicionales:**  
   Esta arquitectura permite a la LSTM aprender patrones como:
   * En el estándar de Corea, el dígito 3 suele repetir el valor del dígito 1 (`d3 == d1`).
   * En generadores con *Modulo Bias*, los dígitos más significativos (`d1` y `d2`) tienen menor probabilidad de ser `8` o `9`.
   * En generadores LCG lineales, la periodicidad de los bits bajos se manifiesta con mayor fuerza en el último dígito (`d6`).

---

## 4. Arquitectura de la Red Neuronal LSTM (Caja Negra / Secuencias Temporales)

### A. Ventana Deslizante (Sliding Window):
La red no analiza contraseñas aisladas; analiza una **secuencia histórica de longitud L** (ejemplo: los últimos $L = 5$ OTPs generados) para predecir el OTP del siguiente instante ($t+1$):

```text
Entrada a la LSTM (Ventana de 5 pasos temporales x 6 dígitos):
Paso t-4: [d1, d2, d3, d4, d5, d6]
Paso t-3: [d1, d2, d3, d4, d5, d6]
Paso t-2: [d1, d2, d3, d4, d5, d6]
Paso t-1: [d1, d2, d3, d4, d5, d6]
Paso t:   [d1, d2, d3, d4, d5, d6]
             |
             v
   [CAPA OCULTA LSTM (128 unidades recurrentes con memoria de largo plazo)]
             |
             +---------------+---------------+---------------+
             |               |               |               |
             v               v               v               v
       [Densa d1]      [Densa d2]       ...            [Densa d6]
     (Softmax: 0..9) (Softmax: 0..9)                 (Softmax: 0..9)
             |               |                               |
             v               v                               v
    Predicción d1   Predicción d2                   Predicción d6
```

### B. Literatura Científica y Repositorios Clave de LSTM en PRNG:
* **Repositorio GitHub de Referencia:**  
  [YashaPushak/PredictingPRNGs](https://github.com/YashaPushak/PredictingPRNGs) — Repositorio que implementa arquitecturas de Machine Learning y LSTMs para predecir secuencias de generadores pseudoaleatorios (LCG, Mersenne Twister).
* **Paper Científico Base:**  
  *"Predicting pseudo-random number generator output with sequential analysis"* (Investigación sobre redes neuronales recurrentes y LSTMs para vulnerar generadores lineales y de registro).
* **Paper Criptoanálisis con Deep Learning:**  
  *"Machine Learning Cryptanalysis of a Quantum Random Number Generator"* ([arXiv:2103.03831](https://arxiv.org/abs/2103.03831)).

---

## 5. Arquitectura del Enfoque de Caja Blanca: Patrón Estrategia (Strategy Pattern)

Cuando se realiza una auditoría de **Caja Blanca** (tenemos acceso al código fuente de la app o backend víctima), el ataque no es probabilístico con IA, sino **determinista mediante recuperación de semilla (Seed Recovery)**.

### ¿Cómo opera el proceso paso a paso?

```text
[1. INSPECCIÓN DE CÓDIGO FUENTE DE LA APP]
El analista examina la clase generadora y encuentra la vulnerabilidad:
- Caso 1: Encontró System.currentTimeMillis() o time(NULL) -> Patrón Timestamp.
- Caso 2: Encontró java.util.Random o rand() de C -> Patrón LCG.
- Caso 3: Encontró claves cortas o fijas en un archivo config -> Patrón Diccionario.
                           |
                           v
[2. SELECCIÓN DINÁMICA DE LA ESTRATEGIA (Strategy Pattern)]
El CLI selecciona el Solver correspondiente mediante polimorfismo:
solver = SolverFactory.get_solver("timestamp", time_window="2026-09-25 19:00", margin=30)
                           |
                           v
[3. CAPTURA DE 2 OTPs EN TIEMPO REAL]
Se capturan dos códigos consecutivos emitidos por la app:
- OTP_0 en T0
- OTP_1 en T1 (T0 + 30 segundos)
                           |
                           v
[4. EJECUCIÓN CONCURRENTE DEL SOLVER]
El solver itera en paralelo sobre el espacio colapsado:
Por cada semilla_i candidata:
    ¿TOTP(semilla_i, T0) == OTP_0?
    SI: Comprueba si TOTP(semilla_i, T1) == OTP_1 (Filtro de Colisión Dual)
                           |
                           v
[5. CLAVE MAESTRA RECUPERADA EN < 1 SEGUNDO]
La semilla secreta K queda expuesta.
A partir de este instante, el Módulo 2 genera el 100% de los códigos futuros.
```

### Diagrama de Clases del Patrón Estrategia en Python:

```text
                 +-----------------------------------------+
                 |            <<abstract>>                 |
                 |             BaseSolver                  |
                 +-----------------------------------------+
                 | + solve(otp0, t0, otp1, t1): bytes      |
                 +-----------------------------------------+
                                      ^
                                      |
         +----------------------------+----------------------------+
         |                                                         |
+-----------------------------------+             +-----------------------------------+
|         TimestampSolver           |             |             LCGSolver             |
+-----------------------------------+             +-----------------------------------+
| - window_start: int               |             | - multiplier: int                 |
| - window_end: int                 |             | - addend: int                     |
| + solve(otp0, t0, otp1, t1)       |             | + solve(otp0, t0, otp1, t1)       |
+-----------------------------------+             +-----------------------------------+
```
