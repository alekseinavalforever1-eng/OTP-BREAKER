# Diseño Metodológico, Alcance y Objetivos: Módulo Predictor / Rompedor (Módulo 2)

**Proyecto de Trabajo de Integración Curricular (TIC):**  
*Análisis de Predictibilidad de Generadores de Contraseñas de un solo uso mediante análisis de Entropía, Modelos Estadísticos y Aprendizaje Automático*  
**Institución:** Escuela Politécnica Nacional (EPN) — Facultad de Ingeniería de Sistemas  
**Carrera:** Ingeniería en Software  
**Director del Proyecto:** Prof. Jhonattan Javier Barriga Andrade  
**Responsable del Módulo 2:** Julián Aleksei Narváez Vinueza (Estudiante B)  

---

## 1. Preguntas de Investigación (Metodología Académica)

Siguiendo la metodología formal de formulación de proyectos de investigación:

### Pregunta General de Investigación
> **¿En qué medida la aplicación de modelos secuenciales (Redes LSTM y Modelos Ocultos de Markov) sobre secuencias temporales de contraseñas de un solo uso (OTP) generadas bajo implementaciones defectuosas permite predecir valores o dígitos posicionales específicos, reduciendo significativamente el espacio de búsqueda frente a la fuerza bruta convencional?**

### Preguntas Específicas de Investigación
1. **P1 (Entrada y Diagnóstico):** ¿Qué parámetros, metadatos y anomalías estadísticas detectadas por el Módulo Evaluador (caída de entropía de Shannon, fallos en pruebas del NIST) son determinantes para orientar la estrategia de predicción?
2. **P2 (Modelado Secuencial):** ¿Cómo estructurar y entrenar un Modelo de Markov y una Red LSTM para capturar tanto dependencias de transición inmediata como correlaciones temporales a largo plazo en secuencias de contraseñas numéricas?
3. **P3 (Capacidad de Ruptura):** ¿Qué ventaja predictiva (Accuracy posicional, reducción del espacio de combinaciones y tiempo de ataque) logra el motor de ruptura frente a generadores defectuosos (como la falla de extracción de Corea o semillas débiles) en contraste con generadores robustos (como Google Authenticator / RFC 6238)?
4. **P4 (Operatividad y Generalidad):** ¿Cómo diseñar una interfaz de línea de comandos (CLI) modular y parametrizable que permita ejecutar el pipeline de ataque sobre cualquier flujo arbitrario de OTPs sin depender de una implementación fija?

---

## 2. Objetivos del Módulo 2

### Objetivo General
Desarrollar un motor de inferencia, predicción y ruptura concurrente en una interfaz de línea de comandos (CLI), fundamentado en Modelos de Markov y Redes Neuronales Recurrentes (LSTM), para evaluar experimentalmente la predictibilidad de contraseñas de un solo uso (OTP), cuantificar la reducción del espacio de búsqueda y contrastar la resistencia de implementaciones con colapso entrópico frente a estándares seguros.

---

### Objetivos Específicos

1. **OE1 — Integración de Datos de Entrada:**  
   Definir e implementar el protocolo de ingestión para consumir el dataset estructurado generado por el Módulo Evaluador (Módulo 1), extrayendo vectores de contraseñas numéricas, marcas de tiempo (timestamps), contadores de eventos y diagnósticos previos de aleatoriedad (alertas NIST y Entropía de Shannon).

2. **OE2 — Modelado Estadístico y de Aprendizaje Automático:**  
   Diseñar y entrenar dos modelos complementarios para el análisis de secuencias:
   * **Modelo de Markov:** para cuantificar matrices de transición de estados y detectar bucles de repetición inmediata (como el colapso a 256 estados del estándar coreano).
   * **Red Neuronal LSTM:** para modelar dependencias no lineales a través del tiempo y realizar clasificación multi-salida por posición (predecir qué dígito del 0 al 9 tiene mayor probabilidad en cada posición del OTP).

3. **OE3 — Motor de Ruptura Concurrente (Fuerza Bruta Guiada):**  
   Construir un generador paralelo que reproduzca localmente el algoritmo de autenticación y ejecute un ataque de fuerza bruta optimizado, probando de forma concurrente los candidatos más probables sugeridos por los modelos (Top-K) dentro de la ventana de validez (TTL).

4. **OE4 — Evaluación Cuantitativa y Comparativa:**  
   Medir y comparar la efectividad del ataque entre escenarios vulnerables (extracción defectuosa TTA coreana y semillas de baja entropía) frente a escenarios seguros de referencia (RFC 4226 / Google Authenticator), reportando métricas formales de Accuracy posicional, factor de reducción del espacio de claves y probabilidad de autenticación forzada.

5. **OE5 — Interfaz CLI y Exportación de Resultados:**  
   Desarrollar una interfaz de línea de comandos (CLI) intuitiva y configurable que permita cargar cualquier dataset de contraseñas, seleccionar el modelo de ataque, ejecutar la predicción y exportar reportes estructurados (JSON/CSV) destinados al Módulo Validador (Módulo 3).

---

## 3. Delimitación y Alcance del Módulo

### Lo que SÍ abarca el Módulo (Alcance)
* **Generalidad del Sistema:** El software no estará atado a una sola empresa o algoritmo; podrá evaluar flujos de OTPs de cualquier longitud estándar (4, 6 u 8 dígitos) basados en eventos (HOTP) o basados en tiempo (TOTP).
* **Diagnóstico de Predicción:** Demostrará empíricamente si un flujo de contraseñas es predecible o si se comporta como ruido blanco uniforme (inrompible).
* **Predicción por Posición y Dígito:** Capacidad de aislar cada posición de la contraseña (ejemplo: Posición 1 a 6) y calcular la distribución de probabilidad de cada dígito del 0 al 9.
* **Simulación Realista de Ataque:** Simulación concurrente que mide si el código puede adivinarse antes de que expire la ventana de validez (TTL de 30 o 60 segundos).
* **Interoperabilidad:** Entrada y salida estandarizada para conectarse de forma fluida con el Módulo 1 (Jahir Rocha) y el Módulo 3 (Esteban Gómez).

### Lo que NO abarca el Módulo (Fuera de Alcance)
* No busca romper las primitivas criptográficas robustas (SHA-256 o AES) cuando son alimentadas con semillas verdaderamente aleatorias.
* No realiza ataques de red en tiempo real contra servidores bancarios en producción (se trabaja en un banco de pruebas de simulación controlada y ética).
* No reemplaza el cálculo estadístico puro de entropía sobre bits brutos, ya que esa tarea le corresponde exclusivamente al Módulo 1.

---

## 4. Definición Formal del Concepto "ROMPER"

En seguridad informática y en el contexto de esta tesis, la palabra **"ROMPER" (Break)** no significa hallar una falla matemática en SHA-1 o descifrar la clave AES por fuerza bruta total (lo cual requeriría millones de años).

**En este proyecto, ROMPER significa:**

```text
===================================================================================
                    DEFINICIÓN CIENTÍFICA DE "ROMPER"
===================================================================================

1. RUPTURA POR COLAPSO DEL ESPACIO DE BÚSQUEDA:
   - Escenario Seguro (Google): 1.000.000 de combinaciones (probabilidad = 0.0001%).
   - Escenario Roto (Corea): Se reduce a 256 combinaciones fijas (probabilidad = 0.39%).
   -> VENTAJA DEL ATACANTE: 4.000 veces superior a la fuerza bruta convencional.

2. RUPTURA PARCIAL (INFERENCIA POSICIONAL):
   - Escenario Seguro: Cada posición tiene una probabilidad uniforme del 10% (1/10).
   - Escenario Roto: El modelo demuestra que una posición específica (ej. posición 4)
     tiene una probabilidad del 60% o 70% de ser un dígito específico.
   -> VENTAJA: Permite fijar dígitos conocidos y probar solo las posiciones restantes.

3. RUPTURA TEMPORAL (INFERENCIA SECUENCIAL):
   - Escenario Seguro: Conocer los OTPs pasados aporta 0 información sobre el siguiente.
   - Escenario Roto: Conociendo los últimos N códigos, el modelo predice el código
     siguiente dentro de los primeros K intentos antes de que expire el TTL.
===================================================================================
```

---

## 5. Arquitectura del Módulo 2: El Pipeline de 4 Fases

Tal como solicitaste, el motor del CLI se estructurará en 4 fases operativas:

```text
+-------------------+      +-------------------+      +-------------------+      +-------------------+
|     FASE 1        |      |     FASE 2        |      |     FASE 3        |      |     FASE 4        |
|    ENTRADA        | ---> |    ANÁLISIS       | ---> |    RUPTURA        | ---> |    SALIDA         |
|                   |      | (Estrategia IA)   |      |  (Fuerza Bruta    |      |  (Métricas y      |
| (Dataset Módulo 1)|      | (Markov / LSTM)   |      |   Concurrente)    |      |   Reportes)       |
+-------------------+      +-------------------+      +-------------------+      +-------------------+
```

---

### Fase 1: Entrada (¿Qué le pedimos al Módulo 1?)

El Módulo Evaluador debe entregar un dataset estructurado (en archivo CSV o JSON) que represente la secuencia capturada durante la auditoría.

#### Estructura del Dataset de Entrada:
```text
id, timestamp, counter, otp_decimal, d1, d2, d3, d4, d5, d6, nist_alerts, shannon_entropy
```

* **`id` / `counter`:** Número de evento secuencial (0, 1, 2, ...).
* **`timestamp`:** Marca de tiempo en segundos o milisegundos.
* **`otp_decimal`:** La contraseña de 6 dígitos completa (ejemplo: `"849201"`).
* **`d1, d2, d3, d4, d5, d6`:** Cada dígito descompuesto como entero independiente del 0 al 9 (ejemplo: `8, 4, 9, 2, 0, 1`). Esto es indispensable para el entrenamiento de la LSTM posicional.
* **`nist_alerts`:** Resumen de pruebas falladas en el Módulo 1 (ejemplo: `["BlockFrequency", "FFT", "Serial"]`).
* **`shannon_entropy`:** Valor numérico de entropía calculado por el Módulo 1.

---

### Fase 2: Análisis y Selección de Estrategia

El motor analiza los metadatos y decide automáticamente qué técnica de ruptura emplear:

```text
                              [ANÁLISIS DEL DIAGNÓSTICO]
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
        v                                                                   v
[ALERTA DE FRECUENCIA O BLOQUES]                          [ALERTA DE PERIODICIDAD O SERIAL]
(Ej. Colapso de Corea TTAK.KO-12.0193)                   (Ej. Semillas lineales LCG / timestamps)
        |                                                                   |
        v                                                                   v
-> Activa MODELO DE MARKOV                                -> Activa RED NEURONAL LSTM
-> Construye matriz de transición entre estados.          -> Ingiere ventana deslizante de N códigos.
-> Identifica el conjunto reducido de candidatos          -> Infiere probabilidades dígito a dígito
   con alta frecuencia de aparición (Top-256).               para la siguiente ventana temporal.
```

---

### Fase 3: Proceso de Ruptura (Fuerza Bruta Concurrente Guiada)

Una vez que el modelo genera las probabilidades:

1. **Ordenamiento de Candidatos (Top-K):**  
   El modelo ordena las combinaciones posibles de mayor a menor probabilidad.  
   En lugar de probar 1.000.000 de números a ciegas, genera una lista priorizada de candidatos (ejemplo: los 256 más probables en Corea, o los 100 mejores candidatos calculados por la LSTM).
2. **Generador Paralelo Concurrente:**  
   Un grupo de hilos de ejecución (*worker threads*) toma los candidatos priorizados y los valida de forma simultánea contra el validador de contraseñas.
3. **Condición de Parada:**  
   * **Éxito:** Si uno de los hilos acierta la contraseña antes de que expire el tiempo (TTL).
   * **Tiempo Agotado:** Si el contador o el tiempo vence antes de encontrar la clave.

---

### Fase 4: Salida (Output para el Módulo 3)

El CLI genera un reporte estructurado (JSON y visualización en consola) que responde a las preguntas clave:

```json
{
  "resultado_ataque": {
    "se_logro": true,
    "otp_real": "934475",
    "otp_predicho": "934475",
    "intentos_utilizados": 14,
    "tiempo_ruptura_ms": 48.2,
    "ventana_ttl_segundos": 30.0,
    "estado": "VULNERADO_EXITOSAMENTE"
  },
  "metricas_predictivas": {
    "espacio_original": 1000000,
    "espacio_reducido_candidatos": 256,
    "porcentaje_reduccion_espacio": 99.9744,
    "ventaja_frente_al_azar_factor": 3906.25,
    "probabilidad_exito_ttl": 0.0546
  },
  "precision_posicional_digitos": {
    "posicion_1": {"acierto": true, "confianza": 0.88},
    "posicion_2": {"acierto": true, "confianza": 0.76},
    "posicion_3": {"acierto": true, "confianza": 0.92},
    "posicion_4": {"acierto": true, "confianza": 0.64},
    "posicion_5": {"acierto": true, "confianza": 0.81},
    "posicion_6": {"acierto": true, "confianza": 0.79}
  }
}
```

---

## 6. Comparativa Técnica: ¿Dónde Aplicar Markov y Dónde Aplicar LSTM?

| Criterio | Cadenas de Markov / HMM | Redes Neuronales LSTM |
| :--- | :--- | :--- |
| **Principio Matemático** | Probabilidad condicional entre estados discretos contiguos: P(S_actual \| S_anterior). | Celdas recurrentes con compuertas de olvido, entrada y salida que retienen memoria a largo plazo. |
| **Mejor Caso de Uso** | **El caso de Corea (TTAK.KO-12.0193):** Al colapsar los bytes a 256 estados fijos, la matriz de Markov identifica de inmediato las transiciones infladas. | **Casos con dependencia temporal:** Semillas basadas en funciones predecibles o generadores lineales donde el patrón evoluciona con el tiempo. |
| **Velocidad de Inferencia** | Extremadamente rápida (milisegundos, cálculo directo de matrices). | Requiere entrenamiento previo (épocas), pero ofrece inferencia rápida una vez entrenada. |
| **Capacidad Posicional** | Modela transiciones globales entre códigos o dígitos consecutivos. | **Excelente para clasificación posicional:** Permite construir un modelo con 6 salidas softmax (una por cada posición del código). |
| **Interpretabilidad** | Totalmente transparente (se puede imprimir la matriz de probabilidades). | Caja negra probabilística con vectores de pesos. |

> **Estrategia Recomendada para tu Módulo:**  
> Implementar una **Arquitectura Híbrida / Modular**:  
> * El usuario en el CLI puede seleccionar: `--modelo markov`, `--modelo lstm` o `--modelo auto` (donde el CLI analiza el diagnóstico del NIST y selecciona el modelo óptimo automáticamente).

---

## 7. Hoja de Ruta para el Desarrollo del CLI

```text
Paso 1: Estructurar la carpeta del módulo con la arquitectura modular en Python.
Paso 2: Crear el módulo de ingestión (data_loader.py) para leer datasets CSV/JSON.
Paso 3: Implementar el modelo de Markov (markov_breaker.py).
Paso 4: Implementar el modelo LSTM multi-salida posicional (lstm_breaker.py).
Paso 5: Construir el gestor de ataque concurrente y simulación de TTL (attack_engine.py).
Paso 6: Ensamblar la interfaz de línea de comandos CLI (cli.py con argparse/click).
Paso 7: Pruebas experimentales contrastando Corea vs. Google Authenticator.
```
