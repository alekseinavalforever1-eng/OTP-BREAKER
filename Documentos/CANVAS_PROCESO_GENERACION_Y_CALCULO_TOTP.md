# Canvas Explicativo: Proceso de Generación y Cálculo de una OTP (TOTP)
## Guía Integral de Arquitectura, Checklist Normativo (RFC / OWASP / NIST) y Transformación Byte por Byte

Este documento está estructurado paso a paso en formato de **lienzo explicativo (Canvas)** para visualizar y presentar la generación, aprovisionamiento y cálculo criptográfico de una contraseña de un solo uso basada en tiempo (TOTP), integrando las normas **RFC 4226**, **RFC 6238**, **RFC 2104**, **NIST SP 800-63B** y la **Guía de Seguridad OWASP**.

---

## MAPA GENERAL DEL CANVAS (LOS 5 BLOQUES DEL SISTEMA)

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [BLOQUE 1: SERVIDOR]       Generación Criptográfica de la Semilla (K)                 │
│                            • Checklist de seguridad (RFC / NIST / OWASP)               │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [BLOQUE 2: APROVISIONAMIENTO]  Compartición Segura Servidor ──▶ Cliente                │
│                                • Base32, URI otpauth y Código QR                       │
│                                • Almacenamiento seguro en ambos extremos               │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼ (A partir de aquí: 100% OFFLINE)
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [BLOQUE 3: EL RELOJ TEMPORAL]  Cálculo de la Ventana Temporal (Cada 30 Segundos)       │
│                                • Unix Epoch / 30 ──▶ Contador C (8 bytes Big-Endian)   │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [BLOQUE 4: CRIPTOGRAFÍA]   Hashing y Truncamiento Dinámico (Byte por Byte)            │
│                            • HS = HMAC-SHA1(K, C) ──▶ 20 bytes                         │
│                            • 1 Sola Extracción (RFC 4226) vs Falla Coreana de 3 rondas │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [BLOQUE 5: CÓDIGO FINAL]   ¿Por qué "mod 10^d" y cómo acaba el proceso?                │
│                            • DBC & 0x7FFFFFFF mod 10^6 ──▶ 6 Dígitos ("686038")        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## BLOQUE 1: El Servidor y la Generación de la Semilla (Shared Secret K)

El ciclo de vida de TOTP comienza obligatoriamente en el servidor de autenticación cuando el usuario solicita activar la verificación en dos pasos (2FA).

```text
  ┌───────────────────────────────┐
  │     SERVIDOR DE AUTENTICACIÓN │
  │                               │
  │     [ CSPRNG de Sistema ]     │
  │               │               │
  │               ▼               │
  │      Semilla K (20 bytes)     │
  │    160 bits de entropía pura  │
  └───────────────────────────────┘
```

### Checklist Oficial de Seguridad para la Semilla (RFCs, NIST y OWASP)

Antes de emitir cualquier semilla, el servidor debe cumplir estrictamente esta lista de verificación técnica:

| # | Requisito de Seguridad | Estándar de Referencia | Especificación Técnica Obligatoria | ¿Por qué es crítico? |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **Longitud de Clave** | **RFC 4226 (R6)**<br>**RFC 6238 (Sec. 5)** | Mínimo 128 bits (16 bytes).<br>**Recomendado: 160 bits (20 bytes)**. | Si se usa HMAC-SHA1, la longitud de la semilla debe igualar la salida del hash (160 bits) para evitar degradación de entropía. |
| **2** | **Generador Criptográfico (CSPRNG)** | **RFC 4086**<br>**NIST SP 800-90A** | Prohibido usar `rand()` o `Math.random()`.<br>Debe usarse entropía del kernel (`/dev/urandom`, `SecureRandom`, `crypto.randomBytes`). | Los PRNG estándar tienen estados internos reconstruibles con pocas muestras; un CSPRNG es estadísticamente impredecible. |
| **3** | **Entropía Completa** | **NIST SP 800-22** | Cada byte debe tener 8 bits de entropía pura uniforme (de `0x00` a `0xFF`). | Evita sesgos que permitan ataques de diccionario o reducción del espacio de claves. |
| **4** | **Codificación de Tránsito** | **RFC 4648 (Base32)** | Alfabeto Base32 estándar: letras `A-Z` y números `2-7` (exactamente 32 caracteres para 160 bits). | Elimina caracteres humanos ambiguos (`0` vs `O`, `1` vs `l`, `8` vs `B`) en caso de que el usuario deba escribir la clave manualmente. |
| **5** | **Cifrado en Reposo** | **OWASP 2FA Cheat Sheet**<br>**NIST SP 800-63B** | La semilla **NUNCA** se guarda en texto plano en la base de datos.<br>Debe cifrarse con **AES-256-GCM** o residir en un **HSM / KMS**. | Si la base de datos es filtrada (SQL Injection), el atacante no puede clonar los tokens TOTP de los usuarios. |
| **6** | **Unicidad e Inmutabilidad** | **RFC 6238 (Sec. 3)** | Cada usuario y cada cuenta deben tener una semilla totalmente independiente generada de cero. | Evita ataques masivos en cascada si un token individual se ve comprometido. |

---

## BLOQUE 2: Aprovisionamiento y Compartición Segura (Servidor ──▶ Cliente)

Una vez que el servidor genera la semilla `K`, debe transmitirla de forma segura al dispositivo móvil del usuario para que ambos compartan el mismo secreto simétrico.

```text
 [SERVIDOR]                                                   [USUARIO / CELULAR]
     │                                                                 │
     │ 1. Empaqueta URI estándar:                                      │
     │    otpauth://totp/Google:usuario@gmail.com                      │
     │    ?secret=6Z2SFWHN2OGNAZSRPESYFFO3AZXWKGVU                     │
     │    &issuer=Google&algorithm=SHA1&digits=6&period=30             │
     │                                                                 │
     │ 2. Convierte la URI en Código QR                                │
     │                                                                 │
     │ 3. Envía por canal seguro TLS 1.3 (HTTPS) ────────────────────▶ │
     │                                                                 │ 4. Escanea QR con cámara
     │                                                                 │    de Google Authenticator
     │                                                                 │
     │ 5. Guarda K cifrada en BDD                                      │ 6. Guarda K en Enclave Seguro
     │    (AES-256-GCM)                                                │    (Android Keystore / iOS Keychain)
     ▼                                                                 ▼
 ══════════════════════════════════════════════════════════════════════════════════════════
 ★ A PARTIR DE ESTE MOMENTO: EL SERVIDOR Y EL CELULAR NO SE VUELVEN A COMUNICAR ★
 Ambos poseen la misma semilla K y calcularán exactamente el mismo código de forma OFFLINE.
 ══════════════════════════════════════════════════════════════════════════════════════════
```

---

## BLOQUE 3: El Reloj Temporal y el Contador C (Cada X Segundos)

¿Por qué el celular puede generar códigos sin conexión a internet y coincidir exactamente con el servidor?
Porque ambos utilizan el **tiempo coordinado universal (UTC)** sincronizado por protocolo NTP (*Network Time Protocol*).

```text
           [ Reloj del Celular ]                    [ Reloj del Servidor ]
                     │                                         │
                     ▼                                         ▼
            Timestamp Unix Actual                    Timestamp Unix Actual
            (Segundos desde 1970)                    (Segundos desde 1970)
                     │                                         │
                     └────────────────────┬────────────────────┘
                                          ▼
                                   Paso T = 30 seg
                                          │
                                          ▼
                               C = piso(Timestamp / 30)
                                          │
                                          ▼
                            Contador C en 8 Bytes (Big-Endian)
                            Ejemplo: 00 00 00 00 03 86 97 87
```

### Parámetros de Tiempo (RFC 6238):
1. **Época de Referencia ($T_0$):** `0` (1 de enero de 1970, 00:00:00 UTC).
2. **Paso de Tiempo ($X$):** `30 segundos` (estándar universal adoptado por Google, Microsoft y GitHub).
3. **Fórmula del Contador:**
   ```text
   C = piso( (Tiempo_Actual - T0) / X )
   ```
4. **Empaquetado Binario:** El contador `C` se convierte a un número de **64 bits (8 bytes) en formato Big-Endian** (los bytes más significativos van al principio).

---

## BLOQUE 4: Criptografía y Truncamiento Dinámico (Byte por Byte)

Aquí se ejecuta la matemática criptográfica que transforma la semilla y el contador temporal en un flujo binario uniforme.

### Paso 4.1: Hashing Criptográfico HMAC-SHA1 (RFC 2104)

```text
    Clave K (20 bytes)                  Contador C (8 bytes)
            │                                     │
            ▼                                     │
   Relleno a 64 bytes                             │
   K_pad = K || 00...00                           │
            │                                     │
    ┌───────┴───────┐                             │
    ▼               ▼                             │
  XOR 0x36        XOR 0x5C                        │
 (ipad: 64B)     (opad: 64B)                      │
    │               │                             │
    ▼               │                             │
 [ipad || C] ◀──────┴─────────────────────────────┘
    │
    ▼
 SHA-1 Interno ──▶ Hash_Interno (20 bytes)
                        │
                        ▼
            [opad || Hash_Interno]
                        │
                        ▼
                   SHA-1 Externo
                        │
                        ▼
                 HS = HMAC-SHA1 (20 bytes criptográficos)
```

Tomando la clave real de Google y un contador de prueba, el hash resultante `HS` mide exactamente **20 bytes** (numerados del índice 0 al 19):

```text
Índice:    0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19
Byte HEX: 40  79  38  16  6a  7a  ad  b7  55  90  f8  f9  20  52  a6  a8  da  56  ae  10
```

---

### Paso 4.2: ¿Cuántas Rondas de Extracción o Movidas Son?

Esta fue una de las dudas centrales: **¿cuántas movidas se hacen para extraer los bytes?**

#### En Google Authenticator / RFC 4226: ¡ES EXACTAMENTE 1 SOLA RONDA DE EXTRACCIÓN!
Google y el estándar internacional RFC 4226 realizan una única operación de selección:
1. Miran el último byte del hash: `HS[19] = 0x10`.
2. Toman sus 4 bits más bajos aplicando la máscara `0x0F`:
   ```text
   Offset = HS[19] & 0x0F = 0x10 & 0x0F = 0
   ```
   *(Esto da siempre un número entero entre 0 y 15).*
3. A partir de esa posición `Offset`, extraen **4 bytes contiguos de una sola vez**:
   ```text
   Bytes extraídos = HS[0], HS[1], HS[2], HS[3]
                   = 0x40,  0x79,  0x38,  0x16
   ```
   **Listo.** No hay más rondas. Se extraen 4 bytes contiguos y se conservan **32 bits de entropía independientes**.

---

#### En el Estándar Coreano Vulnerable (TTAK.KO-12.0193): ¡INVENTARON 3 RONDAS ENCADENADAS!
Los diseñadores coreanos quisieron ser "más inteligentes" y en lugar de 1 sola extracción, inventaron **3 rondas recursivas dependientes**:

```text
  Ronda 1:  Offset_1 = HS[19] & 0x0F = 0     ──▶ b1 = HS[0] = 0x40
  Ronda 2:  Offset_2 = b1 & 0x0F     = 0     ──▶ b2 = HS[0] = 0x40  (¡Coincidió!)
  Ronda 3:  Offset_3 = b2 & 0x0F     = 0     ──▶ b3 = HS[0] = 0x40  (¡Coincidió!)

  Resultado: b1=0x40, b2=0x40, b3=0x40  ──▶ ¡3 bytes exactamente idénticos!
```

* **Por qué falló el coreano:** Al encadenar las rondas, si el último dígito de `b1` coincide con `Offset_1` (lo que ocurre con probabilidad matemática de **1 de cada 16 veces = 6.25%**), el algoritmo entra en un bucle cerrado y produce 3 bytes repetidos, colapsando la entropía.

---

## BLOQUE 5: ¿Por qué "mod 10^d" y Cómo Acaba el Proceso?

Muchos desarrolladores se confunden con la expresión matemática `mod 10^d`. A continuación se explica con total claridad:

### 1. ¿Qué significa "mod 10^d"?
* **$10$:** Representa la base del sistema numérico decimal (los dígitos humanos del 0 al 9).
* **$d$:** Es la cantidad de dígitos que tendrá la contraseña final.
  * Para una OTP de **6 dígitos**: $d = 6 \implies 10^6 = 10 \times 10 \times 10 \times 10 \times 10 \times 10 = \mathbf{1{,}000{,}000}$.
  * Para una OTP de **8 dígitos**: $d = 8 \implies 10^8 = \mathbf{100{,}000{,}000}$.
* **`mod` (Módulo):** Es la operación que calcula el **residuo o sobrante de una división entera**.

### 2. La Propiedad Mágica del Módulo Decimal
Cualquier número entero positivo del universo, sin importar qué tan gigantesco sea, al aplicarle `mod 1,000,000` **se queda obligatoriamente con sus últimos 6 dígitos decimales**.

Ejemplo:
```text
      1,081,686,038  dividido entre  1,000,000
    = Cociente: 1,081
    = Residuo:  686,038  (¡Los últimos 6 dígitos!)
```

---

### Paso 5.1: Conversión a Entero de 31 bits (DBC - Dynamic Binary Code)
Google toma los 4 bytes extraídos en la Fase 4: `0x40, 0x79, 0x38, 0x16`.
Para evitar que lenguajes como Java o C interpreten el primer bit como un número negativo, se aplica una máscara de 31 bits con `0x7FFFFFFF` (limpia el bit 31):

```text
  Byte 0: 0x40 (01000000) ──▶ Enmascara bit 7: 0x40 & 0x7F = 0x40
  Byte 1: 0x79
  Byte 2: 0x38
  Byte 3: 0x16

  DBC = (0x40 << 24) | (0x79 << 16) | (0x38 << 8) | 0x16
      = 0x40793816 en hexadecimal
      = 1,081,686,038 en decimal
```

---

### Paso 5.2: El Módulo Final y el Código de 6 Dígitos
Ahora se aplica el módulo:

```text
Código_OTP = 1,081,686,038 mod 10^6
           = 1,081,686,038 mod 1,000,000
           = 686038
```

Si el resultado fuera menor a 100,000 (por ejemplo, `4532`), el estándar manda rellenar con ceros a la izquierda (`%06d`) para mostrar siempre 6 cifras completas: `"004532"`.

```text
  ┌──────────────────────────────────────────────┐
  │                                              │
  │            PANTALLA DE TU CELULAR            │
  │           (Google Authenticator)             │
  │                                              │
  │                   686 038                    │
  │                                              │
  │          [======== 24s restantes ]           │
  │                                              │
  └──────────────────────────────────────────────┘
```

---
---

## BLOQUE 6: Ejemplo Práctico Completo: Sustitución en la Fórmula Matemática (Paso a Paso y Byte por Byte)

Para comprender cómo se articulan todas las fórmulas en un escenario de la vida real, desarrollamos el paso a paso exacto a partir de una fecha y hora humana concreta.

### 6.1. Escenario Real: "Son las 16:00:00 UTC del 8 de Octubre de 2024"

```text
  [FECHA HUMANA]   8 de Octubre de 2024, 16:00:00 UTC
         │
         ▼
  [TIMESTAMP UNIX] 1,728,403,200 segundos transcurridos desde 1970
         │
         ▼
  [FÓRMULA C]      C = piso((1,728,403,200 - 0) / 30) = 57,613,440
         │
         ▼
  [C EN 8 BYTES]   00 00 00 00 03 6f 1c 80 (Big-Endian)
         │
         ▼
  [HMAC-SHA1]      HS = HMAC-SHA1(K, C) (20 bytes criptográficos)
         │
         ▼
  [OFFSET]         Offset = HS[19] & 0x0F
         │
         ▼
  [4 BYTES]        Ventana deslizante HS[Offset ... Offset + 3]
         │
         ▼
  [DBC 31-BIT]     Enmascarar bit de signo con 0x7FFFFFFF
         │
         ▼
  [MÓDULO FINAL]   DBC mod 10^6 ──▶ CÓDIGO DE 6 DÍGITOS
```

---

#### Paso 1: Conversión de Fecha Humana a Timestamp Unix
* **Fecha elegida:** 8 de Octubre de 2024 a las 16:00:00 UTC.
* **Cálculo de segundos Unix:**
  Han transcurrido exactamente **1,728,403,200 segundos** desde la medianoche del 1 de enero de 1970 UTC.

---

#### Paso 2: Reemplazo en la Fórmula del Contador C (RFC 6238)
La fórmula oficial estipula:
```text
C = piso( (Tiempo_Unix - T0) / X )
```
Sustituyendo los valores del estándar (T0 = 0 y X = 30 segundos):
```text
C = piso( (1,728,403,200 - 0) / 30 )
C = piso( 57,613,440.0 )
C = 57,613,440  (en base decimal)
```

---

#### Paso 3: Empaquetado a 8 Bytes (64 bits) en Formato Big-Endian
El contador `57,613,440` se convierte a hexadecimal:
`57,613,440 = 0x036F1C80` (ocupa 4 bytes).

El estándar RFC 6238 exige **obligatoriamente un arreglo de 8 bytes** (16 caracteres hexadecimales). Por convención Big-Endian, se rellena con ceros a la izquierda:
```text
C_bytes = 00 00 00 00 03 6f 1c 80
```

---

#### Paso 4: Cálculo del Hash HMAC-SHA1 (20 Bytes)
Se calcula el hash autenticado utilizando la clave secreta compartida:

* **Con la Clave del Vector Oficial RFC (`12345678901234567890`):**
  ```text
  HS = af 28 7b 68 90 6c 69 28 fa 52 f1 56 c8 c8 3a fa 42 b3 f7 e8
  ```
  *(Arreglo de 20 bytes, con índices del 0 al 19).*

---

#### Paso 5: Extracción Dinámica del Offset (RFC 4226)
1. Se examina el último byte del hash:
   `HS[19] = 0xe8` (en binario: `1110 1000`).
2. Se extrae su nibble inferior aplicando la máscara `0x0F` (binario `0000 1111`):
   ```text
   Offset = 0xe8 & 0x0F = 0x08 = 8  (en decimal)
   ```
   *El Offset obtenido es 8.* Esto indica que la ventana de extracción comienza en el índice 8.

---

#### Paso 6: Extracción de los 4 Bytes Contiguos
A partir de la posición `Offset = 8`, se seleccionan los 4 bytes siguientes `HS[8 ... 11]`:
```text
Índice 8:  0xfa
Índice 9:  0x52
Índice 10: 0xf1
Índice 11: 0x56

Bytes seleccionados = fa 52 f1 56
```

---

#### Paso 7: Conversión a Entero Positivo de 31 bits (DBC)
Para asegurar que el entero sea positivo en cualquier arquitectura de 32 bits con signo (como Java), se aplica la máscara `0x7F` sobre el primer byte (o `0x7FFFFFFF` sobre el entero completo):
```text
Byte 0: 0xfa & 0x7F = 0x7a
Bytes restantes: 52 f1 56

DBC = (0x7a << 24) | (0x52 << 16) | (0xf1 << 8) | 0x56
    = 0x7a52f156 en hexadecimal
    = 2,052,256,086 en decimal
```

---

#### Paso 8: El Módulo Final (`mod 10^6` o `mod 10^8`)
Aplicamos la operación módulo para quedarnos con los dígitos deseados:

* **Para código estándar de 6 dígitos:**
  ```text
  OTP = 2,052,256,086 mod 10^6
      = 2,052,256,086 mod 1,000,000
      = 256086
  ```
  **Código mostrado en pantalla:** `256086`

* **Para código extendido de 8 dígitos:**
  ```text
  OTP = 2,052,256,086 mod 10^8
      = 2,052,256,086 mod 100,000,000
      = 52256086
  ```
  **Código mostrado en pantalla:** `52256086`

---

## BLOQUE 7: Vectores de Prueba Oficiales del Estándar RFC 6238 (Apéndice B)

El RFC 6238 incluye un conjunto de vectores de prueba oficiales para verificar que cualquier implementación en el mundo esté calculando exactamente los mismos valores sin fallos de desbordamiento o endianness.

### 7.1. Parámetros del Vector Oficial
* **Secreto Compartido (K):** `"12345678901234567890"`
  * En caracteres ASCII, cada número ocupa 1 byte:
    `'1'` = `0x31`, `'2'` = `0x32`, ..., `'0'` = `0x30`.
  * La cadena completa de 20 caracteres equivale a los **20 bytes hexadecimales**:
    `31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30`
  * **Longitud:** Exactamente **160 bits**, igualando el tamaño de salida de SHA-1.
* **Intervalo de Tiempo (X):** `30 segundos`.
* **Época Inicial (T0):** `0` (1 de enero de 1970 UTC).
* **Algoritmo de Hash (H):** `SHA-1` (salida de 20 bytes, bloque de 64 bytes).

---

### 7.2. Tabla de Variaciones de Tiempo y Formato de 8 Bytes (64 bits)

A medida que el tiempo avanza, el contador `C` va incrementándose y ocupando más bits dentro del campo de 8 bytes. El estándar probó escenarios históricos, contemporáneos y futuros para validar el comportamiento tras el año 2038 (desbordamiento de 32 bits):

| Caso | Tiempo Unix (Segundos) | Fecha Calendario (UTC) | Pasos C = piso(T/30) | Contador C en 8 Bytes (Hex Big-Endian) | Hash HMAC-SHA1 (20 Bytes) | Offset | Bytes Extraídos | Código OTP (8 Dígitos) | Código OTP (6 Dígitos) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **A** | `59` | 1970-01-01 00:00:59 | `1` | `0000000000000001` | `75a48a19d4cbe100644e8ac1397eea747a2d33ab` | **11** | `c1 39 7e ea` | **94287082** | **287082** |
| **B** | `1,111,111,109` | 2005-03-18 01:58:29 | `37,037,036` | `00000000023523EC` | `278c02e53610f84c40bd9135acd4101012410a14` | **4** | `36 10 f8 4c` | **07081804** | **081804** |
| **C** | `1,111,111,111` | 2005-03-18 01:58:31 | `37,037,037` | `00000000023523ED` | `b0092b21d048af209da0a1ddd498ade8a79487ed` | **13** | `98 ad e8 a7` | **14050471** | **050471** |
| **D** | `1,234,567,890` | 2009-02-13 23:31:30 | `41,152,263` | `000000000273EF07` | `907cd1a9116564ecb9d5d1780325f246173fe703` | **3** | `a9 11 65 64` | **89005924** | **005924** |
| **E** | `2,000,000,000` | 2033-05-18 03:33:20 | `66,666,666` | `0000000003F940AA` | `25a326d31fc366244cad054976020c7b56b13d5f` | **15** | `7b 56 b1 3d` | **69279037** | **279037** |
| **F** | `20,000,000,000` | 2603-10-11 11:33:20 | `666,666,666` | `0000000027BC86AA` | `ab07e97e2c1278769dbcd75783aabde75ed8550a` | **10** | `d7 57 83 aa` | **65353130** | **353130** |

* **Detalle técnico del Caso F (Año 2603):** El valor de `T` supera los 32 bits (`0x27BC86AA`), demostrando por qué el estándar exige manejar enteros de 64 bits (8 bytes) para evitar el problema del año 2038 (*Y2K38*).

---

## BLOQUE 8: Herramientas Web Interactivas para Visualizar las Transiciones (Offset y Bytes)

Si deseas explorar estas transiciones de forma interactiva en la web (ver en colores cómo se resalta el último byte, cómo se calcula el offset y cómo se extraen los 4 bytes contiguos), las herramientas más recomendadas en la industria son:

1. **RootProjects Authenticator Debugger & Visualizer (AJ O'Neal):**
   * **URL:** `https://rootprojects.org/authenticator/`
   * **Qué muestra:** Es el visualizador más didáctico existente. Permite ingresar cualquier secreto Base32 o HEX y cualquier marca de tiempo. En pantalla resalta el hash HMAC completo, colorea en rojo el último byte `HS[19]`, indica en amarillo el offset resultante y resalta los 4 bytes de la ventana deslizante que se transforman en el número final.

2. **CyberChef (Herramienta Oficial de Criptografía de GCHQ):**
   * **URL:** `https://gchq.github.io/CyberChef/`
   * **Qué muestra:** Permite armar recetas criptográficas en vivo combinando las operaciones: `HMAC` (con clave y mensaje), `Subset` (para aislar bytes por offset), `To Hex` y operaciones lógicas bit a bit.

3. **Token2 TOTP Toolset:**
   * **URL:** `https://www.token2.com/site/page/totp-toolset`
   * **Qué muestra:** Interfaz visual completa para auditoría de tokens. Permite cambiar entre SHA-1, SHA-256 y SHA-512, alternar entre 6 y 8 dígitos, y comparar el código generado contra la hora actual del servidor.

4. **Authgear TOTP Generator & Debugger:**
   * **URL:** `https://www.authgear.com/tools/totp-generator`
   * **Qué muestra:** Generador de código abierto para depuración rápida de parámetros URI (`otpauth://`) con inspección de derivación de claves.

5. **GAuth Authenticator Web (Emulador de Google Authenticator):**
   * **URL:** `https://gauth.apps.gbraad.nl/`
   * **Qué muestra:** Aplicación web cliente pura en HTML5/JavaScript para verificar el comportamiento exacto de Google Authenticator en el navegador.

---

---

## RESUMEN PARA TU PRESENTACIÓN (CANVAS STORYBOARD)

Cuando presentes tu lámina explicativa, el flujo se cuenta en 5 oraciones directas:

1. **El Servidor (Génesis):** Genera una semilla criptográfica segura de 160 bits (20 bytes) usando un generador CSPRNG y cumpliendo la checklist de NIST/OWASP.
2. **El Aprovisionamiento (Entrega):** Servidor y cliente comparten la semilla una sola vez escaneando un código QR cifrado con TLS; a partir de ahí, la comunicación de red termina.
3. **El Reloj (Sincronía):** Cada 30 segundos, el reloj Unix avanza y genera un contador entero `C` de 8 bytes sin necesidad de internet.
4. **La Extracción (1 sola ronda):** Se calcula HMAC-SHA1 y, mediante **1 sola extracción dinámica contigua** (RFC 4226), se extraen 4 bytes protegidos contra la vulnerabilidad de colapso que afectó al estándar coreano.
5. **El Módulo (Salida Humana):** Se aplica `mod 10^6` (residuo de dividir entre un millón) para aislar exactamente 6 dígitos limpios y legibles para el usuario humano.