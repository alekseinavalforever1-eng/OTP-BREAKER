# Implementaciones Nuevas y Adaptadas

Esta carpeta contiene implementaciones modernas construidas para casos de uso reales o para análisis comparativos frente a los estándares originales.

---

## ⚡ Guía Rápida de Ejecución

| Archivo | Descripción Breve | Comando en PowerShell / Terminal | Salida Principal |
| :--- | :--- | :--- | :--- |
| **`TOTPGoogleAuth.java`** ⭐ | Genera el código TOTP actual en tiempo real para Google Authenticator con cuenta regresiva. | `javac TOTPGoogleAuth.java; java TOTPGoogleAuth` | Recuadro ASCII con cuenta, hora, código de 6 dígitos y segundos restantes. |
| **`KoreaOTP.java`** | Simulación Monte Carlo (100k) de la vulnerabilidad en tarjetas OTP surcoreanas. | `javac KoreaOTP.java; java KoreaOTP` | Estadísticas de colapso de entropía y repetición de secuencias defectuosas vs seguras. |

### 🚀 ¿Cómo correr `TOTPGoogleAuth.java` paso a paso?

1. Abre una terminal (PowerShell o CMD) y sitúate en esta carpeta:
   ```powershell
   cd c:\Users\Aleks\Carrera\TIC\Material\CodigosRFC\2_Implementaciones_Nuevas
   ```
2. Compila y ejecuta el programa en una sola línea:
   ```powershell
   javac TOTPGoogleAuth.java; java TOTPGoogleAuth
   ```
3. **¿Qué verás en pantalla?**  
   Aparecerá un recuadro con la información de la cuenta (`alekseinavalforever@gmail.com`), la marca de tiempo Epoch/UTC/Local, y un recuadro central con el código TOTP actual (ej. `[ TOTP: 890653 ]`) junto a los segundos que le quedan de validez (`Válido por: 15 segundos`). Puedes abrir tu celular con Google Authenticator y comprobar que el código es exactamente idéntico.

---

## 📋 Catálogo Detallado de Archivos y Conceptos

### 1. `TOTPGoogleAuth.java` (Adaptación moderna para Google Authenticator)
* **¿Qué hace?** Es una versión completa y lista para producción que conecta el algoritmo TOTP con la aplicación móvil Google Authenticator (y compatibles como Authy o Microsoft Authenticator).
* **¿Cómo funciona?** 
  1. Utiliza la clave secreta y los parámetros extraídos del código QR de la aplicación móvil.
  2. Lee la hora actual del sistema, calcula la ventana temporal de 30 segundos, genera el código de 6 dígitos actual y calcula los segundos restantes de validez en cuenta regresiva.
* **Comandos de compilación y ejecución:**
  ```powershell
  javac TOTPGoogleAuth.java
  java TOTPGoogleAuth
  ```

### 2. `KoreaOTP.java` (Estándar coreano TTAK.KO-12.0193 y análisis de vulnerabilidad)
* **¿Qué hace?** Modela las especificaciones del estándar de OTP de Corea del Sur y reproduce la vulnerabilidad detectada en tarjetas inteligentes donde la selección de bytes se implementó de forma encadenada/dependiente.
* **¿Cómo funciona?** 
  1. Ejecuta una simulación Monte Carlo de 100,000 muestras.
  2. Mide la tasa de colapso de bytes (b1 == b2 == b3), demostrando la probabilidad teórica de 1/16 = 6.25%.
  3. Compara las repeticiones máximas de dígitos entre el algoritmo uniforme seguro (máximo ~4 repeticiones) y el algoritmo defectuoso (hasta 40 repeticiones), confirmando la reducción drástica de entropía.
* **Comandos de compilación y ejecución:**
  ```powershell
  javac KoreaOTP.java
  java KoreaOTP
  ```

---

## 🔍 Desglose a Fondo: El Estándar de Google Authenticator y su Código QR

Google utiliza dos estándares distintos para representar credenciales OTP en códigos QR:

### A. Los Dos Formatos de Google

| Formato | Esquema URI | Uso principal | Características |
| :--- | :--- | :--- | :--- |
| **Provisión Clásica** | `otpauth://totp/...` | Registro inicial en una web/servicio | Texto plano, una sola cuenta por QR, fácil de leer. |
| **Migración / Transferencia** | `otpauth-migration://offline?data=...` | Transferir cuentas entre celulares | Formato binario comprimido (**Protocol Buffers** en Base64), permite transferir múltiples cuentas en un único QR. |

---

### B. Análisis del Código QR de Transferencia Escaneado

Al escanear el código QR de la pantalla *"Descarga la app de Google Authenticator en tu nuevo dispositivo"*, se obtiene la siguiente cadena URI completa:

```text
otpauth-migration://offline?data=ClgKFPZ1Itjt04zQZlF5JYKV2wZvZRq0Eh1hbGVrc2VpbmF2YWxmb3JldmVyQGdtYWlsLmNvbRoGR29vZ2xlIAEoATACQhMzNjAwNzYxNzcyODI3MjA1NDk3EAIYASAA
```

#### 1. ¿Cómo está construido este enlace?
1. **Esquema:** `otpauth-migration://offline` indica que es una transferencia local de credenciales que no requiere conexión a internet para ser procesada.
2. **Parámetro `data=`:** Contiene una secuencia binaria serializada mediante **Google Protocol Buffers (Protobuf)** y codificada en **Base64** estándar.

---

### C. Esquema Protobuf (`MigrationPayload`)

Google define internamente la estructura de este mensaje de la siguiente forma:

```protobuf
syntax = "proto3";

message MigrationPayload {
  enum Algorithm {
    ALGORITHM_UNSPECIFIED = 0;
    ALGORITHM_SHA1 = 1;
    ALGORITHM_SHA256 = 2;
    ALGORITHM_SHA512 = 3;
    ALGORITHM_MD5 = 4;
  }

  enum DigitCount {
    DIGIT_COUNT_UNSPECIFIED = 0;
    DIGIT_COUNT_SIX = 1;
    DIGIT_COUNT_EIGHT = 2;
  }

  enum OtpType {
    OTP_TYPE_UNSPECIFIED = 0;
    OTP_TYPE_HOTP = 1;
    OTP_TYPE_TOTP = 2;
  }

  message OtpParameters {
    bytes secret = 1;          // Clave secreta compartida (bytes brutos)
    string name = 2;           // Nombre de la cuenta (correo o usuario)
    string issuer = 3;         // Emisor del servicio (ej. "Google")
    Algorithm algorithm = 4;   // Función hash (SHA1, SHA256, SHA512)
    DigitCount digits = 5;     // Cantidad de dígitos (6 u 8)
    OtpType type = 6;          // Tipo: 1 = HOTP (evento), 2 = TOTP (tiempo)
    int64 counter = 7;         // Contador inicial (si es HOTP)
    string account_id = 8;     // Identificador interno de cuenta de Google
  }

  repeated OtpParameters otp_parameters = 1; // Lista de cuentas en este QR
  int32 version = 2;                         // Versión del protocolo (valor: 2)
  int32 batch_size = 3;                      // Total de lotes de exportación (valor: 1)
  int32 batch_index = 4;                     // Índice del lote actual (valor: 0)
  int32 batch_id = 5;                        // ID único de la sesión de transferencia
}
```

---

### D. Desgranado Campo por Campo de tu Código QR

Al decodificar la cadena Base64 (`96 bytes` binarios) contra el esquema Protobuf, se obtienen los siguientes datos exactos:

| Campo | Valor Extraído | Significado / Propósito |
| :--- | :--- | :--- |
| **`version`** | `2` | Versión del protocolo de migración de Google Authenticator. |
| **`batch_size`** | `1` | Indica que este QR contiene 1 lote completo (no hay QR adicionales que escanear). |
| **`batch_index`** | `0` | Índice del lote (0 de 1). |
| **`secret` (Bruto)** | 20 bytes binarios | Los 160 bits de la clave simétrica compartida. |
| **`secret` (HEX)** | `f67522d8edd38cd0665179258295db066f651ab4` | Formato hexadecimal utilizado internamente en [TOTPGoogleAuth.java](file:///c:/Users/Aleks/Carrera/TIC/Material/CodigosRFC/2_Implementaciones_Nuevas/TOTPGoogleAuth.java#L285). |
| **`secret` (Base32)** | `6Z2SFWHN2OGNAZSRPESYFFO3AZXWKGVU` | Representación estándar RFC 4648 sin caracteres confusos (0, 1, 8, 9). |
| **`name`** | `alekseinavalforever@gmail.com` | La cuenta de Google asociada al 2FA. |
| **`issuer`** | `Google` | El proveedor de identidad que emite el código. |
| **`algorithm`** | `1` (`ALGORITHM_SHA1`) | La función hash criptográfica requerida por Google para este token. |
| **`digits`** | `1` (`DIGIT_COUNT_SIX`) | Código de 6 dígitos numéricos. |
| **`type`** | `2` (`OTP_TYPE_TOTP`) | Algoritmo basado en tiempo con paso de 30 segundos (RFC 6238). |
| **`account_id` (Campo 8)** | `3600761772827205497` | Identificador interno de enrutamiento y sincronización de Google. |

---

### D.1 Transcripción y Mapeo Binario Byte por Byte (Los 96 Bytes)

La cadena Base64 del QR (`ClgKFPZ1...`) decodifica a un arreglo exacto de **96 bytes binarios** (del byte 0 al byte 95).

A continuación se muestra el volcado hexadecimal completo organizado en bloques de 16 bytes:

```text
Byte 00-15:  0a 58 0a 14 f6 75 22 d8 ed d3 8c d0 66 51 79 25
Byte 16-31:  82 95 db 06 6f 65 1a b4 12 1d 61 6c 65 6b 73 65
Byte 32-47:  69 6e 61 76 61 6c 66 6f 72 65 76 65 72 40 67 6d
Byte 48-63:  61 69 6c 2e 63 6f 6d 1a 06 47 6f 6f 67 6c 65 20
Byte 64-79:  01 28 01 30 02 42 13 33 36 30 30 37 36 31 37 37
Byte 80-95:  32 38 32 37 32 30 35 34 39 37 10 02 18 01 20 00
```

---

#### Tabla Maestra de Interpretación Byte por Byte

En Protocol Buffers, cada encabezado se codifica en binario como:
`Encabezado = (Número_de_Campo << 3) | Tipo_de_Dato_Wire`
* **Wire Type 0 (Varint):** Enteros y enums (1 byte o más).
* **Wire Type 2 (Length-delimited):** Cadenas, arreglos de bytes y sub-mensajes precedidos por su longitud.

| Rango de Bytes | Bytes en Hexadecimal | Elemento Protobuf | Desglose a Nivel Binario | Interpretación / Valor Final |
| :---: | :--- | :--- | :--- | :--- |
| **0 - 1** | `0a 58` | Sub-mensaje `OtpParameters` | `0x0a` = (Campo 1, Wire 2)<br>`0x58` = Longitud 88 bytes | **Abre el contenedor de la cuenta.** Los siguientes 88 bytes contienen los parámetros del token. |
| **2 - 3** | `0a 14` | Campo 1: `secret` | `0x0a` = (Campo 1, Wire 2)<br>`0x14` = Longitud 20 bytes | **Encabezado de la clave secreta.** Anuncia los 20 bytes de la semilla criptográfica. |
| **4 - 23** | `f6 75 22 d8 ed d3 8c d0 66 51 79 25 82 95 db 06 6f 65 1a b4` | Valor de `secret` | 20 bytes crudos (160 bits) | **Semilla criptográfica:**<br>• HEX: `f67522d8edd38cd0665179258295db066f651ab4`<br>• Base32: `6Z2SFWHN2OGNAZSRPESYFFO3AZXWKGVU` |
| **24 - 25** | `12 1d` | Campo 2: `name` | `0x12` = (Campo 2, Wire 2)<br>`0x1d` = Longitud 29 bytes | **Encabezado del nombre de cuenta.** |
| **26 - 54** | `61 6c 65 6b 73 65 69 6e 61 76 61 6c 66 6f 72 65 76 65 72 40 67 6d 61 69 6c 2e 63 6f 6d` | Valor de `name` | 29 caracteres en ASCII | `"alekseinavalforever@gmail.com"` |
| **55 - 56** | `1a 06` | Campo 3: `issuer` | `0x1a` = (Campo 3, Wire 2)<br>`0x06` = Longitud 6 bytes | **Encabezado del emisor.** |
| **57 - 62** | `47 6f 6f 67 6c 65` | Valor de `issuer` | 6 caracteres en ASCII | `"Google"` |
| **63 - 64** | `20 01` | Campo 4: `algorithm` | `0x20` = (Campo 4, Wire 0)<br>`0x01` = Valor 1 | Enum `ALGORITHM_SHA1` (función hash HMAC-SHA1). |
| **65 - 66** | `28 01` | Campo 5: `digits` | `0x28` = (Campo 5, Wire 0)<br>`0x01` = Valor 1 | Enum `DIGIT_COUNT_SIX` (código numérico de 6 dígitos). |
| **67 - 68** | `30 02` | Campo 6: `type` | `0x30` = (Campo 6, Wire 0)<br>`0x02` = Valor 2 | Enum `OTP_TYPE_TOTP` (basado en tiempo con paso de 30 segundos). |
| **69 - 70** | `42 13` | Campo 8: `account_id` | `0x42` = (Campo 8, Wire 2)<br>`0x13` = Longitud 19 bytes | **Encabezado del identificador interno.** |
| **71 - 89** | `33 36 30 30 37 36 31 37 37 32 38 32 37 32 30 35 34 39 37` | Valor de `account_id` | 19 caracteres en ASCII | `"3600761772827205497"` (ID interno de Google). |
| **90 - 91** | `10 02` | Campo 2: `version` | `0x10` = (Campo 2, Wire 0)<br>`0x02` = Valor 2 | **Versión del protocolo de migración:** Versión 2. |
| **92 - 93** | `18 01` | Campo 3: `batch_size` | `0x18` = (Campo 3, Wire 0)<br>`0x01` = Valor 1 | **Tamaño del lote:** 1 solo código QR en esta exportación. |
| **94 - 95** | `20 00` | Campo 4: `batch_index` | `0x20` = (Campo 4, Wire 0)<br>`0x00` = Valor 0 | **Índice del QR:** Lote 0 (el primero y único). |

---

### E. Equivalencia con la URI de Provisión Estándar

Si convirtiéramos este código QR de migración binaria al formato URI estándar abierto que utilizan servicios como GitHub o AWS al activar el 2FA, se vería exactamente así:

```text
otpauth://totp/Google:alekseinavalforever@gmail.com?secret=6Z2SFWHN2OGNAZSRPESYFFO3AZXWKGVU&issuer=Google&algorithm=SHA1&digits=6&period=30
```

---

### F. ¿Por qué TOTPGoogleAuth.java coincide con tu celular?

1. Tanto la app de Google Authenticator como tu programa Java leen la hora exacta del reloj del sistema.
2. Dividen los segundos transcurridos desde 1970 (Epoch) entre 30 para calcular el contador de pasos temporales:
   `T = piso(Tiempo_Actual / 30)`
3. Calculan el hash criptográfico oficial:
   `HMAC-SHA1(Clave_Secreta, T)`
4. Aplican el **truncamiento dinámico** (especificado en la RFC 4226) para extraer 4 bytes del resultado y tomar el residuo módulo 10^6.
5. Debido a que ambos usan la misma clave secreta extraída (`f67522d8...`) y la misma hora coordinada (NTP), **el número resultante es obligatoriamente idéntico**.

---

## 🔬 G. Guía Fase a Fase: Generación de una OTP con tu Semilla Real
### (Comparativa: Google Authenticator RFC 4226 vs. Estándar Coreano TTAK.KO-12.0193)

A continuación se detalla la transformación matemática y de bytes a lo largo de las **4 fases** del ciclo de vida de un OTP, utilizando los datos reales extraídos de tu cuenta:

* **Semilla Base32:** `6Z2SFWHN2OGNAZSRPESYFFO3AZXWKGVU`
* **Semilla Hexadecimal (20 bytes):** `f6 75 22 d8 ed d3 8c d0 66 51 79 25 82 95 db 06 6f 65 1a b4`
* **Usuario:** `alekseinavalforever@gmail.com`
* **Emisor:** `Google`

```text
  [FASE 0: ENTRADA]      Semilla K (20 bytes)  +  Contador C (8 bytes)
                                       │
                                       ▼
  [FASE 1: CRIPTO]       HS = HMAC-SHA1(K, C) ──▶ 20 bytes (160 bits)
                         (AMBOS ESTÁNDARES LO HACEN PERFECTO AQUÍ)
                                       │
                                       ▼
  [FASE 2: TRUNCAMIENTO] ──▶ ★ AQUÍ ES DONDE DIFIERE EL COREANO DE GOOGLE ★
      • Google (RFC 4226):   1 Offset ──▶ Extrae 4 bytes contiguos (Entropía intacta)
      • Corea (Vulnerable):  3 Offsets encadenados ──▶ Colapsa a b1=b2=b3 (Falla del 6.25%)
                                       │
                                       ▼
  [FASE 3: CÓDIGO FINAL] Truncamiento mod 10^6 ──▶ OTP de 6 dígitos numéricos
```

---

### FASE 0: La Semilla Criptográfica y el Contador Temporal

1. **La Semilla Simétrica (K):**
   Tu cuenta utiliza una clave secreta compartida de exactamente **20 bytes (160 bits)**:
   ```text
   K = f6 75 22 d8 ed d3 8c d0 66 51 79 25 82 95 db 06 6f 65 1a b4
   ```

2. **El Contador de Tiempo (C):**
   Se calcula leyendo el tiempo UNIX actual (segundos desde el 1 de enero de 1970) y dividiéndolo entre la ventana de validez (30 segundos):
   ```text
   C = piso(Tiempo_Actual / 30)
   ```
   Ese entero se codifica como un entero de **8 bytes (64 bits) en formato Big-Endian** (el byte más significativo primero):
   * Ejemplo con contador `C = 26`:
     ```text
     C_bytes = 00 00 00 00 00 00 00 1a
     ```
   * Ejemplo con tiempo actual `C = 59152263`:
     ```text
     C_bytes = 00 00 00 00 03 86 97 87
     ```

* **Diagnóstico de la Fase 0:**
  - ✅ **Google:** Excelente. Clave con 160 bits de entropía pura.
  - ✅ **Corea:** Excelente. El estándar coreano también utiliza semillas de 160 bits y contadores válidos. **Aquí el coreano NO falló.**

---

### FASE 1: Hashing Criptográfico HMAC-SHA1 (RFC 2104)

Tanto Google Authenticator como el estándar coreano aplican el algoritmo oficial HMAC con la función hash SHA-1.

1. **Preparación de las almohadillas (Pads):**
   La clave `K` de 20 bytes se rellena con ceros a la derecha hasta completar el tamaño de bloque de 64 bytes (`B = 64`).
   Luego se realizan dos operaciones XOR con constantes fijas:
   * `ipad` (Inner Pad): Clave XOR `0x36` repetido 64 veces.
   * `opad` (Outer Pad): Clave XOR `0x5C` repetido 64 veces.

2. **Cálculo del Hash Interno y Hash Final:**
   ```text
   Hash_Interno = SHA1(ipad || C_bytes)                     (20 bytes)
   HS           = SHA1(opad || Hash_Interno)                (20 bytes)
   ```

Tomando tu clave real y el contador `C = 26`, el resultado de `HS` (20 bytes, numerados del 0 al 19) es:

```text
Índice:   [0] [1] [2] [3] [4] [5] [6] [7] [8] [9] [10][11][12][13][14][15][16][17][18][19]
Byte HEX:  40  79  38  16  6a  7a  ad  b7  55  90  f8  f9  20  52  a6  a8  da  56  ae  10
```

* **Diagnóstico de la Fase 1:**
  - ✅ **Google:** Excelente. SHA-1 distribuye los bits de forma pseudoaleatoria.
  - ✅ **Corea:** Excelente. El estándar coreano utiliza este mismo bloque de 20 bytes. **Aquí el coreano TAMPOCO falló.**

---

### FASE 2: Truncamiento y Extracción de Bytes (¡EL PUNTO CRÍTICO DE LA FALLA!)

Aquí es donde se produce la bifurcación entre el estándar seguro internacional y el estándar coreano defectuoso.

#### A. Cómo lo hace Google Authenticator (RFC 4226 / RFC 6238) - CORRECTO:
Google extrae **4 bytes contiguos** usando un único offset:
1. Mira el último byte del hash: `HS[19] = 0x10`.
2. Extrae los 4 bits inferiores (nibble bajo):
   ```text
   Offset = HS[19] & 0x0F = 0x10 & 0x0F = 0
   ```
3. Extrae los **4 bytes contiguos** a partir de esa posición `[Offset ... Offset + 3]`:
   ```text
   Bytes extraídos = HS[0], HS[1], HS[2], HS[3]
                   = 0x40, 0x79, 0x38, 0x16
   ```
   **Resultado:** 4 bytes completamente independientes y pseudoaleatorios con **32 bits de entropía intacta**.

---

#### B. Cómo lo hizo el estándar coreano (TTAK.KO-12.0193 Improved) - ¡FALLA CATASTRÓFICA!:
Los diseñadores coreanos quisieron "mejorar" la aleatoriedad en tarjetas inteligentes encadenando 3 offsets dinámicos para extraer 3 bytes discontinuos:
1. **Primer byte (b1):**
   ```text
   Offset_1 = HS[19] & 0x0F = 0x10 & 0x0F = 0
   b1 = HS[Offset_1] = HS[0] = 0x40
   ```
2. **Segundo byte (b2):** En lugar de tomar el siguiente byte contiguo, calculan el offset a partir de `b1`:
   ```text
   Offset_2 = b1 & 0x0F = 0x40 & 0x0F = 0    <-- ¡COINCIDIÓ CON OFFSET 1!
   b2 = HS[Offset_2] = HS[0] = 0x40          <-- ¡SELECCIONA EL MISMO BYTE!
   ```
3. **Tercer byte (b3):** Calculan el offset a partir de `b2`:
   ```text
   Offset_3 = b2 & 0x0F = 0x40 & 0x0F = 0
   b3 = HS[Offset_3] = HS[0] = 0x40          <-- ¡OTRA VEZ EL MISMO BYTE!
   ```

* **El colapso de bytes:**
  Los 3 bytes extraídos por el algoritmo coreano resultan ser:
  ```text
  b1 = 0x40,  b2 = 0x40,  b3 = 0x40  (¡Tres bytes exactamente idénticos!)
  ```
  La entropía se desplomó de 24 bits a solo **8 bits** (un único byte repetido 3 veces).
* **Frecuencia del fallo:** Ocurre matemáticamente siempre que `(b1 & 0x0F) == Offset_1`, lo cual pasa exactamente **1 de cada 16 veces (6.25% de todas las OTPs generadas)**.

---

### FASE 3: Conversión Numérica y Módulo 10^6 (Código Final)

#### A. Google Authenticator (RFC 4226):
1. Toma los 4 bytes: `0x40, 0x79, 0x38, 0x16`.
2. Enmascara el bit de signo (bit 31) con `0x7FFFFFFF` para evitar enteros negativos en Java/C:
   ```text
   Entero_31bit = 0x40793816 & 0x7FFFFFFF = 1,081,686,038
   ```
3. Aplica módulo 10^6 para obtener el código de 6 dígitos:
   ```text
   Código_OTP = 1,081,686,038 mod 1,000,000 = 686,038
   ```
   **Código mostrado en la App de Google:** `686038` (Uniforme y seguro).

---

#### B. Estándar Coreano Vulnerable:
1. Concatena los 3 bytes idénticos en un entero de 24 bits:
   ```text
   Valor = (0x40 << 16) | (0x40 << 8) | 0x40
         = 0x404040 = 4,210,752
   ```
   Observa que matemáticamente:
   `Valor = 0x40 * (65536 + 256 + 1) = 64 * 65793 = 4,210,752`
2. Aplica módulo 10^6:
   ```text
   Código_OTP = 4,210,752 mod 1,000,000 = 210,752
   ```
   **Código mostrado al usuario coreano:** `210752`.

* **El impacto en seguridad:**
  Como el byte `b1` solo puede tomar valores entre 0 y 255, cuando ocurre la falla del 6.25%, el código generado **está restringido obligatoriamente a solo 256 números en todo el mundo** (`000000`, `065793`, `131586`, `197379`, `210752`, etc.).
  Un atacante que intente forzar el acceso a tu cuenta no necesita probar 1,000,000 de combinaciones: probando esa lista reducida de 256 números tiene un 6.25% de éxito garantizado.

---

### Resumen Comparativo de las 4 Fases

| Fase | Qué se procesa | Google Authenticator (RFC 4226 / 6238) | Estándar Coreano (TTAK.KO-12.0193) | ¿Dónde falló? |
| :---: | :--- | :--- | :--- | :---: |
| **Fase 0** | Semilla (K) y Contador (C) | 160 bits (CSPRNG) + Tiempo Unix / 30 | 160 bits + Contador de evento o tiempo | ✅ Ambos Bien |
| **Fase 1** | Hashing criptográfico | HMAC-SHA1 estándar (20 bytes) | HMAC-SHA1 estándar (20 bytes) | ✅ Ambos Bien |
| **Fase 2** | Truncamiento y Extracción | **1 Offset** -> 4 bytes contiguos.<br>Conserva 32 bits de entropía pura. | **3 Offsets encadenados** -> 3 bytes.<br>Colapso a bytes idénticos (6.25%). | ❌ **AQUÍ FALLÓ COREA** |
| **Fase 3** | Truncamiento a 6 dígitos | Máscara `& 0x7FFFFFFF` mod 10^6.<br>Distribución equiprobable en 10^6. | Concatenación 24 bits mod 10^6.<br>256 códigos con repetición anómala. | ❌ Consecuencia directa de Fase 2 |

