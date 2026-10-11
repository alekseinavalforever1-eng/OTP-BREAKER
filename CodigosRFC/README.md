# Guía Completa de la Carpeta CodigosRFC

Esta carpeta reúne el código de referencia, las implementaciones prácticas y los bancos de pruebas de los principales estándares criptográficos para **Contraseñas de Un Solo Uso (OTP)** y **Códigos de Autenticación de Mensajes basados en Hash (HMAC)**.

---

## ⚡ Tabla Resumen: Descripción de Cada Archivo y Cómo Ejecutarlo

Si buscas correr un archivo de inmediato, usa esta tabla de referencia rápida:

| Archivo | Subcarpeta | Breve Descripción | Comando para Compilar y Ejecutar (PowerShell) |
| :--- | :--- | :--- | :--- |
| **`TOTPGoogleAuth.java`** ⭐ | `2_Implementaciones_Nuevas` | **Compatible con Google Authenticator:** Genera el código OTP actual de 6 dígitos en tiempo real según el reloj del sistema, con cuenta regresiva de 30 segundos. | `cd 2_Implementaciones_Nuevas`<br>`javac TOTPGoogleAuth.java; java TOTPGoogleAuth` |
| **`KoreaOTP.java`** | `2_Implementaciones_Nuevas` | **Estándar surcoreano TTAK.KO-12.0193:** Simulación Monte Carlo (100k) comparando la generación segura frente a una implementación defectuosa con sesgo de entropía. | `cd 2_Implementaciones_Nuevas`<br>`javac KoreaOTP.java; java KoreaOTP` |
| **`TOTP.java`** | `1_Estandares_Originales_RFC` | **Estándar RFC 6238:** Código oficial IETF que genera vectores temporales OTP de 8 dígitos para SHA-1, SHA-256 y SHA-512 en distintas fechas históricas y futuras. | `cd 1_Estandares_Originales_RFC`<br>`javac TOTP.java; java TOTP` |
| **`OneTimePasswordAlgorithm.java`** | `1_Estandares_Originales_RFC` | **Estándar RFC 4226 (HOTP):** Código canónico OATH que calcula los códigos OTP por eventos/contador (del 0 al 9) con y sin suma de verificación Luhn. | `cd 1_Estandares_Originales_RFC`<br>`javac OneTimePasswordAlgorithm.java; java OneTimePasswordAlgorithm` |
| **`rfc2104.c`** | `1_Estandares_Originales_RFC` | **HMAC-MD5 en Lenguaje C puro (RFC 2104):** Valida a bajo nivel la mezcla criptográfica `ipad`/`opad` contra los 3 vectores de prueba estandarizados. | `cd 1_Estandares_Originales_RFC`<br>`clang rfc2104.c -o rfc2104.exe; .\rfc2104.exe` *(o con `gcc`)* |
| **`TestHMACMD5.java`** | `3_Pruebas_y_Ejemplos` | **Verificador HMAC en Java:** Batería automatizada que valida los 3 vectores del RFC 2104 con `javax.crypto.Mac` imprimiendo `[PASS]` o `[FAIL]`. | `cd 3_Pruebas_y_Ejemplos`<br>`javac TestHMACMD5.java; java TestHMACMD5` |
| **`TestHOTP.java`** | `3_Pruebas_y_Ejemplos` | **Prueba modular con paquetes Java:** Verifica la clase empaquetada bajo `org.openauthentication.otp.*` asegurando su portabilidad e integración. | `cd 3_Pruebas_y_Ejemplos`<br>`javac org\openauthentication\otp\OneTimePasswordAlgorithm.java`<br>`javac -cp . TestHOTP.java; java -cp . TestHOTP` |

---

## 📁 Estructura del Directorio y Catálogo de Archivos

```text
CodigosRFC/
│
├── README.md                          # Guía central de navegación, ejecución y conceptos
│
├── 1_Estandares_Originales_RFC/       # Códigos oficiales de los estándares IETF y OATH
│   ├── README.md                      # Explicación conceptual y guía de comandos locales
│   ├── rfc2104.c                      # Implementación canónica de HMAC-MD5 en Lenguaje C (RFC 2104)
│   ├── OneTimePasswordAlgorithm.java  # Algoritmo HOTP oficial basado en eventos (RFC 4226)
│   └── TOTP.java                      # Algoritmo TOTP oficial basado en tiempo (RFC 6238)
│
├── 2_Implementaciones_Nuevas/         # Aplicaciones modernas y código para investigación
│   ├── README.md                      # Explicación conceptual y guía de comandos locales
│   ├── TOTPGoogleAuth.java            # Versión para Google Authenticator (Base32, tiempo real y QR)
│   └── KoreaOTP.java                  # Modelo y simulación del estándar surcoreano (TTAK.KO-12.0193)
│
└── 3_Pruebas_y_Ejemplos/              # Banco de pruebas automatizadas y paquetes estructurados
    ├── README.md                      # Explicación conceptual y guía de comandos locales
    ├── TestHOTP.java                  # Verificador de vectores oficiales HOTP usando paquete OATH
    ├── TestHMACMD5.java               # Verificador automatizado de HMAC-MD5 en Java (RFC 2104)
    └── org/                           # Paquete Java canónico de la iniciativa OATH
        └── openauthentication/
            └── otp/
                └── OneTimePasswordAlgorithm.java # Código fuente empaquetado para importación
```

---

## 🚀 ¿Cómo compilar y ejecutar cada archivo?

A continuación se detallan los comandos exactos para PowerShell o Terminal, explicando **qué hace cada programa**, **si vale la pena ejecutarlo** y **qué salida esperar**.

---

### 📂 Carpeta 1: `1_Estandares_Originales_RFC`

Navega primero a la carpeta:
```powershell
cd c:\Users\Aleks\Carrera\TIC\Material\CodigosRFC\1_Estandares_Originales_RFC
```

#### 1. `rfc2104.c` (HMAC en C)
* **¿Sirve de algo correrlo?**  
  **Sí, es fundamental.** Este archivo es una implementación pura y autónoma en C (incluye su propio motor MD5 según RFC 1321 y el algoritmo HMAC según RFC 2104). Al ejecutarlo, corre una suite de pruebas criptográficas oficiales con 3 vectores de prueba estandarizados por el IETF. Sirve para validar que el compilador maneje correctamente el orden de bytes (endianness), las operaciones bit a bit (`XOR`, desplazamientos) y genere hashes idénticos a los definidos en el estándar antes de trabajar en capas de más alto nivel.
* **Compilación y ejecución:**
  * **Con Clang (LLVM):**
    ```powershell
    clang rfc2104.c -o rfc2104.exe
    .\rfc2104.exe
    ```
  * **Con GCC (MinGW / MSYS2):**
    ```powershell
    gcc rfc2104.c -o rfc2104.exe
    .\rfc2104.exe
    ```
* **Salida esperada:**
  Imprime en consola los 3 vectores de prueba oficiales, comparando la clave, el mensaje de texto, el hash calculado y el hash esperado (debe coincidir exactamente con `929472...`, `750c78...`, `56be34...`).

#### 2. `OneTimePasswordAlgorithm.java` (HOTP - RFC 4226)
* **¿Sirve de algo correrlo?**  
  **Sí.** Es el código fuente oficial de la iniciativa OATH para contraseñas de un solo uso basadas en un contador por eventos (clics o transacciones). Su método `main` genera la tabla canónica del estándar para los contadores del 0 al 9.
* **Compilación y ejecución:**
  ```powershell
  javac OneTimePasswordAlgorithm.java
  java OneTimePasswordAlgorithm
  ```
* **Salida esperada:**
  Una tabla con 10 filas mostrando el valor del contador, el código OTP de 6 dígitos (ej. `755224` para el contador 0) y la variante de 7 dígitos con dígito de control de errores (checksum de Luhn).

#### 3. `TOTP.java` (TOTP - RFC 6238)
* **¿Sirve de algo correrlo?**  
  **Sí.** Es el estándar publicado por el IETF en 2011 que extiende HOTP para basarse en el reloj (tiempo Unix / 30 segundos). Su `main` evalúa marcas temporales históricas y futuras (desde 1970 hasta el año 2603) comparando los algoritmos SHA-1, SHA-256 y SHA-512.
* **Compilación y ejecución:**
  ```powershell
  javac TOTP.java
  java TOTP
  ```
* **Salida esperada:**
  Una tabla completa con marcas de tiempo en segundos, formato UTC legible, valor del contador $T$ en hexadecimal, y los códigos OTP de 8 dígitos generados bajo los tres modos criptográficos.

---

### 📂 Carpeta 2: `2_Implementaciones_Nuevas`

Navega primero a la carpeta:
```powershell
cd c:\Users\Aleks\Carrera\TIC\Material\CodigosRFC\2_Implementaciones_Nuevas
```

#### 1. `TOTPGoogleAuth.java` (Compatible con Google Authenticator)
* **¿Sirve de algo correrlo?**  
  **Sí, es una de las pruebas más interactivas.** Conecta los estándares matemáticos con las aplicaciones móviles comerciales (Google Authenticator, Microsoft Authenticator, Authy). Decodifica la clave en formato Base32, lee la hora del sistema y genera el código OTP exacto para los 30 segundos en curso.
* **Compilación y ejecución:**
  ```powershell
  javac TOTPGoogleAuth.java
  java TOTPGoogleAuth
  ```
* **Salida esperada:**
  Un recuadro en consola con la cuenta configurada, el secreto en Base32, la hora UTC y local, la ventana temporal, el tiempo restante de validez en segundos (cuenta regresiva) y el **código de 6 dígitos actual** (puedes compararlo con la app en tu teléfono y verificar que coincide).
* **Anatomía del Código QR y Protobuf de Google:**  
  Para ver el desglose completo campo por campo del QR escaneado (`otpauth-migration://offline?data=...`), el esquema Protobuf y cómo se extrajo la clave secreta, consulta la sección dedicada en [2_Implementaciones_Nuevas/README.md](file:///c:/Users/Aleks/Carrera/TIC/Material/CodigosRFC/2_Implementaciones_Nuevas/README.md#d-desgranado-campo-por-campo-de-tu-código-qr).

#### 2. `KoreaOTP.java` (Estándar Surcoreano y Simulación de Vulnerabilidad)
* **¿Sirve de algo correrlo?**  
  **Sí, demuestra experimentalmente la ruptura criptográfica analizada en el proyecto.** Modela el estándar surcoreano TTAK.KO-12.0193 y compara el método seguro frente al método defectuoso implementado en tarjetas inteligentes comerciales (donde la extracción de bytes depende del valor anterior).
* **Compilación y ejecución:**
  ```powershell
  javac KoreaOTP.java
  java KoreaOTP
  ```
* **Salida esperada:**
  Ejecuta una simulación Monte Carlo de 100,000 muestras. Muestra:
  1. El colapso de bytes idénticos (b1 == b2 == b3 con probabilidad teórica de 1/16 = 6.25% vs observada).
  2. La comparativa de repeticiones máximas entre el algoritmo de control uniforme (máximo 4 repeticiones) y el algoritmo defectuoso (hasta 40 repeticiones), evidenciando el sesgo crítico de seguridad.

---

### 📂 Carpeta 3: `3_Pruebas_y_Ejemplos`

Navega primero a la carpeta:
```powershell
cd c:\Users\Aleks\Carrera\TIC\Material\CodigosRFC\3_Pruebas_y_Ejemplos
```

#### 1. `TestHOTP.java` (Prueba de integración con paquete Java)
* **¿Sirve de algo correrlo?**  
  **Sí.** Comprueba la integración modular en Java cuando el algoritmo reside dentro del paquete oficial `org.openauthentication.otp.OneTimePasswordAlgorithm`.
* **Compilación y ejecución:**
  ```powershell
  # 1. Compilar la clase del paquete
  javac org\openauthentication\otp\OneTimePasswordAlgorithm.java

  # 2. Compilar y correr el test referenciando el classpath actual (.)
  javac -cp . TestHOTP.java
  java -cp . TestHOTP
  ```
* **Salida esperada:**
  La tabla con los 10 códigos generados del contador 0 al 9 comprobando que la importación del paquete funciona sin fallos.

#### 2. `TestHMACMD5.java` (Suite automatizada de vectores HMAC en Java)
* **¿Sirve de algo correrlo?**  
  **Sí.** Ejecuta los mismos 3 vectores de prueba que `rfc2104.c`, pero utilizando la API nativa de criptografía de Java (`javax.crypto.Mac`). Valida automáticamente los resultados contra los hashes esperados e imprime explícitamente `[PASS]` o `[FAIL]`.
* **Compilación y ejecución:**
  ```powershell
  javac TestHMACMD5.java
  java TestHMACMD5
  ```
* **Salida esperada:**
  Detalle de cada uno de los 3 casos de prueba con sus digests calculados y el estado `CORRECTO [PASS]`.

---

## 💡 Dudas Frecuentes y Aspectos Técnicos

### 1. ¿Qué son exactamente los archivos `.class`?
* En Java, el archivo `.java` es el **código fuente** en texto plano legible para los humanos.
* Al ejecutar `javac Archivo.java`, el compilador no genera código máquina directo para el procesador (como hace C o C++ en un `.exe`), sino un archivo intermedio binario llamado **Bytecode**. Ese archivo tiene la extensión `.class`.
* La **Máquina Virtual de Java (JVM)** (`java.exe`) lee el `.class` y lo ejecuta mediante compilación JIT (Just-In-Time) optimizada para el sistema operativo donde se ejecute.

### 2. ¿Son necesarios los archivos `.class`? ¿Se pueden borrar?
* **Para ejecutar el programa:** La JVM necesita el `.class` (o cargarlo en memoria). Sin él, el comando `java NombreClase` daría error de clase no encontrada.
* **Para el repositorio / control de versiones:** **NO son necesarios y NO deben guardarse.**
  * Son **artefactos de compilación temporales (build artifacts)**.
  * Si los borras todos, no se pierde absolutamente nada de tu trabajo: basta con volver a ejecutar `javac Archivo.java` y se regeneran en fracciones de segundo.
  * En proyectos profesionales, los archivos `.class` siempre se ignoran mediante `.gitignore` y se ocultan en el editor para evitar ensuciar el explorador de archivos con duplicados binarios.

### 3. ¿Cómo se configuró para que no se vean en el editor?
Se añadió una regla en el archivo general de configuración del espacio de trabajo ([.vscode/settings.json](file:///c:/Users/Aleks/Carrera/TIC/Material/.vscode/settings.json)):

```json
{
  "files.exclude": {
    "**/*.class": true
  }
}
```

* **Efecto:** Oculta automáticamente cualquier archivo `.class` del árbol de carpetas, de la búsqueda de archivos y de la interfaz visual del editor.
* **Ventaja:** No los borra del disco duro (por lo que tus programas compilados siguen listos para ejecutarse con `java`), pero mantiene tu entorno limpio y enfocado exclusivamente en el código fuente editable (`.java`, `.c`, `.md`).
