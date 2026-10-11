# Estándares Originales de RFC

Esta carpeta contiene los tres códigos oficiales históricos publicados por los organismos internacionales de internet (IETF y la iniciativa OATH) como parte de sus documentos de especificación técnica (RFC).

---

## 📋 Catálogo de Archivos y Conceptos

### 1. `rfc2104.c` (Código de autenticación HMAC en C)
* **¿Qué hace?** Funciona como un sello digital de autenticidad e integridad para mensajes (HMAC-MD5).
* **¿Cómo funciona?** Toma un mensaje de texto y una clave secreta, los mezcla matemáticamente en dos fases con padding interno (`ipad = 0x36`) y externo (`opad = 0x5c`) usando MD5 (RFC 1321), y produce un resumen criptográfico de 16 bytes.
* **¿Sirve de algo correrlo?** Sí. Ejecuta una batería de 3 vectores de prueba oficiales estandarizados en la RFC 2104. Permite comprobar a nivel de bajo nivel (C) que el compilador procesa adecuadamente los desplazamientos lógicos, el padding y la independencia de plataforma (endianness).
* **Comandos de compilación y ejecución:**
  ```powershell
  # Con Clang:
  clang rfc2104.c -o rfc2104.exe
  .\rfc2104.exe

  # O con GCC:
  gcc rfc2104.c -o rfc2104.exe
  .\rfc2104.exe
  ```

### 2. `OneTimePasswordAlgorithm.java` (HOTP / RFC 4226)
* **¿Qué hace?** Genera códigos numéricos de un solo uso basados en contador de eventos.
* **¿Cómo funciona?** Firma el contador con HMAC-SHA1, extrae 4 bytes mediante truncamiento dinámico (`offset = hash[19] & 0x0f`), calcula el módulo $10^d$ para obtener 6 dígitos, y opcionalmente añade un dígito de suma de verificación mediante el algoritmo de Luhn (7 dígitos).
* **Comandos de compilación y ejecución:**
  ```powershell
  javac OneTimePasswordAlgorithm.java
  java OneTimePasswordAlgorithm
  ```

### 3. `TOTP.java` (TOTP / RFC 6238)
* **¿Qué hace?** Genera códigos temporales sincronizados que cambian cada 30 segundos.
* **¿Cómo funciona?** Divide el tiempo epoch de Unix entre la ventana de 30s ($T = (CurrentTime - T0) / X$). Firma el contador temporal $T$ con la clave secreta y deriva el código numérico. Soporta variantes con HMAC-SHA1, HMAC-SHA256 y HMAC-SHA512.
* **Comandos de compilación y ejecución:**
  ```powershell
  javac TOTP.java
  java TOTP
  ```
