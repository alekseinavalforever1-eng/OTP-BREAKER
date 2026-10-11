# Pruebas y Ejemplos de Verificación

Esta carpeta reúne los ejecutores de prueba utilizados para comprobar que los algoritmos funcionen de acuerdo con las especificaciones oficiales y no contengan errores de cálculo.

---

## 📋 Catálogo de Archivos y Conceptos

### 1. `TestHOTP.java` (Verificador de contraseñas por evento)
* **¿Qué hace?** Genera una tabla de 10 contraseñas consecutivas para comprobar que el generador HOTP produce exactamente las mismas combinaciones de dígitos que el estándar RFC 4226 (Apéndice D).
* **¿Cómo funciona?** Importa `org.openauthentication.otp.OneTimePasswordAlgorithm`, usa la clave de prueba `"12345678901234567890"` y calcula los códigos del contador 0 al 9 con y sin suma de comprobación Luhn.
* **Comandos de compilación y ejecución:**
  ```powershell
  # Compilar la clase del paquete org
  javac org\openauthentication\otp\OneTimePasswordAlgorithm.java

  # Compilar y ejecutar el test usando el classpath local
  javac -cp . TestHOTP.java
  java -cp . TestHOTP
  ```

### 2. `TestHMACMD5.java` (Verificador de firmas HMAC en Java)
* **¿Qué hace?** Comprueba que la firma digital de mensajes funcione correctamente utilizando los vectores oficiales de la RFC 2104 directamente sobre el proveedor criptográfico de Java (`javax.crypto.Mac`).
* **¿Cómo funciona?** Evalúa 3 casos de prueba con diferentes claves y tamaños de datos, compara los resultados calculados contra los hashes esperados e imprime el estado `CORRECTO [PASS]` o `FALLO [FAIL]`.
* **Comandos de compilación y ejecución:**
  ```powershell
  javac TestHMACMD5.java
  java TestHMACMD5
  ```

### 3. ¿Qué es la carpeta `org/`?
* **¿Qué es?** Es la estructura de carpetas estándar de paquetes en Java (`org/openauthentication/otp/`).
* **¿Para qué sirve?** Contiene el código fuente `OneTimePasswordAlgorithm.java` empaquetado bajo el espacio de nombres oficial de la iniciativa OATH para que otras aplicaciones y clases de prueba (como `TestHOTP.java`) puedan importarlo de forma limpia y desacoplada.
