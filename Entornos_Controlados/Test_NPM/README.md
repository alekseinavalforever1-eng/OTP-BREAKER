# Entorno Controlado de Laboratorio: Test_NPM (CVE-2021-23451)

**Proyecto de Trabajo de Integración Curricular (TIC) — EPN**  
**Módulo:** Entornos Controlados de Evaluación (Testbeds Locales)  
**Objetivo:** Demostración práctica y reproducible de la vulnerabilidad de aleatoriedad insegura en la librería `otp-generator` (npm) previa a la versión 3.0.0.

---

## 📌 1. Ficha Técnica de la Vulnerabilidad

* **Librería Instalada:** `otp-generator@2.0.1` (Versión oficial de npm previa al parche 3.0.0).
* **Identificador CVE:** [CVE-2021-23451 (NVD NIST)](https://nvd.nist.gov/vuln/detail/CVE-2021-23451)
* **Aviso de Seguridad de GitHub:** [GHSA-6x93-h9g3-9phr](https://github.com/advisories/GHSA-6x93-h9g3-9phr)
* **Severidad:** Crítica (npm audit reporta *1 critical severity vulnerability*).
* **Clasificación MITRE:** 
  * [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
  * [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/338.html)

---

## 🔍 2. Causa Raíz en el Código Fuente

Al inspeccionar el archivo instalado en `node_modules/otp-generator/index.js`, se observa la función de generación de números:

```javascript
// Líneas 9 a 12 de node_modules/otp-generator/index.js:
function rand (min, max) {
  const random = Math.random() // <-- ERROR: No es criptográficamente seguro
  return Math.floor(random * (max - min) + min)
}
```

* **Impacto Criptográfico:** `Math.random()` en el motor V8 de Node.js utiliza el algoritmo determinista **xorshift128+**, diseñado para velocidad de renderizado en navegadores y no para seguridad. Su estado interno es pequeño (128 bits) y carece de entropía del sistema operativo.
* **Impacto Estadístico:** La línea 39 tiene un error de límite (`rand(0, allowsChars.length - 1)`), lo que provoca un sesgo donde el último carácter permitido tiene menor probabilidad de salir.

---

## 🚀 3. ¿Cómo Ejecutar y Probar este Laboratorio?

Todos los archivos se ejecutan desde la carpeta `Entornos_Controlados\Test_NPM`:

### Modo 1: Prueba de Consola Rápida
Genera 10 códigos numéricos de 6 dígitos consecutivos en la consola:
```powershell
node test_generador.js
# O mediante npm script:
npm run test-generador
```

### Modo 2: Servidor HTTP Local en Vivo
Inicia el servidor backend vulnerable en el puerto 3000:
```powershell
node server.js
# O mediante npm script:
npm start
```
* **Rutas HTTP activas:**
  * `GET  http://localhost:3000/api/solicitar-otp` -> Emite un nuevo código OTP.
  * `POST http://localhost:3000/api/verificar-otp` -> Valida un código enviado en formato JSON (`{"otp": "123456"}`).
  * `GET  http://localhost:3000/api/info` -> Retorna los metadatos de la vulnerabilidad.

### Modo 3: Auditoría Inter-Plataforma con Python
Con el servidor Node.js corriendo en una terminal, abre otra terminal y ejecuta el auditor en Python:
```powershell
python cliente_auditor.py
```
Este script se conecta por HTTP, captura los códigos emitidos y prueba la verificación en tiempo real.
