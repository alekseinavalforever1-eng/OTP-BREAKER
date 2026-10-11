/**
 * server.js
 * =========
 * Servidor HTTP local de autenticación vulnerable para laboratorio (Testbed).
 * Utiliza otp-generator@2.0.1 para emitir contraseñas de un solo uso.
 *
 * Endpoints:
 * - GET  /api/solicitar-otp  -> Emite un código OTP de 6 dígitos numéricos.
 * - POST /api/verificar-otp  -> Valida el código enviado en el cuerpo JSON.
 * - GET  /api/info           -> Metadatos de la librería y CVE asociado.
 */

const http = require('http');
const otpGenerator = require('otp-generator');

const PORT = 3000;
let ultimoOtpGenerado = null;
let timestampUltimoOtp = null;

function generarCodigoVulnerable() {
  return otpGenerator.generate(6, {
    digits: true,
    alphabets: false,
    upperCase: false,
    specialChars: false
  });
}

const server = http.createServer((req, res) => {
  // Configuración de encabezados CORS y JSON
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // 1. Endpoint: Solicitar OTP
  if (req.method === 'GET' && req.url === '/api/solicitar-otp') {
    ultimoOtpGenerado = generarCodigoVulnerable();
    timestampUltimoOtp = Math.floor(Date.now() / 1000);

    const respuesta = {
      status: 'ok',
      mensaje: 'OTP emitido por servidor vulnerable',
      otp: ultimoOtpGenerado,
      timestamp: timestampUltimoOtp,
      longitud: 6,
      motor_prng: 'Math.random() (V8 xorshift128+)'
    };

    console.log(`[+] [${new Date().toLocaleTimeString()}] OTP emitido: ${ultimoOtpGenerado}`);
    res.writeHead(200);
    res.end(JSON.stringify(respuesta, null, 2));
    return;
  }

  // 2. Endpoint: Verificar OTP
  if (req.method === 'POST' && req.url === '/api/verificar-otp') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const datos = JSON.parse(body || '{}');
        const otpEnviado = String(datos.otp || '').trim();

        if (!ultimoOtpGenerado) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'No se ha emitido ningun OTP previo' }));
          return;
        }

        const esValido = (otpEnviado === ultimoOtpGenerado);
        console.log(`[*] [${new Date().toLocaleTimeString()}] Intento de verificacion: ${otpEnviado} -> ${esValido ? 'ACCESO CONCEDIDO' : 'ACCESO DENEGADO'}`);

        res.writeHead(esValido ? 200 : 401);
        res.end(JSON.stringify({
          autenticado: esValido,
          mensaje: esValido ? 'Autenticacion exitosa' : 'Codigo OTP incorrecto'
        }));
      } catch (err) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'JSON malformado' }));
      }
    });
    return;
  }

  // 3. Endpoint: Información de Laboratorio
  if (req.method === 'GET' && req.url === '/api/info') {
    res.writeHead(200);
    res.end(JSON.stringify({
      proyecto: 'Trabajo de Integracion Curricular (TIC) - EPN',
      entorno: 'Laboratorio Local Controlado (Testbed)',
      libreria_afectada: 'otp-generator@2.0.1',
      vulnerabilidad: 'CVE-2021-23451 / GHSA-6x93-h9g3-9phr',
      clasificacion_cwe: ['CWE-330', 'CWE-338'],
      puerto: PORT
    }, null, 2));
    return;
  }

  // Ruta no encontrada
  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Ruta no encontrada' }));
});

server.listen(PORT, () => {
  console.log('===============================================================');
  console.log(`[+] SERVIDOR VULNERABLE DE LABORATORIO ACTIVO EN http://localhost:${PORT}`);
  console.log('    Rutas disponibles:');
  console.log('    - GET  http://localhost:3000/api/solicitar-otp');
  console.log('    - POST http://localhost:3000/api/verificar-otp');
  console.log('    - GET  http://localhost:3000/api/info');
  console.log('===============================================================');
});
