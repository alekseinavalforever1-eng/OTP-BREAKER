/**
 * test_generador.js
 * =================
 * Demostración del generador de OTP vulnerable (otp-generator@2.0.1).
 * Genera contraseñas numéricas de 6 dígitos para observar la secuencia.
 */

const otpGenerator = require('otp-generator');

console.log('===============================================================');
console.log('LABORATORIO LOCAL: PRUEBA DE GENERACIÓN OTP-GENERATOR (v2.0.1)');
console.log('Vulnerabilidad: CVE-2021-23451 / Insecure Randomness (Math.random)');
console.log('===============================================================\n');

console.log('[*] Generando 10 contraseñas OTP consecutivas (6 dígitos numéricos):\n');

for (let i = 1; i <= 10; i++) {
  // Configuración para OTP bancario/2FA: solo dígitos, 6 caracteres
  const otp = otpGenerator.generate(6, {
    digits: true,
    alphabets: false,
    upperCase: false,
    specialChars: false
  });
  console.log(`  Intento ${String(i).padStart(2, '0')}: OTP = ${otp}`);
}

console.log('\n[!] Alerta de Seguridad (npm audit):');
console.log('    La función interna rand() utiliza Math.random() de V8 (xorshift128+).');
console.log('    El flujo de bits carece de entropía criptográfica (CWE-330 / CWE-338).');
console.log('===============================================================');
