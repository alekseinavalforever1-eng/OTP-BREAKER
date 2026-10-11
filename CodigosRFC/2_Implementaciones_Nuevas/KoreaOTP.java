import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implementación de los Algoritmos de Extracción del Estándar Coreano TTA (TTAK.KO-12.0193)
 * y comparación con RFC 4226 (HOTP) / RFC 6238 (TOTP).
 * 
 * Basado en el paper:
 * "Analysis of Vulnerabilities That Can Occur When Generating One-Time Password"
 * (Kim, Han, Park, Yi - Applied Sciences 2020)
 */
public class KoreaOTP {

    private static final String HMAC_ALGO = "HmacSHA1";

    /**
     * Genera un bloque pseudoaleatorio de 20 bytes (160 bits) mediante HMAC-SHA1.
     */
    public static byte[] generateBlock(byte[] key, long counter) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.putLong(counter);
            return mac.doFinal(buffer.array());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Error en HMAC: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // FASE 2: ALGORITMOS DE EXTRACCIÓN
    // =========================================================================

    /**
     * 1. Extracción Estática (Static Extraction):
     * Toma siempre 3 bytes en posiciones fijas (ej. bytes 0, 1 y 2).
     */
    public static byte[] extractStatic(byte[] block) {
        return new byte[] { block[0], block[1], block[2] };
    }

    /**
     * 2. Extracción Dinámica Estándar / Control (Dynamic Extraction):
     * Especificado en el estándar coreano TTAK.KO-12.0193 y conceptualmente análogo a RFC 4226.
     * Offset = block[19] & 0x0F (entero entre 0 y 15).
     * Extrae 3 bytes continuos: block[offset], block[offset+1], block[offset+2].
     */
    public static byte[] extractDynamicControl(byte[] block) {
        int offset = block[19] & 0x0F;
        return new byte[] { block[offset], block[offset + 1], block[offset + 2] };
    }

    /**
     * 3. Extracción Dinámica "Mejorada" VULNERABLE (Improved Dynamic Extraction):
     * Especificada en TTAK.KO-12.0193 para tarjetas inteligentes y USIM.
     * 
     * Offset 1 = block[19] & 0x0F      -> b1 = block[Offset 1]
     * Offset 2 = b1 & 0x0F             -> b2 = block[Offset 2]
     * Offset 3 = b2 & 0x0F             -> b3 = block[Offset 3]
     * Retorna: b1 || b2 || b3
     * 
     * VULNERABILIDAD CRÍTICA:
     * Si (b1 & 0x0F) == Offset 1, entonces Offset 2 = Offset 1 y Offset 3 = Offset 1.
     * En ese caso: b1 == b2 == b3.
     * Ocurre con probabilidad de 1/16 (6.25%). Reduce el espacio de búsqueda a sólo 256 valores.
     */
    public static byte[] extractImprovedVulnerable(byte[] block) {
        int offset1 = block[19] & 0x0F;
        byte b1 = block[offset1];

        int offset2 = b1 & 0x0F;
        byte b2 = block[offset2];

        int offset3 = b2 & 0x0F;
        byte b3 = block[offset3];

        return new byte[] { b1, b2, b3 };
    }

    /**
     * 4. Truncamiento Dinámico Estándar RFC 4226 / Google Authenticator:
     * Offset = block[19] & 0x0F.
     * Extrae 4 bytes contiguos y elimina el bit de signo.
     */
    public static int extractGoogleRFC4226(byte[] block) {
        int offset = block[19] & 0x0F;
        return ((block[offset] & 0x7F) << 24)
                | ((block[offset + 1] & 0xFF) << 16)
                | ((block[offset + 2] & 0xFF) << 8)
                | (block[offset + 3] & 0xFF);
    }

    // =========================================================================
    // FASE 3 Y 4: CONVERSIÓN A ENTERO Y TRUNCAMIENTO A OTP DE 6 DÍGITOS
    // =========================================================================

    public static int toOtp6Digits(byte[] extracted3Bytes) {
        int val = ((extracted3Bytes[0] & 0xFF) << 16)
                | ((extracted3Bytes[1] & 0xFF) << 8)
                | (extracted3Bytes[2] & 0xFF);
        return val % 1_000_000;
    }

    // =========================================================================
    // GENERACIÓN DE ARCHIVOS BINARIOS PARA NIST STS (1.000.000 BYTES)
    // =========================================================================

    public static void generateBinaryDataset(String filename, String mode, int targetBytes, byte[] key) throws IOException {
        System.out.println("[*] Generando dataset binario: " + filename + " (" + mode + ")...");
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            int written = 0;
            long counter = 0;
            while (written < targetBytes) {
                byte[] block = generateBlock(key, counter++);
                byte[] extracted;
                if ("improved_vulnerable".equals(mode)) {
                    extracted = extractImprovedVulnerable(block);
                } else if ("dynamic_control".equals(mode)) {
                    extracted = extractDynamicControl(block);
                } else if ("static".equals(mode)) {
                    extracted = extractStatic(block);
                } else {
                    throw new IllegalArgumentException("Modo no reconocido: " + mode);
                }

                int toWrite = Math.min(extracted.length, targetBytes - written);
                fos.write(extracted, 0, toWrite);
                written += toWrite;
            }
        }
        System.out.println("    -> Completado: " + targetBytes + " bytes guardados.");
    }

    // =========================================================================
    // DEMOSTRACIÓN DEL EXPERIMENTO 2 (FRECUENCIAS DECIMALES)
    // =========================================================================

    public static void simulateExperiment2(int samples, byte[] key) {
        System.out.println("\n" + "=".repeat(70));
        System.out.println("EXPERIMENTO 2 (JAVA): SIMULACIÓN DE FRECUENCIAS EN CÓDIGOS DE 6 DÍGITOS");
        System.out.println("Muestras evaluadas: " + String.format("%,d", samples));
        System.out.println("=".repeat(70));

        Map<Integer, Integer> countVuln = new HashMap<>();
        Map<Integer, Integer> countCtrl = new HashMap<>();
        int colapsos = 0;

        for (long c = 0; c < samples; c++) {
            byte[] block = generateBlock(key, c);

            // Algoritmo vulnerable
            byte[] v = extractImprovedVulnerable(block);
            if (v[0] == v[1] && v[1] == v[2]) {
                colapsos++;
            }
            int otpVuln = toOtp6Digits(v);
            countVuln.put(otpVuln, countVuln.getOrDefault(otpVuln, 0) + 1);

            // Algoritmo control
            byte[] ctrl = extractDynamicControl(block);
            int otpCtrl = toOtp6Digits(ctrl);
            countCtrl.put(otpCtrl, countCtrl.getOrDefault(otpCtrl, 0) + 1);
        }

        double pObs = (double) colapsos / samples;
        System.out.println("\n[1] COLAPSO DE BYTES IDÉNTICOS (b1 == b2 == b3):");
        System.out.printf("    - Probabilidad Teórica:  1/16 = 6.2500%%\n");
        System.out.printf("    - Probabilidad Observada: %,d de %,d (%.4f%%)\n", colapsos, samples, pObs * 100);

        int maxVuln = countVuln.values().stream().max(Integer::compare).orElse(0);
        int maxCtrl = countCtrl.values().stream().max(Integer::compare).orElse(0);
        double mediaEsperada = (double) samples / 1_000_000.0;

        System.out.println("\n[2] COMPARACIÓN DE MÁXIMAS REPETICIONES (MAX[X]):");
        System.out.printf("    - Esperanza Uniforme E[X]: %.4f\n", mediaEsperada);
        System.out.printf("    - Algoritmo Control MAX[X]: %d veces\n", maxCtrl);
        System.out.printf("    - Algoritmo Vulnerable MAX[X]: %d veces (¡Sesgo crítico!)\n", maxVuln);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = "12345678901234567890".getBytes();
        simulateExperiment2(100_000, key);
    }
}
