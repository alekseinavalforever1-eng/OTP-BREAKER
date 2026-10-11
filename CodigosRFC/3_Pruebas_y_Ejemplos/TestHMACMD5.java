import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Ejecutor en Java para los vectores de prueba de HMAC-MD5 (RFC 2104).
 */
public class TestHMACMD5 {

    public static String hmacMD5(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacMD5");
        mac.init(secretKey);
        byte[] rawHmac = mac.doFinal(data);

        StringBuilder sb = new StringBuilder();
        for (byte b : rawHmac) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        try {
            System.out.println("==========================================================");
            System.out.println("       Vectores de Prueba HMAC-MD5 (RFC 2104) en Java     ");
            System.out.println("==========================================================");

            // Test Vector 1
            byte[] key1 = new byte[16];
            java.util.Arrays.fill(key1, (byte) 0x0b);
            byte[] data1 = "Hi There".getBytes(StandardCharsets.US_ASCII);
            String digest1 = hmacMD5(key1, data1);
            System.out.println("Test 1:");
            System.out.println("  Calculado: " + digest1);
            System.out.println("  Esperado:  9294727a3638bb1c13f48ef8158bfc9d");
            System.out.println("  Estado:    " + (digest1.equals("9294727a3638bb1c13f48ef8158bfc9d") ? "CORRECTO [PASS]" : "FALLO [FAIL]"));
            System.out.println();

            // Test Vector 2
            byte[] key2 = "Jefe".getBytes(StandardCharsets.US_ASCII);
            byte[] data2 = "what do ya want for nothing?".getBytes(StandardCharsets.US_ASCII);
            String digest2 = hmacMD5(key2, data2);
            System.out.println("Test 2:");
            System.out.println("  Calculado: " + digest2);
            System.out.println("  Esperado:  750c783e6ab0b503eaa86e310a5db738");
            System.out.println("  Estado:    " + (digest2.equals("750c783e6ab0b503eaa86e310a5db738") ? "CORRECTO [PASS]" : "FALLO [FAIL]"));
            System.out.println();

            // Test Vector 3
            byte[] key3 = new byte[16];
            java.util.Arrays.fill(key3, (byte) 0xAA);
            byte[] data3 = new byte[50];
            java.util.Arrays.fill(data3, (byte) 0xDD);
            String digest3 = hmacMD5(key3, data3);
            System.out.println("Test 3:");
            System.out.println("  Calculado: " + digest3);
            System.out.println("  Esperado:  56be34521d144c88dbb8c733f0e8b3f6");
            System.out.println("  Estado:    " + (digest3.equals("56be34521d144c88dbb8c733f0e8b3f6") ? "CORRECTO [PASS]" : "FALLO [FAIL]"));
            System.out.println("==========================================================");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
