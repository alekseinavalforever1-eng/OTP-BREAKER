import java.nio.charset.StandardCharsets;
import org.openauthentication.otp.OneTimePasswordAlgorithm;

/**
 * Clase ejecutora para probar el algoritmo HOTP (RFC 4226)
 * con los vectores de prueba oficiales.
 */
public class TestHOTP {
    public static void main(String[] args) {
        try {
            // Clave secreta compartida estándar de la RFC 4226 (20 bytes: "12345678901234567890")
            byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

            System.out.println("+-------+---------------+-------------------+");
            System.out.println("| Count | HOTP (6 dig)  | HOTP (Checksum)   |");
            System.out.println("+-------+---------------+-------------------+");

            for (int count = 0; count < 10; count++) {
                // Generar OTP de 6 dígitos sin checksum y con truncamiento dinámico (-1)
                String otp = OneTimePasswordAlgorithm.generateOTP(secret, count, 6, false, -1);
                // Generar OTP de 6 dígitos con checksum de Luhn (resulta en 7 dígitos)
                String otpWithChecksum = OneTimePasswordAlgorithm.generateOTP(secret, count, 6, true, -1);

                System.out.printf("|   %d   |    %s     |      %s      |%n", count, otp, otpWithChecksum);
            }
            System.out.println("+-------+---------------+-------------------+");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
