// <CODE BEGINS>
// <INICIO DEL CÓDIGO>

/**
Copyright (c) 2011 IETF Trust and the persons identified as
authors of the code. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, is permitted pursuant to, and subject to the license
terms contained in, the Simplified BSD License set forth in Section
4.c of the IETF Trust's Legal Provisions Relating to IETF Documents
(http://trustee.ietf.org/license-info).

[ES]
Copyright (c) 2011 IETF Trust y las personas identificadas como
autoras del código. Todos los derechos reservados.

Se permite la redistribución y el uso en formas de código fuente y binario, con o sin
modificaciones, conforme y sujeto a los términos de licencia contenidos en la
Licencia BSD Simplificada establecida en la Sección 4.c de las Disposiciones Legales
del IETF Trust relativas a Documentos del IETF (http://trustee.ietf.org/license-info).
*/

import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.TimeZone;

/**
 * This is an example implementation of the OATH
 * TOTP algorithm.
 * Visit www.openauthentication.org for more information.
 *
 * [ES] Esta es una implementación de ejemplo del algoritmo
 * TOTP de OATH.
 * Visite www.openauthentication.org para más información.
 *
 * @author Johan Rydell, PortWise, Inc.
 */

public class TOTP {

    private TOTP() {
    }

    /**
     * This method uses the JCE to provide the crypto algorithm.
     * HMAC computes a Hashed Message Authentication Code with the
     * crypto hash algorithm as a parameter.
     *
     * [ES] Este método utiliza la JCE (Java Cryptography Extension) para
     * proporcionar
     * el algoritmo criptográfico. HMAC calcula un Código de Autenticación de
     * Mensajes
     * basado en Hash utilizando el algoritmo de hash criptográfico como parámetro.
     *
     * @param crypto:   the crypto algorithm (HmacSHA1, HmacSHA256,
     *                  HmacSHA512)
     *                  [ES] el algoritmo criptográfico (HmacSHA1, HmacSHA256,
     *                  HmacSHA512)
     * @param keyBytes: the bytes to use for the HMAC key
     *                  [ES] los bytes a utilizar como clave HMAC
     * @param text:     the message or text to be authenticated
     *                  [ES] el mensaje o texto que será autenticado
     */
    private static byte[] hmac_sha(String crypto, byte[] keyBytes,
            byte[] text) {
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

    /**
     * This method converts a HEX string to Byte[]
     *
     * [ES] Este método convierte una cadena de texto HEX a un arreglo Byte[]
     *
     * @param hex: the HEX string
     *             [ES] la cadena en formato HEX
     *
     * @return: a byte array
     *          [ES] un arreglo de bytes
     */

    private static byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // [ES] Se agrega un byte para asegurar una conversión correcta
        // Values starting with "0" can be converted
        // [ES] Permite convertir valores que comiencen con "0"
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        // [ES] Copia todos los bytes REALES, omitiendo el "primer" byte añadido
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    private static final int[] DIGITS_POWER
    // 0 1 2 3 4 5 6 7 8
            = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

    /**
     * This method generates a TOTP value for the given
     * set of parameters.
     *
     * [ES] Este método genera un valor TOTP (usando HmacSHA1 por defecto)
     * para el conjunto de parámetros dado.
     *
     * @param key:          the shared secret, HEX encoded
     *                      [ES] el secreto compartido, codificado en HEX
     * @param time:         a value that reflects a time
     *                      [ES] un valor que refleja el tiempo (contador T)
     * @param returnDigits: number of digits to return
     *                      [ES] número de dígitos a devolver en el código
     *
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     *          [ES] una cadena numérica en base 10 con los dígitos solicitados
     */

    public static String generateTOTP(String key,
            String time,
            String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }

    /**
     * This method generates a TOTP value for the given
     * set of parameters.
     *
     * [ES] Este método genera un valor TOTP usando HmacSHA256
     * para el conjunto de parámetros dado.
     *
     * @param key:          the shared secret, HEX encoded
     *                      [ES] el secreto compartido, codificado en HEX
     * @param time:         a value that reflects a time
     *                      [ES] un valor que refleja el tiempo (contador T)
     * @param returnDigits: number of digits to return
     *                      [ES] número de dígitos a devolver en el código
     *
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     *          [ES] una cadena numérica en base 10 con los dígitos solicitados
     */

    public static String generateTOTP256(String key,
            String time,
            String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }

    /**
     * This method generates a TOTP value for the given
     * set of parameters.
     *
     * [ES] Este método genera un valor TOTP usando HmacSHA512
     * para el conjunto de parámetros dado.
     *
     * @param key:          the shared secret, HEX encoded
     *                      [ES] el secreto compartido, codificado en HEX
     * @param time:         a value that reflects a time
     *                      [ES] un valor que refleja el tiempo (contador T)
     * @param returnDigits: number of digits to return
     *                      [ES] número de dígitos a devolver en el código
     *
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     *          [ES] una cadena numérica en base 10 con los dígitos solicitados
     */

    public static String generateTOTP512(String key,
            String time,
            String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA512");
    }

    /**
     * This method generates a TOTP value for the given
     * set of parameters.
     *
     * [ES] Este método genera un valor TOTP para el conjunto de parámetros
     * y función hash criptográfica especificada.
     *
     * @param key:          the shared secret, HEX encoded
     *                      [ES] el secreto compartido, codificado en HEX
     * @param time:         a value that reflects a time
     *                      [ES] un valor que refleja el tiempo (contador T)
     * @param returnDigits: number of digits to return
     *                      [ES] número de dígitos a devolver en el código
     * @param crypto:       the crypto function to use
     *                      [ES] la función criptográfica a utilizar (HmacSHA1,
     *                      HmacSHA256, HmacSHA512)
     *
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     *          [ES] una cadena numérica en base 10 con los dígitos solicitados
     */

    public static String generateTOTP(String key,
            String time,
            String returnDigits,
            String crypto) {
        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;

        // Using the counter
        // [ES] Usando el contador de tiempo
        // First 8 bytes are for the movingFactor
        // [ES] Los primeros 8 bytes corresponden al factor de movimiento (movingFactor
        // / T)
        // Compliant with base RFC 4226 (HOTP)
        // [ES] Compatible con el algoritmo base RFC 4226 (HOTP)
        while (time.length() < 16)
            time = "0" + time;

        // Get the HEX in a Byte[]
        // [ES] Convertir el mensaje HEX en un arreglo Byte[]
        byte[] msg = hexStr2Bytes(time);
        byte[] k = hexStr2Bytes(key);
        byte[] hash = hmac_sha(crypto, k, msg);

        // put selected bytes into result int
        // [ES] Colocar los bytes seleccionados en el int resultado (truncamiento
        // dinámico)
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = Integer.toString(otp);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }

    public static void main(String[] args) {
        // Seed for HMAC-SHA1 - 20 bytes
        // [ES] Semilla para HMAC-SHA1 - 20 bytes
        String seed = "3132333435363738393031323334353637383930";
        // Seed for HMAC-SHA256 - 32 bytes
        // [ES] Semilla para HMAC-SHA256 - 32 bytes
        String seed32 = "3132333435363738393031323334353637383930" +
                "313233343536373839303132";
        // Seed for HMAC-SHA512 - 64 bytes
        // [ES] Semilla para HMAC-SHA512 - 64 bytes
        String seed64 = "3132333435363738393031323334353637383930" +
                "3132333435363738393031323334353637383930" +
                "3132333435363738393031323334353637383930" +
                "31323334";
        long T0 = 0;
        long X = 30;
        long testTime[] = { 59L, 1111111109L, 1111111111L,
                1234567890L, 2000000000L, 20000000000L };

        String steps = "0";
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            System.out.println(
                    "+---------------+-----------------------+" +
                            "------------------+--------+--------+");
            System.out.println(
                    "|  Time(sec)    |   Time (UTC format)   " +
                            "| Value of T(Hex)  |  TOTP  | Mode   |");
            System.out.println(
                    "+---------------+-----------------------+" +
                            "------------------+--------+--------+");

            for (int i = 0; i < testTime.length; i++) {
                long T = (testTime[i] - T0) / X;
                steps = Long.toHexString(T).toUpperCase();
                while (steps.length() < 16)
                    steps = "0" + steps;
                String fmtTime = String.format("%1$-11s", testTime[i]);
                String utcTime = df.format(new Date(testTime[i] * 1000));
                System.out.print("|  " + fmtTime + "  |  " + utcTime +
                        "  | " + steps + " |");
                System.out.println(generateTOTP(seed, steps, "8",
                        "HmacSHA1") + "| SHA1   |");
                System.out.print("|  " + fmtTime + "  |  " + utcTime +
                        "  | " + steps + " |");
                System.out.println(generateTOTP(seed32, steps, "8",
                        "HmacSHA256") + "| SHA256 |");
                System.out.print("|  " + fmtTime + "  |  " + utcTime +
                        "  | " + steps + " |");
                System.out.println(generateTOTP(seed64, steps, "8",
                        "HmacSHA512") + "| SHA512 |");

                System.out.println(
                        "+---------------+-----------------------+" +
                                "------------------+--------+--------+");
            }
        } catch (final Exception e) {
            System.out.println("Error : " + e);
        }
    }
}

// <CODE ENDS>
// <FIN DEL CÓDIGO>