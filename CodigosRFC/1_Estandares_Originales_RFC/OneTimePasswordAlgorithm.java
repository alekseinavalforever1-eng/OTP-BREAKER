/*
 * OneTimePasswordAlgorithm.java
 * OATH Initiative,
 * HOTP one-time password algorithm (RFC 4226)
 *
 * [ES] OneTimePasswordAlgorithm.java
 * Iniciativa OATH,
 * Algoritmo de contraseña de un solo uso HOTP (RFC 4226)
 */

/* Copyright (C) 2004, OATH.  All rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "OATH HOTP Algorithm" in all material
 * mentioning or referencing this software or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as
 *  "derived from OATH HOTP algorithm"
 * in all material mentioning or referencing the derived work.
 *
 * OATH (Open AuTHentication) and its members make no
 * representations concerning either the merchantability of this
 * software or the suitability of this software for any particular
 * purpose.
 *
 * It is provided "as is" without express or implied warranty
 * of any kind and OATH AND ITS MEMBERS EXPRESSaLY DISCLAIMS
 * ANY WARRANTY OR LIABILITY OF ANY KIND relating to this software.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 *
 * [ES] Copyright (C) 2004, OATH. Todos los derechos reservados.
 *
 * Se concede licencia para copiar y utilizar este software siempre que se
 * identifique como el "Algoritmo OATH HOTP" en todo el material que
 * mencione o haga referencia a este software o a esta función.
 *
 * También se concede licencia para realizar y utilizar obras derivadas siempre
 * que dichas obras se identifiquen como "derivadas del algoritmo OATH HOTP"
 * en todo el material que mencione o haga referencia a la obra derivada.
 *
 * Este software se proporciona "tal cual" sin garantía expresa o implícita.
 */

// package org.openauthentication.otp;

import java.io.IOException;
import java.io.File;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.charset.StandardCharsets;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class contains static methods that are used to calculate the
 * One-Time Password (OTP) using
 * JCE to provide the HMAC-SHA-1.
 *
 * [ES] Esta clase contiene métodos estáticos utilizados para calcular la
 * Contraseña de Un Solo Uso (OTP) utilizando la
 * JCE (Java Cryptography Extension) para proporcionar HMAC-SHA-1.
 *
 * @author Loren Hart
 * @version 1.0
 */
public class OneTimePasswordAlgorithm {
    private OneTimePasswordAlgorithm() {}

    // These are used to calculate the check-sum digits.
    // [ES] Se utilizan para calcular los dígitos de la suma de comprobación (checksum de Luhn).
    //                                0  1  2  3  4  5  6  7  8  9
    private static final int[] doubleDigits =
                    { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };

    /**
     * Calculates the checksum using the credit card algorithm.
     * This algorithm has the advantage that it detects any single
     * mistyped digit and any single transposition of
     * adjacent digits.
     *
     * [ES] Calcula la suma de comprobación (checksum) utilizando el algoritmo de tarjetas de crédito (Luhn).
     * Este algoritmo tiene la ventaja de que detecta cualquier dígito mal escrito de forma individual
     * y cualquier transposición de dígitos adyacentes.
     *
     * @param num the number to calculate the checksum for
     *            [ES] el número para el cual calcular la suma de comprobación
     * @param digits number of significant places in the number
     *               [ES] número de posiciones significativas en el número
     *
     * @return the checksum of num
     *         [ES] el dígito de suma de comprobación de num
     */
    public static int calcChecksum(long num, int digits) {
        boolean doubleDigit = true;
        int     total = 0;
        while (0 < digits--) {
            int digit = (int) (num % 10);
            num /= 10;
            if (doubleDigit) {
                digit = doubleDigits[digit];
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        int result = total % 10;
        if (result > 0) {
            result = 10 - result;
        }
        return result;
    }

    /**
     * This method uses the JCE to provide the HMAC-SHA-1 algorithm.
     * HMAC computes a Hashed Message Authentication Code and
     * in this case SHA1 is the hash algorithm used.
     *
     * [ES] Este método utiliza JCE para proporcionar el algoritmo HMAC-SHA-1.
     * HMAC calcula un Código de Autenticación de Mensajes basado en Hash y
     * en este caso SHA1 es el algoritmo hash utilizado.
     *
     * @param keyBytes   the bytes to use for the HMAC-SHA-1 key
     *                   [ES] los bytes a usar como clave para HMAC-SHA-1
     * @param text       the message or text to be authenticated.
     *                   [ES] el mensaje o texto a autenticar.
     *
     * @throws NoSuchAlgorithmException if no provider makes
     *       either HmacSHA1 or HMAC-SHA-1
     *       digest algorithms available.
     *       [ES] si ningún proveedor tiene disponible HmacSHA1 o HMAC-SHA-1.
     * @throws InvalidKeyException
     *       The secret provided was not a valid HMAC-SHA-1 key.
     *       [ES] el secreto proporcionado no es una clave HMAC-SHA-1 válida.
     */
    public static byte[] hmac_sha1(byte[] keyBytes, byte[] text)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        Mac hmacSha1;
        try {
            hmacSha1 = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException nsae) {
            hmacSha1 = Mac.getInstance("HMAC-SHA-1");
        }
        SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
        hmacSha1.init(macKey);
        return hmacSha1.doFinal(text);
    }

    private static final int[] DIGITS_POWER
    // 0 1  2   3    4     5      6       7        8
    = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    /**
     * This method generates an OTP value for the given set of parameters.
     *
     * [ES] Este método genera un valor OTP (según RFC 4226) para el conjunto
     * de parámetros especificado.
     *
     * @param secret       the shared secret
     *                     [ES] el secreto compartido
     * @param movingFactor the counter, time, or other value that
     *                     changes on a per use basis.
     *                     [ES] el contador, tiempo u otro valor que cambia con cada uso.
     * @param codeDigits   the number of digits in the OTP, not
     *                     including the checksum, if any.
     *                     [ES] la cantidad de dígitos del OTP (sin incluir el checksum).
     * @param addChecksum  a flag that indicates if a checksum digit
     *                     should be appended to the OTP.
     *                     [ES] indicador de si se debe anexar el dígito de suma de verificación.
     * @param truncationOffset the offset into the MAC result to
     *                     begin truncation.  If this value is out of
     *                     the range of 0 ... 15, then dynamic
     *                     truncation will be used.
     *                     Dynamic truncation is when the last 4
     *                     bits of the last byte of the MAC are
     *                     used to determine the start offset.
     *                     [ES] el desplazamiento (offset) en el resultado MAC para iniciar
     *                     el truncamiento. Si está fuera de 0...15, se usa truncamiento dinámico
     *                     (usando los últimos 4 bits del último byte del hash).
     * @throws NoSuchAlgorithmException if no provider makes
     *                     either HmacSHA1 or HMAC-SHA-1
     *                     digest algorithms available.
     *                     [ES] si el algoritmo hash no está disponible.
     * @throws InvalidKeyException
     *                     The secret provided was not
     *                     a valid HMAC-SHA-1 key.
     *                     [ES] si la clave no es válida.
     *
     * @return A numeric String in base 10 that includes
     * {@link codeDigits} digits plus the optional checksum
     * digit if requested.
     * [ES] Una cadena numérica en base 10 con los dígitos solicitados más el checksum opcional.
     */
    static public String generateOTP(byte[] secret,
               long movingFactor,
               int codeDigits,
               boolean addChecksum,
               int truncationOffset)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        // put movingFactor value into text byte array
        // [ES] Colocar el valor de movingFactor en el arreglo de bytes text (8 bytes, big-endian)
        String result = null;
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }

        // compute hmac hash
        // [ES] Calcular el hash HMAC-SHA1
        byte[] hash = hmac_sha1(secret, text);

        // put selected bytes into result int
        // [ES] Colocar los bytes seleccionados en el resultado int (truncamiento dinámico o fijo)
        int offset = hash[hash.length - 1] & 0xf;
        if ((0 <= truncationOffset) && (truncationOffset < (hash.length - 4))) {
            offset = truncationOffset;
        }
        int binary =
            ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];
        if (addChecksum) {
            otp = (otp * 10) + calcChecksum(otp, codeDigits);
        }
        result = Integer.toString(otp);
        while (result.length() < digits) {
            result = "0" + result;
        }
        return result;
    }

    /**
     * Main method to execute and test the HOTP algorithm with official RFC 4226 test vectors.
     * [ES] Método main para ejecutar y probar el algoritmo HOTP con los vectores oficiales de la RFC 4226.
     */
    public static void main(String[] args) {
        try {
            // Shared secret key from RFC 4226 (20 bytes ASCII: "12345678901234567890")
            // [ES] Clave secreta compartida de la RFC 4226 (20 bytes ASCII: "12345678901234567890")
            byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

            System.out.println("+-------+---------------+-------------------+");
            System.out.println("| Count | HOTP (6 dig)  | HOTP (Checksum)   |");
            System.out.println("+-------+---------------+-------------------+");

            for (int count = 0; count < 10; count++) {
                String otp = generateOTP(secret, count, 6, false, -1);
                String otpWithChecksum = generateOTP(secret, count, 6, true, -1);

                System.out.printf("|   %d   |    %s     |      %s      |%n", count, otp, otpWithChecksum);
            }
            System.out.println("+-------+---------------+-------------------+");
        } catch (Exception e) {
            System.out.println("Error : " + e);
        }
    }
}
