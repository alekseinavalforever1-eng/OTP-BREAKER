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
  * Implementación TOTP que utiliza la clave secreta extraída de Google Authenticator
  * para generar códigos OTP compatibles con la app.
  *
  * La clave fue extraída del protobuf de exportación de Google Authenticator
  * (otpauth-migration) codificado en Base64.
  *
  * Parámetros de Google Authenticator:
  *   - Algoritmo: HMAC-SHA1
  *   - Dígitos: 6
  *   - Período: 30 segundos
  *   - Cuenta: alekseinavalforever@gmail.com
  *   - Issuer: Google
  *
  * [EN] TOTP implementation using the secret key extracted from Google Authenticator
  * to generate OTP codes compatible with the app.
  *
  * @author Basado en la implementación RFC 6238 de Johan Rydell, PortWise, Inc.
  */

 public class TOTPGoogleAuth {

     private TOTPGoogleAuth() {}

     /**
      * This method uses the JCE to provide the crypto algorithm.
      * HMAC computes a Hashed Message Authentication Code with the
      * crypto hash algorithm as a parameter.
      *
      * [ES] Este método utiliza la JCE (Java Cryptography Extension) para proporcionar
      * el algoritmo criptográfico. HMAC calcula un Código de Autenticación de Mensajes
      * basado en Hash utilizando el algoritmo de hash criptográfico como parámetro.
      *
      * @param crypto: the crypto algorithm (HmacSHA1, HmacSHA256,
      *                             HmacSHA512)
      *                [ES] el algoritmo criptográfico (HmacSHA1, HmacSHA256, HmacSHA512)
      * @param keyBytes: the bytes to use for the HMAC key
      *                [ES] los bytes a utilizar como clave HMAC
      * @param text: the message or text to be authenticated
      *                [ES] el mensaje o texto que será autenticado
      */
      private static byte[] hmac_sha(String crypto, byte[] keyBytes,
             byte[] text){
         try {
             Mac hmac;
             hmac = Mac.getInstance(crypto);
             SecretKeySpec macKey =
                 new SecretKeySpec(keyBytes, "RAW");
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

     private static byte[] hexStr2Bytes(String hex){
         // Adding one byte to get the right conversion
         // [ES] Se agrega un byte para asegurar una conversión correcta
         // Values starting with "0" can be converted
         // [ES] Permite convertir valores que comiencen con "0"
         byte[] bArray = new BigInteger("10" + hex,16).toByteArray();

         // Copy all the REAL bytes, not the "first"
         // [ES] Copia todos los bytes REALES, omitiendo el "primer" byte añadido
         byte[] ret = new byte[bArray.length - 1];
         for (int i = 0; i < ret.length; i++)
             ret[i] = bArray[i+1];
         return ret;
     }

     private static final int[] DIGITS_POWER
     // 0 1  2   3    4     5      6       7        8
     = {1,10,100,1000,10000,100000,1000000,10000000,100000000 };

     /**
      * This method generates a TOTP value for the given
      * set of parameters.
      *
      * [ES] Este método genera un valor TOTP (usando HmacSHA1 por defecto)
      * para el conjunto de parámetros dado.
      *
      * @param key: the shared secret, HEX encoded
      *             [ES] el secreto compartido, codificado en HEX
      * @param time: a value that reflects a time
      *              [ES] un valor que refleja el tiempo (contador T)
      * @param returnDigits: number of digits to return
      *                      [ES] número de dígitos a devolver en el código
      *
      * @return: a numeric String in base 10 that includes
      *              {@link truncationDigits} digits
      *          [ES] una cadena numérica en base 10 con los dígitos solicitados
      */

     public static String generateTOTP(String key,
             String time,
             String returnDigits){
         return generateTOTP(key, time, returnDigits, "HmacSHA1");
     }


     /**
      * This method generates a TOTP value for the given
      * set of parameters.
      *
      * [ES] Este método genera un valor TOTP usando HmacSHA256
      * para el conjunto de parámetros dado.
      *
      * @param key: the shared secret, HEX encoded
      *             [ES] el secreto compartido, codificado en HEX
      * @param time: a value that reflects a time
      *              [ES] un valor que refleja el tiempo (contador T)
      * @param returnDigits: number of digits to return
      *                      [ES] número de dígitos a devolver en el código
      *
      * @return: a numeric String in base 10 that includes
      *              {@link truncationDigits} digits
      *          [ES] una cadena numérica en base 10 con los dígitos solicitados
      */

     public static String generateTOTP256(String key,
             String time,
             String returnDigits){
         return generateTOTP(key, time, returnDigits, "HmacSHA256");
     }




     /**
      * This method generates a TOTP value for the given
      * set of parameters.
      *
      * [ES] Este método genera un valor TOTP usando HmacSHA512
      * para el conjunto de parámetros dado.
      *
      * @param key: the shared secret, HEX encoded
      *             [ES] el secreto compartido, codificado en HEX
      * @param time: a value that reflects a time
      *              [ES] un valor que refleja el tiempo (contador T)
      * @param returnDigits: number of digits to return
      *                      [ES] número de dígitos a devolver en el código
      *
      * @return: a numeric String in base 10 that includes
      *              {@link truncationDigits} digits
      *          [ES] una cadena numérica en base 10 con los dígitos solicitados
      */

     public static String generateTOTP512(String key,
             String time,
             String returnDigits){
         return generateTOTP(key, time, returnDigits, "HmacSHA512");
     }


     /**
      * This method generates a TOTP value for the given
      * set of parameters.
      *
      * [ES] Este método genera un valor TOTP para el conjunto de parámetros
      * y función hash criptográfica especificada.
      *
      * @param key: the shared secret, HEX encoded
      *             [ES] el secreto compartido, codificado en HEX
      * @param time: a value that reflects a time
      *              [ES] un valor que refleja el tiempo (contador T)
      * @param returnDigits: number of digits to return
      *                      [ES] número de dígitos a devolver en el código
      * @param crypto: the crypto function to use
      *                [ES] la función criptográfica a utilizar (HmacSHA1, HmacSHA256, HmacSHA512)
      *
      * @return: a numeric String in base 10 that includes
      *              {@link truncationDigits} digits
      *          [ES] una cadena numérica en base 10 con los dígitos solicitados
      */

     public static String generateTOTP(String key,
             String time,
             String returnDigits,
             String crypto){
         int codeDigits = Integer.decode(returnDigits).intValue();
         String result = null;

         // Using the counter
         // [ES] Usando el contador de tiempo
         // First 8 bytes are for the movingFactor
         // [ES] Los primeros 8 bytes corresponden al factor de movimiento (movingFactor / T)
         // Compliant with base RFC 4226 (HOTP)
         // [ES] Compatible con el algoritmo base RFC 4226 (HOTP)
         while (time.length() < 16 )
             time = "0" + time;

         // Get the HEX in a Byte[]
         // [ES] Convertir el mensaje HEX en un arreglo Byte[]
         byte[] msg = hexStr2Bytes(time);
         byte[] k = hexStr2Bytes(key);
         byte[] hash = hmac_sha(crypto, k, msg);

         // put selected bytes into result int
         // [ES] Colocar los bytes seleccionados en el int resultado (truncamiento dinámico)
         int offset = hash[hash.length - 1] & 0xf;

         int binary =
             ((hash[offset] & 0x7f) << 24) |
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

         // ================================================================
         // CLAVE SECRETA EXTRAÍDA DE GOOGLE AUTHENTICATOR
         // [EN] SECRET KEY EXTRACTED FROM GOOGLE AUTHENTICATOR
         // ================================================================
         // Cadena Base64 original (protobuf de exportación):
         // ClgKFPZ1Itjt04zQZlF5JYKV2wZvZRq0Eh1hbGVrc2VpbmF2YWxmb3JldmVyQGdtYWlsLmNvbRoGR29vZ2xlIAEoATACQhMzNjAwNzYxNzcyODI3MjA1NDk3EAIYASAA
         //
         // Datos extraídos del protobuf:
         //   Cuenta:    alekseinavalforever@gmail.com
         //   Issuer:    Google
         //   Algoritmo: SHA1 (HmacSHA1)
         //   Dígitos:   6
         //   Período:   30 segundos
         //   Secret (Base32): 6Z2SFWHN2OGNAZSRPESYFFO3AZXWKGVU
         //   Secret (HEX):    f67522d8edd38cd0665179258295db066f651ab4
         // ================================================================

         // Clave secreta en formato HEX (20 bytes = 160 bits para HMAC-SHA1)
         // [EN] Secret key in HEX format (20 bytes = 160 bits for HMAC-SHA1)
         String secretHex = "f67522d8edd38cd0665179258295db066f651ab4";

         // Parámetros TOTP de Google Authenticator
         // [EN] Google Authenticator TOTP parameters
         long T0 = 0;   // Unix epoch como inicio / Unix epoch as start
         long X  = 30;  // Período de 30 segundos / 30-second period

         // Obtener el tiempo actual en segundos Unix
         // [EN] Get current time in Unix seconds
         long currentTimeSeconds = System.currentTimeMillis() / 1000L;

         // Calcular el contador T = (tiempo_actual - T0) / X
         // [EN] Calculate the counter T = (current_time - T0) / X
         long T = (currentTimeSeconds - T0) / X;

         // Convertir T a hexadecimal
         // [EN] Convert T to hexadecimal
         String steps = Long.toHexString(T).toUpperCase();
         while (steps.length() < 16) steps = "0" + steps;

         // Calcular el tiempo restante antes de que el código cambie
         // [EN] Calculate remaining time before the code changes
         long secondsRemaining = X - (currentTimeSeconds % X);

         DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
         df.setTimeZone(TimeZone.getTimeZone("UTC"));
         String utcTime = df.format(new Date(currentTimeSeconds * 1000));

         DateFormat dfLocal = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
         String localTime = dfLocal.format(new Date(currentTimeSeconds * 1000));

         try {
             System.out.println("╔══════════════════════════════════════════════════════╗");
             System.out.println("║     TOTP - Google Authenticator Verification         ║");
             System.out.println("║     Verificación TOTP con Google Authenticator        ║");
             System.out.println("╠══════════════════════════════════════════════════════╣");
             System.out.println("║                                                      ║");
             System.out.println("║  Cuenta / Account:                                   ║");
             System.out.println("║    alekseinavalforever@gmail.com                     ║");
             System.out.println("║                                                      ║");
             System.out.println("║  Issuer: Google                                      ║");
             System.out.println("║                                                      ║");
             System.out.println("║  Secret (Base32): 6Z2SFWHN2OGNAZSRPESYFFO3AZXWKGVU   ║");
             System.out.println("║  Secret (HEX):    f67522d8edd38cd066517925...         ║");
             System.out.println("║                                                      ║");
             System.out.println("║  Algoritmo / Algorithm: HMAC-SHA1                    ║");
             System.out.println("║  Dígitos / Digits:      6                            ║");
             System.out.println("║  Período / Period:      30 segundos / seconds        ║");
             System.out.println("║                                                      ║");
             System.out.println("╠══════════════════════════════════════════════════════╣");
             System.out.println("║  TIEMPO / TIME                                       ║");
             System.out.println("╠══════════════════════════════════════════════════════╣");
             System.out.println("║                                                      ║");
             System.out.println("║  Epoch (seg/sec):  " + String.format("%-35s", currentTimeSeconds) + "║");
             System.out.println("║  UTC:              " + String.format("%-35s", utcTime) + "║");
             System.out.println("║  Local:            " + String.format("%-35s", localTime) + "║");
             System.out.println("║  T (contador/ctr): " + String.format("%-35s", T) + "║");
             System.out.println("║  T (hex):          " + String.format("%-35s", steps) + "║");
             System.out.println("║                                                      ║");
             System.out.println("╠══════════════════════════════════════════════════════╣");
             System.out.println("║  CÓDIGO OTP GENERADO / GENERATED OTP CODE            ║");
             System.out.println("╠══════════════════════════════════════════════════════╣");
             System.out.println("║                                                      ║");

             // Generar el TOTP con HmacSHA1, 6 dígitos (igual que Google Authenticator)
             // [EN] Generate TOTP with HmacSHA1, 6 digits (same as Google Authenticator)
             String totpCode = generateTOTP(secretHex, steps, "6", "HmacSHA1");

             System.out.println("║         ┌─────────────────┐                         ║");
             System.out.println("║         │   TOTP:  " + totpCode + "   │                         ║");
             System.out.println("║         └─────────────────┘                         ║");
             System.out.println("║                                                      ║");
             System.out.println("║  Válido por / Valid for: " + String.format("%-2d", secondsRemaining) + " segundos / seconds       ║");
             System.out.println("║                                                      ║");
             System.out.println("║  [ES] Compare este código con el que muestra          ║");
             System.out.println("║       Google Authenticator en su dispositivo.         ║");
             System.out.println("║  [EN] Compare this code with the one shown in         ║");
             System.out.println("║       Google Authenticator on your device.            ║");
             System.out.println("║                                                      ║");
             System.out.println("╚══════════════════════════════════════════════════════╝");

         } catch (final Exception e){
             System.out.println("Error : " + e);
         }
     }
 }

// <CODE ENDS>
// <FIN DEL CÓDIGO>
