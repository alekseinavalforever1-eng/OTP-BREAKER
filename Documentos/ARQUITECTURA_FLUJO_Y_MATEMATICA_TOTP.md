# Arquitectura, Flujo Operativo y Fundamento Matemático de TOTP

Este documento consolida la arquitectura completa del protocolo **TOTP** (*Time-Based One-Time Password*), unificando el flujo cliente-servidor, los estándares de generación y longitud de semillas según las especificaciones del IETF y NIST, y la derivación matemática paso a paso resultante de la fusión de las **RFC 2104**, **RFC 4226** y **RFC 6238**.

---

## 1. Diagrama de Secuencia: Ciclo de Vida Completo Cliente-Servidor

El siguiente diagrama modela las tres fases fundamentales del sistema:
1. **Fase de Aprovisionamiento (Enrollment):** Generación y entrega segura de la semilla simétrica compartida.
2. **Fase de Generación Desconectada:** El usuario genera el código de 6 dígitos en su aplicación móvil sin conexión de red.
3. **Fase de Validación y Verificación:** El servidor autentica el código, previene ataques de repetición y tolera desfases de reloj.

```mermaid
sequenceDiagram
    autonumber
    actor Usuario as Usuario (Dispositivo Móvil / Google Auth)
    participant Web as Servidor Web / Aplicación
    participant Auth as Servicio de Autenticación / BDD
    participant NTP as Servidor de Tiempo (NTP)

    Note over Web,Auth: FASE 1: APROVISIONAMIENTO (ENROLLMENT)
    Usuario->>Web: 1. Solicita activar autenticación de dos factores (2FA)
    Web->>Auth: 2. Pide generar credencial TOTP
    Auth->>Auth: 3. Genera Semilla K con CSPRNG (160 bits / 20 bytes)
    Auth->>Auth: 4. Almacena K cifrada en reposo vinculada al usuario
    Auth-->>Web: 5. Retorna URI: otpauth://totp/...?secret=BASE32...
    Web->>Web: 6. Renderiza código QR con la URI
    Web-->>Usuario: 7. Muestra código QR en pantalla segura (HTTPS)
    Usuario->>Usuario: 8. Escanea el QR con la App Google Authenticator
    Usuario->>Usuario: 9. Almacena la semilla K de forma segura en el llavero local

    Note over Usuario,Web: FASE 2: GENERACIÓN DESCONECTADA (CADA 30 SEGUNDOS)
    loop Cada 30 Segundos (Totalmente Offline)
        Usuario->>Usuario: 10. Lee timestamp Unix local (segundos desde 1970)
        Usuario->>Usuario: 11. Calcula ventana de tiempo: T = piso(now / 30)
        Usuario->>Usuario: 12. Calcula hash: HS = HMAC-SHA1(K, T)
        Usuario->>Usuario: 13. Trunca dinámicamente HS a entero de 31 bits
        Usuario->>Usuario: 14. Aplica módulo 10^6 -> Obtiene código de 6 dígitos
        Usuario->>Usuario: 15. Muestra código en pantalla con barra de cuenta regresiva
    end

    Note over Usuario,Auth: FASE 3: VERIFICACIÓN EN INICIO DE SESIÓN
    Usuario->>Web: 16. Envía usuario + password + Código TOTP de 6 dígitos
    Web->>Auth: 17. Solicita validar código TOTP para el usuario
    Auth->>NTP: 18. Obtiene tiempo atómico sincronizado (now_server)
    Auth->>Auth: 19. Recupera y descifra la semilla K del usuario
    Auth->>Auth: 20. Calcula T_actual = piso(now_server / 30)
    Auth->>Auth: 21. Evalúa ventana de tolerancia: T - 1, T, T + 1
    alt El código coincide con alguna ventana y NO ha sido usado
        Auth->>Auth: 22. Marca el código/ventana como USADO (Antirreplay)
        Auth-->>Web: 23. Autenticación EXITOSA
        Web-->>Usuario: 24. Acceso Concedido (Sesión iniciada)
    else Código incorrecto, expirado o reutilizado
        Auth-->>Web: 25. Autenticación FALLIDA
        Web-->>Usuario: 26. Error: Código inválido o expirado
    end
```

---

## 2. El Estándar de Generación de la Semilla (Shared Secret)

La seguridad de todo el esquema TOTP depende críticamente de la **calidad criptográfica y entropía** de la semilla compartida $K$.

### A. Requisitos de los Estándares IETF

* **RFC 4226 (HOTP, Sección 4 - Requisito R6):**
  > *"El algoritmo DEBE usar un secreto compartido fuerte. La longitud del secreto compartido DEBE ser de al menos 128 bits. Este documento RECOMIENDA una longitud de secreto compartido de 160 bits."*
* **RFC 6238 (TOTP, Sección 3 - Requisito R6 y Sección 5):**
  > *"Las claves DEBEN elegirse al azar o derivarse mediante algoritmos de derivación de claves criptográficas. Las claves DEBEN ser de la longitud de la salida del HMAC para facilitar la interoperabilidad."*
  * Para **HMAC-SHA1**: Salida de 160 bits $\rightarrow$ Clave recomendada de **160 bits (20 bytes)**.
  * Para **HMAC-SHA256**: Salida de 256 bits $\rightarrow$ Clave recomendada de **256 bits (32 bytes)**.
  * Para **HMAC-SHA512**: Salida de 512 bits $\rightarrow$ Clave recomendada de **512 bits (64 bytes)**.

### B. La Semilla de Google Authenticator
Google Authenticator sigue estrictamente la recomendación óptima del RFC:
* **Longitud binaria:** Exactamente **20 bytes** (160 bits de entropía pura).
* **Representación Base32 (RFC 4648):**
  Como cada caracter en Base32 codifica 5 bits ($160 / 5 = 32$ caracteres), la semilla exportada tiene **exactamente 32 caracteres alfanuméricos** (por ejemplo: `6Z2SFWHN2OGNAZSRPESYFFO3AZXWKGVU`).
* **Representación Hexadecimal:** 40 caracteres hexadecimales (por ejemplo: `f67522d8edd38cd0665179258295db066f651ab4`).

### C. Generadores de Semillas Estándar (CSPRNG)
Según la **RFC 4086** (*Randomness Requirements for Security*) y el estándar **NIST SP 800-90A**:
1. **Nunca usar generadores pseudoaleatorios estándar** (como `rand()` de C o `Math.random()` de JavaScript/Java), pues sus estados internos son predecibles conociendo pocas muestras.
2. **Fuentes aprobadas en la industria:**
   * En Linux/Unix: Lectura directa de `/dev/urandom` o llamadas al sistema `getrandom(2)`.
   * En Java: `java.security.SecureRandom` configurado con algoritmo `NativePRNG` o `SHA1PRNG`.
   * En Python: Módulo `secrets` (`secrets.token_bytes(20)`).
   * En Node.js: `crypto.randomBytes(20)`.

### D. Almacenamiento Seguro (NIST SP 800-63B y OWASP)
* El servidor **nunca debe almacenar la semilla en texto plano**.
* Debe cifrarse en reposo en la base de datos utilizando **AES-256-GCM** mediante una clave de cifrado de claves (KEK) o residir dentro de un módulo de seguridad de hardware (**HSM / KMS**).

---

## 3. El Estándar Global en la Industria

### A. ¿Por qué 6 dígitos y no 7 u 8?

Aunque los RFCs admiten formalmente longitudes de 6 a 8 dígitos:

| Longitud | Espacio de Búsqueda | Tiempo de Entrada Humana | Adopción en la Industria | Caso de Uso Típico |
| :---: | :---: | :---: | :---: | :--- |
| **6 dígitos** | $1,000,000$ combinaciones | $\sim 3$ a $5$ segundos | **> 95% (Estándar de Facto)** | Google Authenticator, Microsoft Auth, Authy, GitHub, AWS, banca móvil. |
| **7 dígitos** | $10,000,000$ combinaciones | $\sim 5$ a $7$ segundos | $< 1\%$ | RFC 4226 con checksum de Luhn (prácticamente en desuso comercial). |
| **8 dígitos** | $100,000,000$ combinaciones | $\sim 7$ a $10$ segundos | $\sim 4\%$ | Tokens físicos militares, consolas de infraestructura crítica (YubiKey OTP empresarial). |

**Razón del éxito de los 6 dígitos:**
El factor limitante de seguridad de TOTP **no es la longitud del número**, sino la **caducidad de 30 segundos** y las **políticas de bloqueo por intentos** (*rate limiting*). Un atacante que intente adivinar un código de 6 dígitos dispone de $1$ posibilidad entre $1,000,000$. Con un bloqueo tras 3 intentos fallidos, la probabilidad de éxito de un ataque de fuerza bruta es del $0.0003\%$, haciendo innecesario obligar al usuario a memorizar y teclear 8 dígitos en su teléfono.

### B. ¿Por qué HMAC-SHA-1 sigue siendo el rey sobre SHA-256?

1. **Inmunidad de HMAC contra colisiones:** Las vulnerabilidades criptográficas de SHA-1 (como el ataque *SHAttered*) demostraron colisiones para firmas de documentos idénticos. Sin embargo, en 2006 Mihir Bellare demostró que **HMAC no se apoya en la resistencia a colisiones**, sino en la pseudoaleatoriedad de la función interna. No existe ningún ataque práctico conocido contra HMAC-SHA1.
2. **Interoperabilidad absoluta:** Millones de tarjetas inteligentes, llaveros electrónicos y microcontroladores antiguos solo tienen soporte nativo acelerado por hardware para SHA-1. Si los proveedores forzaran SHA-256, romperían la compatibilidad con millones de dispositivos sin ganar seguridad real en un token que muere a los 30 segundos.

---

## 4. Deducción Matemática Paso a Paso: Fusión de RFC 6238, 4226 y 2104

Para entender de dónde sale el código final, procedemos a realizar la **sustitución directa y formal** de cada una de las capas matemáticas que componen el estándar.

---

### Capa 1: El Factor de Tiempo (RFC 6238)

El protocolo TOTP define que el factor dinámico $T$ es un contador entero de 64 bits (8 bytes) que representa la cantidad de pasos de tiempo transcurridos desde la época Unix:

$$T = \left\lfloor \frac{\text{TiempoActual} - T_0}{X} \right\rfloor$$

Donde:
* $\text{TiempoActual}$: Segundos transcurridos desde el 1 de enero de 1970 UTC (Unix Epoch).
* $T_0$: Tiempo de inicio del sistema (por defecto $T_0 = 0$).
* $X$: Ventana o paso de tiempo en segundos (por defecto $X = 30$).
* $\lfloor \dots \rfloor$: Función suelo (redondeo hacia abajo al entero más cercano).

$T$ se codifica obligatoriamente como un arreglo de **8 bytes en formato Big-Endian** (el byte más significativo primero):

$$\mathbf{C} = \text{Bytes}_{8}(T)$$

---

### Capa 2: El Algoritmo HOTP y Truncamiento Dinámico (RFC 4226)

La RFC 6238 establece que TOTP es simplemente HOTP evaluado sobre el contador de tiempo $\mathbf{C}$:

$$\text{TOTP}(K, \text{TiempoActual}) = \text{HOTP}(K, \mathbf{C})$$

A su vez, la RFC 4226 define $\text{HOTP}$ como:

$$\text{HOTP}(K, \mathbf{C}) = \text{Truncate}\Big(\text{HMAC}(K, \mathbf{C})\Big) \bmod 10^d$$

Donde $d$ es el número de dígitos ($d = 6 \implies 10^6 = 1,000,000$).

#### El Algoritmo de Truncamiento Dinámico (Truncate):
El resultado de la función HMAC es un arreglo `HS` de 20 bytes (índices del 0 al 19). Para convertir esos 20 bytes en un número entero legible:

1. Se toma el último byte `HS[19]` y se extraen sus últimos 4 bits aplicando una máscara binaria AND con `0x0F`:
   $$\text{offset} = \mathbf{HS}[19] \land \text{0x0F}$$
   Esto produce un índice de inicio entre `0` y `15`.
2. Se extraen 4 bytes contiguos a partir de esa posición `P = HS[offset ... offset+3]`.
3. Se enmascara el bit más significativo (bit de signo) aplicando AND con `0x7FFFFFFF` para garantizar un entero positivo de 31 bits:
   $$\text{DBC} = \Big((\mathbf{HS}[\text{offset}] \land \text{0x7F}) \ll 24\Big) \lor \Big(\mathbf{HS}[\text{offset}+1] \ll 16\Big) \lor \Big(\mathbf{HS}[\text{offset}+2] \ll 8\Big) \lor \mathbf{HS}[\text{offset}+3]$$

En código Java / C equivalente:
```java
int offset = hash[hash.length - 1] & 0x0F;
int binary = ((hash[offset] & 0x7F) << 24) |
             ((hash[offset + 1] & 0xFF) << 16) |
             ((hash[offset + 2] & 0xFF) << 8) |
             (hash[offset + 3] & 0xFF);
```

---

### Capa 3: La Definición Criptográfica de HMAC (RFC 2104)

La función $\text{HMAC}$ utilizada en la Capa 2 viene formalmente definida en la **RFC 2104** como:

$$\text{HMAC}_K(m) = H\Big((K^+ \oplus \text{opad}) \parallel H((K^+ \oplus \text{ipad}) \parallel m)\Big)$$

Donde:
* $H$: Función de dispersión criptográfica (SHA-1 en el estándar universal).
* $m$: Mensaje a autenticar. En nuestro caso, el contador de tiempo $\mathbf{C} = \text{Bytes}_8(T)$.
* $B$: Tamaño de bloque interno de la función hash en bytes ($B = 64$ bytes para SHA-1).
* $K^+$: Clave $K$ rellenada con ceros a la derecha hasta alcanzar $B$ bytes de longitud:
  $$K^+ = K \parallel \mathbf{0}^{B - |K|}$$
* $\text{ipad}$ (*inner pad*): Constante de 64 bytes compuesta por el valor `0x36` repetido 64 veces.
* $\text{opad}$ (*outer pad*): Constante de 64 bytes compuesta por el valor `0x5C` repetido 64 veces.
* $\oplus$: Operación lógica XOR a nivel de bytes.
* $\parallel$: Concatenación de cadenas de bytes.

---

### La Gran Ecuación Unificada de TOTP

Al sustituir la definición de la **RFC 2104** y el factor de tiempo de la **RFC 6238** directamente dentro de la fórmula de la **RFC 4226**, obtenemos la **fórmula consolidada final**:

$$\text{OTP} = \text{Truncate}\left( H\left((K^+ \oplus \text{opad}) \parallel H\left((K^+ \oplus \text{ipad}) \parallel \text{Bytes}_8\left(\left\lfloor \frac{t - T_0}{X} \right\rfloor\right)\right)\right) \right) \pmod{10^d}$$

---

## 5. Demostración Matemática y Transformación Bit a Bit (Paso a Paso)

A continuación se realiza el desglose **bit por bit y byte por byte** utilizando **la clave secreta real extraída de tu cuenta de Google Authenticator** y la marca temporal de prueba `t = 1790438713` segundos (correspondiente a la ejecución de [TOTPGoogleAuth.java](file:///c:/Users/Aleks/Carrera/TIC/Material/CodigosRFC/2_Implementaciones_Nuevas/TOTPGoogleAuth.java)), demostrando cómo se llega con precisión absoluta al código final **`850032`**.

---

### Paso 0: La Semilla Criptográfica de Entrada ($K$)

* **Representación en Base32 (32 caracteres):**
  ```text
  6Z2SFWHN2OGNAZSRPESYFFO3AZXWKGVU
  ```
* **Decodificación Base32 a Bits (5 bits por caracter según RFC 4648):**
  Cada caracter alfanumérico se expande a su quinteto de bits:
  * `6` → `11110` | `Z` → `11001` | `2` → `00010` | `S` → `10010` | `F` → `00101` ...
  * Total: $32 \times 5 = 160$ bits de entropía pura.
* **Agrupación en 20 Bytes Hexadecimales (160 bits):**
  ```text
  f6 75 22 d8 ed d3 8c d0 66 51 79 25 82 95 db 06 6f 65 1a b4
  ```
* **Transcripción Bit por Bit de la Semilla (20 bytes):**
  ```text
  Byte 00 (0xf6): 11110110    Byte 01 (0x75): 01110101    Byte 02 (0x22): 00100010    Byte 03 (0xd8): 11011000
  Byte 04 (0xed): 11101101    Byte 05 (0xd3): 11010011    Byte 06 (0x8c): 10001100    Byte 07 (0xd0): 11010000
  Byte 08 (0x66): 01100110    Byte 09 (0x51): 01010001    Byte 10 (0x79): 01111001    Byte 11 (0x25): 00100101
  Byte 12 (0x82): 10000010    Byte 13 (0x95): 10010101    Byte 14 (0xdb): 11011011    Byte 15 (0x06): 00000110
  Byte 16 (0x6f): 01101111    Byte 17 (0x65): 01100101    Byte 18 (0x1a): 00011010    Byte 19 (0xb4): 10110100
  ```

---

### Transformación 1: La Dimensión Temporal (RFC 6238)

* **Tiempo Unix ($t$):** `1790438713` segundos (desde el 01/01/1970 UTC).
* **Parámetros:** Inicio $T_0 = 0$, ventana $X = 30$ segundos.
* **Cálculo del contador entero $T$:**
  $$T = \left\lfloor \frac{1790438713 - 0}{30} \right\rfloor = \lfloor 59681290.4333 \rfloor = 59681290$$
* **Conversión de $T$ a entero de 64 bits (8 bytes) en formato Big-Endian:**
  * Decimal: `59681290`
  * Hexadecimal de 8 bytes: `00 00 00 00 03 8e aa 0a`
* **Transcripción Bit por Bit del Contador $\mathbf{C}$ (64 bits):**
  ```text
  Byte 0 (0x00): 00000000    Byte 1 (0x00): 00000000
  Byte 2 (0x00): 00000000    Byte 3 (0x00): 00000000
  Byte 4 (0x03): 00000011    Byte 5 (0x8e): 10001110
  Byte 6 (0xaa): 10101010    Byte 7 (0x0a): 00001010
  ```

---

### Transformación 2: Preparación de Clave y Pads en HMAC (RFC 2104)

* El tamaño de bloque interno de SHA-1 es $B = 64$ bytes (512 bits).
* Como la clave $K$ mide 20 bytes, se rellena con 44 bytes de ceros (`0x00`) para formar $K^+$ (64 bytes):
  ```text
  f6 75 22 d8 ed d3 8c d0 66 51 79 25 82 95 db 06 6f 65 1a b4
  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00 00 00 00 00
  ```
* **Constantes de pad:**
  * `ipad` = 64 bytes formados por `0x36` (`00110110` en binario).
  * `opad` = 64 bytes formados por `0x5c` (`01011100` en binario).

* **Operación XOR bit a bit interna ($K_{ipad} = K^+ \oplus ipad$):**
  * Para el byte 0: `0xf6 ^ 0x36 = 11110110 ^ 00110110 = 11000000 = 0xc0`
  * Para el byte 1: `0x75 ^ 0x36 = 01110101 ^ 00110110 = 01000011 = 0x43`
  * ...
  * Para los bytes 20 al 63: `0x00 ^ 0x36 = 0x36`
  * **Resultado $K_{ipad}$ (64 bytes):**
    ```text
    c0 43 14 ee db e5 ba e6 50 67 4f 13 b4 a3 ed 30 59 53 2c 82
    36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36
    36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36
    36 36 36 36
    ```

* **Operación XOR bit a bit externa ($K_{opad} = K^+ \oplus opad$):**
  * Para el byte 0: `0xf6 ^ 0x5c = 11110110 ^ 01011100 = 10101010 = 0xaa`
  * Para el byte 1: `0x75 ^ 0x5c = 01110101 ^ 01011100 = 00101001 = 0x29`
  * ...
  * Para los bytes 20 al 63: `0x00 ^ 0x5c = 0x5c`
  * **Resultado $K_{opad}$ (64 bytes):**
    ```text
    aa 29 7e 84 b1 8f d0 8c 3a 0d 25 79 de c9 87 5a 33 39 46 e8
    5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c
    5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c
    5c 5c 5c 5c
    ```

---

### Transformación 3: Hashing Interno SHA-1 ($H_{in}$)

Se concatena la clave enmascarada $K_{ipad}$ con los 8 bytes del contador de tiempo $\mathbf{C}$:
$$\text{MensajeInterno} = K_{ipad} \parallel \mathbf{C} \quad (64 + 8 = 72 \text{ bytes})$$

* **Mensaje a dispersar (72 bytes en Hexadecimal):**
  ```text
  c0 43 14 ee db e5 ba e6 50 67 4f 13 b4 a3 ed 30 59 53 2c 82
  36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36
  36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36
  36 36 36 36 00 00 00 00 03 8e aa 0a
  ```
* Se procesa con la función de dispersión **SHA-1** ($H(MensajeInterno)$).
* **Hash Interno Resultante $H_{in}$ (20 bytes / 160 bits):**
  ```text
  aa df 60 90 5e 63 67 a0 d7 e7 80 d8 79 7c 04 75 3d d7 be 0f
  ```
* **Transcripción Bit por Bit de $H_{in}$ (160 bits):**
  ```text
  10101010 11011111 01100000 10010000 01011110 01100011 01100111 10100000
  11010111 11100111 10000000 11011000 01111001 01111100 00000100 01110101
  00111101 11010111 10111110 00001111
  ```

---

### Transformación 4: Hashing Externo HMAC-SHA1 ($HS$)

Se concatena la clave enmascarada externa $K_{opad}$ con el hash interno obtenido $H_{in}$:
$$\text{MensajeExterno} = K_{opad} \parallel H_{in} \quad (64 + 20 = 84 \text{ bytes})$$

* **Mensaje a dispersar (84 bytes en Hexadecimal):**
  ```text
  aa 29 7e 84 b1 8f d0 8c 3a 0d 25 79 de c9 87 5a 33 39 46 e8
  5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c
  5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c
  5c 5c 5c 5c aa df 60 90 5e 63 67 a0 d7 e7 80 d8 79 7c 04 75
  3d d7 be 0f
  ```
* Se procesa con la función de dispersión **SHA-1** ($H(MensajeExterno)$).
* **Hash HMAC Final $\mathbf{HS}$ (20 bytes / 160 bits):**
  ```text
  7c 8f 30 b3 f0 87 01 f1 50 4c a4 b9 ea 14 7c 72 a6 a5 36 01
  ```
* **Transcripción Bit por Bit del Digest $\mathbf{HS}$ (160 bits):**
  ```text
  Byte 00 (0x7c): 01111100    Byte 01 (0x8f): 10001111    Byte 02 (0x30): 00110000    Byte 03 (0xb3): 10110011
  Byte 04 (0xf0): 11110000    Byte 05 (0x87): 10000111    Byte 06 (0x01): 00000001    Byte 07 (0xf1): 11110001
  Byte 08 (0x50): 01010000    Byte 09 (0x4c): 01001100    Byte 10 (0xa4): 10100100    Byte 11 (0xb9): 10111001
  Byte 12 (0xea): 11101010    Byte 13 (0x14): 00010100    Byte 14 (0x7c): 01111100    Byte 15 (0x72): 01110010
  Byte 16 (0xa6): 10100110    Byte 17 (0xa5): 10100101    Byte 18 (0x36): 00110110    Byte 19 (0x01): 00000001
  ```

---

### Transformación 5: Truncamiento Dinámico (RFC 4226)

1. **Lectura del último byte ($\mathbf{HS}[19]$):**
   * $\mathbf{HS}[19] = \text{0x01}$ (`00000001` en binario).
2. **Cálculo del desplazamiento (offset):**
   Tomamos los 4 bits menos significativos con una operación lógica AND con `0x0F`:
   ```text
     00000001  (0x01)
   & 00001111  (0x0F)
   ----------
     00000001  (offset = 1)
   ```
3. **Extracción de la ventana de 4 bytes a partir del offset 1 ($\mathbf{HS}[1 \dots 4]$):**
   * Byte en offset 1: `0x8f` (`10001111`)
   * Byte en offset 2: `0x30` (`00110000`)
   * Byte en offset 3: `0xb3` (`10110011`)
   * Byte en offset 4: `0xf0` (`11110000`)
   * Arreglo de 4 bytes concatenados: `0x8f30b3f0` (32 bits).
4. **Enmascaramiento del bit de signo (AND con `0x7FFFFFFF`):**
   Se apaga el bit más significativo (bit 31) para garantizar que el valor siempre sea tratado como un número entero positivo:
   ```text
     10001111 00110000 10110011 11110000  (0x8f30b3f0)
   & 01111111 11111111 11111111 11111111  (0x7fffffff)
   ----------------------------------------------------
     00001111 00110000 10110011 11110000  (0x0f30b3f0)
   ```
5. **Conversión del valor de 31 bits a entero decimal:**
   $$\text{DBC} = \text{0x0f30b3f0}_{16} = 254850032_{10}$$

---

### Transformación 6: Reducción Módulo $10^6$ y Formateo Final

* **Operación módulo $10^6$:**
  $$\text{Código} = \text{DBC} \bmod 10^6$$
  $$\text{Código} = 254850032 \bmod 1,000,000 = 850032$$
* **Formateo de salida:**
  Como ya cuenta con 6 dígitos completos, no requiere rellenado con ceros a la izquierda.
* **Resultado Final del Token TOTP:**
  ```text
  ┌───────────────┐
  │  OTP: 850032  │
  └───────────────┘
  ```

> [!NOTE]
> Este valor **`850032`** coincide con absoluta precisión bit por bit con:
> 1. La salida de tu programa Java [TOTPGoogleAuth.java](file:///c:/Users/Aleks/Carrera/TIC/Material/CodigosRFC/2_Implementaciones_Nuevas/TOTPGoogleAuth.java) ejecutado en el segundo `1790438713`.
> 2. El código mostrado por la app oficial de **Google Authenticator** en ese mismo intervalo de tiempo.

---

## 6. Consideraciones de Seguridad en la Validación (NIST SP 800-63B)

Para que el servidor valide de forma segura este cálculo, debe aplicar tres controles obligatorios:

1. **Ventana de Tolerancia Temporal:**
   Debido a posibles desfases de reloj entre el teléfono y el servidor (o el tiempo que tarda el usuario en escribir el código), el servidor debe calcular y validar los códigos correspondientes a $T-1$, $T$ y $T+1$ (una ventana de $\pm 30$ segundos, total 90 segundos de validez).
2. **Protección Antirreplay (Un solo uso garantizado):**
   Una vez que un código de una ventana específica (ej. $T$) ha sido validado satisfactoriamente, el servidor debe almacenar temporalmente el identificador $(Usuario, T)$ para rechazar cualquier reenvío posterior dentro de esa misma ventana de tiempo.
3. **Comparación en Tiempo Constante:**
   Al verificar si la entrada del usuario coincide con el código calculado por el servidor, la comparación debe ejecutarse en tiempo constante (ej. `MessageDigest.isEqual()` en Java) para evitar fugas de información a través de ataques de temporización (*timing attacks*).

