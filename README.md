# Repositorio de Investigación y Trabajo de Integración Curricular (TIC) — EPN

**Tema de Grado:** *Análisis de Predictibilidad de Generadores de Contraseñas de un solo uso mediante análisis de Entropía, Modelos Estadísticos y Aprendizaje Automático*  
**Autor:** Julián Aleksei Narváez Vinueza (Estudiante B — Módulo Predictor / Rompedor)  
**Director de Tesis:** Ing. Jhonattan Barriga, Ph.D.  
**Institución:** Escuela Politécnica Nacional (EPN), Quito, Ecuador  

---

## 📌 1. Mapa General del Repositorio

El repositorio se encuentra estructurado en carpetas especializadas que cubren desde los fundamentos teóricos y estándares RFC oficiales hasta los bancos de pruebas del NIST, los códigos de ataque y la literatura científica internacional:

```text
Material/
│
├── README.md                                  # [ESTE ARCHIVO] Índice maestro del repositorio y compendio de enlaces
├── TOTP_Fundamento_Teorico.md                 # Tratado teórico integral sobre el algoritmo TOTP y HMAC
│
├── Documentos/                                # PDFs de normas, RFCs oficiales y Canvas metodológicos
│   ├── Tesis.pdf                              # Propuesta y alcance formal del TIC
│   ├── rfc2104.pdf                            # RFC oficial de HMAC (Krawczyk, Bellare, Canetti)
│   ├── rfc4226.pdf                            # RFC oficial de HOTP basado en eventos (OATH)
│   ├── rfc6238.pdf                            # RFC oficial de TOTP basado en tiempo
│   ├── NIST.SP.800-63B-4.pdf                  # Directriz de gestión de identidades digitales (NIST)
│   ├── Analysis of Vulnerabilities...pdf      # Paper del estándar coreano TTAK.KO-12.0193 (MDPI 2020)
│   ├── ARQUITECTURA_FLUJO_Y_MATEMATICA_TOTP.md# Diagrama de bloques paso a paso de HMAC-SHA1 y truncamiento
│   └── CANVAS_PROCESO_GENERACION_TOTP.md      # Canvas visual del flujo de datos cliente-servidor
│
├── CodigosRFC/                                # Implementaciones canónicas en C y Java
│   ├── README.md                              # Guía completa de compilación y ejecución de códigos RFC
│   ├── 1_Estandares_Originales_RFC/           # rfc2104.c, OneTimePasswordAlgorithm.java, TOTP.java
│   ├── 2_Implementaciones_Nuevas/             # TOTPGoogleAuth.java (Google Auth en vivo), KoreaOTP.java
│   └── 3_Pruebas_y_Ejemplos/                  # TestHMACMD5.java, TestHOTP.java (bancos de prueba)
│
├── sts-2.1.2/                                 # Suite oficial NIST STS v2.1.2 compilada para Windows
│   ├── assess.exe                             # Binario ejecutable compilado con GCC
│   ├── data/                                  # Flujos binarios de entrada (.bin)
│   └── experiments/AlgorithmTesting/          # Salida de resultados: finalAnalysisReport.txt
│
├── Suite_NIST_Korea/                          # Pipeline automatizado de evaluación con NIST STS
│   ├── generador_nist_otp.py                  # Generador de flujos binarios masivos (1 MB) para NIST
│   ├── ejecutar_nist.py                       # Orquestador automatizado de assess.exe
│   ├── experimento2_decimal.py                # Simulación de frecuencias de 256 números colapsados
│   └── GUIA_PRUEBAS_NIST_STS.md               # Manual de las 15 pruebas estadísticas del NIST
│
├── Modulo_Rompedor_Predictor/                 # Núcleo del Módulo 2 (Julián Narváez)
│   ├── DISENO_METODOLOGICO_Y_ALCANCE.md       # Preguntas de investigación, objetivos y alcance formal
│   ├── ANALISIS_ETAPAS_VULNERABILIDADES...md   # Las 6 etapas de falla, análisis del NIST y ruptura
│   ├── COMPENDIO_INVESTIGACIONES_FALLAS...md   # Clasificación de papers, estándares mundiales y CVEs
│   ├── ANALISIS_LIBRERIAS_VULNERABLES...md     # Auditoría de librerías reales y selección de objetivo #1
│   ├── ESPECIFICACION_INTERFAZ_Y_MODELO_LSTM.md# Contrato de datos M1->M2, arquitectura multi-cabezal LSTM y Caja Blanca
│   ├── codigo/                                # Scripts ejecutables del predictor y simulador
│   └── datos/                                 # Datasets generados (.csv)
│
└── Entornos_Controlados/                      # Bancos de pruebas y testbeds locales de vulnerabilidades
    └── Test_NPM/                              # Laboratorio Node.js con otp-generator@2.0.1 (CVE-2021-23451)
        ├── package.json                       # Configuración y dependencias desactualizadas vulnerables
        ├── server.js                          # Servidor HTTP local que expone endpoints de autenticación
        ├── test_generador.js                  # Script de prueba rápida en consola de 10 OTPs
        ├── cliente_auditor.py                 # Cliente auditor en Python que consume la API
        └── README.md                          # Ficha técnica y comandos de ejecución
```

---

## 📚 2. Índice Maestro de Documentos Markdown Creados

A lo largo del proyecto se han estructurado documentos técnicos de alta densidad académica para sustentar cada fase de la investigación:

| Documento Markdown | Ubicación | Contenido Principal |
| :--- | :--- | :--- |
| **`Test_NPM/README.md`** | `Entornos_Controlados/Test_NPM/` | **Laboratorio Local CVE-2021-23451:** Guía del testbed con `otp-generator@2.0.1`, causa raíz en `Math.random()` y comandos de ejecución. |
| **`ESPECIFICACION_INTERFAZ_Y_MODELO_LSTM.md`** | `Modulo_Rompedor_Predictor/` | **Entrega Formal de Interfaces:** Esquema exacto de columnas CSV (M1->M2), justificación de dígitos d1..d6 para LSTM, arquitectura multi-cabezal y diagrama del Patrón Estrategia para Caja Blanca. |
| **`DISENO_METODOLOGICO_Y_ALCANCE.md`** | `Modulo_Rompedor_Predictor/` | Metodología de Massarik, preguntas de investigación, definición de "romper", objetivos generales/específicos, y roles de Markov vs LSTM. |
| **`ANALISIS_ETAPAS_VULNERABILIDADES_Y_RUPTURA.md`** | `Modulo_Rompedor_Predictor/` | Naturaleza del NIST STS (por qué no predice), las 6 etapas del ciclo de vida del OTP, deducción matemática de Corea (6.25% y 256 números) y diseño del CLI. |
| **`COMPENDIO_INVESTIGACIONES_FALLAS_REALES_Y_ESTANDARES.md`** | `Modulo_Rompedor_Predictor/` | Clasificación rigurosa en 3 enfoques: Ruptura de Semilla (Caja Blanca), Predicción OTP Directa (Caja Negra) y Fallas de Servidor / Rate Limiting. |
| **`ANALISIS_LIBRERIAS_VULNERABLES_Y_SELECCION_OBJETIVO.md`** | `Modulo_Rompedor_Predictor/` | Auditoría de código real (`otp-generator`, Android ICSE, cajeros EMV), por qué persisten vulnerables hoy, y selección del Objetivo Primario (Semillas por tiempo y LCG). |
| **`GUIA_PRUEBAS_NIST_STS.md`** | `Suite_NIST_Korea/` | Manual técnico de las 15 pruebas del NIST SP 800-22 Rev. 1a, interpretación de valores p, proporciones y comparación con el paper coreano. |
| **`CodigosRFC/README.md`** | `CodigosRFC/` | Catálogo de ejecución paso a paso de los estándares en C y Java con comandos para terminal y PowerShell. |
| **`ARQUITECTURA_FLUJO_Y_MATEMATICA_TOTP.md`** | `Documentos/` | Desglose matemático profundo: funciones de compresión SHA-1, padding de 512 bits, `ipad`/`opad` y truncamiento dinámico. |
| **`CANVAS_PROCESO_GENERACION_Y_CALCULO_TOTP.md`** | `Documentos/` | Representación en lienzo visual de la sincronización cliente-servidor y el ciclo de vida del token de 30 segundos. |
| **`TOTP_Fundamento_Teorico.md`** | Raíz (`Material/`) | Tratado teórico base sobre algoritmos OTP, sincronización de relojes y análisis de seguridad contra ataques de repetición. |

---

## 🌐 3. Compendio Exhaustivo de Enlaces Externos Oficiales

A continuación se recopilan **todos los enlaces oficiales, DOIs, papers académicos, avisos de seguridad y CVEs** analizados y citados durante la investigación:

### A. Papers Científicos Publicados en Conferencias Internacionales
1. **Paper del Estándar Nacional Coreano TTAK.KO-12.0193 (MDPI 2020):**
   * *Título:* "Analysis of Vulnerabilities That Can Occur When Generating One-Time Password" (Kim et al.).
   * *DOI Oficial:* [https://doi.org/10.3390/app10092961](https://doi.org/10.3390/app10092961)
2. **Paper de Falla Masiva en Generación de OTP en Android (ICSE 2021):**
   * *Título:* "Fine with '1234'? An Analysis of SMS One-Time Password Randomness in Android Apps" (Zhang et al. - 399 apps comerciales afectadas).
   * *Enlace arXiv:* [https://arxiv.org/abs/2104.14856](https://arxiv.org/abs/2104.14856)
3. **Paper de Vulnerabilidad en Estándar Bancario EMV Chip & PIN (IEEE S&P 2014):**
   * *Título:* "Chip and Skim: Cloning EMV Cards with the Pre-play Attack" (Murdoch, Anderson et al. - Universidad de Cambridge).
   * *DOI IEEE:* [https://doi.org/10.1109/SP.2014.11](https://doi.org/10.1109/SP.2014.11) | [PDF Cambridge](https://www.cl.cam.ac.uk/research/srg/netos/projects/archive/cam20/eprint/preplay.pdf)
4. **Paper de Análisis Empírico Masivo de Sistemas 2FA (2024):**
   * *Título:* "Simple But Not Secure: An Empirical Security Analysis of Two-factor Authentication Systems" (Ding et al. - Top 10.000 sitios web).
   * *Enlace arXiv:* [https://arxiv.org/abs/2401.07727](https://arxiv.org/abs/2401.07727)
5. **Paper de Fallas de Privacidad y Respaldo en Apps 2FA (USENIX Security '23):**
   * *Título:* "Security and Privacy Failures in Popular 2FA Apps" (Zhang et al.).
   * *Enlace USENIX:* [https://www.usenix.org/conference/usenixsecurity23/presentation/zhang-yitao](https://www.usenix.org/conference/usenixsecurity23/presentation/zhang-yitao)
6. **Paper sobre Manipulación de Deriva Temporal en TOTP:**
   * *Título:* "Time Is on My Side: Forward-Replay Attacks to TOTP Authentication".
   * *Enlace ResearchGate:* [https://www.researchgate.net/publication/348270505_Time_Is_on_My_Side_Forward-Replay_Attacks_to_TOTP_Authentication](https://www.researchgate.net/publication/348270505_Time_Is_on_My_Side_Forward-Replay_Attacks_to_TOTP_Authentication)
7. **Paper sobre Vulnerabilidades en Lectores USB de Banca en Línea (2010):**
   * *Título:* "Designed to Fail: A USB-Connected Reader for Online Banking" (Radboud University).
   * *Enlace PDF:* [https://www.cs.ru.nl/E.Poll/papers/dimva10.pdf](https://www.cs.ru.nl/E.Poll/papers/dimva10.pdf)

---

### B. Vulnerabilidades Reportadas (CVEs) y Estándares de la Industria (MITRE)
1. **CVE-2021-23451 (`otp-generator` npm Math.random):**
   * [NIST NVD CVE-2021-23451](https://nvd.nist.gov/vuln/detail/CVE-2021-23451) | [Snyk Vulnerability Advisory](https://security.snyk.io/vuln/SNYK-JS-OTPGENERATOR-1655480)
2. **CVE-2020-25506 (Fuerza Bruta Concurrente sin Rate Limiting en WordPress 2FA):**
   * [NIST NVD CVE-2020-25506](https://nvd.nist.gov/vuln/detail/CVE-2020-25506)
3. **CVE-2022-31656 (Bypass de 2FA y Fuerza Bruta en VMware Workspace ONE Access):**
   * [NIST NVD CVE-2022-31656](https://nvd.nist.gov/vuln/detail/CVE-2022-31656)
4. **CVE-2013-7372 (Falla del PRNG en Android `SecureRandom` / Apache Harmony):**
   * [Boletín de Seguridad Oficial de Google Android](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html)
5. **Yubico Security Advisory YSA-2019-02 (Degradación de Entropía en YubiKey FIPS):**
   * [Yubico Security Advisory YSA-2019-02](https://www.yubico.com/support/security-advisories/ysa-2019-02/)
6. **Estándares MITRE CWE:**
   * [CWE-337: Predictable Seed in Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/337.html)
   * [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/338.html)
   * [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

---

### C. Estándares Oficiales Mundiales y Casos Históricos de Alto Impacto
1. **NIST SP 800-90A (Dual_EC_DRBG Backdoor y Revocación Oficial):**
   * [NIST SP 800-90A Rev. 1 Publication](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final)
2. **El Robo de Semillas de RSA SecurID y el Ataque a Lockheed Martin (2011):**
   * [Investigación de Wired Magazine](https://www.wired.com/2011/05/rsa-hack-lockheed/)
3. **Estándares IETF Oficiales:**
   * [RFC 2104: HMAC - Keyed-Hashing for Message Authentication](https://datatracker.ietf.org/doc/html/rfc2104)
   * [RFC 4226: HOTP - An HMAC-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc4226)
   * [RFC 6238: TOTP - Time-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)
   * [NIST SP 800-63B: Digital Identity Guidelines - Authentication](https://pages.nist.gov/800-63-3/sp800-63b.html)
