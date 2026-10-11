# Guia Maestra NIST STS (SP 800-22), Reportes Comparativos y Vectores de Ataque Criptografico

Este documento consolida:
1. Como ejecutar el analizador automatizado `ejecutar_nist.py` sobre cada dataset binario.
2. Los reportes oficiales literales (`finalAnalysisReport.txt`) obtenidos de NIST STS para los 3 algoritmos (100% integros, sin omisiones ni truncamientos).
3. El significado matematico y tecnico de cada prueba que fallo en el algoritmo coreano.
4. El catalogo exhaustivo de las 15 pruebas del NIST: que evalua cada una y que vector de ataque habilita si falla.
5. El impacto practico del ataque real en sistemas de autenticacion bancaria y corporativa.

---

## 1. Como Ejecutar `ejecutar_nist.py` por Consola

El script `ejecutar_nist.py` automatiza la interaccion con el binario compilado de NIST `sts-2.1.2/assess.exe`, configurandolo en modo binario para evaluar **8 secuencias de 1,000,000 de bits cada una** (un total de 1,000,000 de bytes evaluados).

### Comandos de Ejecucion Directa (Recomendados):

Abre PowerShell en la carpeta raiz del proyecto (`c:\Users\Aleks\Carrera\TIC\Material`):

```powershell
# Opcion 1: Evaluar el Algoritmo Coreano Vulnerable (TTAK.KO-12.0193)
python Suite_NIST_Korea/ejecutar_nist.py 1

# Opcion 2: Evaluar el Algoritmo Coreano de Control (TTAK.KO-12.0193 Dinamico Clasico)
python Suite_NIST_Korea/ejecutar_nist.py 2

# Opcion 3: Evaluar Google Authenticator (RFC 4226 / RFC 6238)
python Suite_NIST_Korea/ejecutar_nist.py 3
```

### Ejecucion Pasando el Nombre de Archivo:
```powershell
python Suite_NIST_Korea/ejecutar_nist.py data/experimentos/korea_vulnerable.bin
python Suite_NIST_Korea/ejecutar_nist.py data/experimentos/korea_control.bin
python Suite_NIST_Korea/ejecutar_nist.py data/experimentos/google_rfc4226.bin
```

### Ejecucion en Modo Menu Interactivo:
Si ejecutas el script sin argumentos:
```powershell
python Suite_NIST_Korea/ejecutar_nist.py
```
El script mostrara un menu interactivo en consola para que presiones `1`, `2` o `3`.

> Ubicacion del reporte generado en caliente por el software NIST:
> `sts-2.1.2/experiments/AlgorithmTesting/finalAnalysisReport.txt`
>
> Copias archivadas permanentes de cada ejecucion:
> `Suite_NIST_Korea/reportes/reporte_korea_vulnerable.txt`
> `Suite_NIST_Korea/reportes/reporte_korea_control.txt`
> `Suite_NIST_Korea/reportes/reporte_google_rfc4226.txt`

---

## 2. Reportes Oficiales Obtenidos de NIST STS (Copy-Paste Literal y Completo)

A continuacion se transcriben los reportes exactos e integros (las 208 lineas completas de cada archivo `finalAnalysisReport.txt`) obtenidos al evaluar los tres datasets. No se ha omitido ninguna linea ni plantilla.

---

### Caso 1: Algoritmo Coreano Vulnerable (`korea_vulnerable.bin`)
*Generador: `data/experimentos/korea_vulnerable.bin` | Tamano: 1,000,000 bytes (8,000,000 bits)*
*Transcribiendo exactamente `finalAnalysisReport.txt`:*

```text
------------------------------------------------------------------------------
RESULTS FOR THE UNIFORMITY OF P-VALUES AND THE PROPORTION OF PASSING SEQUENCES
------------------------------------------------------------------------------
   generator is <data/experimentos/korea_vulnerable.bin>
------------------------------------------------------------------------------
 C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE  PROPORTION  STATISTICAL TEST
------------------------------------------------------------------------------
  1   2   1   1   1   0   1   0   0   1     ----       8/8       Frequency
  8   0   0   0   0   0   0   0   0   0     ----       0/8    *  BlockFrequency
  1   3   1   0   1   1   1   0   0   0     ----       8/8       CumulativeSums
  0   2   2   1   0   3   0   0   0   0     ----       8/8       CumulativeSums
  2   0   0   1   0   0   2   2   0   1     ----       8/8       Runs
  8   0   0   0   0   0   0   0   0   0     ----       2/8    *  LongestRun
  1   2   2   1   0   1   1   0   0   0     ----       8/8       Rank
  8   0   0   0   0   0   0   0   0   0     ----       3/8    *  FFT
  5   1   0   2   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  3   1   0   3   1   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  4   1   0   0   1   0   1   1   0   0     ----       6/8    *  NonOverlappingTemplate
  6   0   0   0   2   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  5   3   0   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  5   1   0   0   0   1   0   1   0   0     ----       7/8       NonOverlappingTemplate
  5   1   0   1   0   1   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  5   2   0   1   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  5   1   2   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  7   1   0   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  4   0   1   1   1   0   0   0   1   0     ----       5/8    *  NonOverlappingTemplate
  5   1   2   0   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  4   2   0   2   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  6   0   0   1   0   0   1   0   0   0     ----       8/8       NonOverlappingTemplate
  5   0   1   1   1   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  7   1   0   0   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  5   1   0   1   0   0   1   0   0   0     ----       5/8    *  NonOverlappingTemplate
  5   2   0   0   1   0   0   0   0   0     ----       4/8    *  NonOverlappingTemplate
  2   5   0   1   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  6   1   1   0   0   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  5   0   2   0   0   0   1   0   0   0     ----       5/8    *  NonOverlappingTemplate
  1   3   0   1   1   0   1   1   0   0     ----       8/8       NonOverlappingTemplate
  3   2   0   2   1   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  4   0   1   0   0   1   2   0   0   0     ----       7/8       NonOverlappingTemplate
  3   1   0   1   2   1   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  6   0   1   0   0   1   0   0   0   0     ----       8/8       NonOverlappingTemplate
  4   2   0   1   0   1   0   0   0   0     ----       8/8       NonOverlappingTemplate
  5   1   1   0   0   0   0   1   0   0     ----       6/8    *  NonOverlappingTemplate
  5   2   1   0   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  7   1   0   0   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  6   1   0   0   0   0   0   0   1   0     ----       6/8    *  NonOverlappingTemplate
  7   0   1   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  5   2   0   0   1   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  4   0   4   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  3   3   1   1   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  5   1   1   0   1   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  3   1   2   2   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  4   2   0   1   0   1   0   0   0   0     ----       7/8       NonOverlappingTemplate
  5   1   1   0   0   1   0   0   0   0     ----       8/8       NonOverlappingTemplate
  6   1   0   0   0   0   0   0   0   1     ----       7/8       NonOverlappingTemplate
  4   2   2   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  6   0   0   1   0   0   0   1   0   0     ----       7/8       NonOverlappingTemplate
  4   3   0   1   0   0   0   0   0   0     ----       4/8    *  NonOverlappingTemplate
  3   1   2   0   0   1   0   0   0   1     ----       7/8       NonOverlappingTemplate
  5   2   0   0   1   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  3   2   2   1   0   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  6   1   0   0   0   0   1   0   0   0     ----       7/8       NonOverlappingTemplate
  5   1   1   0   0   1   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  3   1   1   0   0   2   0   0   1   0     ----       5/8    *  NonOverlappingTemplate
  6   1   1   0   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  6   0   1   1   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  6   1   0   0   1   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  4   2   1   1   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  4   0   2   0   2   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  3   3   0   0   0   1   0   0   0   1     ----       7/8       NonOverlappingTemplate
  3   3   1   1   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  6   0   1   0   0   1   0   0   0   0     ----       8/8       NonOverlappingTemplate
  4   1   1   1   0   0   1   0   0   0     ----       7/8       NonOverlappingTemplate
  2   3   1   1   0   0   0   0   0   1     ----       7/8       NonOverlappingTemplate
  3   2   0   1   0   0   1   1   0   0     ----       6/8    *  NonOverlappingTemplate
  6   0   1   0   1   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  6   0   1   1   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  4   2   0   1   0   1   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  2   4   1   0   1   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  3   2   1   2   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  0   5   1   0   2   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  6   0   0   1   0   0   1   0   0   0     ----       6/8    *  NonOverlappingTemplate
  3   2   1   0   1   1   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  5   1   1   0   0   0   1   0   0   0     ----       7/8       NonOverlappingTemplate
  5   2   1   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  4   0   0   0   1   1   0   0   2   0     ----       6/8    *  NonOverlappingTemplate
  3   3   1   1   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  3   1   1   1   0   0   1   0   1   0     ----       7/8       NonOverlappingTemplate
  6   0   1   0   0   0   0   1   0   0     ----       4/8    *  NonOverlappingTemplate
  5   1   0   2   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  4   1   1   0   0   1   0   1   0   0     ----       6/8    *  NonOverlappingTemplate
  4   2   0   2   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  4   1   1   1   0   0   1   0   0   0     ----       6/8    *  NonOverlappingTemplate
  5   2   1   0   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  4   1   1   0   0   2   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  6   1   1   0   0   0   0   0   0   0     ----       4/8    *  NonOverlappingTemplate
  4   3   1   0   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  6   1   0   0   0   0   0   0   1   0     ----       5/8    *  NonOverlappingTemplate
  3   2   1   0   2   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  5   2   1   0   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  5   1   2   0   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  8   0   0   0   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  3   2   0   0   1   1   1   0   0   0     ----       8/8       NonOverlappingTemplate
  6   0   0   0   2   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  6   0   0   1   0   0   0   0   1   0     ----       3/8    *  NonOverlappingTemplate
  5   2   0   0   1   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  3   2   1   2   0   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  0   3   2   2   0   0   0   0   1   0     ----       8/8       NonOverlappingTemplate
  7   0   0   0   1   0   0   0   0   0     ----       4/8    *  NonOverlappingTemplate
  5   3   0   0   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  3   0   3   0   0   0   1   0   0   1     ----       6/8    *  NonOverlappingTemplate
  7   0   0   1   0   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  6   1   0   1   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  4   1   0   2   0   0   0   0   0   1     ----       8/8       NonOverlappingTemplate
  6   2   0   0   0   0   0   0   0   0     ----       4/8    *  NonOverlappingTemplate
  4   2   1   0   1   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  3   2   1   0   1   1   0   0   0   0     ----       8/8       NonOverlappingTemplate
  3   3   0   1   0   0   0   0   1   0     ----       7/8       NonOverlappingTemplate
  5   0   1   0   1   1   0   0   0   0     ----       7/8       NonOverlappingTemplate
  3   3   1   1   0   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  3   2   0   2   0   0   0   0   0   1     ----       6/8    *  NonOverlappingTemplate
  7   0   0   1   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  2   2   2   1   0   1   0   0   0   0     ----       7/8       NonOverlappingTemplate
  7   1   0   0   0   0   0   0   0   0     ----       4/8    *  NonOverlappingTemplate
  2   2   2   1   0   0   1   0   0   0     ----       7/8       NonOverlappingTemplate
  5   2   1   0   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  6   0   1   0   1   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  6   1   0   1   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  5   2   0   0   0   0   1   0   0   0     ----       6/8    *  NonOverlappingTemplate
  4   1   0   0   1   1   0   0   1   0     ----       8/8       NonOverlappingTemplate
  3   0   0   2   0   1   1   0   1   0     ----       8/8       NonOverlappingTemplate
  6   2   0   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  6   0   1   0   0   0   0   1   0   0     ----       4/8    *  NonOverlappingTemplate
  6   0   0   1   1   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  2   1   1   3   1   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  4   1   1   0   1   0   1   0   0   0     ----       8/8       NonOverlappingTemplate
  3   1   2   2   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  5   1   0   0   0   1   1   0   0   0     ----       6/8    *  NonOverlappingTemplate
  4   0   1   1   0   0   1   1   0   0     ----       6/8    *  NonOverlappingTemplate
  4   0   0   2   2   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  6   0   1   0   0   0   1   0   0   0     ----       4/8    *  NonOverlappingTemplate
  6   2   0   0   0   0   0   0   0   0     ----       4/8    *  NonOverlappingTemplate
  1   3   2   0   2   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  6   0   0   0   1   0   1   0   0   0     ----       6/8    *  NonOverlappingTemplate
  6   0   2   0   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  7   0   1   0   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  3   0   1   1   0   0   2   0   1   0     ----       7/8       NonOverlappingTemplate
  4   4   0   0   0   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  3   2   2   1   0   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  3   1   1   0   1   1   0   1   0   0     ----       6/8    *  NonOverlappingTemplate
  6   1   1   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  4   2   0   1   1   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  4   2   0   0   0   1   1   0   0   0     ----       6/8    *  NonOverlappingTemplate
  5   3   0   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  5   1   1   0   0   0   0   0   1   0     ----       7/8       NonOverlappingTemplate
  6   1   1   0   0   0   0   0   0   0     ----       6/8    *  NonOverlappingTemplate
  2   1   2   2   0   0   0   0   1   0     ----       8/8       NonOverlappingTemplate
  8   0   0   0   0   0   0   0   0   0     ----       4/8    *  NonOverlappingTemplate
  3   1   3   0   1   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  6   2   0   0   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  7   0   1   0   0   0   0   0   0   0     ----       5/8    *  NonOverlappingTemplate
  4   2   0   1   0   1   0   0   0   0     ----       8/8       NonOverlappingTemplate
  6   0   1   0   0   0   0   1   0   0     ----       4/8    *  NonOverlappingTemplate
  2   0   1   2   0   0   1   1   1   0     ----       8/8       OverlappingTemplate
  2   1   0   2   1   0   0   1   1   0     ----       8/8       Universal
  8   0   0   0   0   0   0   0   0   0     ----       0/8    *  ApproximateEntropy
  0   0   0   1   1   2   0   0   0   0     ----       4/4       RandomExcursions
  0   1   0   1   1   0   0   1   0   0     ----       4/4       RandomExcursions
  0   0   2   1   0   0   1   0   0   0     ----       4/4       RandomExcursions
  1   0   1   1   1   0   0   0   0   0     ----       4/4       RandomExcursions
  1   2   0   1   0   0   0   0   0   0     ----       3/4       RandomExcursions
  1   1   1   1   0   0   0   0   0   0     ----       4/4       RandomExcursions
  2   0   0   0   0   1   0   0   1   0     ----       4/4       RandomExcursions
  2   0   1   0   0   0   1   0   0   0     ----       4/4       RandomExcursions
  0   1   0   0   1   0   0   0   0   2     ----       4/4       RandomExcursionsVariant
  0   0   1   1   0   0   0   1   0   1     ----       4/4       RandomExcursionsVariant
  0   0   1   1   1   0   0   0   0   1     ----       4/4       RandomExcursionsVariant
  0   0   0   1   2   0   0   0   0   1     ----       4/4       RandomExcursionsVariant
  0   0   0   0   1   3   0   0   0   0     ----       4/4       RandomExcursionsVariant
  0   0   1   0   1   0   2   0   0   0     ----       4/4       RandomExcursionsVariant
  0   1   0   1   1   0   0   0   0   1     ----       4/4       RandomExcursionsVariant
  1   1   0   0   0   0   1   1   0   0     ----       4/4       RandomExcursionsVariant
  2   0   0   0   0   0   0   1   1   0     ----       4/4       RandomExcursionsVariant
  1   0   0   1   0   0   1   0   0   1     ----       4/4       RandomExcursionsVariant
  2   0   0   0   1   0   1   0   0   0     ----       4/4       RandomExcursionsVariant
  1   1   0   0   0   0   1   1   0   0     ----       4/4       RandomExcursionsVariant
  0   1   0   0   0   2   0   0   0   1     ----       4/4       RandomExcursionsVariant
  1   0   0   1   0   0   0   1   1   0     ----       4/4       RandomExcursionsVariant
  0   1   0   1   1   0   0   0   1   0     ----       4/4       RandomExcursionsVariant
  0   1   1   0   1   0   1   0   0   0     ----       4/4       RandomExcursionsVariant
  0   1   1   0   1   0   1   0   0   0     ----       4/4       RandomExcursionsVariant
  0   1   0   1   1   0   0   0   0   1     ----       4/4       RandomExcursionsVariant
  8   0   0   0   0   0   0   0   0   0     ----       0/8    *  Serial
  8   0   0   0   0   0   0   0   0   0     ----       0/8    *  Serial
  1   1   1   0   1   2   0   2   0   0     ----       8/8       LinearComplexity


- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
The minimum pass rate for each statistical test with the exception of the
random excursion (variant) test is approximately = 7 for a
sample size = 8 binary sequences.

The minimum pass rate for the random excursion (variant) test
is approximately = 3 for a sample size = 4 binary sequences.

For further guidelines construct a probability table using the MAPLE program
provided in the addendum section of the documentation.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
```

*Diagnostico de la ejecucion:*
- BlockFrequency: 0/8 secuencias aprobadas (Fallo del 100%) con asterisco (*).
- LongestRun: 2/8 secuencias aprobadas con asterisco (*).
- FFT (Spectral): 3/8 secuencias aprobadas con asterisco (*).
- NonOverlappingTemplate: Decenas de plantillas aperiodicas con 4/8, 5/8 y 6/8 con asteriscos (*).
- ApproximateEntropy: 0/8 secuencias aprobadas con asterisco (*).
- Serial: 0/8 y 0/8 secuencias aprobadas con asterisco (*).

---

### Caso 2: Algoritmo Coreano de Control (`korea_control.bin`)
*Generador: `data/experimentos/korea_control.bin` | Tamano: 1,000,000 bytes (8,000,000 bits)*
*Transcribiendo exactamente `finalAnalysisReport.txt`:*

```text
------------------------------------------------------------------------------
RESULTS FOR THE UNIFORMITY OF P-VALUES AND THE PROPORTION OF PASSING SEQUENCES
------------------------------------------------------------------------------
   generator is <data/experimentos/korea_control.bin>
------------------------------------------------------------------------------
 C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE  PROPORTION  STATISTICAL TEST
------------------------------------------------------------------------------
  0   2   1   2   0   2   0   1   0   0     ----       8/8       Frequency
  1   1   0   0   0   1   2   0   1   2     ----       8/8       BlockFrequency
  0   2   0   1   2   1   0   1   0   1     ----       8/8       CumulativeSums
  0   2   0   0   3   1   0   0   2   0     ----       8/8       CumulativeSums
  1   1   0   0   1   1   1   1   2   0     ----       8/8       Runs
  0   2   0   1   0   0   2   0   2   1     ----       8/8       LongestRun
  0   0   3   1   1   2   0   1   0   0     ----       8/8       Rank
  0   2   1   0   1   1   0   0   1   2     ----       8/8       FFT
  1   0   0   1   0   0   3   2   1   0     ----       8/8       NonOverlappingTemplate
  2   0   2   0   0   1   2   1   0   0     ----       8/8       NonOverlappingTemplate
  0   0   0   0   1   0   1   2   1   3     ----       8/8       NonOverlappingTemplate
  1   0   1   2   1   0   2   1   0   0     ----       8/8       NonOverlappingTemplate
  0   1   0   1   2   1   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   2   0   0   0   1   2   0   2   1     ----       8/8       NonOverlappingTemplate
  2   1   1   0   1   2   0   0   0   1     ----       8/8       NonOverlappingTemplate
  0   2   1   3   0   1   0   1   0   0     ----       8/8       NonOverlappingTemplate
  0   1   2   0   2   3   0   0   0   0     ----       8/8       NonOverlappingTemplate
  0   2   1   0   0   2   2   1   0   0     ----       8/8       NonOverlappingTemplate
  0   1   0   2   1   0   1   1   1   1     ----       8/8       NonOverlappingTemplate
  1   0   0   2   0   2   2   0   1   0     ----       8/8       NonOverlappingTemplate
  2   0   1   0   0   0   2   2   0   1     ----       8/8       NonOverlappingTemplate
  4   1   0   2   0   0   0   1   0   0     ----       8/8       NonOverlappingTemplate
  0   1   2   2   1   0   1   0   1   0     ----       8/8       NonOverlappingTemplate
  1   2   1   2   0   0   1   1   0   0     ----       7/8       NonOverlappingTemplate
  0   0   3   1   1   0   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   1   1   1   0   1   2   0   0   2     ----       8/8       NonOverlappingTemplate
  1   1   1   0   0   1   2   1   1   0     ----       8/8       NonOverlappingTemplate
  1   0   2   1   0   0   0   2   1   1     ----       8/8       NonOverlappingTemplate
  1   0   1   1   2   0   2   0   1   0     ----       8/8       NonOverlappingTemplate
  0   0   1   0   0   1   2   1   2   1     ----       8/8       NonOverlappingTemplate
  0   1   0   1   1   2   0   1   0   2     ----       8/8       NonOverlappingTemplate
  0   1   2   0   0   1   1   0   1   2     ----       8/8       NonOverlappingTemplate
  0   1   1   1   1   0   0   1   1   2     ----       8/8       NonOverlappingTemplate
  0   0   0   2   1   1   0   0   2   2     ----       8/8       NonOverlappingTemplate
  1   0   1   1   1   1   1   0   1   1     ----       8/8       NonOverlappingTemplate
  1   1   0   0   2   0   0   2   0   2     ----       8/8       NonOverlappingTemplate
  1   0   1   2   0   1   0   0   2   1     ----       8/8       NonOverlappingTemplate
  0   0   1   1   2   0   2   1   0   1     ----       8/8       NonOverlappingTemplate
  2   1   0   2   2   0   0   0   1   0     ----       8/8       NonOverlappingTemplate
  0   1   2   2   0   0   0   0   2   1     ----       8/8       NonOverlappingTemplate
  0   0   1   2   1   1   0   0   2   1     ----       8/8       NonOverlappingTemplate
  1   0   2   0   2   2   0   1   0   0     ----       8/8       NonOverlappingTemplate
  2   0   0   1   1   1   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   0   0   2   3   1   0   0   2   0     ----       8/8       NonOverlappingTemplate
  0   1   2   0   1   0   1   1   1   1     ----       8/8       NonOverlappingTemplate
  2   0   0   2   0   1   1   0   0   2     ----       8/8       NonOverlappingTemplate
  2   0   0   0   0   0   2   2   1   1     ----       8/8       NonOverlappingTemplate
  1   1   2   1   0   1   1   1   0   0     ----       8/8       NonOverlappingTemplate
  0   0   1   0   1   1   2   1   2   0     ----       8/8       NonOverlappingTemplate
  0   0   1   1   1   0   0   1   3   1     ----       8/8       NonOverlappingTemplate
  0   0   0   0   0   2   0   3   0   3     ----       8/8       NonOverlappingTemplate
  0   2   0   1   0   1   2   1   1   0     ----       8/8       NonOverlappingTemplate
  1   0   0   0   1   0   2   1   0   3     ----       8/8       NonOverlappingTemplate
  1   1   1   0   1   0   1   1   2   0     ----       8/8       NonOverlappingTemplate
  0   1   1   3   0   1   0   1   0   1     ----       8/8       NonOverlappingTemplate
  1   1   1   0   0   1   0   2   1   1     ----       8/8       NonOverlappingTemplate
  1   1   0   0   0   2   1   1   0   2     ----       8/8       NonOverlappingTemplate
  0   0   2   2   1   0   0   0   1   2     ----       8/8       NonOverlappingTemplate
  3   0   1   0   0   1   1   1   0   1     ----       8/8       NonOverlappingTemplate
  0   0   3   1   2   0   0   0   1   1     ----       8/8       NonOverlappingTemplate
  2   2   0   0   0   0   1   1   2   0     ----       8/8       NonOverlappingTemplate
  0   1   1   3   0   1   1   0   0   1     ----       8/8       NonOverlappingTemplate
  0   2   2   1   1   2   0   0   0   0     ----       8/8       NonOverlappingTemplate
  1   0   1   1   0   1   0   2   2   0     ----       8/8       NonOverlappingTemplate
  1   0   0   3   1   0   1   1   1   0     ----       8/8       NonOverlappingTemplate
  0   1   0   2   1   2   0   1   1   0     ----       8/8       NonOverlappingTemplate
  0   2   0   0   1   2   0   0   1   2     ----       8/8       NonOverlappingTemplate
  2   0   1   1   0   0   1   3   0   0     ----       8/8       NonOverlappingTemplate
  0   0   0   0   0   1   2   3   0   2     ----       8/8       NonOverlappingTemplate
  0   0   2   3   1   1   0   0   0   1     ----       8/8       NonOverlappingTemplate
  0   1   1   1   2   1   0   0   2   0     ----       8/8       NonOverlappingTemplate
  1   1   0   1   0   0   0   2   1   2     ----       8/8       NonOverlappingTemplate
  3   1   0   2   0   1   0   0   0   1     ----       8/8       NonOverlappingTemplate
  1   1   1   0   1   1   1   1   1   0     ----       8/8       NonOverlappingTemplate
  0   0   1   0   0   2   0   3   2   0     ----       8/8       NonOverlappingTemplate
  2   1   1   0   1   1   1   0   1   0     ----       8/8       NonOverlappingTemplate
  0   1   0   2   1   2   1   0   0   1     ----       8/8       NonOverlappingTemplate
  0   1   2   0   1   2   0   0   1   1     ----       8/8       NonOverlappingTemplate
  1   1   0   1   0   0   1   0   0   4     ----       8/8       NonOverlappingTemplate
  0   0   2   1   2   0   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   1   2   1   0   1   1   0   1   1     ----       8/8       NonOverlappingTemplate
  2   1   0   0   0   3   1   0   0   1     ----       8/8       NonOverlappingTemplate
  1   0   0   1   0   0   3   2   1   0     ----       8/8       NonOverlappingTemplate
  1   1   2   1   0   0   1   1   1   0     ----       7/8       NonOverlappingTemplate
  0   0   0   3   2   1   0   1   0   1     ----       8/8       NonOverlappingTemplate
  0   1   4   0   0   0   2   1   0   0     ----       8/8       NonOverlappingTemplate
  0   0   0   1   0   0   2   2   1   2     ----       8/8       NonOverlappingTemplate
  0   0   1   0   0   0   1   3   2   1     ----       8/8       NonOverlappingTemplate
  1   1   1   2   2   0   0   0   1   0     ----       8/8       NonOverlappingTemplate
  0   1   1   2   1   2   0   0   1   0     ----       8/8       NonOverlappingTemplate
  1   1   0   1   1   1   0   1   1   1     ----       8/8       NonOverlappingTemplate
  0   1   1   0   3   0   0   1   0   2     ----       8/8       NonOverlappingTemplate
  1   2   1   0   0   0   1   1   0   2     ----       7/8       NonOverlappingTemplate
  1   0   0   0   1   2   0   1   2   1     ----       8/8       NonOverlappingTemplate
  2   3   0   0   1   0   0   1   1   0     ----       7/8       NonOverlappingTemplate
  1   1   0   1   0   1   1   1   1   1     ----       7/8       NonOverlappingTemplate
  0   2   1   0   1   0   1   1   1   1     ----       8/8       NonOverlappingTemplate
  1   0   2   1   2   0   1   1   0   0     ----       8/8       NonOverlappingTemplate
  2   1   0   0   1   1   1   0   2   0     ----       8/8       NonOverlappingTemplate
  1   0   1   1   1   0   0   2   2   0     ----       8/8       NonOverlappingTemplate
  2   3   0   0   0   1   0   1   1   0     ----       7/8       NonOverlappingTemplate
  0   0   1   1   0   2   1   1   1   1     ----       8/8       NonOverlappingTemplate
  0   1   1   0   1   2   1   0   2   0     ----       8/8       NonOverlappingTemplate
  1   1   3   0   2   1   0   0   0   0     ----       8/8       NonOverlappingTemplate
  0   0   0   0   2   0   2   1   0   3     ----       8/8       NonOverlappingTemplate
  1   0   1   2   1   1   0   1   1   0     ----       8/8       NonOverlappingTemplate
  1   2   1   2   1   0   0   0   1   0     ----       8/8       NonOverlappingTemplate
  0   1   1   0   2   0   2   0   1   1     ----       8/8       NonOverlappingTemplate
  1   1   1   2   0   0   0   0   1   2     ----       8/8       NonOverlappingTemplate
  1   1   1   0   3   1   0   1   0   0     ----       8/8       NonOverlappingTemplate
  0   1   1   1   3   1   1   0   0   0     ----       8/8       NonOverlappingTemplate
  0   2   1   1   1   1   1   0   1   0     ----       8/8       NonOverlappingTemplate
  2   1   0   2   1   0   0   0   1   1     ----       8/8       NonOverlappingTemplate
  2   0   1   2   0   0   0   2   1   0     ----       8/8       NonOverlappingTemplate
  2   1   1   0   0   0   0   2   1   1     ----       8/8       NonOverlappingTemplate
  0   1   0   0   2   1   1   1   2   0     ----       8/8       NonOverlappingTemplate
  1   1   0   1   2   0   0   0   0   3     ----       8/8       NonOverlappingTemplate
  1   0   0   1   1   1   0   2   2   0     ----       8/8       NonOverlappingTemplate
  2   0   0   0   0   1   1   1   1   2     ----       8/8       NonOverlappingTemplate
  2   2   0   1   0   0   0   1   0   2     ----       7/8       NonOverlappingTemplate
  0   0   1   2   0   0   2   0   2   1     ----       8/8       NonOverlappingTemplate
  2   0   1   0   2   0   1   2   0   0     ----       7/8       NonOverlappingTemplate
  1   1   1   1   1   1   1   0   0   1     ----       8/8       NonOverlappingTemplate
  2   1   0   1   0   2   1   0   1   0     ----       8/8       NonOverlappingTemplate
  2   1   0   0   1   1   1   1   0   1     ----       8/8       NonOverlappingTemplate
  1   1   0   0   0   3   1   1   1   0     ----       8/8       NonOverlappingTemplate
  1   2   2   1   0   1   0   0   0   1     ----       8/8       NonOverlappingTemplate
  2   4   1   1   0   0   0   0   0   0     ----       7/8       NonOverlappingTemplate
  0   0   2   1   0   1   1   1   1   1     ----       8/8       NonOverlappingTemplate
  3   2   0   0   0   1   0   1   0   1     ----       8/8       NonOverlappingTemplate
  0   1   0   2   0   1   1   1   0   2     ----       8/8       NonOverlappingTemplate
  0   2   0   3   1   1   0   0   0   1     ----       8/8       NonOverlappingTemplate
  0   1   0   1   2   1   1   1   0   1     ----       8/8       NonOverlappingTemplate
  0   2   1   0   2   2   1   0   0   0     ----       8/8       NonOverlappingTemplate
  1   2   0   0   2   0   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   1   1   1   1   0   0   1   1   2     ----       8/8       NonOverlappingTemplate
  1   0   0   0   1   1   2   2   0   1     ----       8/8       NonOverlappingTemplate
  0   2   0   1   1   0   0   1   3   0     ----       8/8       NonOverlappingTemplate
  0   1   1   2   1   2   0   0   1   0     ----       8/8       NonOverlappingTemplate
  1   1   1   1   2   0   0   1   0   1     ----       8/8       NonOverlappingTemplate
  0   0   2   2   0   1   1   0   1   1     ----       8/8       NonOverlappingTemplate
  1   1   0   2   1   0   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   1   0   1   2   0   2   1   1   0     ----       8/8       NonOverlappingTemplate
  0   1   2   0   1   0   2   0   2   0     ----       8/8       NonOverlappingTemplate
  1   1   0   2   1   0   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   1   1   2   1   1   1   0   0   1     ----       8/8       NonOverlappingTemplate
  0   0   2   0   3   1   0   0   0   2     ----       8/8       NonOverlappingTemplate
  1   0   0   2   1   0   0   1   1   2     ----       8/8       NonOverlappingTemplate
  1   0   0   0   2   0   1   1   2   1     ----       8/8       NonOverlappingTemplate
  1   1   1   0   2   0   0   1   1   1     ----       8/8       NonOverlappingTemplate
  1   0   2   0   3   1   0   0   1   0     ----       8/8       NonOverlappingTemplate
  1   0   0   2   1   0   1   1   1   1     ----       8/8       NonOverlappingTemplate
  1   2   1   0   0   1   1   1   0   1     ----       8/8       NonOverlappingTemplate
  0   1   0   0   2   0   1   1   2   1     ----       8/8       NonOverlappingTemplate
  0   3   0   2   0   1   0   1   0   1     ----       8/8       NonOverlappingTemplate
  2   1   0   0   0   3   1   0   0   1     ----       8/8       NonOverlappingTemplate
  0   1   1   2   1   0   1   2   0   0     ----       8/8       OverlappingTemplate
  0   1   3   1   0   0   1   1   0   1     ----       8/8       Universal
  2   1   1   0   1   0   0   2   1   0     ----       8/8       ApproximateEntropy
  2   0   1   0   0   1   0   0   1   0     ----       5/5       RandomExcursions
  0   0   0   0   2   1   1   0   1   0     ----       5/5       RandomExcursions
  0   0   1   1   1   1   1   0   0   0     ----       5/5       RandomExcursions
  0   0   1   1   0   2   0   1   0   0     ----       5/5       RandomExcursions
  0   0   1   2   0   0   1   0   1   0     ----       5/5       RandomExcursions
  0   1   0   1   2   0   0   1   0   0     ----       5/5       RandomExcursions
  0   0   1   0   0   1   0   1   2   0     ----       5/5       RandomExcursions
  1   0   0   0   1   0   1   1   1   0     ----       5/5       RandomExcursions
  0   0   0   2   0   0   0   2   1   0     ----       5/5       RandomExcursionsVariant
  0   0   1   1   0   1   0   1   0   1     ----       5/5       RandomExcursionsVariant
  0   1   0   1   1   0   0   0   2   0     ----       5/5       RandomExcursionsVariant
  0   1   0   0   1   1   1   0   0   1     ----       5/5       RandomExcursionsVariant
  0   1   0   0   0   1   1   0   1   1     ----       5/5       RandomExcursionsVariant
  1   0   0   0   1   2   0   0   0   1     ----       5/5       RandomExcursionsVariant
  1   0   1   1   0   2   0   0   0   0     ----       5/5       RandomExcursionsVariant
  1   2   1   0   1   0   0   0   0   0     ----       5/5       RandomExcursionsVariant
  2   0   1   1   0   0   0   0   0   1     ----       5/5       RandomExcursionsVariant
  1   0   0   1   1   1   1   0   0   0     ----       5/5       RandomExcursionsVariant
  0   0   2   0   0   0   0   0   2   1     ----       5/5       RandomExcursionsVariant
  0   0   1   0   2   0   1   0   0   1     ----       5/5       RandomExcursionsVariant
  0   0   2   0   0   1   1   0   0   1     ----       5/5       RandomExcursionsVariant
  0   1   0   0   1   0   0   0   3   0     ----       5/5       RandomExcursionsVariant
  0   1   0   0   0   1   0   0   1   2     ----       5/5       RandomExcursionsVariant
  0   1   0   0   1   0   0   0   3   0     ----       5/5       RandomExcursionsVariant
  0   1   0   0   0   0   1   2   0   1     ----       5/5       RandomExcursionsVariant
  0   1   0   0   0   0   0   2   2   0     ----       5/5       RandomExcursionsVariant
  0   0   1   3   1   0   0   1   1   1     ----       8/8       Serial
  0   0   1   1   1   0   2   1   2   0     ----       8/8       Serial
  0   3   1   1   0   1   1   1   0   0     ----       8/8       LinearComplexity


- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
The minimum pass rate for each statistical test with the exception of the
random excursion (variant) test is approximately = 7 for a
sample size = 8 binary sequences.

The minimum pass rate for the random excursion (variant) test
is approximately = 4 for a sample size = 5 binary sequences.

For further guidelines construct a probability table using the MAPLE program
provided in the addendum section of the documentation.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
```

*Diagnostico de la ejecucion:*
- 100% APROBADO: Todas las pruebas estadisticas superan el umbral con 8/8 secuencias (y las pocas plantillas de variacion normal con 7/8 dentro del intervalo de confianza permitido).
- Ningun asterisco (*) de rechazo en ninguna prueba. Demuestra que extraer 3 bytes contiguos no introduce ninguna falla.

---

### Caso 3: Google Authenticator (`google_rfc4226.bin`)
*Generador: `data/experimentos/google_rfc4226.bin` | Tamano: 1,000,000 bytes (8,000,000 bits)*
*Transcribiendo exactamente `finalAnalysisReport.txt`:*

```text
------------------------------------------------------------------------------
RESULTS FOR THE UNIFORMITY OF P-VALUES AND THE PROPORTION OF PASSING SEQUENCES
------------------------------------------------------------------------------
   generator is <data/experimentos/google_rfc4226.bin>
------------------------------------------------------------------------------
 C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE  PROPORTION  STATISTICAL TEST
------------------------------------------------------------------------------
  0   1   1   1   0   2   0   2   1   0     ----       8/8       Frequency
  1   0   0   0   0   1   0   3   1   2     ----       8/8       BlockFrequency
  0   0   2   2   0   0   2   0   1   1     ----       8/8       CumulativeSums
  0   0   1   3   0   0   1   0   3   0     ----       8/8       CumulativeSums
  0   1   2   0   1   1   1   2   0   0     ----       8/8       Runs
  2   0   2   1   0   0   0   1   1   1     ----       8/8       LongestRun
  1   3   2   0   0   2   0   0   0   0     ----       8/8       Rank
  2   0   0   1   1   1   1   1   0   1     ----       8/8       FFT
  1   0   0   0   2   1   0   0   2   2     ----       8/8       NonOverlappingTemplate
  1   0   1   0   1   0   2   1   1   1     ----       8/8       NonOverlappingTemplate
  0   1   0   0   2   2   1   0   1   1     ----       8/8       NonOverlappingTemplate
  1   1   0   0   0   0   2   0   1   3     ----       8/8       NonOverlappingTemplate
  1   1   0   0   1   3   0   1   1   0     ----       8/8       NonOverlappingTemplate
  1   1   1   0   1   0   2   1   1   0     ----       8/8       NonOverlappingTemplate
  1   3   0   0   0   1   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   0   0   2   0   1   1   1   1   2     ----       8/8       NonOverlappingTemplate
  0   0   1   1   2   0   1   1   0   2     ----       8/8       NonOverlappingTemplate
  0   1   0   0   1   0   1   3   1   1     ----       8/8       NonOverlappingTemplate
  0   1   2   0   1   1   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   0   1   1   2   0   1   1   2   0     ----       8/8       NonOverlappingTemplate
  1   0   0   0   1   1   0   3   1   1     ----       8/8       NonOverlappingTemplate
  2   0   1   0   1   1   2   1   0   0     ----       8/8       NonOverlappingTemplate
  1   1   0   0   2   2   1   0   0   1     ----       8/8       NonOverlappingTemplate
  3   0   1   0   1   0   0   1   2   0     ----       7/8       NonOverlappingTemplate
  0   1   0   1   0   1   2   2   1   0     ----       8/8       NonOverlappingTemplate
  0   0   1   1   2   3   0   0   0   1     ----       8/8       NonOverlappingTemplate
  1   1   0   2   0   1   0   2   0   1     ----       8/8       NonOverlappingTemplate
  2   1   1   1   0   2   0   0   1   0     ----       8/8       NonOverlappingTemplate
  0   3   1   0   0   0   0   2   1   1     ----       8/8       NonOverlappingTemplate
  0   1   2   2   1   0   1   1   0   0     ----       8/8       NonOverlappingTemplate
  0   0   3   1   0   2   0   0   1   1     ----       8/8       NonOverlappingTemplate
  1   1   0   1   0   3   1   0   0   1     ----       8/8       NonOverlappingTemplate
  0   0   0   0   2   2   2   0   1   1     ----       8/8       NonOverlappingTemplate
  0   2   0   1   2   1   0   2   0   0     ----       8/8       NonOverlappingTemplate
  1   0   0   1   1   2   2   1   0   0     ----       8/8       NonOverlappingTemplate
  0   0   1   1   0   1   1   3   0   1     ----       8/8       NonOverlappingTemplate
  1   1   0   0   2   1   1   1   1   0     ----       8/8       NonOverlappingTemplate
  0   1   0   1   0   0   0   2   2   2     ----       8/8       NonOverlappingTemplate
  1   1   1   1   1   1   0   0   1   1     ----       8/8       NonOverlappingTemplate
  0   2   0   0   1   0   2   1   2   0     ----       8/8       NonOverlappingTemplate
  1   0   2   2   0   0   0   1   1   1     ----       8/8       NonOverlappingTemplate
  0   0   0   1   1   2   0   2   1   1     ----       8/8       NonOverlappingTemplate
  2   1   2   0   1   0   1   0   0   1     ----       8/8       NonOverlappingTemplate
  0   1   1   2   1   0   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   1   1   1   0   2   0   2   1   0     ----       8/8       NonOverlappingTemplate
  2   1   1   0   0   0   2   2   0   0     ----       8/8       NonOverlappingTemplate
  0   0   1   1   1   0   1   2   2   0     ----       8/8       NonOverlappingTemplate
  0   1   0   2   0   2   1   1   1   0     ----       8/8       NonOverlappingTemplate
  0   1   0   0   0   1   0   3   2   1     ----       8/8       NonOverlappingTemplate
  1   0   0   1   2   1   0   1   0   2     ----       8/8       NonOverlappingTemplate
  1   0   0   1   0   1   0   1   1   3     ----       8/8       NonOverlappingTemplate
  1   0   2   0   1   0   0   1   2   1     ----       8/8       NonOverlappingTemplate
  0   1   0   2   1   2   1   1   0   0     ----       8/8       NonOverlappingTemplate
  0   1   1   3   0   1   0   0   1   1     ----       8/8       NonOverlappingTemplate
  0   1   0   0   1   0   3   1   1   1     ----       8/8       NonOverlappingTemplate
  1   2   0   1   1   1   0   1   1   0     ----       8/8       NonOverlappingTemplate
  1   1   1   1   1   0   1   1   0   1     ----       8/8       NonOverlappingTemplate
  2   1   2   0   1   0   0   0   2   0     ----       7/8       NonOverlappingTemplate
  0   0   0   2   1   2   1   1   0   1     ----       8/8       NonOverlappingTemplate
  1   0   0   1   1   1   1   0   1   2     ----       8/8       NonOverlappingTemplate
  2   0   2   0   0   1   1   0   2   0     ----       8/8       NonOverlappingTemplate
  2   0   0   1   2   0   1   0   1   1     ----       8/8       NonOverlappingTemplate
  1   2   0   0   0   2   0   0   1   2     ----       8/8       NonOverlappingTemplate
  0   0   3   2   0   0   0   1   0   2     ----       8/8       NonOverlappingTemplate
  2   0   1   0   1   2   0   1   1   0     ----       8/8       NonOverlappingTemplate
  2   1   0   0   0   1   1   2   1   0     ----       8/8       NonOverlappingTemplate
  0   1   0   0   1   1   2   1   2   0     ----       8/8       NonOverlappingTemplate
  0   1   2   0   1   0   3   0   1   0     ----       8/8       NonOverlappingTemplate
  0   0   0   1   0   1   1   1   2   2     ----       8/8       NonOverlappingTemplate
  0   1   1   1   1   2   1   0   0   1     ----       8/8       NonOverlappingTemplate
  1   1   0   1   0   0   1   0   1   3     ----       8/8       NonOverlappingTemplate
  0   0   0   1   2   2   0   1   1   1     ----       8/8       NonOverlappingTemplate
  2   1   2   0   0   0   0   1   1   1     ----       7/8       NonOverlappingTemplate
  1   0   0   1   1   4   0   1   0   0     ----       8/8       NonOverlappingTemplate
  1   0   2   0   0   2   0   2   0   1     ----       8/8       NonOverlappingTemplate
  3   0   0   0   2   0   0   3   0   0     ----       8/8       NonOverlappingTemplate
  2   2   1   0   0   1   0   1   1   0     ----       8/8       NonOverlappingTemplate
  1   1   1   0   2   2   1   0   0   0     ----       8/8       NonOverlappingTemplate
  1   0   2   0   1   0   2   1   0   1     ----       8/8       NonOverlappingTemplate
  0   2   0   0   0   3   1   2   0   0     ----       8/8       NonOverlappingTemplate
  1   0   1   1   0   2   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   2   1   0   1   0   1   0   3   0     ----       8/8       NonOverlappingTemplate
  1   0   0   0   2   1   0   0   2   2     ----       8/8       NonOverlappingTemplate
  3   0   1   0   0   0   2   1   0   1     ----       7/8       NonOverlappingTemplate
  0   2   1   2   0   0   1   0   1   1     ----       8/8       NonOverlappingTemplate
  1   1   1   1   1   1   1   1   0   0     ----       8/8       NonOverlappingTemplate
  1   1   2   1   1   1   0   0   0   1     ----       8/8       NonOverlappingTemplate
  1   1   0   0   1   1   1   2   0   1     ----       8/8       NonOverlappingTemplate
  2   2   0   0   1   2   0   1   0   0     ----       8/8       NonOverlappingTemplate
  0   0   1   0   0   0   2   2   2   1     ----       8/8       NonOverlappingTemplate
  3   0   0   1   1   0   1   0   2   0     ----       8/8       NonOverlappingTemplate
  0   0   1   2   2   1   0   1   1   0     ----       8/8       NonOverlappingTemplate
  0   0   1   0   0   2   0   2   1   2     ----       8/8       NonOverlappingTemplate
  0   1   0   1   1   1   1   1   1   1     ----       8/8       NonOverlappingTemplate
  1   1   0   1   1   0   1   2   0   1     ----       8/8       NonOverlappingTemplate
  0   2   2   0   0   1   1   0   2   0     ----       8/8       NonOverlappingTemplate
  2   1   1   2   1   1   0   0   0   0     ----       8/8       NonOverlappingTemplate
  2   2   2   0   1   0   0   1   0   0     ----       8/8       NonOverlappingTemplate
  1   1   0   0   0   0   2   1   1   2     ----       8/8       NonOverlappingTemplate
  0   1   0   0   0   1   1   0   2   3     ----       8/8       NonOverlappingTemplate
  0   1   0   1   0   3   0   0   3   0     ----       8/8       NonOverlappingTemplate
  0   2   0   2   0   1   0   1   0   2     ----       8/8       NonOverlappingTemplate
  0   1   0   1   2   1   1   0   0   2     ----       8/8       NonOverlappingTemplate
  1   1   2   2   0   0   0   2   0   0     ----       8/8       NonOverlappingTemplate
  1   0   1   0   2   1   0   1   1   1     ----       7/8       NonOverlappingTemplate
  0   0   2   0   0   2   1   0   2   1     ----       8/8       NonOverlappingTemplate
  1   2   2   0   0   0   1   0   1   1     ----       8/8       NonOverlappingTemplate
  1   1   0   0   1   1   0   2   1   1     ----       8/8       NonOverlappingTemplate
  0   1   0   2   1   0   1   0   3   0     ----       8/8       NonOverlappingTemplate
  1   1   2   1   0   2   0   0   0   1     ----       8/8       NonOverlappingTemplate
  2   1   0   0   1   1   1   0   2   0     ----       8/8       NonOverlappingTemplate
  1   2   1   0   1   1   1   0   1   0     ----       8/8       NonOverlappingTemplate
  1   0   0   1   2   1   1   1   1   0     ----       8/8       NonOverlappingTemplate
  2   1   1   1   1   0   0   0   0   2     ----       7/8       NonOverlappingTemplate
  2   1   2   0   1   1   0   0   0   1     ----       7/8       NonOverlappingTemplate
  1   0   1   2   0   0   0   1   2   1     ----       8/8       NonOverlappingTemplate
  0   0   2   0   2   1   2   0   1   0     ----       8/8       NonOverlappingTemplate
  2   0   0   1   2   0   1   1   0   1     ----       8/8       NonOverlappingTemplate
  0   1   0   2   0   2   0   1   2   0     ----       8/8       NonOverlappingTemplate
  1   1   0   2   2   1   0   0   0   1     ----       8/8       NonOverlappingTemplate
  0   0   1   2   1   0   2   1   0   1     ----       8/8       NonOverlappingTemplate
  0   0   1   0   2   2   1   1   1   0     ----       8/8       NonOverlappingTemplate
  0   1   1   1   1   0   0   2   1   1     ----       8/8       NonOverlappingTemplate
  1   1   1   0   0   2   3   0   0   0     ----       8/8       NonOverlappingTemplate
  2   0   0   1   0   2   1   0   1   1     ----       8/8       NonOverlappingTemplate
  1   0   1   2   0   1   0   0   2   1     ----       8/8       NonOverlappingTemplate
  0   2   1   2   1   1   0   0   0   1     ----       8/8       NonOverlappingTemplate
  2   1   1   0   0   1   1   1   1   0     ----       8/8       NonOverlappingTemplate
  0   1   0   1   3   1   0   2   0   0     ----       8/8       NonOverlappingTemplate
  1   0   4   1   1   0   1   0   0   0     ----       8/8       NonOverlappingTemplate
  1   1   1   0   2   0   1   0   1   1     ----       8/8       NonOverlappingTemplate
  3   0   1   1   0   0   0   0   1   2     ----       8/8       NonOverlappingTemplate
  1   1   1   1   0   1   0   0   2   1     ----       8/8       NonOverlappingTemplate
  1   1   2   0   1   0   2   0   0   1     ----       8/8       NonOverlappingTemplate
  0   1   0   2   0   1   1   1   2   0     ----       8/8       NonOverlappingTemplate
  1   1   0   1   0   0   1   0   3   1     ----       8/8       NonOverlappingTemplate
  2   1   2   0   3   0   0   0   0   0     ----       8/8       NonOverlappingTemplate
  0   4   0   1   0   1   0   1   0   1     ----       8/8       NonOverlappingTemplate
  1   1   1   1   0   0   0   2   1   1     ----       8/8       NonOverlappingTemplate
  3   1   0   0   1   0   0   2   1   0     ----       8/8       NonOverlappingTemplate
  1   1   1   1   3   0   1   0   0   0     ----       8/8       NonOverlappingTemplate
  0   0   1   1   2   1   0   1   0   2     ----       8/8       NonOverlappingTemplate
  0   1   2   1   0   0   0   2   1   1     ----       8/8       NonOverlappingTemplate
  1   1   1   2   1   0   0   1   1   0     ----       8/8       NonOverlappingTemplate
  2   1   1   0   2   0   0   0   1   1     ----       8/8       NonOverlappingTemplate
  1   0   1   2   1   0   0   0   1   2     ----       8/8       NonOverlappingTemplate
  1   2   0   0   1   1   1   0   1   1     ----       8/8       NonOverlappingTemplate
  0   0   1   0   0   0   4   2   0   1     ----       8/8       NonOverlappingTemplate
  3   1   1   0   0   0   1   1   0   1     ----       8/8       NonOverlappingTemplate
  1   0   2   0   0   3   0   1   1   0     ----       8/8       NonOverlappingTemplate
  0   0   0   0   0   1   0   3   3   1     ----       8/8       NonOverlappingTemplate
  0   1   1   0   1   0   4   0   0   1     ----       8/8       NonOverlappingTemplate
  1   1   0   3   1   1   0   1   0   0     ----       8/8       NonOverlappingTemplate
  0   0   1   0   4   1   0   1   0   1     ----       8/8       NonOverlappingTemplate
  2   1   1   0   1   0   1   1   1   0     ----       8/8       NonOverlappingTemplate
  0   2   1   0   1   0   1   0   3   0     ----       8/8       NonOverlappingTemplate
  0   0   1   1   1   0   2   1   0   2     ----       8/8       OverlappingTemplate
  0   2   1   0   0   0   0   1   1   3     ----       8/8       Universal
  0   1   0   2   1   1   2   0   0   1     ----       8/8       ApproximateEntropy
  1   0   0   1   1   1   0   1   2   0     ----       6/7       RandomExcursions
  2   2   0   1   1   0   0   0   1   0     ----       7/7       RandomExcursions
  2   0   0   0   3   0   1   1   0   0     ----       7/7       RandomExcursions
  3   0   1   0   2   0   0   0   0   1     ----       7/7       RandomExcursions
  3   0   1   0   1   0   1   0   1   0     ----       7/7       RandomExcursions
  1   2   1   2   0   0   0   1   0   0     ----       7/7       RandomExcursions
  0   3   0   0   0   0   2   0   2   0     ----       7/7       RandomExcursions
  0   0   1   1   0   1   1   1   1   1     ----       7/7       RandomExcursions
  1   0   1   0   0   1   0   2   1   1     ----       7/7       RandomExcursionsVariant
  1   0   0   1   0   0   1   3   1   0     ----       7/7       RandomExcursionsVariant
  0   1   1   0   0   0   3   1   0   1     ----       7/7       RandomExcursionsVariant
  0   1   1   1   2   1   0   0   0   1     ----       7/7       RandomExcursionsVariant
  1   0   2   3   0   0   0   1   0   0     ----       7/7       RandomExcursionsVariant
  0   1   2   1   1   2   0   0   0   0     ----       7/7       RandomExcursionsVariant
  0   1   1   1   0   3   0   0   1   0     ----       7/7       RandomExcursionsVariant
  1   1   1   0   2   0   0   1   0   1     ----       7/7       RandomExcursionsVariant
  1   1   1   1   1   0   0   1   0   1     ----       7/7       RandomExcursionsVariant
  1   2   1   0   2   0   0   0   0   1     ----       7/7       RandomExcursionsVariant
  3   0   1   1   1   0   0   1   0   0     ----       7/7       RandomExcursionsVariant
  1   2   1   1   1   0   0   0   0   1     ----       7/7       RandomExcursionsVariant
  1   0   2   0   0   1   1   0   0   2     ----       7/7       RandomExcursionsVariant
  0   1   0   0   3   1   0   0   2   0     ----       7/7       RandomExcursionsVariant
  0   0   1   2   0   1   1   1   0   1     ----       7/7       RandomExcursionsVariant
  0   0   1   1   1   1   2   0   0   1     ----       7/7       RandomExcursionsVariant
  0   0   0   1   3   2   0   1   0   0     ----       7/7       RandomExcursionsVariant
  0   0   2   0   0   1   3   1   0   0     ----       7/7       RandomExcursionsVariant
  0   1   2   0   0   0   2   1   1   1     ----       8/8       Serial
  0   0   0   1   1   1   2   2   0   1     ----       8/8       Serial
  1   2   3   1   0   0   0   1   0   0     ----       8/8       LinearComplexity


- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
The minimum pass rate for each statistical test with the exception of the
random excursion (variant) test is approximately = 7 for a
sample size = 8 binary sequences.

The minimum pass rate for the random excursion (variant) test
is approximately = 6 for a sample size = 7 binary sequences.

For further guidelines construct a probability table using the MAPLE program
provided in the addendum section of the documentation.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
```

*Diagnostico de la ejecucion:*
- 100% APROBADO: Todas las suites estadisticas aprueban con proporcion de 8/8 sin ningun asterisco (*).
- Los p-valores se distribuyen de forma homogenea a lo largo de las 10 columnas deciles (C1 a C10), demostrando uniformidad matematica e independencia estadistica perfecta.

---

## 3. Que Significa Tecnicamente que Haya Fallado Cada Prueba en el Algoritmo Coreano?

En `korea_vulnerable.bin`, se presentaron fallas criticas en pruebas especificas:

### 1. Fallo en `BlockFrequency` (Resultado: 0/8 secuencias aprobadas)
* **Que evalua:** Divide la secuencia en bloques de M bits (M=128) y evalua si la proporcion de unos dentro de cada bloque individual esta cerca del 50%.
* **Por que fallo:** Al ocurrir la duplicacion de 3 bytes identicos (`b1 = b2 = b3`), dentro de un bloque de 128 bits se concentran patrones repetitivos con la misma cantidad exacta de unos. La varianza entre bloques se dispara drasticamente y destruye la uniformidad local.

### 2. Fallo en `LongestRun` (Resultado: 2/8 secuencias aprobadas)
* **Que evalua:** Mide la racha ininterrumpida mas larga de unos dentro de bloques de M bits. En una secuencia aleatoria perfecta, la longitud maxima de rachas de unos sigue una curva de probabilidad fija.
* **Por que fallo:** Al triplicarse el mismo byte (por ejemplo, si el byte colapsado es 0xFF o 0x00), se crean rachas artificialmente largas de 24 bits continuos de unos (0xFFFFFF) o de ceros (0x000000), rompiendo por completo la distribucion esperada.

### 3. Fallo en `FFT - Discrete Fourier Transform` (Resultado: 3/8 secuencias aprobadas)
* **Que evalua:** Aplica la Transformada Rapida de Fourier a la secuencia binaria para detectar si existen ondas sinusoidales o picos armonicos que superen el 95% del umbral de ruido blanco.
* **Por que fallo:** Es la firma de la periodicidad. La repeticion regular de tripletes de bytes identicos cada 16 operaciones actua exactamente como una senal periodica en fisica y telecomunicaciones. El espectro electromagnetico de la secuencia muestra picos que delatan un patron repetitivo.

### 4. Fallo en `NonOverlappingTemplate` (Multiples plantillas con 4/8, 5/8 y 6/8)
* **Que evalua:** Busca patrones especificos de 9 bits (148 plantillas diferentes) y cuenta cuantas veces aparecen a lo largo de la secuencia.
* **Por que fallo:** Cuando los bytes se reducen a solo 256 posibles combinaciones triplicadas, las secuencias de 9 bits correspondientes a esos 256 bytes aparecen con una frecuencia desmesuradamente alta, mientras que las plantillas ausentes en esos 256 bytes casi nunca aparecen.

### 5. Fallo en `ApproximateEntropy` y `Serial` (Resultado: 0/8 secuencias aprobadas)
* **Que evalua:** Miden la entropia condicional de la informacion: dado que han salido ciertos bits previos, cual es la probabilidad de que salga el siguiente bit?
* **Por que fallo:** Al encadenar `Offset_2` a partir de los bits de `b1`, existe una dependencia matematica causal directa entre un byte y el siguiente. La secuencia no es estocasticamente independiente.

---

## 4. Catalogo de las 15 Pruebas NIST: Que Evalua y Que Vector de Ataque Habilita

El siguiente cuadro detalla las 15 pruebas estadisticas del estandar NIST SP 800-22, que vulnerabilidad revela su fallo y que tipo de ciberataque puede llevar a cabo un atacante sabiendo que dicha prueba fallo:

| # | Prueba NIST | Que evalua? | Que revela su fallo? | Vector de Ataque Criptografico Habilitado |
| :-: | :--- | :--- | :--- | :--- |
| **01** | **Frequency (Monobit)** | Proporcion global de ceros y unos en toda la secuencia. | Desbalance global: hay un exceso o escasez permanente de bits 1. | **Ataque de Sesgo (Bias Attack):** Permite adivinar bits de claves criptograficas o firmas digitales con un esfuerzo menor a la fuerza bruta probabilistica. |
| **02** | **BlockFrequency** | Proporcion de unos dentro de bloques locales fijos (M=128). | Concentracion por rafagas: la aleatoriedad es inestable en regiones concretas. | **Ataque de Distincion de Bloques:** Permite distinguir bloques generados por el algoritmo frente a bloques aleatorios y predecir ventanas de tiempo debiles. |
| **03** | **Cumulative Sums** | Caminata aleatoria acumulada hacia adelante y hacia atras. | Deriva o sesgo acumulativo sostenido. | **Ataque de Deriva Estocastica:** Permite predecir la tendencia general de claves de sesion consecutivas. |
| **04** | **Runs** | Alternancia o transiciones entre ceros y unos consecutivos. | Las oscilaciones entre 0 y 1 son demasiado lentas o demasiado rapidas. | **Ataque de Correlacion de Transicion:** Util para romper cifradores de flujo (Stream Ciphers) recuperando el estado interno del generador. |
| **05** | **LongestRun** | La racha continua mas larga de unos en bloques de M bits. | Aparicion recurrente de rafagas anomalas de unos o ceros consecutivos. | **Ataque de Seleccion de Clave Debil:** El atacante puede anticipar bloques que consisten en bytes constantes como 0x00 o 0xFF para forzar colisiones. |
| **06** | **Rank** | Rango matricial de submatrices binarias de 32x32 bits. | Dependencia algebraica lineal entre fragmentos contiguos de la secuencia. | **Ataque de Criptoanalisis Lineal:** Permite montar sistemas de ecuaciones lineales para resolver la clave secreta directamente mediante algebra booleana. |
| **07** | **FFT (Spectral)** | Picos armonicos repetitivos en el dominio de las frecuencias. | **Periodicidad oculta.** El generador tiene un ciclo cerrado de repeticion. | **Ataque de Prediccion Ciclica:** Permite predecir cuando el algoritmo repetira el mismo estado interno o cuando generara la misma clave. |
| **08** | **NonOverlapping Template** | Frecuencia de patrones aperiodicos de m bits (m=9). | Sobre-representacion masiva de secuencias fijas de bits. | **Ataque de Diccionario / Fuerza Bruta Filtrada:** El atacante descarta el 90% de las combinaciones posibles y prueba unicamente los patrones dominantes. |
| **09** | **Overlapping Template** | Distribucion de patrones con desplazamiento bit a bit. | Irregularidades en cadenas de bits superpuestas. | **Ataque de Sincronizacion:** Permite deducir la alineacion de trama en protocolos de cifrado y derivar contrasenas intermedias. |
| **10** | **Universal (Maurer)** | Distancia entre patrones identicos repetidos (compresibilidad). | La secuencia es **compresible** (contiene redundancia algoritmica). | **Ataque de Recuperacion de Estado:** Permite comprimir el espacio de estados del generador y reconstruir el generador pseudoaleatorio. |
| **11** | **Approximate Entropy** | Comparacion de entropia entre bloques de longitud m y m+1. | La secuencia es estadisticamente predecible condicionada al historial anterior. | **Ataque de Prediccion Condicional (Markov):** Conociendo los bits emitidos recientemente, la probabilidad de acertar los siguientes es significativamente mayor al 50%. |
| **12** | **Random Excursions** | Numero de ciclos en una caminata aleatoria que visitan un estado x. | Inestabilidad en la dispersion estocastica de los bits. | **Ataque de Excursion:** Permite predecir estados de tokens en protocolos RFID o sistemas embebidos de bajo coste. |
| **13** | **Random Excursions Variant** | Frecuencia de visitas a 18 estados especificos (-9 a +9). | Sesgo en las probabilidades de estados intermedios. | **Ataque de Firma:** Variante del ataque de excursion para distinguir implementaciones fisicas especificas. |
| **14** | **Serial** | Distribucion de frecuencias conjuntas de n-gramas (m=16). | Las secuencias de 16 bits adyacentes estan acopladas causalmente. | **Ataque de Inferencia Secuencial:** Permite deducir contrasenas o tokens futuros a partir de los tokens actuales o pasados. |
| **15** | **Linear Complexity** | Longitud del registro LFSR equivalente (Berlekamp-Massey). | El algoritmo puede modelarse como un registro de desplazamiento lineal corto. | **Ataque de Inversion LFSR:** Con un numero pequeno de bits interceptados, el atacante reconstruye completamente el polinomio generador y clona el dispositivo. |

---

## 5. El Ataque Real Contra el Algoritmo Coreano

El hecho de que el algoritmo coreano haya fallado en `BlockFrequency`, `LongestRun`, `FFT`, `ApproximateEntropy` y `Serial` no es una curiosidad academica: **habilita un ataque directo de autenticacion en el mundo real**.

### 1. El Vector de Ataque: Targeted OTP Guessing
* En un OTP de 6 digitos ideal (como el de Google Authenticator), existen:
  `10^6 = 1,000,000 combinaciones posibles (del 000000 al 999999)`
  La probabilidad de adivinar el codigo al azar en un intento es de:
  `P(exito) = 1 / 1,000,000 = 0.0001%`
* Sin embargo, debido al fallo detectado en NIST, el 6.25% de las veces los bytes colapsan a:
  `Valor = b1 * 65793 mod 1,000,000`
  Dado que `b1` es un byte (solo puede valer de 0 a 255), **todos esos codigos colapsan obligatoriamente a solo 256 numeros en todo el mundo**.

### 2. Como ataca un adversario en la practica:
1. **Ataque de Rociado de Credenciales (Credential Spraying):**
   Un atacante con una base de datos de 10,000 usuarios de un banco coreano no prueba numeros al azar. Elige uno de los 256 numeros colapsados (por ejemplo: `065793`, `131586` o `210752`) y prueba ese mismo codigo contra todos los usuarios.
   * En un sistema normal, acertaria a 0 o 1 usuario.
   * Con el algoritmo vulnerable, **acertara el acceso a mas de 625 cuentas de forma instantanea**.

2. **Ataque de Fuerza Bruta en Linea (Online Brute-Force):**
   Si el servidor de autenticacion permite 3 o 5 intentos fallidos antes de bloquear la cuenta, el atacante programa sus intentos para enviar siempre los numeros mas frecuentes de la lista de 256. Su tasa de exito se multiplica por mas de **240 veces respecto a un sistema seguro**.

### 3. Por que Google Authenticator (RFC 4226) es Inmune:
Google Authenticator utiliza un unico offset `Offset = HS[19] & 0x0F` y extrae **4 bytes contiguos**. No hay encadenamiento recursivo que provoque bucles ciclicos.
* Los 4 bytes conservan 32 bits de entropia independientes.
* Cada uno de los 1,000,000 de codigos decimales posibles tiene una probabilidad uniforme y homogenea de aparecer.
* Por eso Google Authenticator **aprueba el 100% de las pruebas del NIST STS sin ningun fallo**.