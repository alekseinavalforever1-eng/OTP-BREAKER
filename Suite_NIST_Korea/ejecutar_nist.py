#!/usr/bin/env python3
"""
Ejecutor y Analizador Automatizado de NIST STS (SP 800-22)
Permite correr assess.exe contra cualquier dataset binario generado y muestra
el reporte oficial con el desglose de pruebas y aprobación.
"""

import os
import subprocess
import sys

STS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sts-2.1.2"))
ASSESS_BIN = os.path.join(STS_DIR, "assess.exe")
EXP_DIR = os.path.join(STS_DIR, "data", "experimentos")

OPCIONES = {
    "1": ("data/experimentos/korea_vulnerable.bin", "Algoritmo Coreano Improved Dynamic (Vulnerable)"),
    "2": ("data/experimentos/korea_control.bin", "Algoritmo Coreano Dinámico Estándar (Control)"),
    "3": ("data/experimentos/google_rfc4226.bin", "Google Authenticator (RFC 4226 / 6238)")
}

def resolver_archivo(arg: str) -> str:
    """Resuelve la ruta relativa para assess.exe a partir del argumento."""
    if arg in OPCIONES:
        return OPCIONES[arg][0]
    
    # Si pasaron solo el nombre del archivo (ej: 'google_rfc4226.bin')
    posible_exp = os.path.join(EXP_DIR, arg)
    if os.path.exists(posible_exp):
        return f"data/experimentos/{arg}"
        
    posible_sts = os.path.join(STS_DIR, arg)
    if os.path.exists(posible_sts):
        return arg
        
    return arg

def ejecutar_nist(target_file: str, stream_length: int = 1_000_000, num_streams: int = 8):
    """
    Ejecuta assess.exe pasando la configuración por stdin.
    target_file debe ser relativo a STS_DIR (ej. 'data/experimentos/korea_vulnerable.bin')
    """
    if not os.path.exists(ASSESS_BIN):
        print(f"[-] Error: No se encontró {ASSESS_BIN}. Debe compilarse primero.")
        return

    full_target_path = os.path.join(STS_DIR, target_file.replace("/", os.sep))
    if not os.path.exists(full_target_path):
        print(f"[-] Error: El archivo no existe en: {full_target_path}")
        print("    Asegúrate de haber corrido primero: python Suite_NIST_Korea/generador_nist_otp.py")
        return

    # Secuencia de respuestas para assess.exe:
    # 0 = Input File
    # target_file = ruta relativa
    # 1 = Apply ALL The Tests
    # 0 = Default parameters
    # num_streams = 8
    # 1 = Binary format (8 bits por byte)
    respuestas = f"0\n{target_file}\n1\n0\n{num_streams}\n1\n"

    print("=" * 85)
    print(f"[*] Evaluando con NIST STS: {target_file}")
    print(f"    - Secuencias: {num_streams} streams de {stream_length:,} bits c/u")
    print(f"    - Total evaluado: {num_streams * stream_length:,} bits ({num_streams * stream_length // 8:,} bytes)")
    print("=" * 85)
    
    proc = subprocess.Popen(
        [ASSESS_BIN, str(stream_length)],
        cwd=STS_DIR,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    stdout, stderr = proc.communicate(input=respuestas)
    
    reporte_path = os.path.join(STS_DIR, "experiments", "AlgorithmTesting", "finalAnalysisReport.txt")
    if os.path.exists(reporte_path):
        print(f"[+] Pruebas completadas exitosamente. Reporte obtenido:\n")
        with open(reporte_path, "r", encoding="utf-8", errors="ignore") as f:
            lineas = f.readlines()
        
        # Mostrar las primeras 45 líneas del reporte (las pruebas principales)
        print("-" * 85)
        for linea in lineas[5:45]:
            print(linea.rstrip())
        print("-" * 85)
        print(f"[i] Reporte completo guardado en:\n    {reporte_path}\n")
    else:
        print("[-] No se pudo generar el reporte. Salida de consola:")
        print(stdout[-500:])

if __name__ == "__main__":
    if len(sys.argv) > 1:
        archivo = resolver_archivo(sys.argv[1])
    else:
        print("\n=== SELECTOR DE DATASET PARA NIST STS ===")
        print(" [1] Algoritmo Coreano Improved Dynamic (Vulnerable - TTAK.KO-12.0193)")
        print(" [2] Algoritmo Coreano Dinámico Estándar (Control)")
        print(" [3] Google Authenticator (RFC 4226 / RFC 6238)")
        seleccion = input("\nElige una opción (1, 2 o 3) [defecto: 1]: ").strip()
        if seleccion not in OPCIONES:
            seleccion = "1"
        archivo = OPCIONES[seleccion][0]

    ejecutar_nist(archivo, stream_length=1_000_000, num_streams=8)
