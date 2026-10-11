#!/usr/bin/env python3
"""
Generador de Secuencias Binarias para NIST STS (SP 800-22)
Basado en: "Analysis of Vulnerabilities That Can Occur When Generating One-Time Password"
(Kim et al., Applied Sciences 2020) y estándares TTAK.KO-12.0193 vs RFC 4226 / RFC 6238.

Genera archivos binarios de 1,000,000 bytes (8,000,000 bits) en:
- Suite_NIST_Korea/sts_datasets/
- sts-2.1.2/data/experimentos/

NO ejecuta NIST STS automáticamente ni ejecuta simulaciones adicionales.
"""

import os
import hmac
import hashlib
import struct

# Clave compartida por defecto (20 bytes)
DEFAULT_KEY = b"12345678901234567890"

def generar_bloque_hmac(key: bytes, counter: int) -> bytes:
    """Genera un bloque de 20 bytes (160 bits) usando HMAC-SHA1 (RFC 4226)."""
    msg = struct.pack(">Q", counter)
    return hmac.new(key, msg, hashlib.sha1).digest()

# =====================================================================
# ALGORITMOS DE EXTRACCIÓN (FASE 2)
# =====================================================================

def extraccion_coreana_improved_vulnerable(bloque: bytes) -> bytes:
    """
    Extracción Dinámica Mejorada Vulnerable (TTAK.KO-12.0193 para Smart Cards / USIM):
    Offset 1 = bloque[19] & 0x0F -> b1 = bloque[Offset 1]
    Offset 2 = b1 & 0x0F         -> b2 = bloque[Offset 2]
    Offset 3 = b2 & 0x0F         -> b3 = bloque[Offset 3]
    Retorna: b1 || b2 || b3
    
    FALLA: Si (b1 & 0x0F) == Offset 1, entonces Offset 2 = Offset 1 y Offset 3 = Offset 1.
    Provoca que b1 == b2 == b3 con probabilidad 1/16 (6.25%).
    """
    offset1 = bloque[19] & 0x0F
    b1 = bloque[offset1]
    
    offset2 = b1 & 0x0F
    b2 = bloque[offset2]
    
    offset3 = b2 & 0x0F
    b3 = bloque[offset3]
    
    return bytes([b1, b2, b3])

def extraccion_dinamica_control(bloque: bytes) -> bytes:
    """
    Extracción dinámica estándar de control (TTAK.KO-12.0193):
    Offset = bloque[19] & 0x0F (0 a 15)
    Extrae 3 bytes contiguos: bloque[offset : offset + 3]
    """
    offset = bloque[19] & 0x0F
    return bloque[offset : offset + 3]

def extraccion_google_rfc4226(bloque: bytes) -> bytes:
    """
    Truncamiento Dinámico oficial de RFC 4226 / Google Authenticator:
    Offset = bloque[19] & 0x0F
    Extrae 4 bytes contiguos generados por HMAC-SHA1 preservando los 8 bits de entropía.
    """
    offset = bloque[19] & 0x0F
    return bloque[offset : offset + 4]

# =====================================================================
# GENERADOR DE DATASETS BINARIOS PARA NIST STS
# =====================================================================

def generar_dataset_nist(modo: str, num_bytes: int = 1_000_000, key: bytes = DEFAULT_KEY) -> bytes:
    """
    Genera un flujo continuo de bytes extraídos hasta acumular 'num_bytes'.
    """
    buffer = bytearray()
    counter = 0
    
    while len(buffer) < num_bytes:
        bloque = generar_bloque_hmac(key, counter)
        counter += 1
        
        if modo == "korea_vulnerable":
            extraido = extraccion_coreana_improved_vulnerable(bloque)
        elif modo == "korea_control":
            extraido = extraccion_dinamica_control(bloque)
        elif modo == "google_rfc":
            extraido = extraccion_google_rfc4226(bloque)
        else:
            raise ValueError(f"Modo desconocido: {modo}")
            
        buffer.extend(extraido)
        
    return bytes(buffer[:num_bytes])

if __name__ == "__main__":
    local_dir = os.path.join(os.path.dirname(__file__), "sts_datasets")
    os.makedirs(local_dir, exist_ok=True)
    
    # Subcarpeta aislada dentro de NIST sts-2.1.2/data/experimentos
    nist_experimentos_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "sts-2.1.2", "data", "experimentos")
    )
    os.makedirs(nist_experimentos_dir, exist_ok=True)
    
    print("=" * 75)
    print("GENERADOR DE DATASETS BINARIOS PARA NIST STS (SP 800-22)")
    print("Tamaño: 1,000,000 bytes (8,000,000 bits) por archivo")
    print("=" * 75)
    
    datasets = [
        ("korea_vulnerable.bin", "korea_vulnerable", "Algoritmo Coreano Improved Dynamic (TTAK.KO-12.0193)"),
        ("korea_control.bin", "korea_control", "Algoritmo Coreano Dinámico Estándar (Control)"),
        ("google_rfc4226.bin", "google_rfc", "Algoritmo Google Authenticator (RFC 4226 / 6238)")
    ]
    
    for filename, modo, desc in datasets:
        print(f"[*] Generando {filename} ({desc})...")
        data = generar_dataset_nist(modo, num_bytes=1_000_000)
        
        # 1. Guardar en Suite_NIST_Korea/sts_datasets/
        path_local = os.path.join(local_dir, filename)
        with open(path_local, "wb") as f:
            f.write(data)
            
        # 2. Guardar en sts-2.1.2/data/experimentos/
        path_nist = os.path.join(nist_experimentos_dir, filename)
        with open(path_nist, "wb") as f:
            f.write(data)
            
        print(f"    -> Guardado en datasets: {path_local}")
        print(f"    -> Copiado a NIST data:  {path_nist}")
        
    print("\n[+] Todos los archivos binarios fueron generados exitosamente.")
    print("    La carpeta principal sts-2.1.2/data mantiene sus archivos por defecto intactos.")
    print("    Tus datasets están organizados en: sts-2.1.2/data/experimentos/")
    print("=" * 75)
