"""
simulador_dataset_interfaz.py
=============================
Genera datasets de prueba siguiendo el contrato de interfaz formal entre
el Módulo 1 (Jahir Rocha) y el Módulo 2 (Julián Narváez).

Ubicación: Modulo_Rompedor_Predictor/codigo/
Datos de salida: Modulo_Rompedor_Predictor/datos/
"""

import os
import time
import hmac
import hashlib
import struct
import pandas as pd
import numpy as np

def generar_totp_rfc6238(secret_bytes, timestamp, step=30, digits=6):
    """Implementación canónica RFC 6238 (Segura - Control Negativo)."""
    counter = timestamp // step
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    truncated_hash = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    otp = truncated_hash % (10 ** digits)
    return str(otp).zfill(digits)

def generar_totp_corea_vulnerable(secret_bytes, timestamp, step=30, digits=6):
    """
    Simulación del estándar coreano TTAK.KO-12.0193 con falla en la extracción dinámica.
    En el 6.25% de las llamadas, los punteros colapsan en bucle (b1 == b2 == b3).
    """
    counter = timestamp // step
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    
    # Simulación de extracción dependiente
    offset_1 = h[-1] & 0x0F
    b1 = h[offset_1]
    offset_2 = b1 & 0x0F
    
    # Si colisionan, ocurre el bucle idéntico
    if offset_2 == offset_1:
        b2 = b1
        b3 = b1
    else:
        b2 = h[offset_2]
        offset_3 = b2 & 0x0F
        b3 = h[offset_3]
        
    val_24bits = (b1 << 16) | (b2 << 8) | b3
    otp = val_24bits % (10 ** digits)
    return str(otp).zfill(digits)

def generar_dataset_simulado(num_muestras=1000, escenario="korea", archivo_salida=None):
    """
    Crea el archivo CSV con la estructura acordada intermódulos.
    """
    if archivo_salida is None:
        carpeta_datos = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "datos"))
        os.makedirs(carpeta_datos, exist_ok=True)
        archivo_salida = os.path.join(carpeta_datos, f"dataset_{escenario}.csv")
    else:
        os.makedirs(os.path.dirname(archivo_salida), exist_ok=True)

    print(f"[*] Generando {num_muestras} muestras para el escenario: '{escenario}'...")
    
    base_time = int(time.time()) - (num_muestras * 30)
    secret_key = b"TIC_EPN_SECRET_KEY_12345"
    
    registros = []
    
    for i in range(num_muestras):
        t = base_time + (i * 30)
        c = t // 30
        
        if escenario == "korea":
            otp = generar_totp_corea_vulnerable(secret_key, t)
            alerta = "FAIL_FFT;FAIL_BLOCK_FREQ"
        elif escenario == "rfc_seguro":
            otp = generar_totp_rfc6238(secret_key, t)
            alerta = "PASS"
        else:
            # Escenario LCG débil
            otp = str((1664525 * i + 1013904223) % 1000000).zfill(6)
            alerta = "FAIL_SERIAL;FAIL_RUNS"
            
        d1, d2, d3, d4, d5, d6 = [int(ch) for ch in otp]
        
        registros.append({
            "id": i + 1,
            "timestamp": t,
            "counter": c,
            "otp_decimal": otp,
            "d1": d1,
            "d2": d2,
            "d3": d3,
            "d4": d4,
            "d5": d5,
            "d6": d6,
            "alertas_nist": alerta
        })
        
    df = pd.DataFrame(registros)
    df.to_csv(archivo_salida, index=False)
    print(f"[+] Dataset guardado con éxito en:\n    {archivo_salida}")
    print(f"[+] Vista previa (3 primeras filas):\n{df.head(3)}\n")
    return df

if __name__ == "__main__":
    carpeta_datos = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "datos"))
    os.makedirs(carpeta_datos, exist_ok=True)
    
    # Genera escenario de Corea y escenario RFC Seguro de control
    ruta_korea = os.path.join(carpeta_datos, "dataset_otps_ejemplo.csv")
    generar_dataset_simulado(num_muestras=1000, escenario="korea", archivo_salida=ruta_korea)
    
    ruta_control = os.path.join(carpeta_datos, "dataset_rfc_control.csv")
    generar_dataset_simulado(num_muestras=1000, escenario="rfc_seguro", archivo_salida=ruta_control)
