#!/usr/bin/env python3
"""
EXPERIMENTO 2: Simulación de Frecuencia y Colisiones en Códigos Decimales de 6 Dígitos
Basado en: "Analysis of Vulnerabilities That Can Occur When Generating One-Time Password"
(Kim et al., Applied Sciences 2020, Sección 4.2 y Figuras 8 y 9).

Demuestra cómo el colapso de bytes b1 == b2 == b3 (que ocurre con probabilidad 1/16 = 6.25%)
provoca que el 6.25% de todos los códigos OTP de 6 dígitos generados colapsen en exactamente
256 números específicos, multiplicando su frecuencia por más de 250 veces respecto a la media.
"""

import hmac
import hashlib
import struct
from collections import Counter

DEFAULT_KEY = b"12345678901234567890"  # Clave de 20 bytes

def generar_bloque_hmac(key: bytes, counter: int) -> bytes:
    msg = struct.pack(">Q", counter)
    return hmac.new(key, msg, hashlib.sha1).digest()

def extraccion_coreana_improved_vulnerable(bloque: bytes) -> bytes:
    offset1 = bloque[19] & 0x0F
    b1 = bloque[offset1]
    
    offset2 = b1 & 0x0F
    b2 = bloque[offset2]
    
    offset3 = b2 & 0x0F
    b3 = bloque[offset3]
    
    return bytes([b1, b2, b3])

def extraccion_dinamica_control(bloque: bytes) -> bytes:
    offset = bloque[19] & 0x0F
    return bloque[offset : offset + 3]

def extraccion_google_rfc4226(bloque: bytes) -> bytes:
    offset = bloque[19] & 0x0F
    return bloque[offset : offset + 4]

def ejecutar_experimento_2(num_muestras: int = 200_000, key: bytes = DEFAULT_KEY):
    print("=" * 75)
    print(f"EXPERIMENTO 2: SIMULACIÓN DE FRECUENCIA DECIMAL ({num_muestras:,} MUESTRAS)")
    print("Demostración del colapso a 256 números OTP en el estándar coreano")
    print("=" * 75)
    
    conteo_vulnerable = Counter()
    conteo_control = Counter()
    conteo_google = Counter()
    
    colapsos_detectados = 0
    
    for c in range(num_muestras):
        bloque = generar_bloque_hmac(key, c)
        
        # 1. Algoritmo Coreano Vulnerable (TTAK.KO-12.0193 Improved)
        ext_vuln = extraccion_coreana_improved_vulnerable(bloque)
        if ext_vuln[0] == ext_vuln[1] == ext_vuln[2]:
            colapsos_detectados += 1
        val_vuln = (ext_vuln[0] << 16) | (ext_vuln[1] << 8) | ext_vuln[2]
        otp_vuln = val_vuln % 1_000_000
        conteo_vulnerable[otp_vuln] += 1
        
        # 2. Algoritmo Coreano Dinámico Estándar (Control)
        ext_ctrl = extraccion_dinamica_control(bloque)
        val_ctrl = (ext_ctrl[0] << 16) | (ext_ctrl[1] << 8) | ext_ctrl[2]
        otp_ctrl = val_ctrl % 1_000_000
        conteo_control[otp_ctrl] += 1
        
        # 3. Google Authenticator / RFC 4226
        ext_goog = extraccion_google_rfc4226(bloque)
        val_goog = ((ext_goog[0] & 0x7F) << 24) | (ext_goog[1] << 16) | (ext_goog[2] << 8) | ext_goog[3]
        otp_goog = val_goog % 1_000_000
        conteo_google[otp_goog] += 1

    prob_teorica_colapso = 1 / 16.0
    prob_real_colapso = colapsos_detectados / num_muestras
    
    print(f"\n[1] DETECCIÓN DE COLAPSO DE BYTES IDÉNTICOS (b1 == b2 == b3):")
    print(f"    - Probabilidad teórica: 1/16 = 6.2500%")
    print(f"    - Probabilidad observada: {colapsos_detectados:,} de {num_muestras:,} ({prob_real_colapso*100:.4f}%)")
    
    max_vuln = max(conteo_vulnerable.values())
    max_ctrl = max(conteo_control.values())
    max_goog = max(conteo_google.values())
    
    media_esperada = num_muestras / 1_000_000.0
    print(f"\n[2] COMPARACIÓN DE MÁXIMAS REPETICIONES DE UN MISMO CÓDIGO:")
    print(f"    - Media esperada en distribución uniforme E[X]: {media_esperada:.4f}")
    print(f"    - Google Authenticator (RFC 4226) Máx repeticiones: {max_goog} veces")
    print(f"    - Algoritmo Control Dinámico Máx repeticiones:      {max_ctrl} veces")
    print(f"    - Algoritmo Coreano Vulnerable Máx repeticiones:    {max_vuln} veces (¡ANOMALÍA MASIVA!)")
    
    print(f"\n[3] TOP 5 OTPs MÁS FRECUENTES EN EL ALGORITMO COREANO VULNERABLE:")
    for otp, count in conteo_vulnerable.most_common(5):
        ratio = count / max(media_esperada, 0.0001)
        print(f"    - OTP {otp:06d}: apareció {count} veces (Ratio vs media: {ratio:.1f}x veces más frecuente)")

    # Números que superan con creces el umbral uniforme
    umbral = max(5, int(media_esperada * 5) + 3)
    numeros_anomalos = [otp for otp, count in conteo_vulnerable.items() if count >= umbral]
    print(f"\n[4] TOTAL DE NÚMEROS ANÓMALOS DETECTADOS (esperado teórico: exactamente 256): {len(numeros_anomalos)}")
    print("=" * 75)

if __name__ == "__main__":
    ejecutar_experimento_2(num_muestras=200_000)
