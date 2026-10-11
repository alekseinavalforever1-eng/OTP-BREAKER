"""
demostracion_ruptura_en_vivo.py
===============================
Demostración real, práctica y verificable de ruptura de OTPs.

Implementa dos escenarios reales:
1. DEMOSTRACIÓN A: Ataque de Ruptura de Semilla (Seed Recovery Attack).
   - La víctima genera su clave 2FA usando el reloj del sistema (CWE-337).
   - El atacante observa 2 OTPs, deduce la semilla exacta K y predice con
     100% de acierto todas las contraseñas futuras de la víctima.

2. DEMOSTRACIÓN B: Ataque al Estándar Coreano TTAK.KO-12.0193.
   - Demuestra la efectividad real de probar únicamente los 256 números
     colapsados frente a Google Authenticator (RFC 6238).
"""

import time
import hmac
import hashlib
import struct
import numpy as np

# =====================================================================
# FUNCIONES AUXILIARES DE GENERACIÓN TOTP
# =====================================================================

def hmac_sha1_totp(secret_bytes, timestamp, step=30, digits=6):
    """Generador estándar RFC 6238 (Google Authenticator)."""
    counter = timestamp // step
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    truncated = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)

def totp_corea_vulnerable(secret_bytes, timestamp, step=30, digits=6):
    """Generador del estándar coreano TTAK.KO-12.0193 (Extracción dependiente)."""
    counter = timestamp // step
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    
    offset1 = h[-1] & 0x0F
    b1 = h[offset1]
    offset2 = b1 & 0x0F
    b2 = h[offset2]
    offset3 = b2 & 0x0F
    b3 = h[offset3]
    
    val_24bits = (b1 << 16) | (b2 << 8) | b3
    return str(val_24bits % (10 ** digits)).zfill(digits)


# =====================================================================
# DEMOSTRACIÓN 1: ATAQUE DE RUPTURA DE SEMILLA (Caja Blanca / Tiempo)
# =====================================================================

def demo_ruptura_semilla():
    print("\n" + "="*70)
    print("DEMOSTRACIÓN 1: ATAQUE DE RECUPERACIÓN DE SEMILLA (SEED RECOVERY)")
    print("="*70)
    
    # 1. LA VÍCTIMA CREA SU CUENTA
    # Supongamos que la víctima creó su cuenta hoy a las 14:15:30.
    # El desarrollador cometió el error: seed = SHA1(timestamp_en_segundos)
    hora_creacion_real = 1758844530  # Marca de tiempo exacta de la víctima
    semilla_secreta_victima = hashlib.sha1(str(hora_creacion_real).encode()).digest()
    
    print("[1] VÍCTIMA:")
    print(f"    - Cuenta creada en timestamp Unix: {hora_creacion_real}")
    print(f"    - Clave secreta real (K): {semilla_secreta_victima.hex()[:16]}... (160 bits)")
    
    # La víctima genera dos códigos en vivo para iniciar sesión:
    t0 = hora_creacion_real + 600   # 10 minutos después
    t1 = t0 + 30                   # 30 segundos después
    otp0_victima = hmac_sha1_totp(semilla_secreta_victima, t0)
    otp1_victima = hmac_sha1_totp(semilla_secreta_victima, t1)
    
    print(f"    - Código OTP emitido en T0 ({t0}): {otp0_victima}")
    print(f"    - Código OTP emitido en T1 ({t1}): {otp1_victima}")
    print("    [!] El atacante intercepta estos 2 códigos.")

    # 2. EL ATACANTE EJECUTA EL MÓDULO ROMPEDOR
    print("\n[2] ATACANTE (Módulo Rompedor):")
    print("    - El atacante sabe que la cuenta se creó hoy entre las 14:00 y las 14:30.")
    print("    - Ventana de búsqueda: 1.800 segundos posibles.")
    print("    - Buscando semilla que genere ambos OTPs...")
    
    ventana_inicio = hora_creacion_real - 930   # 14:00
    ventana_fin = hora_creacion_real + 870      # 14:30
    
    t_inicio = time.perf_counter()
    semilla_encontrada = None
    intentos = 0
    
    for cand_time in range(ventana_inicio, ventana_fin + 1):
        intentos += 1
        cand_seed = hashlib.sha1(str(cand_time).encode()).digest()
        
        # Comprueba contra OTP 0
        if hmac_sha1_totp(cand_seed, t0) == otp0_victima:
            # Comprueba contra OTP 1 (Filtro de Colisión)
            if hmac_sha1_totp(cand_seed, t1) == otp1_victima:
                semilla_encontrada = cand_seed
                timestamp_recuperado = cand_time
                break
                
    t_fin = time.perf_counter()
    tiempo_ms = (t_fin - t_inicio) * 1000
    
    print(f"\n[+] ¡ÉXITO! Semilla recuperada en {tiempo_ms:.2f} ms ({intentos} intentos probados).")
    print(f"    - Timestamp deducido:      {timestamp_recuperado} (Coincidencia: {timestamp_recuperado == hora_creacion_real})")
    print(f"    - Semilla reconstruida (K): {semilla_encontrada.hex()[:16]}...")
    print(f"    - ¿Coincide con la clave real?: {semilla_encontrada == semilla_secreta_victima}")
    
    # 3. VERIFICACIÓN: PREDECIR EL FUTURO CON 100% DE ACIERTO
    print("\n[3] PREDICCIÓN A FUTURO (Prueba de Ruptura Total):")
    aciertos = 0
    for paso in range(2, 7):
        t_futuro = t0 + (paso * 30)
        otp_real_futuro = hmac_sha1_totp(semilla_secreta_victima, t_futuro)
        otp_predicho_atacante = hmac_sha1_totp(semilla_encontrada, t_futuro)
        
        coincide = (otp_real_futuro == otp_predicho_atacante)
        if coincide:
            aciertos += 1
        print(f"    - Futuro T+{paso*30}s: Real={otp_real_futuro} | Predicho={otp_predicho_atacante} -> {'ACIERTO [100%]' if coincide else 'FALLO'}")
        
    print(f"\n[+] Tasa de Acierto en códigos futuros: {(aciertos/5)*100:.1f}%")
    print("="*70)


# =====================================================================
# DEMOSTRACIÓN 2: ATAQUE AL ESTÁNDAR COREANO (256 Códigos Colapsados)
# =====================================================================

def demo_ataque_corea():
    print("\n" + "="*70)
    print("DEMOSTRACIÓN 2: ATAQUE A LOS 256 CÓDIGOS VULNERABLES DE COREA")
    print("="*70)
    
    # 1. El atacante pre-calcula los 256 códigos colapsados teóricos:
    # Cuando ocurre el bucle en TTAK.KO-12.0193, los 3 bytes son iguales: b1 || b1 || b1
    # Para b1 entre 0 y 255:
    codigos_vulnerables_corea = set()
    for b in range(256):
        val = (b << 16) | (b << 8) | b
        otp = str(val % 1000000).zfill(6)
        codigos_vulnerables_corea.add(otp)
        
    print(f"[1] PREPARACIÓN DEL ATAQUE:")
    print(f"    - Total de números en el universo normal:  1.000.000")
    print(f"    - Total de números en el grupo colapsado: 256")
    print(f"    - Ejemplos de números colapsados: {list(sorted(codigos_vulnerables_corea))[:5]}...")

    # 2. Simulamos 10.000 inicios de sesión (logins) de usuarios:
    # Caso A: Sistema Vulnerable de Corea
    # Caso B: Sistema Seguro de Google (RFC 6238)
    num_logins = 10000
    clave_prueba = b"CLAVE_SECRETA_ALEATORIA_12345"
    
    print(f"\n[2] SIMULANDO {num_logins} INTENTOS DE ACCESO EN VIVO...")
    
    aciertos_corea = 0
    aciertos_google = 0
    
    for i in range(num_logins):
        t = 1758844800 + (i * 30)
        
        # OTP generado por el servidor de Corea
        otp_corea = totp_corea_vulnerable(clave_prueba, t)
        # OTP generado por el servidor de Google
        otp_google = hmac_sha1_totp(clave_prueba, t)
        
        # El atacante prueba si el código emitido está dentro de los 256 candidatos
        if otp_corea in codigos_vulnerables_corea:
            aciertos_corea += 1
            
        if otp_google in codigos_vulnerables_corea:
            aciertos_google += 1
            
    tasa_corea = (aciertos_corea / num_logins) * 100
    tasa_google = (aciertos_google / num_logins) * 100
    
    print("\n[3] RESULTADOS COMPARATIVOS:")
    print(f"  A. En el Estándar Vulnerable de Corea:")
    print(f"     - Aciertos dentro del grupo de 256: {aciertos_corea} de {num_logins}")
    print(f"     - Probabilidad real de acierto:     {tasa_corea:.2f}% (Teórica esperada: ~6.25%)")
    
    print(f"\n  B. En Google Authenticator (RFC Seguro):")
    print(f"     - Aciertos dentro del grupo de 256: {aciertos_google} de {num_logins}")
    print(f"     - Probabilidad real de acierto:     {tasa_google:.2f}% (Teórica azar: 0.0256%)")
    
    ventaja = tasa_corea / (tasa_google if tasa_google > 0 else 0.0256)
    print(f"\n[+] CONCLUSIÓN CIENTÍFICA:")
    print(f"    - El atacante tiene una ventaja de {ventaja:.1f} VECES MAYOR en el sistema de Corea.")
    print(f"    - Mientras en Google acierta 2 de cada 10.000 veces, en Corea acierta más de 600 veces.")
    print("="*70 + "\n")


if __name__ == "__main__":
    demo_ruptura_semilla()
    demo_ataque_corea()
