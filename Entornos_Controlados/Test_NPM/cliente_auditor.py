"""
cliente_auditor.py
==================
Script cliente en Python que interactúa con el servidor vulnerable
local de Node.js (http://localhost:3000).

Flujo:
1. Consulta la información del servidor (/api/info).
2. Solicita códigos OTP consecutivos (/api/solicitar-otp).
3. Envía intentos de verificación (/api/verificar-otp) simulando el Módulo 2.
"""

import urllib.request
import json
import time

SERVER_URL = "http://localhost:3000"

def hacer_peticion_get(endpoint):
    url = f"{SERVER_URL}{endpoint}"
    with urllib.request.urlopen(url) as response:
        return json.loads(response.read().decode())

def hacer_peticion_post(endpoint, datos):
    url = f"{SERVER_URL}{endpoint}"
    data_bytes = json.dumps(datos).encode('utf-8')
    req = urllib.request.Request(url, data=data_bytes, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

def ejecutar_auditoria():
    print("===============================================================")
    print("AUDITORÍA EN VIVO: CLIENTE PYTHON -> SERVIDOR NODE.JS")
    print("===============================================================\n")

    # 1. Metadatos del Servidor
    try:
        info = hacer_peticion_get("/api/info")
        print("[+] Conexión establecida con el servidor de laboratorio:")
        print(f"    - Librería:       {info['libreria_afectada']}")
        print(f"    - Vulnerabilidad: {info['vulnerabilidad']}")
        print(f"    - Clasificación:  {', '.join(info['clasificacion_cwe'])}\n")
    except Exception as e:
        print(f"[!] Error: No se pudo conectar al servidor en {SERVER_URL}.")
        print("[i] Asegúrate de correr en otra terminal: npm start (dentro de Test_NPM)")
        return

    # 2. Captura de Códigos Emitidos
    print("[*] Solicitando 3 códigos OTP consecutivos al servidor:")
    otps_capturados = []
    for i in range(1, 4):
        res = hacer_peticion_get("/api/solicitar-otp")
        print(f"    - Código {i} recibido: {res['otp']} (Timestamp: {res['timestamp']})")
        otps_capturados.append(res['otp'])
        time.sleep(0.5)

    # 3. Prueba de Verificación con el último OTP
    ultimo_otp = otps_capturados[-1]
    print(f"\n[*] Probando validación contra el endpoint /api/verificar-otp:")
    print(f"    - Enviando OTP correcto ({ultimo_otp})...")
    status, res_val = hacer_peticion_post("/api/verificar-otp", {"otp": ultimo_otp})
    print(f"      Respuesta HTTP {status}: {res_val['mensaje']}")

    print(f"    - Enviando código incorrecto (999999)...")
    status_fail, res_fail = hacer_peticion_post("/api/verificar-otp", {"otp": "999999"})
    print(f"      Respuesta HTTP {status_fail}: {res_fail['mensaje']}")

    print("\n===============================================================")
    print("[+] Demostración de comunicación inter-plataforma completada.")
    print("===============================================================")

if __name__ == "__main__":
    ejecutar_auditoria()
