"""
predictor_secuencias.py
=======================
Motor de predicción de secuencias OTP y reducción de espacio de búsqueda
mediante análisis de transiciones condicionales de Markov y heurística
de colapso de estados.

Funciona de forma nativa con NumPy y Pandas (sin requerir PyTorch).

Ubicación: Modulo_Rompedor_Predictor/codigo/
"""

import os
import time
import pandas as pd
import numpy as np

class MarkovOTPBreaker:
    """
    Modelador de transiciones secuenciales y detector de estados colapsados.
    """
    def __init__(self, top_k=256):
        self.top_k = top_k
        self.frecuencias_otps = {}
        self.matriz_transicion = {}
        self.estados_detectados = set()

    def entrenar(self, otps_entrenamiento):
        """Aprende las frecuencias y probabilidades de salto entre OTPs consecutivos."""
        print(f"[*] Entrenando modelo de Markov con {len(otps_entrenamiento)} muestras...")
        
        # 1. Frecuencias individuales
        for otp in otps_entrenamiento:
            self.frecuencias_otps[otp] = self.frecuencias_otps.get(otp, 0) + 1
            self.estados_detectados.add(otp)
            
        # 2. Transiciones condicionales P(OTP_t | OTP_{t-1})
        for i in range(len(otps_entrenamiento) - 1):
            prev_otp = otps_entrenamiento[i]
            next_otp = otps_entrenamiento[i + 1]
            
            if prev_otp not in self.matriz_transicion:
                self.matriz_transicion[prev_otp] = {}
            self.matriz_transicion[prev_otp][next_otp] = self.matriz_transicion[prev_otp].get(next_otp, 0) + 1

        print(f"[+] Total de estados únicos detectados: {len(self.estados_detectados)}")
        if len(self.estados_detectados) <= 256:
            print("    [!] ALERTA CRÍTICA: Se detectó colapso severo de estados (Espacio <= 256).")

    def predecir_top_k(self, otp_actual):
        """Retorna los K candidatos más probables para el siguiente instante."""
        # Si existe historia de transición condicional
        if otp_actual in self.matriz_transicion:
            candidatos_ordenados = sorted(
                self.matriz_transicion[otp_actual].items(),
                key=lambda x: x[1],
                reverse=True
            )
            top = [item[0] for item in candidatos_ordenados[:self.top_k]]
            if len(top) >= self.top_k:
                return top
        else:
            top = []
            
        # Rellena con los OTPs más frecuentes a nivel global
        mas_frecuentes = sorted(
            self.frecuencias_otps.items(),
            key=lambda x: x[1],
            reverse=True
        )
        for item in mas_frecuentes:
            if item[0] not in top:
                top.append(item[0])
            if len(top) == self.top_k:
                break
                
        return top


def evaluar_rompedor(csv_path, top_k=256, porcentaje_train=0.8):
    """Evalúa la efectividad de ruptura sobre el dataset."""
    df = pd.read_csv(csv_path)
    otps = [str(x).zfill(6) for x in df['otp_decimal'].tolist()]
    
    n_train = int(len(otps) * porcentaje_train)
    train_otps = otps[:n_train]
    test_otps = otps[n_train:]
    
    breaker = MarkovOTPBreaker(top_k=top_k)
    t_inicio_entrenamiento = time.time()
    breaker.entrenar(train_otps)
    tiempo_entrenamiento = (time.time() - t_inicio_entrenamiento) * 1000
    
    # Evaluación en el conjunto de prueba
    aciertos_top_1 = 0
    aciertos_top_k = 0
    tiempos_prediccion = []
    
    for i in range(len(test_otps) - 1):
        actual = test_otps[i]
        esperado = test_otps[i + 1]
        
        t0 = time.perf_counter()
        candidatos = breaker.predecir_top_k(actual)
        t1 = time.perf_counter()
        tiempos_prediccion.append((t1 - t0) * 1000)
        
        if len(candidatos) > 0 and candidatos[0] == esperado:
            aciertos_top_1 += 1
        if esperado in candidatos:
            aciertos_top_k += 1
            
    total_eval = len(test_otps) - 1
    tasa_top_1 = (aciertos_top_1 / total_eval) * 100
    tasa_top_k = (aciertos_top_k / total_eval) * 100
    reduccion_espacio = (1.0 - (top_k / 1000000.0)) * 100
    
    print("\n" + "="*50)
    print(f"REPORTE DE RUPTURA: {os.path.basename(csv_path)}")
    print("="*50)
    print(f"  - Muestras de prueba:             {total_eval}")
    print(f"  - Espacio de búsqueda reducido:   de 1.000.000 a {top_k} candidatos")
    print(f"  - Reducción del espacio de claves: {reduccion_espacio:.4f}%")
    print(f"  - Accuracy Top-1 (primer intento): {tasa_top_1:.2f}%")
    print(f"  - Accuracy Top-{top_k} (en ventana):  {tasa_top_k:.2f}% (Azar normal: {top_k / 10000:.4f}%)")
    print(f"  - Tiempo medio de inferencia:      {np.mean(tiempos_prediccion):.3f} ms")
    print(f"  - Tiempo total de entrenamiento:   {tiempo_entrenamiento:.2f} ms")
    print("="*50 + "\n")


if __name__ == "__main__":
    carpeta_datos = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "datos"))
    
    # 1. Evalúa el escenario de Corea
    csv_korea = os.path.join(carpeta_datos, "dataset_otps_ejemplo.csv")
    if os.path.exists(csv_korea):
        print("\n>>> EVALUANDO ESCENARIO DEFECTUOSO (COREA TTA) <<<")
        evaluar_rompedor(csv_korea, top_k=256)
        
    # 2. Evalúa el escenario RFC Seguro (Línea base / Control Negativo)
    csv_control = os.path.join(carpeta_datos, "dataset_rfc_control.csv")
    if os.path.exists(csv_control):
        print("\n>>> EVALUANDO LÍNEA BASE SEGURA (GOOGLE RFC 6238) <<<")
        evaluar_rompedor(csv_control, top_k=256)
