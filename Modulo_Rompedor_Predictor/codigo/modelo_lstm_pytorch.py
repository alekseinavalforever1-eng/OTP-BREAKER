"""
modelo_lstm_pytorch.py
======================
Implementación formal de la Red Neuronal Recurrente LSTM con Clasificador
Multi-Cabezal (Multi-Head Positional Classifier) para predicción de OTPs.

Ubicación: Modulo_Rompedor_Predictor/codigo/
Lee datos desde: Modulo_Rompedor_Predictor/datos/
"""

import os
import pandas as pd
import numpy as np

# Verificación de disponibilidad de PyTorch
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import Dataset, DataLoader
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class OTPDatasetTorch:
    """Crea ventanas deslizantes a partir del CSV de OTPs para PyTorch."""
    def __init__(self, df, seq_len=5):
        digit_cols = ['d1', 'd2', 'd3', 'd4', 'd5', 'd6']
        data = df[digit_cols].values.astype(np.float32) / 9.0  # Normalización [0, 1]
        
        self.X = []
        self.y = []
        raw_digits = df[digit_cols].values.astype(np.int64)
        
        for i in range(len(data) - seq_len):
            self.X.append(data[i : i + seq_len])
            self.y.append(raw_digits[i + seq_len])
            
        self.X = np.array(self.X)
        self.y = np.array(self.y)

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return torch.tensor(self.X[idx]), torch.tensor(self.y[idx])


if TORCH_AVAILABLE:
    class OTPLSTMClassifier(nn.Module):
        """
        Red LSTM Multi-Cabezal para predicción posicional de 6 dígitos.
        """
        def __init__(self, input_dim=6, hidden_dim=128, num_layers=2, dropout=0.2):
            super(OTPLSTMClassifier, self).__init__()
            self.hidden_dim = hidden_dim
            self.num_layers = num_layers
            
            # Capa recurrente LSTM
            self.lstm = nn.LSTM(
                input_size=input_dim,
                hidden_size=hidden_dim,
                num_layers=num_layers,
                batch_first=True,
                dropout=dropout if num_layers > 1 else 0.0
            )
            
            # 6 Cabezas de salida independientes (una por dígito, 10 clases: 0..9)
            self.head_d1 = nn.Linear(hidden_dim, 10)
            self.head_d2 = nn.Linear(hidden_dim, 10)
            self.head_d3 = nn.Linear(hidden_dim, 10)
            self.head_d4 = nn.Linear(hidden_dim, 10)
            self.head_d5 = nn.Linear(hidden_dim, 10)
            self.head_d6 = nn.Linear(hidden_dim, 10)

        def forward(self, x):
            lstm_out, _ = self.lstm(x)
            last_hidden = lstm_out[:, -1, :]
            
            out1 = self.head_d1(last_hidden)
            out2 = self.head_d2(last_hidden)
            out3 = self.head_d3(last_hidden)
            out4 = self.head_d4(last_hidden)
            out5 = self.head_d5(last_hidden)
            out6 = self.head_d6(last_hidden)
            
            return [out1, out2, out3, out4, out5, out6]


def entrenar_evaluar_lstm(csv_path, epochs=15, batch_size=16, seq_len=5):
    """Carga el dataset y ejecuta el ciclo de entrenamiento y evaluación."""
    if not TORCH_AVAILABLE:
        print("[!] PyTorch no está instalado en este entorno de Python (Python 3.13).")
        print("[i] Para instalar PyTorch en tu entorno ejecuta:")
        print("    pip install torch")
        print("[i] Ejecutando análisis estadístico y de correlación temporal con NumPy...\n")
        analizar_transiciones_secuencia(csv_path)
        return

    print(f"[*] Cargando dataset desde: {csv_path}")
    df = pd.read_csv(csv_path)
    
    dataset = OTPDatasetTorch(df, seq_len=seq_len)
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    
    model = OTPLSTMClassifier(input_dim=6, hidden_dim=64, num_layers=2)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.005)
    
    print(f"[*] Iniciando entrenamiento Multi-Head LSTM por {epochs} épocas...")
    model.train()
    for epoch in range(1, epochs + 1):
        total_loss = 0.0
        for batch_x, batch_y in dataloader:
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = sum(criterion(outputs[i], batch_y[:, i]) for i in range(6))
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            
        if epoch % 5 == 0 or epoch == 1:
            print(f"    Época [{epoch:02d}/{epochs}] - Loss combinada: {total_loss / len(dataloader):.4f}")
            
    print("\n[+] Entrenamiento completado con éxito.")
    print("[*] Evaluando Accuracy por dígito...")
    model.eval()
    correctas = [0] * 6
    total_muestras = len(dataset)
    
    with torch.no_grad():
        for batch_x, batch_y in dataloader:
            outputs = model(batch_x)
            for i in range(6):
                preds = torch.argmax(outputs[i], dim=1)
                correctas[i] += (preds == batch_y[:, i]).sum().item()
                
    print("\n=== REPORTE DE ACCURACY POSICIONAL (LSTM) ===")
    for i in range(6):
        acc = (correctas[i] / total_muestras) * 100
        print(f"  - Dígito {i+1} (d{i+1}): {acc:.2f}% (Línea base azar: 10.00%)")


def analizar_transiciones_secuencia(csv_path):
    """Análisis estadístico de transición para evaluar predictibilidad cuando no hay PyTorch."""
    df = pd.read_csv(csv_path)
    print("=== ANÁLISIS DE CORRELACIÓN Y SESGO TEMPORAL (NumPy/Pandas) ===")
    
    # 1. Coincidencia de bucle (d1 == d3, d1 == d2 == d3)
    coincidencia_d1_d3 = (df['d1'] == df['d3']).mean() * 100
    bucle_triple = ((df['d1'] == df['d2']) & (df['d2'] == df['d3'])).mean() * 100
    print(f"  - Coincidencia idéntica d1 == d3: {coincidencia_d1_d3:.2f}% (Azar puro esperado: 10.00%)")
    print(f"  - Colapso en bucle triple (d1 == d2 == d3): {bucle_triple:.2f}% (Azar puro esperado: 1.00%)")
    
    # 2. Entropía posicional de Shannon
    print("\n=== ENTROPÍA DE SHANNON POR POSICIÓN (Dígitos d1..d6) ===")
    for i in range(1, 7):
        col = f"d{i}"
        probs = df[col].value_counts(normalize=True).values
        entropia = -np.sum(probs * np.log2(probs + 1e-12))
        entropia_max = np.log2(10)  # ~3.3219 bits
        print(f"  - Posición {col}: {entropia:.4f} bits (Máxima posible: {entropia_max:.4f} bits) -> Eficiencia: {(entropia/entropia_max)*100:.2f}%")


if __name__ == "__main__":
    carpeta_datos = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "datos"))
    ruta_csv = os.path.join(carpeta_datos, "dataset_otps_ejemplo.csv")
    
    if os.path.exists(ruta_csv):
        entrenar_evaluar_lstm(ruta_csv)
    else:
        print(f"[!] No se encontró el dataset en: {ruta_csv}")
        print("[i] Ejecuta primero: python simulador_dataset_interfaz.py")
