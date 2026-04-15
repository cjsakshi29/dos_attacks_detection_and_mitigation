import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

def generate_synthetic_data(n_samples=1000):
    data = []
    
    # Generate Normal Traffic (Poisson-like, high variance)
    for _ in range(n_samples // 2):
        count = np.random.randint(2, 12) # 2 to 11 requests
        # Random intervals between 0.5s and 4.0s
        intervals = np.random.uniform(0.5, 4.0, count)
        data.append({
            'count': count,
            'mean_interval': np.mean(intervals),
            'std_interval': np.std(intervals),
            'max_interval': np.max(intervals),
            'label': 0 # Normal
        })
        
    # Generate DDoS Traffic (Bot-like, low variance, high frequency)
    for _ in range(n_samples // 2):
        count = np.random.randint(15, 30) # 15 to 30 requests
        # Very tight intervals between 0.05s and 0.2s
        intervals = np.random.uniform(0.05, 0.2, count)
        data.append({
            'count': count,
            'mean_interval': np.mean(intervals),
            'std_interval': np.std(intervals),
            'max_interval': np.max(intervals),
            'label': 1 # DDoS
        })
        
    return pd.DataFrame(data)

def train():
    print("🧪 Generating synthetic traffic data...")
    df = generate_synthetic_data(2000)
    
    X = df[['count', 'mean_interval', 'std_interval', 'max_interval']]
    y = df['label']
    
    print("🌲 Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    # Save the model
    model_path = os.path.join(os.path.dirname(__file__), 'ddos_model.pkl')
    joblib.dump(model, model_path)
    
    print(f"✅ Model trained and saved to: {model_path}")
    
    # Print feature importance for transparency
    importances = model.feature_importances_
    for name, imp in zip(X.columns, importances):
        print(f" - Feature '{name}': {imp:.4f}")

if __name__ == "__main__":
    train()
