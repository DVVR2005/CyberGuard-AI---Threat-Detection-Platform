"""
ML Model Training Script for CyberGuard AI.
Generates synthetic security scan data and trains a Random Forest model.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error, r2_score
import joblib
import os


def generate_dataset(n=500):
    """Generate synthetic security scan data with labeled risk scores."""
    np.random.seed(42)
    data = {
        'open_ports': np.random.randint(1, 20, n),
        'vuln_count': np.random.randint(0, 15, n),
        'critical_count': np.random.randint(0, 5, n),
        'high_count': np.random.randint(0, 8, n),
        'ssl_score': np.random.randint(0, 101, n),
        'header_score': np.random.randint(0, 101, n),
        'exposed_dirs': np.random.randint(0, 8, n),
    }

    # Calculate risk score based on weighted formula + noise
    risk = (
        100
        - data['ssl_score'] * 0.2
        - data['header_score'] * 0.15
        + data['vuln_count'] * 3
        + data['critical_count'] * 8
        + data['open_ports'] * 1.5
        + data['exposed_dirs'] * 4
        + np.random.normal(0, 5, n)
    )
    data['risk_score'] = np.clip(risk, 0, 100).round(1)

    return pd.DataFrame(data)


def train():
    """Train the Random Forest model and save artifacts."""
    print("[*] Generating synthetic dataset...")
    df = generate_dataset(500)

    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sample_dataset.csv')
    df.to_csv(csv_path, index=False)
    print(f"[+] Dataset saved to {csv_path} ({len(df)} samples)")

    X = df.drop('risk_score', axis=1)
    y = df['risk_score']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("[*] Training Random Forest model...")
    model = RandomForestRegressor(
        n_estimators=100,
        max_depth=12,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    mae = mean_absolute_error(y_test, predictions)
    r2 = r2_score(y_test, predictions)

    print(f"\n{'=' * 50}")
    print("  Model Evaluation Results")
    print(f"{'=' * 50}")
    print(f"  MAE:  {mae:.2f}")
    print(f"  R²:   {r2:.4f}")
    print(f"\n  Feature Importance:")

    importances = dict(zip(X.columns, model.feature_importances_.round(4)))
    for feature, importance in sorted(importances.items(), key=lambda x: x[1], reverse=True):
        bar = '█' * int(importance * 50)
        print(f"    {feature:20s} {importance:.4f} {bar}")

    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'risk_model.pkl')
    joblib.dump(model, model_path)
    print(f"\n[+] Model saved to {model_path}")
    print("[+] Training complete!")


if __name__ == '__main__':
    train()
