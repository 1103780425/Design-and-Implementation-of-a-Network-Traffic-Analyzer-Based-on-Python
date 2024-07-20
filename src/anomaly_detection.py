# anomaly_detection.py
from sklearn.ensemble import IsolationForest

def train_isolation_forest(data, features):
    model = IsolationForest(n_estimators=100, contamination='auto')
    model.fit(data[features])
    return model

def predict_anomalies(model, new_data, features):
    predictions = model.predict(new_data[features])
    new_data['anomaly'] = predictions
    return new_data
