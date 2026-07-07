import joblib
import pandas as pd
import time
import random

model = joblib.load('intrusion_model.pkl')
feature_columns = joblib.load('intrusion_feature_columns.pkl')
label_mapping = joblib.load('intrusion_label_mapping.pkl')

# Reverse mapping: encoded int -> readable label
reverse_mapping = {v: k for k, v in label_mapping.items()}

replay_data = pd.read_csv('intrusion_replay_sample.csv')


def classify_flow(row):
    """
    Takes one row (a pandas Series) from the replay sample, runs it through 
    the model, and returns a structured result with both the prediction 
    and the ground truth — letting us show predicted vs. actual.
    """
    features = pd.DataFrame([row[feature_columns].values], columns=feature_columns)

    prediction_encoded = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]

    predicted_label = reverse_mapping[prediction_encoded]
    confidence = max(probabilities) * 100

    return {
        'predicted': predicted_label,
        'actual': row['true_label_name'],
        'confidence': round(confidence, 2),
        'correct': predicted_label == row['true_label_name']
    }


def replay_stream(delay_seconds=2):
    """
    Simulates a live feed by replaying the sample rows one at a time, 
    with a delay between each — like flows arriving at a SOC dashboard.
    """
    for idx, row in replay_data.iterrows():
        result = classify_flow(row)
        status = "MATCH" if result['correct'] else "MISMATCH"
        print(f"[{idx}] Predicted: {result['predicted']:15s} | "
              f"Actual: {result['actual']:15s} | "
              f"Confidence: {result['confidence']}% | {status}")
        time.sleep(delay_seconds)


if __name__ == '__main__':
    replay_stream(delay_seconds=1)
