import joblib
import pandas as pd
from features import extract_features

model = joblib.load('phishing_model.pkl')
feature_columns = joblib.load('phishing_feature_columns.pkl')


def predict_url(url):
    features = extract_features(url)
    # Build the row in the EXACT column order the model was trained on
    row = pd.DataFrame([features])[feature_columns]

    prediction = model.predict(row)[0]
    probability = model.predict_proba(row)[0]

    result = "Legitimate" if prediction == 1 else "Phishing"
    confidence = max(probability) * 100

    return {
        'url': url,
        'prediction': result,
        'confidence': round(confidence, 2),
        'features': features
    }


if __name__ == '__main__':
    test_urls = [
        "https://www.google.com",
        "https://www.paypal.com",
        "http://192.168.1.1/secure-login",
        "http://paypal-account-verify-secure.tk",
    ]
    for url in test_urls:
        result = predict_url(url)
        print(f"\nURL: {result['url']}")
        print(f"Prediction: {result['prediction']} ({result['confidence']}% confidence)")
