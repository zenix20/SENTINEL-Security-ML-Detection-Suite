from features import extract_features
import json

url = "https://www.google.com"
result = extract_features(url)
print(json.dumps(result, indent=2))
