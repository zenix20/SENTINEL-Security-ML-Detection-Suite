"""
Unified Security ML Dashboard — Flask Backend
Serves live predictions from the Phishing detector and the Intrusion 
detector (replayed CICIDS2017 test data) through one filterable feed.
"""

from flask import Flask, jsonify, render_template, request
import sys, os, time, random, threading
import pandas as pd
import joblib

# ─── PATH SETUP ───────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
sys.path.append(os.path.join(PROJECT_ROOT, 'phishing'))
sys.path.append(os.path.join(PROJECT_ROOT, 'intrusion'))

app = Flask(__name__)

# ─── LOAD INTRUSION MODEL + REPLAY DATA ──────────────────
intrusion_model = joblib.load(os.path.join(PROJECT_ROOT, 'intrusion', 'intrusion_model.pkl'))
intrusion_feature_columns = joblib.load(os.path.join(PROJECT_ROOT, 'intrusion', 'intrusion_feature_columns.pkl'))
intrusion_label_mapping = joblib.load(os.path.join(PROJECT_ROOT, 'intrusion', 'intrusion_label_mapping.pkl'))
intrusion_reverse_mapping = {v: k for k, v in intrusion_label_mapping.items()}
replay_data = pd.read_csv(os.path.join(PROJECT_ROOT, 'intrusion', 'intrusion_replay_sample.csv'))

# ─── LOAD PHISHING MODEL ──────────────────────────────────
phishing_model = joblib.load(os.path.join(PROJECT_ROOT, 'phishing', 'phishing_model.pkl'))
phishing_feature_columns = joblib.load(os.path.join(PROJECT_ROOT, 'phishing', 'phishing_feature_columns.pkl'))

try:
    from features import extract_features as extract_phishing_features
except ImportError:
    extract_phishing_features = None

# ─── SHARED STATE ──────────────────────────────────────────
feed_lock = threading.Lock()
feed = []
feed_id_counter = 0
replay_index = 0


def classify_intrusion_row():
    global replay_index
    row = replay_data.iloc[replay_index % len(replay_data)]
    replay_index += 1
    features = pd.DataFrame([row[intrusion_feature_columns].values], columns=intrusion_feature_columns)
    prediction_encoded = intrusion_model.predict(features)[0]
    probabilities = intrusion_model.predict_proba(features)[0]
    predicted_label = intrusion_reverse_mapping[prediction_encoded]
    confidence = round(max(probabilities) * 100, 1)
    actual_label = row['true_label_name']
    is_attack = predicted_label != 'Normal Traffic'
    return {
        'module': 'intrusion',
        'label': predicted_label,
        'confidence': confidence,
        'detail': f"Actual: {actual_label} · Dest Port: {int(row.get('Destination Port', 0))}",
        'status': 'alert' if is_attack else 'clear',
        'match': predicted_label == actual_label
    }


def classify_demo_url(url):
    if extract_phishing_features is None:
        return None
    features = extract_phishing_features(url)
    row = pd.DataFrame([features])[phishing_feature_columns]
    prediction = phishing_model.predict(row)[0]
    probability = phishing_model.predict_proba(row)[0]
    result = "Legitimate" if prediction == 1 else "Phishing"
    confidence = round(max(probability) * 100, 1)
    return {
        'module': 'phishing',
        'label': result,
        'confidence': confidence,
        'detail': url,
        'status': 'alert' if result == 'Phishing' else 'clear',
        'match': None
    }


DEMO_URLS = [
    "https://www.google.com",
    "https://www.github.com",
    "http://192.168.1.1/secure-login",
    "https://www.wikipedia.org",
    "http://paypal-account-verify-secure.tk",
    "https://www.cloudflare.com",
]


def background_feed_worker():
    global feed_id_counter
    url_cycle = 0
    while True:
        time.sleep(random.uniform(1.5, 3.0))
        try:
            entry = classify_intrusion_row()
        except Exception as e:
            entry = {'module': 'intrusion', 'label': 'Error', 'confidence': 0,
                     'detail': str(e), 'status': 'clear', 'match': None}
        with feed_lock:
            feed_id_counter += 1
            entry['id'] = feed_id_counter
            entry['timestamp'] = time.time()
            feed.insert(0, entry)
            del feed[200:]

        if random.random() < 0.35 and extract_phishing_features is not None:
            time.sleep(random.uniform(0.5, 1.5))
            url = DEMO_URLS[url_cycle % len(DEMO_URLS)]
            url_cycle += 1
            try:
                p_entry = classify_demo_url(url)
            except Exception as e:
                p_entry = {'module': 'phishing', 'label': 'Error', 'confidence': 0,
                           'detail': str(e), 'status': 'clear', 'match': None}
            if p_entry:
                with feed_lock:
                    feed_id_counter += 1
                    p_entry['id'] = feed_id_counter
                    p_entry['timestamp'] = time.time()
                    feed.insert(0, p_entry)
                    del feed[200:]


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/feed')
def get_feed():
    module_filter = request.args.get('module', 'all')
    with feed_lock:
        if module_filter == 'all':
            data = list(feed)
        else:
            data = [f for f in feed if f['module'] == module_filter]
    return jsonify(data[:100])


@app.route('/api/stats')
def get_stats():
    with feed_lock:
        total = len(feed)
        alerts = len([f for f in feed if f['status'] == 'alert'])
        phishing_count = len([f for f in feed if f['module'] == 'phishing'])
        intrusion_count = len([f for f in feed if f['module'] == 'intrusion'])
        matches = [f for f in feed if f.get('match') is True]
        mismatches = [f for f in feed if f.get('match') is False]
        accuracy = None
        if matches or mismatches:
            accuracy = round(len(matches) / (len(matches) + len(mismatches)) * 100, 1)
    return jsonify({
        'total': total, 'alerts': alerts,
        'phishing_count': phishing_count, 'intrusion_count': intrusion_count,
        'live_accuracy': accuracy
    })


@app.route('/api/scan_url', methods=['POST'])
def scan_url():
    url = request.json.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        result = classify_demo_url(url)
        if result is None:
            return jsonify({'error': 'Phishing module unavailable'}), 500
        with feed_lock:
            global feed_id_counter
            feed_id_counter += 1
            result['id'] = feed_id_counter
            result['timestamp'] = time.time()
            result['manual'] = True
            feed.insert(0, result)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    worker = threading.Thread(target=background_feed_worker, daemon=True)
    worker.start()
    app.run(debug=False, host='0.0.0.0', port=5050)
