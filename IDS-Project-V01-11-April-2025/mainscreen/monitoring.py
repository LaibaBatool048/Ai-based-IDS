from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import joblib
import sqlite3
from collections import defaultdict
import time
import numpy as np
from datetime import datetime
import json
import os
from PyQt5 import QtWidgets

# Load trained model and encoders
model = joblib.load("models/rf_model_resampled.pkl")
encoded_columns = joblib.load("models/encoded_columns_resampled.pkl")
label_encoder = joblib.load("models/label_encoder_resampled.pkl")

print("Class Order:", label_encoder.classes_)


# Set up SQLite database connection (fallback if no controller)
connection = sqlite3.connect("IDS.db")
cursor = connection.cursor()

# Sliding window for traffic-based features
traffic_window = 60  # seconds
packet_history = defaultdict(list)

# Probability thresholds for classification
THRESHOLD_LEVELS = {
    "Low": {"DoS": 0.2, "Probe": 0.4, "R2L": 0.2, "U2R": 0.2, "normal": 0.5},
    "Medium": {"DoS": 0.15, "Probe": 0.38, "R2L": 0.18, "U2R": 0.18, "normal": 0.5},
    "High": {"DoS": 0.12, "Probe": 0.35, "R2L": 0.15, "U2R": 0.15, "normal": 0.5},
}

CONFIG_FILE = "config.txt"

def load_sensitivity():
    if not os.path.exists(CONFIG_FILE):
        return "Medium"
    try:
        with open(CONFIG_FILE, "r") as file:
            settings = json.load(file)
            return settings.get("sensitivity", "Medium")
    except (json.JSONDecodeError, FileNotFoundError):
        return "Medium"

def get_attack_thresholds():
    return THRESHOLD_LEVELS.get(load_sensitivity(), THRESHOLD_LEVELS["Medium"])

thresholds = get_attack_thresholds()
print("Loaded Thresholds:", thresholds)

malicious_packet_count = defaultdict(int)
attack_timestamps = defaultdict(list)

def process_packet(pkt, controller=None):
    # Skip non-IP packets immediately
    if not pkt.haslayer(IP):
        return #"Non-IP packet (skipping)"
    
    current_time = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = pkt[IP]
    
    # Initialize features with proper protocol detection
    features = {
        "protocol_type": {1: "icmp", 6: "tcp", 17: "udp"}.get(ip.proto, "unknown"),
        "src_bytes": len(ip.payload),
        "dst_bytes": len(ip.payload),
        "service": "other",
        "flag": 0,  # Default for non-TCP
        "count": 0,
        "srv_count": 0,
        "same_srv_rate": 0.0,
        "diff_srv_rate": 0.0,
    }

    # If TCP, use the length of the payload (this should represent the data being sent)
    if pkt.haslayer(TCP):
        print("TCP Packet")
        features["src_bytes"] = len(pkt[TCP].payload)  # Size of TCP payload
        features["dst_bytes"] = len(pkt[TCP].payload)  # Size of TCP payload
        tcp = pkt[TCP]
        features.update({
            "flag": int(tcp.flags),
            "service": "http" if tcp.dport == 80 else ("https" if tcp.dport == 443 else "tcp")
        })

    # If UDP, do the same for UDP packets
    elif pkt.haslayer(UDP):
        print("UDP Packet")
        features["src_bytes"] = len(pkt[UDP].payload)  # Size of UDP payload
        features["dst_bytes"] = len(pkt[UDP].payload)  # Size of UDP payload
        udp = pkt[UDP]
        features.update({
            "service": "dns" if udp.dport == 53 else "udp"
        })

    # For ICMP, the length of the payload (ICMP data) will be used
    elif pkt.haslayer(ICMP):
        print("ICMP Packet")
        features["src_bytes"] = len(pkt[ICMP].payload)  # ICMP payload size
        features["dst_bytes"] = len(pkt[ICMP].payload)  # ICMP payload size

    # Get destination IP for traffic analysis
    dst_ip = ip.dst
        
    
    # Update traffic window statistics
    packet_history[dst_ip].append(current_time)
    
    # Clean up old packets from history
    for ip in list(packet_history.keys()):
        packet_history[ip] = [t for t in packet_history[ip] if t > current_time - traffic_window]
        if not packet_history[ip]:
            del packet_history[ip]
    
    # Calculate traffic-based features
    current_count = len(packet_history.get(dst_ip, []))
    features.update({
        "count": current_count,
        "srv_count": sum(1 for t in packet_history.get(dst_ip, []) 
                     if pkt.haslayer(TCP) and pkt[TCP].dport == features.get('service', 0)),
    })
    
    # Calculate service rates
    if current_count > 0:
        features["same_srv_rate"] = features["srv_count"] / current_count
        features["diff_srv_rate"] = (current_count - features["srv_count"]) / current_count

    try:
        # Create DataFrame for model input
        df = pd.DataFrame([features])
        
        # Ensure all required columns exist
        required_columns = ["protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
                          "count", "srv_count", "same_srv_rate", "diff_srv_rate"]
        for col in required_columns:
            if col not in df.columns:
                df[col] = 0
        
        # One-hot encoding
        df_encoded = pd.get_dummies(df, columns=["protocol_type", "service", "flag"], drop_first=False)
        
        # Add missing columns with 0 values
        missing_columns = {col: [0] * len(df_encoded) for col in encoded_columns if col not in df_encoded.columns}
        df_encoded = pd.concat([df_encoded, pd.DataFrame(missing_columns)], axis=1)
        df_encoded = df_encoded[encoded_columns]
        
        if df_encoded.empty:
            return

        #Predict label
        probabilities = model.predict_proba(df_encoded)
        prediction_index = np.argmax(probabilities, axis=1)[0]
        predicted_attack = label_encoder.inverse_transform([prediction_index])[0]
        max_prob = probabilities[0][prediction_index]

        # Apply thresholding
        if max_prob < thresholds.get(predicted_attack, 0.1):
            predicted_attack = "normal"

        # Prepare output
        packet_info = f"Packet Captured:\nFeatures: protocol_type={features['protocol_type']}, " \
                     f"src_bytes={features['src_bytes']}, dst_bytes={features['dst_bytes']}, " \
                     f"service={features['service']}\n" \
                     f"Prediction: {predicted_attack} (Confidence: {max_prob:.2f})"
        
        print(f"\n[{timestamp}] Packet: {features}")
        print(f"Prediction: {predicted_attack}")
        probs_dict = {label: float(prob) for label, prob in zip(label_encoder.classes_, probabilities[0])}
        print("Prediction Probabilities:")
        for label, prob in probs_dict.items():
            print(f"  {label:6}: {prob:.4f}")


        if controller:
            controller.status_updated.emit(packet_info)

        # Attack detection logic
        attack_window = 60
        attack_threshold = 10
        packet_id = hash(str(features))

        if predicted_attack not in ["normal", "unknown"]:
            attack_timestamps[packet_id].append(current_time)
            attack_timestamps[packet_id] = [t for t in attack_timestamps[packet_id] if t > current_time - attack_window]
            malicious_packet_count[packet_id] = len(attack_timestamps[packet_id])

            if malicious_packet_count[packet_id] >= attack_threshold:
                print(f"🚨 ALERT TRIGGERED! Attack: {predicted_attack}")  # Debug
                print(f"Controller exists: {controller is not None}")  # Debug
                malicious_packet_count[packet_id] = 0

                preventions = []
                if controller:
                    print("Calling controller.alert_triggered.emit()")  # Debug
                    preventions = controller.get_preventions(predicted_attack)
                    controller.log_attack((
                        timestamp, features["protocol_type"], features["src_bytes"], features["dst_bytes"],
                        features["service"], features["flag"], features["count"], features["srv_count"],
                        features["same_srv_rate"], features["diff_srv_rate"], predicted_attack
                    ))
                    controller.alert_triggered.emit(predicted_attack, preventions)
                else:
                    cursor.execute("SELECT preventions FROM suggestions WHERE attack = ?", (predicted_attack,))
                    preventions = cursor.fetchall()
                    cursor.execute("""
                    INSERT INTO detected_attacks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (timestamp, features["protocol_type"], features["src_bytes"], features["dst_bytes"],
                           features["service"], features["flag"], features["count"], features["srv_count"],
                           features["same_srv_rate"], features["diff_srv_rate"], predicted_attack))
                    connection.commit()
        return packet_info

    except Exception as e:
        print(f"❌ Error processing packet: {e}")
        if controller:
            controller.status_updated.emit(f"Error: {str(e)}")
        return f"Error: {str(e)}"

