# Import necessary libraries
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
import joblib

# Load dataset
file_path = "D:/Project/data/KDDCup99.csv"
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", 
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", 
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", 
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", 
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", 
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", 
    "dst_host_serror_rate", "dst_host_srv_serror_rate", 
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"
]
data = pd.read_csv(file_path, header=None, names=columns, low_memory=False)

# Map attack categories
def map_attack_category(label):
    if label == "normal":
        return "normal"
    elif label in ["neptune", "smurf", "pod", "teardrop", "back", "land"]:
        return "DoS"
    elif label in ["satan", "ipsweep", "nmap", "portsweep"]:
        return "Probe"
    elif label in ["buffer_overflow", "loadmodule", "rootkit", "perl"]:
        return "U2R"
    elif label in ["guess_passwd", "ftp_write", "imap", "phf", "multihop", "warezmaster", "warezclient", "spy"]:
        return "R2L"
    else:
        return "unknown"

data['label'] = data['label'].apply(map_attack_category)
data = data[data['label'] != "unknown"]

# Encode categorical variables
data = pd.get_dummies(data, columns=["protocol_type", "service", "flag"], drop_first=True)

# Encode labels
label_encoder = LabelEncoder()
data['label'] = label_encoder.fit_transform(data['label'])
joblib.dump(label_encoder, "models/label_encoder_resampled.pkl")

# Split data into features (X) and target (y)
X = data.drop("label", axis=1)
y = data["label"]

# Save feature names
joblib.dump(list(X.columns), "models/encoded_columns_resampled.pkl")

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

# Train RandomForest without SMOTE or scaling
model = RandomForestClassifier(
    n_estimators=150,  # Increase tree count to handle large dataset
    max_depth=10,  # Prevent overfitting
    class_weight="balanced",  # Handle imbalances
    max_features="sqrt",  # Improve efficiency
    n_jobs=2,
    random_state=42
)

# Train the model on original data (no resampling or scaling)
model.fit(X_train, y_train)

# Predict on the test set
y_pred = model.predict(X_test)

# Evaluate model
print("Accuracy: ", accuracy_score(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred, target_names=label_encoder.classes_))

# Save model
joblib.dump(model, "models/rf_model_resampled.pkl")

# Show class distribution
unique, counts = np.unique(y_train, return_counts=True)
print("Class Distribution After Resampling:")
for label, count in zip(unique, counts):
    print(f"Class {label}: {count}")
