import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import warnings

warnings.filterwarnings("ignore")

# -----------------------------
# 1. Load Lazarus Group TTPs
# -----------------------------
data = [
    # Tactic, Tech ID, Technique, Color, Score, Priority, Evidence
    ("Initial Access", "T1589", "Gather Victim Identity Info", "🟡", 4, "High", "Targets employee profiles for spearphishing"),
    ("Initial Access", "T1591", "Gather Victim Org Info", "🟢", 5, "Critical", "Researches target organizations extensively"),
    ("Execution", "T1053", "Scheduled Task/Job", "🟠", 3, "Medium", "Uses cron jobs/task scheduler"),
    ("Execution", "T1204", "Indirect Command Execution", "🟡", 4, "High", "Obfuscated script execution"),
    ("Persistence", "T1098", "Account Manipulation", "🟢", 5, "Critical", "Creates hidden admin accounts"),
    ("Persistence", "T1112", "Modify Registry", "🟢", 5, "Critical", "Modifies registry for persistence"),
    ("Privilege Escalation", "T1055", "Process Injection", "🟢", 5, "Critical", "Injects into legitimate processes"),
    ("Defense Evasion", "T1140", "Deobfuscate Files", "🟢", 5, "Critical", "Uses custom unpackers"),
    ("Defense Evasion", "T1027", "Obfuscated Files", "🟠", 3, "Medium", "Encrypted payloads"),
    ("Credential Access", "T1110", "Brute Force", "🟠", 3, "Medium", "Password spraying attacks"),
    ("Discovery", "T1083", "File/Directory Discovery", "🟤", 2, "Low", "Basic reconnaissance"),
    ("Discovery", "T1046", "Network Service Discovery", "🟠", 3, "Medium", "Port scanning activities"),
    ("Discovery", "T1217", "Browser Info Discovery", "🟡", 4, "High", "Harvests browser credentials"),
    ("Lateral Movement", "T1078", "Valid Accounts", "🔴", 0, "Ignore", "Rarely uses legit credentials"),
    ("Impact", "T1485", "Data Destruction", "🟢", 5, "Critical", "Deploys wiper malware")
]

columns = ["Tactic", "Technique ID", "Technique Name", "Color", "Score", "Priority", "Evidence"]
df = pd.DataFrame(data, columns=columns)

# -----------------------------
# 2. Visualize Score Distribution
# -----------------------------
def plot_score_heatmap():
    plt.figure(figsize=(10, 6))
    pivot = df.pivot_table(index="Technique Name", columns="Tactic", values="Score", aggfunc="mean")
    sns.heatmap(pivot, annot=True, cmap="YlGnBu", linewidths=0.5)
    plt.title("TTP Priority Heatmap (Score-based)")
    plt.tight_layout()
    plt.show()

plot_score_heatmap()

# -----------------------------
# 3. Machine Learning
# -----------------------------
# Encode Priority and Tactic
le_priority = LabelEncoder()
le_tactic = LabelEncoder()
df['Priority_enc'] = le_priority.fit_transform(df['Priority'])
df['Tactic_enc'] = le_tactic.fit_transform(df['Tactic'])

# Features and target
X = df[['Score', 'Tactic_enc']]
y = df['Priority_enc']

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Predict
y_pred = clf.predict(X_test)

# Fixed classification report
report = classification_report(
    y_test, y_pred,
    labels=np.unique(y_test),
    target_names=le_priority.inverse_transform(np.unique(y_test)),
    output_dict=True
)

# Show readable report
print("\n=== ML Classification Report ===")
for label, metrics in report.items():
    if isinstance(metrics, dict):
        print(f"{label}: precision={metrics['precision']:.2f}, recall={metrics['recall']:.2f}, f1-score={metrics['f1-score']:.2f}")

# -----------------------------
# 4. Add Detection Suggestions
# -----------------------------
detection = {
    "T1589": "Monitor social media scraping from unusual IPs",
    "T1591": "Track organization info queries via public forums",
    "T1053": "Detect scheduled jobs created by unknown users",
    "T1204": "Alert on indirect script execution (e.g., rundll32, regsvr32)",
    "T1098": "Detect creation of unexpected admin accounts",
    "T1112": "Log and alert on registry modifications",
    "T1055": "Memory scanning for injected code in processes",
    "T1140": "Detect decoding patterns in traffic or processes",
    "T1027": "Check for obfuscated files or encoded payloads",
    "T1110": "Alert on repeated failed logins (brute force)",
    "T1083": "Watch for excessive directory listing commands",
    "T1046": "Log internal port scans",
    "T1217": "Track credential access via browser storage",
    "T1078": "Login alerts for unused but valid accounts",
    "T1485": "Block and alert on wiper malware behavior"
}

df['Detection'] = df['Technique ID'].map(detection)

# -----------------------------
# 5. Save to Excel
# -----------------------------
df.to_excel("lazarus_threat_intel_analysis.xlsx", index=False)
print("\n[+] Excel report saved as 'lazarus_threat_intel_analysis.xlsx'.")

# -----------------------------
# 6. Bonus Visualization - Pie
# -----------------------------
plt.figure(figsize=(6, 6))
df['Priority'].value_counts().plot.pie(autopct='%1.1f%%', colors=sns.color_palette("Set2"))
plt.title("Priority Distribution of Techniques")
plt.ylabel('')
plt.show()
