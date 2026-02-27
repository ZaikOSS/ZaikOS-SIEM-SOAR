Here is your polished and properly formatted `README.md` file, ready to copy and paste directly into GitHub:

---

# 🛡️ ZaikOS: Advanced SIEM + SOAR Automated Defense Pipeline

**ZaikOS** is an end-to-end Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) architecture. Built from the ground up, this project bridges the gap between offensive security tactics and active defensive engineering.

It autonomously detects network attacks, enriches threat data using global intelligence APIs, permanently blocks malicious actors at the firewall level in milliseconds, and streams the entire process live to a custom cyberpunk-styled SOC dashboard.

---

## 📑 Table of Contents

- [🔎 Project Overview](#-project-overview)
- [✨ Key Features](#-key-features)
- [🏗️ Architecture & Workflow](#️-architecture--workflow)
- [💻 Technology Stack](#-technology-stack)
- [🔬 Deep Dive: System Configurations](#-deep-dive-system-configurations)
- [⚙️ Installation & Deployment](#️-installation--deployment)
- [🔐 Environment Variables](#-environment-variables)
- [👨‍💻 About the Developer](#-about-the-developer)

---

## 🔎 Project Overview

Modern Security Operations Centers (SOCs) suffer from alert fatigue. ZaikOS was built to solve this by automating the triage and response phases of the incident lifecycle.

Instead of a human analyst manually checking an IP address against threat databases and logging into a server to ban them, ZaikOS handles the entire pipeline — from detection to remediation — in under 2 seconds.

---

## ✨ Key Features

- **Real-Time Log Ingestion**
  Wazuh agent continuously monitors `/var/log/auth.log` and Apache error logs for brute-force and SQL injection attempts.

- **Fault-Tolerant Webhooks**
  A custom Python integration script inside Wazuh securely queues and forwards Level 10+ alerts to the backend.

- **Automated Threat Intelligence**
  Instantly queries **VirusTotal** (70+ vendors) and **AbuseIPDB** to calculate a confidence score on the attacking IP.

- **Active Automated Response (SOAR)**
  Utilizes `paramiko` to establish a background SSH connection to the victim machine and dynamically writes `ufw deny` firewall rules to drop the attacker.

- **Live WebSocket Streaming**
  A Node.js backend pushes threat verdicts to the frontend in real-time via `Socket.io`.

- **Cyberpunk SOC Dashboard**
  A React.js frontend featuring animated terminal output, live threat timeline graphs, and system health monitoring.

---

## 🏗️ Architecture & Workflow

ZaikOS operates in a 6-stage lifecycle:

### 1️⃣ The Target (Endpoint)

A Linux VM running:

- Custom SSH (Port 2222)
- Apache Web Server

This is the designated attack surface.

### 2️⃣ The SIEM (Wazuh)

The Wazuh Manager detects anomalous behavior such as:

```
sshd: maximum authentication attempts exceeded
```

and triggers a critical alert.

### 3️⃣ The Orchestrator

The `custom-soar.py` script catches the alert directly within the Wazuh framework and POSTs the JSON payload to the Node.js API.

### 4️⃣ The Brain (Backend Engine)

Node.js receives the webhook and executes `analyzer.py`.

### 5️⃣ Threat Intelligence & Execution

The Python engine:

- Cross-references the IP with VirusTotal and AbuseIPDB.
- If risk level is **High** or **Critical**, it:
  - SSHs into the Target VM
  - Executes:

```bash
sudo ufw deny from <IP>
```

### 6️⃣ The SOC Dashboard

Analysts can watch:

- The attack detection
- API intelligence queries
- The firewall block

All happening live on the React dashboard.

---

## 💻 Technology Stack

### 🛡️ Defensive & Systems

- **Wazuh** – SIEM, log analysis, file integrity monitoring
- **Linux UFW** – Automated firewall blocking
- **Paramiko** – Python SSHv2 protocol library

### ⚙️ Backend (SOAR & API)

- **Node.js & Express.js** – Webhook listener and REST API
- **Python 3** – Threat analysis & execution scripts
- **Socket.io** – Bi-directional WebSocket communication
- **Requests** – API querying with exponential backoff

### 🎨 Frontend (Visibility)

- **React.js** – Component-based UI
- **CSS3** – Custom CRT scanline effects, dark-mode styling

---

## 🔬 Deep Dive: System Configurations

### 1️⃣ Wazuh Integration (`ossec.conf`)

To bridge the SIEM with the custom SOAR backend, configure the Wazuh Manager to forward high-severity alerts (Level 10+):

```xml
<ossec_config>
  <integration>
    <name>custom-soar</name>
    <hook_url>http://<BACKEND_IP>:3000/wazuh-alert</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

---

### 2️⃣ Forwarder Script (`custom-soar.py`)

Deployed at:

```
/var/ossec/integrations/custom-soar
```

This script handles:

- Payload extraction
- Secure transmission
- Internal logging
- Timeout handling

```python
#!/var/ossec/framework/python/bin/python3
import sys
import urllib.request
import datetime

LOG_FILE = "/var/ossec/logs/custom-soar.log"

def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log:
        log.write(f"[{timestamp}] {message}\n")

try:
    alert_file = sys.argv[1]
    hook_url = sys.argv[3]

    with open(alert_file, 'r') as f:
        alert_data = f.read()

    req = urllib.request.Request(
        hook_url,
        data=alert_data.encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )

    urllib.request.urlopen(req, timeout=5)
    log_event(f"SUCCESS: Alert sent to {hook_url}.")

except Exception as e:
    log_event(f"CRITICAL ERROR: {str(e)}")
    sys.exit(1)
```

---

### 3️⃣ Analysis Engine (`analyzer.py`)

Core Python engine features:

- **Lab Spoofing:** Detects local IPs (`192.168.x.x`) and substitutes known malicious IPs for lab simulations.
- **Rate Limit Handling:** Implements exponential backoff for VirusTotal API limits (`HTTP 429`).
- **Secure SSH Execution:** Uses `AutoAddPolicy()` to execute root-level firewall rules safely.

---

## ⚙️ Installation & Deployment

### 📌 Prerequisites

- Wazuh Manager instance
- Target Linux VM with:
  - Wazuh Agent installed
  - UFW enabled

- Node.js (v18+)
- Python (v3.8+)
- API keys for VirusTotal & AbuseIPDB

---

### 🚀 Step 1: Deploy Wazuh Integration

```bash
# Copy integration script
sudo cp custom-soar /var/ossec/integrations/custom-soar

# Set permissions
sudo chmod 750 /var/ossec/integrations/custom-soar

# Restart Wazuh
sudo systemctl restart wazuh-manager
```

---

### 🚀 Step 2: Set Up Backend

```bash
git clone https://github.com/yourusername/SIEM_SOAR_Zaikos.git
cd SIEM_SOAR_Zaikos

# Install Node dependencies
npm install express cors socket.io

# Install Python dependencies
pip3 install requests paramiko

# Start SOAR listener
node app.js
```

---

### 🚀 Step 3: Set Up Frontend Dashboard

```bash
cd soc-dashboard
npm install
npm run dev
```

---

## 🔐 Environment Variables

Create a `.env` file in the root directory:

```ini
VT_API_KEY=your_virustotal_api_key_here
ABUSE_API_KEY=your_abuseipdb_api_key_here
TARGET_HOST=192.168.100.100
TARGET_PORT=22
TARGET_USER=your_ssh_user
TARGET_PASS=your_ssh_password
```

> ⚠️ In production, use SSH key authentication instead of plaintext passwords.

---

## 👨‍💻 About the Developer

Developed by **Zakaria Ouadifi (Zaikos)**.

I am currently a 2nd-year engineering student in Digital Development and Cybersecurity at ENSA Fès, Morocco. I hold ISC2 Candidate status and I am actively preparing for the Certified in Cybersecurity (CC) exam.

I built this project to deepen my understanding of how:

- Offensive security (penetration testing, scripting)
- Defensive infrastructure (threat hunting, automated response)
- Full-stack engineering

all intersect in real-world cybersecurity operations.

### 📬 Contact

- **Email:** [zakaria.ouadifi@usmba.ac.ma](mailto:zakaria.ouadifi@usmba.ac.ma)
- **LinkedIn:** _(Insert your LinkedIn URL here)_

---

⭐ If you found this project interesting, feel free to star the repository!
