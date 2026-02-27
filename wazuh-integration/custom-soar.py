#!/var/ossec/framework/python/bin/python3
import sys
import urllib.request
from urllib.error import URLError, HTTPError
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

    req = urllib.request.Request(hook_url, data=alert_data.encode('utf-8'), headers={'Content-Type': 'application/json'})
    response = urllib.request.urlopen(req, timeout=5)

    log_event(f"SUCCESS: Alert sent to {hook_url}. Server responded with HTTP {response.getcode()}")

except HTTPError as e:
    log_event(f"FAILED: Server returned HTTP Error {e.code} - {e.reason}")
except URLError as e:
    log_event(f"FAILED: Could not reach the Node.js backend. Is it running? Error: {e.reason}")
except Exception as e:
    log_event(f"CRITICAL ERROR: {str(e)}")
    sys.exit(1)