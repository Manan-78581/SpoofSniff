# alert.py
import datetime

LOG_FILE = 'spoofsniff_log.txt'

def show_alert(message):
    """
    Prints an alert message to the console.
    (This function will be less used directly by sniffer.py in GUI mode,
    but kept for completeness or direct console testing.)
    """
    print(f"\n[!!! DNS SPOOFING ALERT !!!] {message}\n")
    log_event(f"[ALERT] {message}")

def log_event(message):
    """
    Logs a message to the spoofsniff_log.txt file with a timestamp.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] {message}\n")

if __name__ == "__main__":
    print("Testing alert.py...")
    log_event("This is a test log entry.")
    show_alert("Test DNS Spoofing Detected: example.com to 1.2.3.4")
    print(f"Check '{LOG_FILE}' for log entries.")