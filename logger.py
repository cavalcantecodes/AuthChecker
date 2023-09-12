import json
import os

class Logger:

    def __init__(self, log_file='scan_logs.json'):
        self.log_file = log_file
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                json.dump([], f)

    def log_scan(self, date, scan_type, result, url):
        log_entry = {
            "Date": date,
            "Scan Type": scan_type,
            "Result": result,
            "URL": url
        }
        
        with open(self.log_file, 'r+') as f:
            logs = json.load(f)
            logs.append(log_entry)
            f.seek(0)
            json.dump(logs, f, indent=4)
