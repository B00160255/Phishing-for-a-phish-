import json
import os
# list of bad words and domains
BAD_WORDS = {
    "urgent": "Urgency word detected",
    "won": "Prize/lottery bait detected"
}

BAD_ATTACHMENTS = {
    ".exe": "Executable file attachment detected",
    ".zip": "Compressed file attachment may contain malware"
}

BAD_LINKS = {
    "notascam.com": "Known phishing link",
    "fake-login.com": "Credential harvesting page"
}

def load_whitelist():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    whitelist_path = os.path.join(script_dir, "whitelist.json")
    
    try:
        with open(whitelist_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Warning: Could not find whitelist.json at {whitelist_path}")
        return []