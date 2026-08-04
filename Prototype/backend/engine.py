from flask import Flask, request, jsonify
from difflib import SequenceMatcher
from db_manager import init_db, load_words_from_db

app = Flask(__name__)
init_db()

@app.route('/scan', methods=['POST'])
def scan_email():
    data = request.get_json() or {}
    sender_domain = data.get("sender_domain", "").strip().lower()
    email_text = data.get("email_text", "").lower()

    BAD_WORDS, BAD_LINKS, APPROVED_DOMAINS, BAD_ATTACHMENTS = load_words_from_db()

    if sender_domain in APPROVED_DOMAINS:
        return jsonify({"colour": "GREEN", "score": 0, "reason": "Sender domain is on the trusted whitelist"})

    score = 0
    reason = ""

    for approved_domain in APPROVED_DOMAINS:
        similarity = SequenceMatcher(None, sender_domain, approved_domain).ratio()
        if similarity >= 0.8:
            score += 50
            reason += f"Sender domain is malicious and may be impersonating the approved domain '{approved_domain}' | "
        break
    
    for attachment in BAD_ATTACHMENTS:
        if attachment in email_text:
            score += 30
            reason += f"Attachment '{attachment}' may be malicious or dangerous file  | "

    for word in BAD_WORDS:
        if word in email_text:
            score += 20
            reason += BAD_WORDS[word] + " | "

    for link in BAD_LINKS:
        if link in email_text:
            score += 50
            reason += BAD_LINKS[link] + " | "

    if score >= 60:
        colour = "RED"
    elif score >= 20:
        colour = "ORANGE"
    else:
        colour = "GREEN"

    return jsonify({
        "colour": colour,
        "score": score,
        "reason": reason
    })

if __name__ == '__main__':
    app.run(port=5000)