"""
app.py — email/phishing scanner with document upload.
 
Self-contained: does not import from engine.py. The only external dependency
is db_manager, which must expose:
 
    init_db()
    load_words_from_db() -> (BAD_WORDS, BAD_LINKS, APPROVED_DOMAINS, BAD_ATTACHMENTS)
 
where BAD_WORDS and BAD_LINKS are dicts {trigger: reason} and the other two
are iterables of strings.
 
Run with python app.py then open http://127.0.0.1:5000
"""
 
from difflib import SequenceMatcher
from email import policy
from email.parser import BytesParser
 
from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename
 
from db_manager import init_db, load_words_from_db

import json, os, urllib.request
 
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024      # 5 MB ceiling
 
ALLOWED_EXTENSIONS = {"eml", "msg", "txt", "html"}
 
SCORE_IMPERSONATION = 50
SCORE_ATTACHMENT = 30
SCORE_BAD_WORD = 20
SCORE_BAD_LINK = 50
SCORE_UNICODE = 50
SCORE_VIRUSTOTAL = 50
 
THRESHOLD_RED = 60
THRESHOLD_ORANGE = 20
 
SIMILARITY_THRESHOLD = 0.8
 
init_db()
 
def is_allowed(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
 
 
def read_upload(file_storage):
    """Turn an uploaded file into (sender_domain, email_text).
 
    .eml and .msg files are parsed as real messages, so we get the actual
    From header and the actual attachment filenames. Everything else is
    treated as plain text with no sender.
    """
    raw = file_storage.read()
    name = secure_filename(file_storage.filename or "").lower()
 
    if not name.endswith((".eml", ".msg")):
        return "", raw.decode("utf-8", errors="ignore").lower()
 
    message = BytesParser(policy=policy.default).parsebytes(raw)
 
    sender = message.get("From", "")
    sender_domain = ""
    if "@" in sender:
        sender_domain = sender.split("@")[-1].strip(" <>\"'").lower()
 
    pieces = [message.get("Subject", "")]
    attachments = []
 
    for part in message.walk():
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
        elif part.get_content_type() in ("text/plain", "text/html"):
            try:
                pieces.append(part.get_content())
            except Exception:
                pass
 
    # attachment names go into the text so the BAD_ATTACHMENTS check sees them
    pieces.extend(attachments)
 
    return sender_domain, "\n".join(str(p) for p in pieces).lower()

def contains_unicode(domain):
    return not domain.isascii()

def check_virustotal_domain(domain):
    try:
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": os.environ.get("VT_API_KEY")},
        )
        data = json.loads(urllib.request.urlopen(req).read())
        stats = data["data"]["attributes"]["last_analysis_stats"]

        if stats["malicious"] or stats["suspicious"]:
            reason = f"VirusTotal flagged {domain}: {stats['malicious']} malicious, {stats['suspicious']} suspicious"
            return SCORE_VIRUSTOTAL, reason
    except Exception:
        pass

    return 0, None

def analyse(sender_domain, email_text):
    """Score an email. Returns {colour, score, reason}."""
    bad_words, bad_links, whitelist, bad_attachments = load_words_from_db()

    sender_domain = (sender_domain or "").strip().lower()
    email_text = (email_text or "").lower()

    if sender_domain and sender_domain in whitelist:
        return {"colour": "GREEN", "score": 0,
                "reason": "Sender domain is on the trusted whitelist"}

    score = 0
    reasons = []

    if sender_domain:
        if contains_unicode(sender_domain):
            score += SCORE_UNICODE
            reasons.append("Sender domain contains unicode characters, therefore could be an homograph impersonation attack.")

        for approved in whitelist:
            if SequenceMatcher(None, sender_domain, approved).ratio() >= SIMILARITY_THRESHOLD:
                score += SCORE_IMPERSONATION
                reasons.append(f"Sender domain closely resembles the approved domain '{approved}'")
                break

        vt_score, vt_reason = check_virustotal_domain(sender_domain)
        if vt_score:
            score += vt_score
            reasons.append(vt_reason)

    for extension, reason in bad_attachments.items():
        if extension in email_text:
            score += SCORE_ATTACHMENT
            reasons.append(reason)

    for word, reason in bad_words.items():
        if word in email_text:
            score += SCORE_BAD_WORD
            reasons.append(reason)

    for link, reason in bad_links.items():
        if link in email_text:
            score += SCORE_BAD_LINK
            reasons.append(reason)

    if score >= THRESHOLD_RED:
        colour = "RED"
    elif score >= THRESHOLD_ORANGE:
        colour = "ORANGE"
    else:
        colour = "GREEN"

    return {"colour": colour, "score": score,
            "reason": " | ".join(reasons) or "No suspicious indicators found"}


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")

    pasted_text = (request.form.get("email_text") or "").strip()
    uploaded = request.files.get("file")

    # pasted text
    if pasted_text:
        sender_domain = (request.form.get("sender_domain") or "").strip().lower()
        return render_template(
            "index.html",
            mode="paste",
            submitted_text=pasted_text,
            submitted_domain=sender_domain,
            result=analyse(sender_domain, pasted_text),
        )

    # uploaded file
    if uploaded and uploaded.filename:
        if not is_allowed(uploaded.filename):
            return render_template(
                "index.html",
                error="That file type isn't supported. Use .eml, .msg, .txt or .html."
            ), 400

        sender_domain, email_text = read_upload(uploaded)
        if not email_text.strip():
            return render_template(
                "index.html",
                error="That file appears to be empty, so there was nothing to scan."
            ), 400

        return render_template("index.html", result=analyse(sender_domain, email_text))

    # neither
    return render_template(
        "index.html", error="Choose a file or paste some text to scan."
    ), 400
 
@app.route("/scan", methods=["POST"])
def scan():
    """JSON API. Accepts either a multipart file upload or a JSON body."""
    if "file" in request.files:
        uploaded = request.files["file"]
        if not uploaded.filename:
            return jsonify({"error": "No file provided"}), 400
        if not is_allowed(uploaded.filename):
            return jsonify({"error": "Unsupported file type"}), 400
        sender_domain, email_text = read_upload(uploaded)
    else:
        data = request.get_json(silent=True) or {}
        sender_domain = data.get("sender_domain", "")
        email_text = data.get("email_text", "")
 
    return jsonify(analyse(sender_domain, email_text))
 
 
@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "File exceeds the 5 MB limit"}), 413
 
 
if __name__ == "__main__":
    app.run(port=5000, debug=True)