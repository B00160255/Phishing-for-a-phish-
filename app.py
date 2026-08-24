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
import json
import os
import re
import unicodedata
import urllib.request
from urllib.parse import urlparse
from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from db_manager import init_db, load_words_from_db

sia = SentimentIntensityAnalyzer()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024      # 5 MB ceiling

ALLOWED_EXTENSIONS = {"eml", "msg", "txt", "html"}

SCORE_IMPERSONATION = 50
SCORE_ATTACHMENT = 30
SCORE_BAD_WORD = 20
SCORE_BAD_LINK = 50
SCORE_UNICODE = 50
SCORE_VIRUSTOTAL = 50
SCORE_MIXED_SCRIPT_SENDER = 30
SCORE_MIXED_SCRIPT_URL = 30
SCORE_SPOOFING = 50
SCORE_PRESSURE = 25

THRESHOLD_RED = 60
THRESHOLD_ORANGE = 20

SIMILARITY_THRESHOLD = 0.8

init_db()

def is_allowed(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def is_trusted(domain, whitelist):
    if not domain:
        return False
    domain = domain.strip().lower()
    for w in whitelist:
        w = (w or "").strip().lower()
        if w and (domain == w or domain.endswith("." + w)):
            return True
    return False

def read_upload(file_storage):
    """Turn an uploaded file into (sender_domain, return_domain, email_text)."""
    raw = file_storage.read()
    name = secure_filename(file_storage.filename or "").lower()

    if not name.endswith((".eml", ".msg")):
        return "", "", raw.decode("utf-8", errors="ignore").lower()

    message = BytesParser(policy=policy.default).parsebytes(raw)

    sender = message.get("From", "")
    return_path = message.get("Return-Path", "")

    sender_domain = (
        sender.split("@")[-1].strip(" <>\"'").lower() if "@" in sender else ""
    )
    return_domain = (
        return_path.split("@")[-1].strip(" <>\"'").lower() if "@" in return_path else ""
    )

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

    pieces.extend(attachments)

    return sender_domain, return_domain, "\n".join(str(p) for p in pieces).lower()

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

def get_detected_scripts(text):
    scripts = set()
    for char in text:
        char_name = unicodedata.name(char, "")
        if "LATIN" in char_name:
            scripts.add("LATIN")
        elif "CYRILLIC" in char_name:
            scripts.add("CYRILLIC")
        elif "GREEK" in char_name:
            scripts.add("GREEK")

    return scripts

def get_url_hostname(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    parsed_url = urlparse(url)
    return parsed_url.hostname or ""

def analyse(sender_domain, email_text, return_domain=""):
    """Score an email. Returns {colour, score, reason}."""
    bad_words, bad_links, whitelist, bad_attachments = load_words_from_db()

    sender_domain = (sender_domain or "").strip().lower()
    return_domain = (return_domain or "").strip().lower()
    email_text = (email_text or "").lower()

    sender_trusted = is_trusted(sender_domain, whitelist)
    return_trusted = is_trusted(return_domain, whitelist) if return_domain else False

    is_spoofed = bool(return_domain and sender_domain != return_domain and not is_trusted(return_domain, whitelist))

    if (sender_trusted or return_trusted) and not is_spoofed:
        return {"colour": "GREEN", "score": 0, "reason": "Sender/Return-Path domain is on the trusted whitelist"}

    score = 0
    reasons = []

    if is_spoofed:
        score += SCORE_SPOOFING
        reasons.append(f"Spoofing Warning: Sender '{sender_domain}' does not match Return-Path '{return_domain}'")

    check_domain = return_domain if (is_spoofed and return_domain) else sender_domain
    if check_domain:
        vt_score, vt_reason = check_virustotal_domain(check_domain)
        if vt_score:
            score += vt_score
            reasons.append(f"Domain check: {vt_reason}")

        detected_scripts = get_detected_scripts(check_domain)
        if len(detected_scripts) > 1:
            scripts_found = ", ".join(sorted(detected_scripts))
            score += SCORE_MIXED_SCRIPT_SENDER
            reasons.append(f"Sender domain '{check_domain}' contains mixed scripts ({scripts_found})")

        for approved in whitelist:
            if SequenceMatcher(None, check_domain, approved).ratio() >= SIMILARITY_THRESHOLD:
                score += SCORE_IMPERSONATION
                reasons.append(f"Sender domain '{check_domain}' closely resembles approved domain '{approved}'")
                break

    for link, reason in bad_links.items():
        if link in email_text:
            score += SCORE_BAD_LINK
            reasons.append(reason)

    for item in email_text.split():
        if item.startswith(("http://", "https://")):
            hostname = get_url_hostname(item)
            if hostname:
                detected_scripts = get_detected_scripts(hostname)
                if len(detected_scripts) > 1:
                    scripts_found = ", ".join(sorted(detected_scripts))
                    score += SCORE_MIXED_SCRIPT_URL
                    reasons.append(f"URL hostname '{hostname}' contains mixed scripts {scripts_found}")

    for extension, reason in bad_attachments.items():
        if extension in email_text:
            score += SCORE_ATTACHMENT
            reasons.append(reason)

    matched_bad_words = []
    for word, reason in bad_words.items():
        if re.search(rf"\b{re.escape(word)}\b", email_text, re.I):
            score += SCORE_BAD_WORD
            reasons.append(reason)
            matched_bad_words.append(word)

    if matched_bad_words:
        sentiment = sia.polarity_scores(email_text)
        if sentiment["compound"] < -0.3 or sentiment["neg"] > 0.25:
            score += SCORE_PRESSURE
            reasons.append("High-pressure threat language detected")

    colour = "RED" if score >= THRESHOLD_RED else ("ORANGE" if score >= THRESHOLD_ORANGE else "GREEN")

    return {"colour": colour, "score": score, "reason": " | ".join(reasons) or "No suspicious indicators found"}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")

    pasted_text = (request.form.get("email_text") or "").strip()
    uploaded = request.files.get("file")

    if pasted_text:
        sender_domain = (request.form.get("sender_domain") or "").strip().lower()
        return render_template(
            "index.html",
            mode="paste",
            submitted_text=pasted_text,
            submitted_domain=sender_domain,
            result=analyse(sender_domain, pasted_text),
        )

    if uploaded and uploaded.filename:
        if not is_allowed(uploaded.filename):
            return render_template(
                "index.html",
                error="That file type isn't supported. Use .eml, .msg, .txt or .html."
            ), 400

        sender_domain, return_domain, email_text = read_upload(uploaded)
        if not email_text.strip():
            return render_template(
                "index.html",
                error="That file appears to be empty, so there was nothing to scan."
            ), 400

        return render_template("index.html", result=analyse(sender_domain, email_text, return_domain))

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
        sender_domain, return_domain, email_text = read_upload(uploaded)
    else:
        data = request.get_json(silent=True) or {}
        sender_domain = data.get("sender_domain", "")
        return_domain = data.get("return_domain", "")
        email_text = data.get("email_text", "")

    return jsonify(analyse(sender_domain, email_text, return_domain))

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "File exceeds the 5 MB limit"}), 413

if __name__ == "__main__":
    app.run(port=5000, debug=True)
