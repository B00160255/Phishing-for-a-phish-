import json
from difflib import SequenceMatcher
from naughty_list import BAD_WORDS, BAD_LINKS, load_whitelist

APPROVED_DOMAINS = load_whitelist()

sender_domain = input("Enter sender domain (e.g. tudublin.ie): ").strip().lower()
email_text = input("Paste your email text here:")
email_text = email_text.lower()

print("DEBUG Whitelist:", APPROVED_DOMAINS)
if sender_domain in APPROVED_DOMAINS:
    color = "GREEN"
    score = 0
    reason = "Sender domain is on the trusted whitelist."

else:
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
        color = "RED"
    elif score >= 20:
        color = "ORANGE"
    else:
        color = "GREEN"

print("Verdict Colour:", color)
print("Total Score:", score)
print("Reasons:", reason)