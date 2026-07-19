from naughty_list import BAD_WORDS, BAD_LINKS

email_text = input("Paste your email text here: ")

email_text = email_text.lower()

score = 0
reason = ""

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