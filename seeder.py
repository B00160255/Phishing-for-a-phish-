import sqlite3

reason = "Common Gambling/Adult-Content scam phrases"

bad_words = [
    "Adult content",
"Bet now",
"Big win",
"Blackjack",
"Casino bonus",
"Cash out now",
"Click to win",
"Double your money",
"Exclusive access",
"Free chips",
"Free spins",
"Gamble online",
"Hot deal",
"Instant winnings",
"Jackpot",
"Live dealer",
"Lottery winner",
"Lucky chance",
"Online betting",
"Online casino",
"Online gaming",
"Poker tournament",
"Risk-free bet",
"Slots jackpot",
"Spin to win",
"Try for free",
"VIP offer",
"Winner announced",
"Winning numbers",
"XXX"
]

conn = sqlite3.connect("words.db")
cursor = conn.cursor()

data = [(w.strip().lower(), reason) for w in bad_words]
cursor.executemany("INSERT OR IGNORE INTO bad_words (word, reason) VALUES (?, ?)", data)

conn.commit()
conn.close()

print(f"That's all folks!")