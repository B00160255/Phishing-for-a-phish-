import os
import sqlite3

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "words.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bad_words (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            word TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bad_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bad_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            extension TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

def add_rule(table, item, reason=""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    item = item.strip().lower()
    
    if table == "bad_words":
        col = "word"
    elif table == "bad_links":
        col = "link"
    elif table == "whitelist":
        col = "domain"
    elif table == "bad_attachments":
        col = "extension"

    try:
        if table == "whitelist":
            cursor.execute(f"INSERT INTO {table} ({col}) VALUES (?)", (item,))
        else:
            cursor.execute(f"INSERT INTO {table} ({col}, reason) VALUES (?, ?)", (item, reason))
        conn.commit()
        print(f" Successfully added '{item}' to {table}.")
    except sqlite3.IntegrityError:
        print(f" Warning: '{item}' already exists in {table}!")
    finally:
        conn.close()

def delete_rule(table, item):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    item = item.strip().lower()
    
    if table == "bad_words":
        col = "word"
    elif table == "bad_links":
        col = "link"
    elif table == "whitelist":
        col = "domain"
    elif table == "bad_attachments":
        col = "extension"

    cursor.execute(f"DELETE FROM {table} WHERE {col} = ?", (item,))
    if cursor.rowcount > 0:
        print(f" Successfully removed '{item}' from {table}.")
    else:
        print(f" Warning: '{item}' was not found in {table}.")
        
    conn.commit()
    conn.close()

def view_words():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("\n--- TRUSTED WHITELIST ---")
    for row in cursor.execute("SELECT domain FROM whitelist"):
        print(f"• {row[0]}")

    print("\n--- BAD WORDS ---")
    for row in cursor.execute("SELECT word, reason FROM bad_words"):
        print(f"• {row[0]} -> {row[1]}")
        
    print("\n--- BAD DOMAINS / LINKS ---")
    for row in cursor.execute("SELECT link, reason FROM bad_links"):
        print(f"• {row[0]} -> {row[1]}")

    print("\n--- BAD ATTACHMENTS ---")
    for row in cursor.execute("SELECT extension, reason FROM bad_attachments"):
        print(f"• {row[0]} -> {row[1]}")
        
    conn.close()

def load_words_from_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    bad_words = {row[0]: row[1] for row in cursor.execute("SELECT word, reason FROM bad_words")}
    bad_links = {row[0]: row[1] for row in cursor.execute("SELECT link, reason FROM bad_links")}
    whitelist = [row[0] for row in cursor.execute("SELECT domain FROM whitelist")]
    bad_attachments = {row[0]: row[1] for row in cursor.execute("SELECT extension, reason FROM bad_attachments")}
    
    conn.close()
    return bad_words, bad_links, whitelist, bad_attachments

if __name__ == "__main__":
    init_db()
    while True:
        print("\n=== THREAT DATABASE MANAGER ===")
        print("1. View All Rules & Whitelist")
        print("2. Add Bad Word")
        print("3. Add Bad Domain")
        print("4. Add Whitelisted Domain")
        print("5. Add Bad Attachment")
        print("6. Delete Bad Word")
        print("7. Delete Bad Domain")
        print("8. Delete Whitelisted Domain")
        print("9. Delete Bad Attachment")
        print("10. Exit")
        
        choice = input("\nSelect an option (1-10): ").strip()
        
        if choice == "1":
            view_words()
        elif choice == "2":
            w = input("Enter word/phrase: ")
            r = input("Enter detection reason: ")
            add_rule("bad_words", w, r)
        elif choice == "3":
            l = input("Enter domain/link: ")
            r = input("Enter detection reason: ")
            add_rule("bad_links", l, r)
        elif choice == "4":
            d = input("Enter domain to whitelist (e.g. tudublin.ie): ")
            add_rule("whitelist", d)
        elif choice == "5":
            a = input("Enter attachment extension (e.g. .iso or .exe): ")
            r = input("Enter detection reason: ")
            add_rule("bad_attachments", a, r)
        elif choice == "6":
            w = input("Enter word to delete: ")
            delete_rule("bad_words", w)
        elif choice == "7":
            l = input("Enter domain/link to delete: ")
            delete_rule("bad_links", l)
        elif choice == "8":
            d = input("Enter whitelisted domain to delete: ")
            delete_rule("whitelist", d)
        elif choice == "9":
            a = input("Enter attachment extension to delete: ")
            delete_rule("bad_attachments", a)
        elif choice == "10":
            print("Goodbye!")
            break