#!/usr/bin/env python3
# JediSecX Hash Cracker - Dictionary Attack
# jedi-sec.com | jedi-sec.us | jedi-sec.cloud | jedi-sec.online | jedi-sec.me

import hashlib
import sys

def crack_hash(hash_to_crack, wordlist_path, hash_type):
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] Failed to read wordlist: {e}")
        return

    print(f"[*] Starting crack for hash: {hash_to_crack} ({hash_type.upper()})\n")

    for word in words:
        if hash_type == "md5":
            hashed = hashlib.md5(word.encode()).hexdigest()
        elif hash_type == "sha1":
            hashed = hashlib.sha1(word.encode()).hexdigest()
        elif hash_type == "sha256":
            hashed = hashlib.sha256(word.encode()).hexdigest()
        else:
            print("[-] Unsupported hash type. Use: md5, sha1, sha256")
            return

        if hashed == hash_to_crack.lower():
            print(f"[+] Match found! Password: {word}")
            return

    print("[-] No match found.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <hash> <wordlist.txt> <hash_type>")
        print(f"Example: {sys.argv[0]} d41d8cd98f00b204e9800998ecf8427e wordlist.txt md5")
        sys.exit(1)

    hash_to_crack = sys.argv[1]
    wordlist_path = sys.argv[2]
    hash_type = sys.argv[3].lower()

    crack_hash(hash_to_crack, wordlist_path, hash_type)
