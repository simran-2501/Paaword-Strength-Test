# password_utils.py

import math
import re

LOWER = re.compile(r"[a-z]")
UPPER = re.compile(r"[A-Z]")
DIGIT = re.compile(r"[0-9]")
SYMBOL = re.compile(r"[^a-zA-Z0-9]")


def charset_size(password: str) -> int:
    size = 0
    if LOWER.search(password):
        size += 26
    if UPPER.search(password):
        size += 26
    if DIGIT.search(password):
        size += 10
    if SYMBOL.search(password):
        size += 32
    return size


def entropy_bits(password: str) -> float:
    if not password:
        return 0.0
    csize = charset_size(password)
    if csize <= 0:
        return 0.0
    return len(password) * math.log2(csize)


def brute_force_time_seconds(password: str, guesses_per_second: float = 1e9) -> float:
    csize = charset_size(password)
    if csize <= 0 or not password:
        return 0.0
    total_combinations = csize ** len(password)
    avg_guesses = total_combinations / 2
    return avg_guesses / guesses_per_second


def friendly_time(seconds: float) -> str:
    if seconds == 0:
        return "instant"
    intervals = [
        ("years", 31536000),
        ("days", 86400),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]
    parts = []
    remaining = int(seconds)
    for name, sec in intervals:
        value = remaining // sec
        if value:
            parts.append(f"{value} {name}")
            remaining -= value * sec
        if len(parts) >= 2:
            break
    return ", ".join(parts)


def score_password(password: str) -> dict:
    length = len(password)
    bits = entropy_bits(password)

    if bits < 28:
        rating = "Very weak"
        numeric = 1
    elif bits < 36:
        rating = "Weak"
        numeric = 2
    elif bits < 60:
        rating = "Moderate"
        numeric = 3
    elif bits < 80:
        rating = "Strong"
        numeric = 4
    else:
        rating = "Very strong"
        numeric = 5

    length_bonus = 0
    if length >= 12:
        length_bonus = 1
    if length >= 16:
        length_bonus = 2

    variety = sum([
        bool(LOWER.search(password)),
        bool(UPPER.search(password)),
        bool(DIGIT.search(password)),
        bool(SYMBOL.search(password)),
    ])

    suggestions = []
    if length < 8:
        suggestions.append("Use at least 8 characters (12+ recommended).")
    if variety < 3:
        suggestions.append("Use uppercase, lowercase, digits & symbols.")
    if re.fullmatch(r"(?i)(password|1234|qwerty|letmein)", password):
        suggestions.append("Avoid common passwords.")

    score = min(bits, 120)
    score += length_bonus * 6
    score += (variety - 1) * 5
    score = int(max(0, min(100, score)))

    return {
        "length": length,
        "entropy_bits": round(bits, 2),
        "score_percent": score,
        "rating": rating,
        "numeric_rating": numeric,
        "variety_count": variety,
        "suggestions": suggestions,
    }
