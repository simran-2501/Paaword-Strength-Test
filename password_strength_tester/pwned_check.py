# pwned_check.py
import hashlib
import requests

API_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"


def sha1_hex(password: str) -> str:
    """
    Return the SHA-1 hex digest (uppercase) of the password.
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def pwned_count(password: str) -> int:
    """
    Return the number of times the password appears in the HIBP dataset.
    Uses k-anonymity: send first 5 chars of SHA-1, then match suffixes returned.
    Returns 0 if not found or on error.
    """
    if not password:
        return 0

    full_hash = sha1_hex(password)
    prefix = full_hash[:5]
    suffix = full_hash[5:]

    try:
        response = requests.get(API_RANGE_URL.format(prefix), timeout=10)
        if response.status_code != 200:
            # Non-200 treated as unknown / not found
            return 0

        for line in response.text.splitlines():
            # Each line is: <HASH_SUFFIX>:<COUNT>
            if ":" not in line:
                continue
            hash_suffix, count_str = line.split(":", 1)
            if hash_suffix.upper() == suffix:
                try:
                    return int(count_str)
                except ValueError:
                    return 0

        return 0

    except requests.RequestException:
        # Network / timeout / DNS errors -> treat as not found (caller can interpret)
        return 0
