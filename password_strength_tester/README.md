# Password Strength Tester


A small Python desktop app that checks password strength and whether a password has been exposed in known breaches using Have I Been Pwned's Pwned Passwords API (k-anonymity).


## Setup


```bash
python -m venv .venv
# activate depending on platform
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate


pip install -r requirements.txt
python main.py