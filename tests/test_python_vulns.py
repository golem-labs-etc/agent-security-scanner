import os
import subprocess

# VULNERABLE: Hardcoded API key
GROQ_API_KEY = "gsk_1234567890abcdefghijklmnop"
DB_PASSWORD = "admin123"

def unsafe_command_exec(user_input):
    # VULNERABLE: Command injection
    os.system(f"echo {user_input}")

def unsafe_file_read(filename):
    # VULNERABLE: Path traversal
    with open(f"/var/log/{filename}", "r") as f:
        return f.read()

# Unused import
import json
