import secrets
secret_key = secrets.token_hex(16)  # 16 bytes long key, generates a 32-character hex string
print(secret_key)
