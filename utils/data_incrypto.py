from cryptography.fernet import Fernet

# एक secret key generate करो (बस ek baar generate karke safe rakho)
# key = Fernet.generate_key()
# print(key)

SECRET_KEY = b'XjMAsA8XIhi8jJhipe3kWAajUQCXJ36ZX-CDA5G-hUI='  # isko .env me rakho
fernet = Fernet(SECRET_KEY)

def encrypt_response(data: dict) -> str:
    import json
    raw = json.dumps(data).encode()
    encrypted = fernet.encrypt(raw)
    return encrypted.decode()

def decrypt_response(encrypted_data: str) -> dict:
    import json
    decrypted = fernet.decrypt(encrypted_data.encode())
    return json.loads(decrypted.decode())
