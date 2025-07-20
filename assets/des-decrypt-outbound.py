from Crypto.Cipher import DES3
from base64 import b64decode
def decrypt_password(encrypted_password, key="rcmail-!24ByteDESkey*Str"):
    try:
        des_key = key.encode('utf-8')  
        data = b64decode(encrypted_password)
        iv = data[:8]  
        ciphertext = data[8:]
        cipher = DES3.new(des_key, DES3.MODE_CBC, iv=iv) 
        decrypted = cipher.decrypt(ciphertext)
        return decrypted.rstrip(b"\0").decode('utf-8', errors='ignore')
    except Exception as e: 
        return f"Error: {str(e)}"
encrypted = "L7Rv00A8TuwJAr67kITxxcSgnIk25Am/"
print(f"Decrypted password: {decrypt_password(encrypted)}")