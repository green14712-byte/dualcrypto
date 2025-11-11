#AES·RSA·SHA 함수 정의
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from hashlib import sha256

def aes_gcm_encrypt(aes_key: bytes, data: bytes) -> bytes:
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce + ct + tag

def aes_gcm_decrypt(aes_key: bytes, blob: bytes) -> bytes:
    nonce, tag = blob[:12], blob[-16:]
    ct = blob[12:-16]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def rsa_wrap_key(pub_pem: bytes, raw_key: bytes) -> bytes:
    pub = RSA.import_key(pub_pem)
    return PKCS1_OAEP.new(pub).encrypt(raw_key)

def rsa_unwrap_key(priv_pem: bytes, enc_key: bytes, passphrase: str|None=None) -> bytes:
    if isinstance(passphrase, str):
      passphrase = passphrase.encode("utf-8")
    priv = RSA.import_key(priv_pem, passphrase=passphrase)
    return PKCS1_OAEP.new(priv).decrypt(enc_key)

def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()
