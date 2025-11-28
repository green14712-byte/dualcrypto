# crypto_utils.py
# AES·RSA·SHA·전자서명 유틸 함수 모음

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256 as CryptoSHA256
from hashlib import sha256


def aes_gcm_encrypt(aes_key: bytes, data: bytes) -> bytes:
    """
    AES-GCM으로 data(평문)를 암호화하여
    nonce(12바이트) + ciphertext + tag(16바이트)를 하나로 붙여 반환한다.
    """
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce + ct + tag


def aes_gcm_decrypt(aes_key: bytes, blob: bytes) -> bytes:
    """
    aes_gcm_encrypt에서 만든 blob을 복호화한다.
    blob = nonce(12) + ciphertext + tag(16)
    """
    nonce, tag = blob[:12], blob[-16:]
    ct = blob[12:-16]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def rsa_wrap_key(pub_pem: bytes, raw_key: bytes) -> bytes:
    """
    RSA 공개키(pub_pem)로 대칭키(raw_key)를 OAEP 모드로 암호화한다.
    """
    pub = RSA.import_key(pub_pem)
    return PKCS1_OAEP.new(pub).encrypt(raw_key)


def rsa_unwrap_key(
    priv_pem: bytes, enc_key: bytes, passphrase: str | None = None
) -> bytes:
    """
    RSA 개인키(priv_pem)와 비밀문자열(passphrase)로
    enc_key(암호화된 대칭키)를 복호화하여 원래 AES 키를 복원한다.
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    priv = RSA.import_key(priv_pem, passphrase=passphrase)
    return PKCS1_OAEP.new(priv).decrypt(enc_key)


def sha256_hex(data: bytes) -> str:
    """
    바이트 data에 대한 SHA-256 해시를 16진 문자열로 반환한다.
    """
    return sha256(data).hexdigest()


def rsa_sign_hash(
    priv_pem: bytes, hash_hex: str, passphrase: str | None = None
) -> bytes:
    """
    sha256_hex()로 만든 해시 문자열(hash_hex)에 대해
    RSA 개인키(priv_pem)로 전자서명을 생성한다.
    반환값: 서명 바이트(signature)
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")

    priv = RSA.import_key(priv_pem, passphrase=passphrase)

    # 해시 문자열 자체(ASCII)를 다시 SHA-256에 넣어 H 객체 생성
    h = CryptoSHA256.new(hash_hex.encode("ascii"))

    # PKCS#1 v1.5 + SHA-256 서명
    signature = pkcs1_15.new(priv).sign(h)
    return signature


def rsa_verify_hash(pub_pem: bytes, hash_hex: str, signature: bytes) -> bool:
    """
    해시 문자열(hash_hex)과 서명(signature)이
    주어진 공개키(pub_pem)에 의해 생성된 것인지 검증한다.
    유효하면 True, 아니면 False 반환.
    """
    pub = RSA.import_key(pub_pem)

    h = CryptoSHA256.new(hash_hex.encode("ascii"))
    try:
        pkcs1_15.new(pub).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
