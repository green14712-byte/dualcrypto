# hybrid_encrypt.py
# 파일을 AES+RSA 하이브리드로 암호화 + SHA-256 + 전자서명(.sig) 생성

import argparse
import os
from getpass import getpass

from Crypto.Random import get_random_bytes
from crypto_utils import (
    aes_gcm_encrypt,
    rsa_wrap_key,
    sha256_hex,
    rsa_sign_hash,
)


def main():
    parser = argparse.ArgumentParser(
        description="AES+RSA 하이브리드 암호화 + SHA-256 + 전자서명 생성"
    )
    parser.add_argument(
        "-i", "--input", required=True, help="암호화할 원본 파일 경로 (예: hello.txt)"
    )
    parser.add_argument(
        "--pubkey",
        required=True,
        help="RSA 공개키 PEM 파일 경로 (예: keys/ytk.pub.pem)",
    )
    args = parser.parse_args()

    in_path = args.input
    base_name = os.path.basename(in_path)  # 예: hello.txt

    # 1) 원본 파일 읽기
    with open(in_path, "rb") as f:
        data = f.read()

    # 2) 랜덤 AES 키 생성 (256비트)
    aes_key = get_random_bytes(32)

    # 3) AES-GCM 암호화 → .enc
    enc_blob = aes_gcm_encrypt(aes_key, data)
    enc_path = f"{base_name}.enc"
    with open(enc_path, "wb") as f:
        f.write(enc_blob)
    print(f"[ENC] AES 암호문 저장: {enc_path}")

    # 4) RSA 공개키로 AES 키 암호화 → .keyenc
    with open(args.pubkey, "rb") as f:
        pub_pem = f.read()
    enc_key = rsa_wrap_key(pub_pem, aes_key)
    keyenc_path = f"{base_name}.keyenc"
    with open(keyenc_path, "wb") as f:
        f.write(enc_key)
    print(f"[KEY] RSA로 암호화된 AES 키 저장: {keyenc_path}")

    # 5) SHA-256 해시 계산 → .sha256
    file_hash = sha256_hex(data)  # 문자열
    hash_path = f"{base_name}.sha256"
    with open(hash_path, "w", encoding="utf-8") as f:
        f.write(file_hash + "\n")
    print(f"[HASH] SHA-256 해시 저장: {hash_path}")

    # 6) 전자서명 생성 여부 물어보기
    ans = input("이 해시에 대해 전자서명을 생성할까요? (y/N): ").strip().lower()
    if ans == "y":
        priv_path = input(
            "서명에 사용할 RSA 개인키 경로 (예: keys/ytk.priv.pem): "
        ).strip()
        if not priv_path:
            print("[SIGN] 개인키 경로가 비어 있어 서명 생성을 건너뜁니다.")
            return

        with open(priv_path, "rb") as f:
            priv_pem = f.read()
        pw = getpass("개인키 암호(없으면 엔터): ")
        pw = pw if pw else None

        signature = rsa_sign_hash(priv_pem, file_hash, pw)
        sig_path = f"{base_name}.sig"
        with open(sig_path, "wb") as f:
            f.write(signature)
        print(f"[SIGN] 전자서명 생성 완료: {sig_path}")
    else:
        print("[SIGN] 전자서명 생략")

    print("\n[DONE] 생성된 파일 목록:")
    print(f"  - {enc_path}")
    print(f"  - {keyenc_path}")
    print(f"  - {hash_path}")
    sig_path = f"{base_name}.sig"
    if os.path.exists(sig_path):
        print(f"  - {sig_path}")


if __name__ == "__main__":
    main()
