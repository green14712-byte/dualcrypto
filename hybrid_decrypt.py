# hybrid_decrypt.py
# AES+RSA 하이브리드 암호문 복호화 + 무결성 검사 + 전자서명 검증

import argparse
import os
from getpass import getpass

from crypto_utils import (
    aes_gcm_decrypt,
    rsa_unwrap_key,
    sha256_hex,
    rsa_verify_hash,
)


def main():
    parser = argparse.ArgumentParser(
        description="AES+RSA 하이브리드 복호화 + SHA-256 무결성 + 전자서명 검증"
    )
    parser.add_argument(
        "--name",
        required=True,
        help="원본 파일 이름(확장자 포함, 예: hello.txt). "
        "같은 폴더에 .enc/.keyenc/.sha256(.sig)이 있어야 함.",
    )
    parser.add_argument(
        "--privkey",
        required=True,
        help="RSA 개인키 PEM 파일 경로 (예: keys/ytk.priv.pem)",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="복호화된 파일 내용을 화면에 출력",
    )
    args = parser.parse_args()

    base_name = args.name
    enc_path = f"{base_name}.enc"
    keyenc_path = f"{base_name}.keyenc"
    hash_path = f"{base_name}.sha256"
    sig_path = f"{base_name}.sig"
    restored_path = f"{base_name}.restored.txt"

    # 필요한 파일 존재 확인
    for p in [enc_path, keyenc_path, hash_path]:
        if not os.path.exists(p):
            raise FileNotFoundError(f"필요한 파일이 없습니다: {p}")

    # 1) 암호화된 AES 키 복호화 → AES 키 복원
    with open(args.privkey, "rb") as f:
        priv_pem = f.read()
    pw = getpass("개인키 암호(없으면 엔터): ")
    pw = pw if pw else None

    with open(keyenc_path, "rb") as f:
        enc_key = f.read()
    aes_key = rsa_unwrap_key(priv_pem, enc_key, pw)
    print("[KEY] AES 키 복원 완료")

    # 2) AES-GCM 복호화 → 평문
    with open(enc_path, "rb") as f:
        enc_blob = f.read()
    plain = aes_gcm_decrypt(aes_key, enc_blob)
    with open(restored_path, "wb") as f:
        f.write(plain)
    print(f"[DEC] 복호화 완료 → {restored_path}")

    # 3) SHA-256 무결성 검사
    new_hash = sha256_hex(plain)
    with open(hash_path, "r", encoding="utf-8") as f:
        orig_hash = f.read().strip()

    if new_hash == orig_hash:
        print("무결성: 일치 ✅")
    else:
        print("무결성: 불일치 ❌ (파일이 변경되었을 수 있음)")

    # 4) 전자서명 검증 (.sig가 있을 때만)
    if os.path.exists(sig_path):
        ans = input(
            "\n전자서명 검증을 진행할까요? (y/N): "
        ).strip().lower()
        if ans == "y":
            pub_path = input(
                "서명 검증에 사용할 공개키 경로 (예: keys/ytk.pub.pem): "
            ).strip()
            if not pub_path:
                print("[SIGN] 공개키 경로가 비어 있어 서명 검증을 건너뜁니다.")
            else:
                with open(pub_path, "rb") as f:
                    pub_pem = f.read()
                with open(sig_path, "rb") as f:
                    signature = f.read()

                ok = rsa_verify_hash(pub_pem, orig_hash, signature)
                if ok:
                    print("[SIGN] 전자서명 검증: 유효 ✅ (해시가 해당 공개키 소유자에 의해 서명됨)")
                else:
                    print("[SIGN] 전자서명 검증: 실패 ❌ (서명 위조 또는 다른 키)")
        else:
            print("[SIGN] 전자서명 검증 생략")
    else:
        print("[SIGN] 서명 파일(.sig)이 없어 전자서명 검증을 생략합니다.")

    # 5) --show 옵션이면 평문 출력
    if args.show:
        print("\n===== 복호화된 파일 내용 =====")
        try:
            print(plain.decode("utf-8"))
        except UnicodeDecodeError:
            print("[주의] UTF-8 텍스트가 아니어서 그대로 표시할 수 없습니다.")


if __name__ == "__main__":
    main()
