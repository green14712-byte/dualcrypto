# hybrid_decrypt.py 복호화
import argparse, getpass, os, sys
from crypto_utils import rsa_unwrap_key, aes_gcm_decrypt, sha256_hex

def try_decode_text(b: bytes):
    """UTF-8 -> CP949 순으로 텍스트 디코딩 시도. 실패 시 (None, None)"""
    for enc in ("utf-8", "cp949"):
        try:
            return b.decode(enc), enc
        except Exception:
            pass
    return None, None

def hexdump(b: bytes, length=256):
    """간단 16진 덤프(앞부분 length 바이트)."""
    if not b:
        return ""
    h = b[:length].hex()
    parts = [h[i:i+32] for i in range(0, len(h), 32)]
    return "\n".join(parts)

def main():
    p = argparse.ArgumentParser(description="AES+RSA 하이브리드 복호화 (+무결성 확인, 선택적 내용 표시)")
    p.add_argument("--name", required=True, help="베이스 이름 (예: hello.txt)")
    p.add_argument("--privkey", required=True, help="개인키 경로 (예: keys/ytk.priv.pem)")
    p.add_argument("-o","--out", default=None, help="복호화 결과를 파일로 저장 (선택)")
    p.add_argument("--show", action="store_true", help="무결성 일치 시 내용 미리보기 출력")
    p.add_argument("--show-full", action="store_true", help="무결성 일치 시 내용 전체 출력(대용량 주의)")
    p.add_argument("--preview-limit", type=int, default=5000, help="미리보기 출력 바이트 수(기본 5000)")
    args = p.parse_args()

    base = args.name
    enc_path, keyenc_path, hash_path = base + ".enc", base + ".keyenc", base + ".sha256"

    # 존재 확인
    for path in (enc_path, keyenc_path, hash_path):
        if not os.path.exists(path):
            print(f"[ERROR] 파일 없음: {path}", file=sys.stderr)
            sys.exit(2)

    enc_blob = open(enc_path, "rb").read()
    enc_key  = open(keyenc_path, "rb").read()
    expected_hash = open(hash_path, "rb").read().decode().strip()

    # 개인키 비밀번호 입력(한글 대응: UTF-8 바이트로 전달)
    pw = getpass.getpass("개인키 암호: ")
    try:
        pw_bytes = pw.encode("utf-8")
    except Exception:
        pw_bytes = pw  # 안전 예외처리

    priv_pem = open(args.privkey, "rb").read()

    # RSA로 AES 키 복원
    try:
        aes_key = rsa_unwrap_key(priv_pem, enc_key, passphrase=pw_bytes)
    except Exception as e:
        print("[ERROR] 개인키로 AES 키 복원 실패. (비밀번호/키 파일 확인)", file=sys.stderr)
        print("상세:", str(e), file=sys.stderr)
        sys.exit(3)

    # AES-GCM 복호화
    try:
        plain = aes_gcm_decrypt(aes_key, enc_blob)
    except Exception as e:
        print("[ERROR] AES 복호화 실패 (nonce/tag/키 불일치).", file=sys.stderr)
        print("상세:", str(e), file=sys.stderr)
        sys.exit(4)

    # 무결성 확인
    digest = sha256_hex(plain)
    ok = (digest == expected_hash)
    print("[OK] 복호화 완료.")
    print("무결성:", "일치" if ok else "불일치")
    if not ok:
        # 불일치 시에는 기본적으로 내용을 자동 노출하지 않음
        pass

    # 파일 저장 옵션
    if args.out:
        open(args.out, "wb").write(plain)
        print(f"[SAVE] 복원 파일 저장: {args.out}")

    # 내용 출력 옵션 처리
    if ok and (args.show or args.show_full):
        text, encoding = try_decode_text(plain)
        if text is not None:
            # 텍스트 파일
            if args.show_full:
                print(f"\n=== 파일 전체 내용 (인코딩: {encoding}) ===\n")
                print(text)
            else:
                limit = args.preview_limit
                body = text if len(plain) <= limit else (text[:limit] + f"\n... (총 {len(plain)}바이트; --show-full로 전체 출력 가능)")
                print(f"\n=== 파일 내용 미리보기 (인코딩: {encoding}, 최대 {limit}B) ===\n")
                print(body)
        else:
            # 바이너리 파일
            limit = args.preview_limit if not args.show_full else min(len(plain), 4096)
            print("\n=== 바이너리 파일 (16진 덤프 일부) ===\n")
            print(hexdump(plain, length=limit))
            if not args.show_full and len(plain) > limit:
                print(f"\n... (총 {len(plain)}바이트; --show-full로 더 많이 표시 가능)")

    elif (not ok) and (args.show or args.show_full):
        # 무결성 불일치: 미리보기만 제한적으로
        text, encoding = try_decode_text(plain)
        limit = min(args.preview_limit, 2000)
        print("\n[NOTICE] 무결성 불일치 상태 — 내용 노출 최소화.\n")
        if text is not None:
            print(f"=== (불일치) 텍스트 미리보기 (인코딩: {encoding}, {limit}B) ===\n")
            print(text[:limit])
        else:
            print(f"=== (불일치) 바이너리 16진 미리보기 ({limit}B) ===\n")
            print(hexdump(plain, length=limit))

if __name__ == "__main__":
    main()
