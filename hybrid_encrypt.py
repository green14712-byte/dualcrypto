#암호화 스크립트
import argparse, os
from Crypto.Random import get_random_bytes
from crypto_utils import aes_gcm_encrypt, rsa_wrap_key, sha256_hex

p = argparse.ArgumentParser()
p.add_argument("-i","--input", required=True)
p.add_argument("--pubkey", required=True)
args = p.parse_args()

data = open(args.input, "rb").read()
aes_key = get_random_bytes(32)
enc_blob = aes_gcm_encrypt(aes_key, data)
digest = sha256_hex(data).encode()

pub = open(args.pubkey,"rb").read()
enc_key = rsa_wrap_key(pub, aes_key)

base = os.path.basename(args.input)
open(base + ".enc", "wb").write(enc_blob)
open(base + ".keyenc", "wb").write(enc_key)
open(base + ".sha256", "wb").write(digest)
print("[OK] 생성:", base+".enc", base+".keyenc", base+".sha256")
