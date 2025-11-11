#RSA 키 쌍 생성
from Crypto.PublicKey import RSA
from getpass import getpass
import os, sys

os.makedirs("keys", exist_ok=True)

def main(user):
    key = RSA.generate(2048)
    pw = getpass(f"[{user}] 개인키 암호 입력: ")
    pw_bytes = pw.encode("utf-8")
    priv = key.export_key(pkcs=8, passphrase=pw, protection="scryptAndAES128-CBC")
    pub  = key.publickey().export_key()
    open(f"keys/{user}.priv.pem","wb").write(priv)
    open(f"keys/{user}.pub.pem","wb").write(pub)
    print("OK:", f"keys/{user}.priv.pem , keys/{user}.pub.pem")

if __name__ == "__main__":
    if len(sys.argv)!=2:
        print("사용: python keygen.py <username>"); sys.exit(1)
    main(sys.argv[1])
