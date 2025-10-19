#!/usr/bin/env python3
"""
encrypt_oaep.py — шифрування повідомлення відкритим ключем RSA у схемі RSA-OAEP
(Optimal Asymmetric Encryption Padding) з MGF1(SHA-256).

Вхід:
  - task_pub.pem       — відкритий ключ RSA у форматі PEM (у тій самій директорії)
  - аргумент 1         — шлях до файлу з відкритим текстом (UTF-8), наприклад plaintext.txt

Вихід:
  - друкує шифротекст у HEX (hexadecimal) у STDOUT
    (перенаправте у task-2-message.txt)
"""
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def main() -> int:
    base = Path(__file__).resolve().parent
    pub_pem = (base / "task_pub.pem").read_bytes()
    public_key = serialization.load_pem_public_key(pub_pem)

    if len(sys.argv) != 2:
        print("Використання: python3 encrypt_oaep.py <plaintext_file>", file=sys.stderr)
        return 2

    plaintext = Path(sys.argv[1]).read_text(encoding="utf-8").encode("utf-8")

    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # MGF1 — генератор маски на SHA-256
            algorithm=hashes.SHA256(),                    # основний хеш OAEP — SHA-256
            label=None
        )
    )

    # Вивід у HEX (вимога завдання)
    print(ciphertext.hex())
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
