#!/usr/bin/env python3
"""
verify_pss.py — верификация подписи RSA-PSS (вероятностная схема подписи)
с хешем SHA-256 при помощи библиотеки 'cryptography'.

Файлы входа:
  - task_pub.pem        — открытый ключ RSA (PEM-контейнер)
  - task_message.txt    — сообщение в HEX (hexadecimal) без 0x
  - task_signature.txt  — подпись в HEX (hexadecimal)

Вывод:
  - «Підпис ВАЛІДНИЙ ✅ (RSA-PSS, SHA-256)» или
  - «Підпис НЕВАЛІДНИЙ ❌ (RSA-PSS, SHA-256)»
"""
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def _read_bytes_from_hex_or_b64(path: Path) -> bytes:
    """
    Читает содержимое файла как HEX; если не получается — пробует Base64.
    Это защищает от типичных ошибок форматирования входных данных.
    """
    raw = path.read_text(encoding="utf-8").strip().replace(" ", "").replace("\n", "")
    # попытка интерпретировать как HEX
    try:
        return bytes.fromhex(raw)
    except ValueError:
        pass
    # попытка интерпретировать как Base64
    try:
        return base64.b64decode(raw, validate=True)
    except Exception:
        raise ValueError(f"Не удалось интерпретировать {path.name} как HEX или Base64")

def main() -> int:
    base = Path(__file__).resolve().parent

    # загрузка открытого ключа RSA из PEM
    pub_pem = (base / "task_pub.pem").read_bytes()
    public_key = serialization.load_pem_public_key(pub_pem)

    # чтение сообщения и подписи
    message = _read_bytes_from_hex_or_b64(base / "task_message.txt")
    signature = _read_bytes_from_hex_or_b64(base / "task_signature.txt")

    # верификация: RSA-PSS + SHA-256 + MGF1(SHA-256)
    try:
        public_key.verify(
            signature=signature,
            data=message,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
        print("Підпис ВАЛІДНИЙ ✅ (RSA-PSS, SHA-256)")
        return 0
    except Exception:
        print("Підпис НЕВАЛІДНИЙ ❌ (RSA-PSS, SHA-256)")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
