import os
import json
import base64
import logging
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": record.levelname,
            "event": record.getMessage()
        }, ensure_ascii=False)


logger = logging.getLogger("CryptoLogger")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.FileHandler("crypto_log.json", encoding='utf-8')
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)


class CryptoEngine:
    def __init__(self):
        self.iterations = 310000

    def derive_key(self, password: str, salt: bytes, length=32) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=self.iterations,
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, file_path, password, mode="GCM"):
        start_time = time.perf_counter()  # Початок заміру часу

        salt = os.urandom(16)
        with open(file_path, 'rb') as f:
            data = f.read()

        if mode == "GCM":
            nonce = os.urandom(12)
            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            auth_tag = b""
        else:
            iv = os.urandom(16)
            nonce = iv
            long_key = self.derive_key(password, salt, length=64)
            enc_key = long_key[:32]
            mac_key = long_key[32:]

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            h = hmac.HMAC(mac_key, hashes.SHA256())
            h.update(iv + ciphertext)
            auth_tag = h.finalize()

        header = {
            "mode": mode,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(auth_tag).decode() if auth_tag else ""
        }

        header_bytes = json.dumps(header).encode()
        out_path = file_path + ".enc"
        with open(out_path, 'wb') as f:
            f.write(len(header_bytes).to_bytes(4, 'big'))
            f.write(header_bytes)
            f.write(ciphertext)

        execution_time = (time.perf_counter() - start_time) * 1000  # Час у мс
        return out_path, execution_time

    def decrypt_file(self, file_path, password):
        start_time = time.perf_counter()

        with open(file_path, 'rb') as f:
            h_len_data = f.read(4)
            if not h_len_data: raise ValueError("Файл порожній")
            h_len = int.from_bytes(h_len_data, 'big')
            header = json.loads(f.read(h_len).decode())
            ciphertext = f.read()

        mode = header["mode"]
        salt = base64.b64decode(header['salt'])
        nonce_iv = base64.b64decode(header['nonce'])

        if mode == "GCM":
            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce_iv, ciphertext, None)
        else:
            long_key = self.derive_key(password, salt, length=64)
            enc_key = long_key[:32]
            mac_key = long_key[32:]
            stored_tag = base64.b64decode(header['tag'])

            h = hmac.HMAC(mac_key, hashes.SHA256())
            h.update(nonce_iv + ciphertext)
            h.verify(stored_tag)

            cipher = Cipher(algorithms.AES(enc_key), modes.CBC(nonce_iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        out_path = file_path.replace(".enc", ".dec.txt")
        with open(out_path, 'wb') as f:
            f.write(decrypted_data)

        execution_time = (time.perf_counter() - start_time) * 1000
        return out_path, execution_time


def main():
    engine = CryptoEngine()
    current_mode = "GCM"

    while True:
        print(f"\n{'=' * 45}\n   AES CRYPTO TOOL | РЕЖИМ: {current_mode}\n{'=' * 45}")
        print("1. Зашифрувати файл\n2. Розшифрувати файл\n3. Змінити режим (GCM/CBC)\n4. Назад/Завершити роботу")

        choice = input("\nОберіть дію: ")

        if choice in ['1', '2']:
            path = input("Введіть шлях до файлу: ").strip().replace('"', '')
            if not os.path.exists(path):
                print("[!] Помилка: Файл не знайдено.")
                continue

            # --- НОВА ПЕРЕВІРКА НА ІСНУВАННЯ ФАЙЛІВ ---
            if choice == '1':
                if path.endswith(".enc"):
                    print("[!] Цей файл уже зашифровано (має розширення .enc)!")
                    continue
                if os.path.exists(path + ".enc"):
                    print(f"[!] Увага: Зашифрована версія '{path}.enc' вже існує!")
                    confirm = input("Перезаписати? (y/n): ").lower()
                    if confirm != 'y': continue

            if choice == '2':
                if not path.endswith(".enc"):
                    print("[!] Помилка: Для розшифрування оберіть файл з розширенням .enc!")
                    continue
                dec_path = path.replace(".enc", ".dec.txt")
                if os.path.exists(dec_path):
                    print(f"[!] Увага: Розшифрована версія '{dec_path}' вже існує!")
                    confirm = input("Перезаписати? (y/n): ").lower()
                    if confirm != 'y': continue
            # ------------------------------------------

            pwd = input("Введіть пароль: ")
            try:
                if choice == '1':
                    res, exec_time = engine.encrypt_file(path, pwd, current_mode)
                    logger.info(f"Успішно зашифровано: {path} за {exec_time:.2f} мс")
                    print(f"[OK] Файл зашифровано! Створено: {res}. За {exec_time:.2f} мс")
                else:
                    res, exec_time = engine.decrypt_file(path, pwd)
                    logger.info(f"Успішно розшифровано: {path} за {exec_time:.2f} мс")
                    print(f"[OK] Файл розшифровано! Створено: {res}. За {exec_time:.2f} мс")
            except Exception as e:
                logger.error(f"ПОМИЛКА ЦІЛІСНОСТІ для {path}: {e}")
                print(f"\n[!!!] ПОМИЛКА ЦІЛІСНОСТІ АБО ПАРОЛЯ!")
                print(f"Дані пошкоджені або виявлено втручання.")

        elif choice == '3':
            current_mode = "CBC" if current_mode == "GCM" else "GCM"
            print(f"[*] Режим успішно змінено на {current_mode}")
        elif choice == '4':
            print("Завершення роботи...")
            break


if __name__ == "__main__":
    main()