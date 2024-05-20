

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
private_key_A = parameters.generate_private_key()
private_key_B = parameters.generate_private_key()
public_key_A = private_key_A.public_key()
public_key_B = private_key_B.public_key()
shared_key_A = private_key_A.exchange(public_key_B)
shared_key_B = private_key_B.exchange(public_key_A)


def derive_key(shared_key):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
aes_key = derive_key(shared_key_A)
assert aes_key == derive_key(shared_key_B)  


def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return plaintext.decode()


message = "Poruka 1"
encrypted_message = encrypt_message(aes_key, message)
decrypted_message = decrypt_message(aes_key, encrypted_message)

print(f"Originalna poruka: {message}")
print(f"Šifrovana poruka: {encrypted_message}")
print(f"Dešifrovana poruka: {decrypted_message}")
