"""

Define DE primitives.

"""
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import blake2b
import secrets
from typing import Optional

__all__ = ["RSADOAEP", "AESSIV", "AESCBC", "AESCMC"]


class PlaintextLenError(Exception):
    pass


pswd_pemfile = secrets.token_bytes(16)


class DEAlgorithm:
    def encrypt(self, msg: bytes) -> bytes:
        raise NotImplementedError


def rsa_key(key_sz: int = 2048, pswd_pemfile: Optional[str] = None):
    """
    Generate an RSA key in PEM format.

    :param key_sz bits for key size. Recommended is >=2048
    :param pswd_pemfile passphrase for RSA key
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_sz, backend=default_backend()
    )

    if pswd_pemfile:
        keyenc_alg = serialization.BestAvailableEncryption(password=pswd_pemfile)
    else:
        keyenc_alg = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=keyenc_alg,
    )

    public_key = private_key.public_key()
    pem_pub = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo,
       # format=serialization.PublicFormat.PKCS8,
       # encryption_algorithm=keyenc_alg,
    )



    # print("-"*50)
    # print(pem)
    # print("-"*50)
    # print(pem_pub)
    # print("-"*50)

    # return RSA.importKey(pem_pub, passphrase=pswd_pemfile)
    return pem_pub



class RSADOAEP(DEAlgorithm):
    def __init__(self, key_sz_bits: int, pswd_pemfile:Optional[str] = None, rsa_pem=None):
        # Use PKCS-OAEP cipher mode for RSA. Maximum plaintext size has to fit into modulus size.
        if not rsa_pem:
            self.rsa_pem = rsa_key(key_sz_bits, pswd_pemfile=pswd_pemfile)
        else:
            self.rsa_pem = rsa_pem

        self.k = RSA.importKey(self.rsa_pem, passphrase=pswd_pemfile)

        self.cipher = PKCS1_OAEP.new(self.k)
        self.name = f"RSA-DOAEP-{key_sz_bits}"

    def encrypt(self, msg: bytes) -> bytes:
        # Padding is a hash of the plaintext -- hence, deterministic
        self.cipher._randfunc = lambda n: blake2b(msg, digest_size=n).digest()
        ciphertext = self.cipher.encrypt(msg)
        return ciphertext

    def export_key(self):
        return self.rsa_pem

class AESSIV(DEAlgorithm):
    name = "AES-SIV"

    def __init__(self, key_size_bits: int):
        key_size_bytes = key_size_bits // 8
        self.aeskey = secrets.token_bytes(key_size_bytes)

    def encrypt(self, msg: bytes) -> bytes:
        cipher = AES.new(self.aeskey, AES.MODE_SIV)
        ciphertext, mac = cipher.encrypt_and_digest(msg)
        return ciphertext


class AESCBC(DEAlgorithm):
    name = "AES-CBC"

    def __init__(self, key_size_bits: int):
        key_size_bytes = key_size_bits // 8
        self.aeskey = secrets.token_bytes(key_size_bytes)
        self.iv = secrets.token_bytes(key_size_bytes / 2)
        self.cipher = Cipher(
            algorithms.AES(self.aeskey), modes.CBC(self.iv), backend=default_backend()
        )

    def encrypt(self, msg: bytes) -> bytes:
        padder = padding.PKCS7(128).padder()
        msg = padder.update(msg) + padder.finalize()
        encryptor = self.cipher.encryptor()
        data = encryptor.update(msg) + encryptor.finalize()
        return data


class AESCMC(DEAlgorithm):
    name = "AES-CMC"

    def __init__(self, key_size_bits: int):
        key_size_bytes = key_size_bits // 8

        self.aeskey = secrets.token_bytes(key_size_bytes)
        self.iv = b"\x00" * int(key_size_bytes / 2)
        self.cipher = Cipher(
            algorithms.AES(self.aeskey), modes.CBC(self.iv), backend=default_backend()
        )

    def encrypt(self, msg: bytes) -> bytes:
        padder = padding.PKCS7(128).padder()
        msg = padder.update(msg) + padder.finalize()

        # First round of AES-CBC
        encryptor = self.cipher.encryptor()
        data = encryptor.update(msg) + encryptor.finalize()

        # Second round of AES-CBC with bytes reversed
        msg_reversed = data[::-1]
        encryptor = self.cipher.encryptor()
        data = encryptor.update(msg_reversed) + encryptor.finalize()
        return data
