import base64
import hashlib
import os
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

    
import base64
import hashlib
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
import ecdsa

class EllipticCurveUtils:
    ELIPTIC_CURVE_PRIME256 = "prime256v1"

    def __init__(self, protocol):
        self.protocol = protocol

    def load_public_key(self, data):
        params = ec.ECParameters(ec._CURVE_TYPES[self.ELIPTIC_CURVE_PRIME256])
        curve = ec.EllipticCurvePublicNumbers.from_encoded_point(params, data)
        return ec.EllipticCurvePublicKey.from_numbers(curve)

    def load_private_key(self, data):
        params = ec.ECParameters(ec._CURVE_TYPES[self.ELIPTIC_CURVE_PRIME256])
        curve = ec.EllipticCurvePrivateNumbers(int.from_bytes(data, byteorder='big'), params)
        return ec.EllipticCurvePrivateKey.from_numbers(curve)

    @staticmethod
    def save_private_key(key):
        return key.private_numbers().private_value.to_bytes(
            (key.curve.key_size + 7) // 8, byteorder='big'
        )

    @staticmethod
    def save_public_key(key):
        return key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

    @staticmethod
    def get_signature(plaintext, private_key):
        signer = private_key.signer(ecdsa.ECDSA(hashes.SHA256()))
        signer.update(plaintext.encode('utf-8'))
        signature = signer.finalize()
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, signature, plaintext, public_key):
        verifier = public_key.verifier(
            base64.b64decode(signature), ecdsa.ECDSA(hashes.SHA256())
        )
        verifier.update(plaintext.encode('utf-8'))
        return verifier.verify()

  
    def do_ecdh(self, private_key, public_key):
        prv_key = self.load_private_key(base64.b64decode(private_key))
        pub_key = self.load_public_key(base64.b64decode(public_key))
        shared_key = prv_key.exchange(ec.ECDH(), pub_key.public_key())
        return base64.b64encode(shared_key).decode('utf-8')

    def generate_keypair(self):
        private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def get_private_key(pair):
        return base64.b64encode(pair.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).decode('utf-8')

    @staticmethod
    def get_public_key(pair):
        return base64.b64encode(pair.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')