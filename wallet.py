from ecdsa_custom import SigningKey, VerifyingKey
import hashlib

class Wallet:
    def __init__(self, private_key: SigningKey = None):
        """
        If private_key is None, generate a new random SigningKey.
        Otherwise use the provided SigningKey instance.
        """
        self.private_key = private_key or SigningKey.generate()
        self.public_key = self.private_key.get_verifying_key()

    def sign(self, message: str) -> str:
        """
        Sign the input message (string), returns hex string of 2-byte signature (r||s).
        """
        signature_bytes = self.private_key.sign(message.encode())
        return signature_bytes.hex()

    def get_public_key_hex(self) -> str:
        """
        Return the public key as a hex string of 2 bytes (x||y).
        """
        return self.public_key.to_string().hex()

    def get_public_key(self) -> VerifyingKey:
        """
        Return the VerifyingKey object corresponding to this wallet.
        """
        return self.public_key

    def get_address(self) -> str:
        """
        Return an address as the SHA256 hex digest of the public key bytes.
        """
        return hashlib.sha256(self.public_key.to_string()).hexdigest()

    @staticmethod
    def public_key_from_hex(hex_str: str) -> VerifyingKey:
        """
        Restore a VerifyingKey object from its 2-byte hex string representation.
        """
        key_bytes = bytes.fromhex(hex_str)
        return VerifyingKey.from_string(key_bytes)
