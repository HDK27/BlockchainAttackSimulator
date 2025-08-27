from ecdsa_custom import VerifyingKey
from wallet import Wallet
from ecdsa_custom import SigningKey

class Transaction:
    def __init__(self, sender_pubkey=None, recipient_pubkey=None, sender_address=None, recipient_address=None, amount=0, is_p2pk=True):
        """
        Support both P2PK (sender_pubkey, recipient_pubkey) and P2PKH (sender_address, recipient_address)
        Use is_p2pk flag to distinguish.
        """
        self.is_p2pk = is_p2pk
        if is_p2pk:
            self.sender_pubkey = sender_pubkey or "SYSTEM"
            self.recipient_pubkey = recipient_pubkey
            self.sender_address = None
            self.recipient_address = None
        else:
            self.sender_address = sender_address or "SYSTEM"
            self.recipient_address = recipient_address
            self.sender_pubkey = None
            self.recipient_pubkey = None

        self.amount = amount
        self.signature = None

    def to_dict(self):
        if self.is_p2pk:
            return {
                'sender_pubkey': self.sender_pubkey,
                'recipient_pubkey': self.recipient_pubkey,
                'amount': self.amount
            }
        else:
            return {
                'sender_address': self.sender_address,
                'recipient_address': self.recipient_address,
                'amount': self.amount
            }

    def compute_hash(self):
        import json, hashlib
        tx_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(tx_str.encode()).hexdigest()

    def sign_transaction(self, sender_wallet: Wallet):
        # Check sender matches wallet for correct signing
        if self.is_p2pk:
            if sender_wallet.get_public_key_hex() != self.sender_pubkey:
                raise ValueError("Sender wallet public key does not match transaction sender_pubkey.")
        else:
            if sender_wallet.get_address() != self.sender_address:
                raise ValueError("Sender wallet address does not match transaction sender_address.")

        tx_hash = self.compute_hash()
        # Our custom ECDSA expects bytes, so convert hex string to bytes
        tx_hash_bytes = bytes.fromhex(tx_hash)
        self.signature = sender_wallet.private_key.sign(tx_hash_bytes).hex()

    def verify_signature(self, wallets_map=None):
        if self.signature is None:
            return False

        tx_hash = self.compute_hash()
        tx_hash_bytes = bytes.fromhex(tx_hash)
        try:
            if self.is_p2pk:
                if self.sender_pubkey == "SYSTEM":
                    return True
                pubkey_bytes = bytes.fromhex(self.sender_pubkey)
                pubkey_obj = VerifyingKey.from_string(pubkey_bytes)
                sig_bytes = bytes.fromhex(self.signature)
                return pubkey_obj.verify(sig_bytes, tx_hash_bytes)
            else:
                if self.sender_address == "SYSTEM":
                    return True
                if wallets_map is None:
                    raise ValueError("wallets_map required for P2PKH verification")
                sender_wallet = wallets_map.get(self.sender_address)
                if sender_wallet is None:
                    return False
                pubkey_obj = sender_wallet.get_public_key()
                sig_bytes = bytes.fromhex(self.signature)
                return pubkey_obj.verify(sig_bytes, tx_hash_bytes)
        except Exception:
            return False

    def __repr__(self):
        if self.is_p2pk:
            sender = self.sender_pubkey[:16] + "..." if self.sender_pubkey != "SYSTEM" else "SYSTEM"
            recipient = self.recipient_pubkey[:16] + "..."
            return f"Transaction(P2PK) from {sender} to {recipient}, amount={self.amount}"
        else:
            sender = self.sender_address[:16] + "..." if self.sender_address != "SYSTEM" else "SYSTEM"
            recipient = self.recipient_address[:16] + "..."
            return f"Transaction(P2PKH) from {sender} to {recipient}, amount={self.amount}"
