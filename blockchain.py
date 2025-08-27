import time
import json
import hashlib
from transaction import Transaction

class Block:
    def __init__(self, index, transactions, previous_hash, difficulty=2):
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.timestamp = time.time()
        self.nonce = 0
        self.difficulty = difficulty
        self.hash = self.compute_hash()

    def compute_hash(self):
        tx_list = []
        for tx in self.transactions:
            tx_dict = tx.to_dict()
            tx_dict['signature'] = tx.signature or ""
            tx_list.append(tx_dict)

        block_content = {
            'index': self.index,
            'transactions': tx_list,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'difficulty': self.difficulty,
            'timestamp': self.timestamp,
        }
        block_string = json.dumps(block_content, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine(self):
        prefix = '0' * self.difficulty
        while not self.hash.startswith(prefix):
            self.nonce += 1
            self.hash = self.compute_hash()

    def __repr__(self):
        return (f"Block(index={self.index}, hash={self.hash[:10]}..., "
                f"prev_hash={self.previous_hash[:10]}..., tx_count={len(self.transactions)})")

    def detailed_str(self):
        lines = [
            f"Block #{self.index}",
            f"Hash: {self.hash}",
            f"Previous Hash: {self.previous_hash}",
            f"Timestamp: {time.ctime(self.timestamp)}",
            f"Nonce: {self.nonce}",
            f"Difficulty: {self.difficulty}",
            f"Transactions ({len(self.transactions)}):"
        ]
        for i, tx in enumerate(self.transactions, 1):
            if tx.is_p2pk:
                sender = tx.sender_pubkey[:16] + "..." if tx.sender_pubkey != "SYSTEM" else "SYSTEM"
                recipient = tx.recipient_pubkey[:16] + "..."
            else:
                sender = tx.sender_address[:16] + "..." if tx.sender_address != "SYSTEM" else "SYSTEM"
                recipient = tx.recipient_address[:16] + "..."
            lines.append(f"  {i}. {sender} -> {recipient} | Amount: {tx.amount}")
        return "\n".join(lines)

class Blockchain:
    def __init__(self, difficulty=2, wallets_map=None):
        self.chain = []
        self.unconfirmed_transactions = []
        self.difficulty = difficulty
        self.wallets_map = wallets_map or {}
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], "0", self.difficulty)
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    def last_block(self):
        return self.chain[-1]

    def id_for_balance(self, tx, is_sender):
        """Normalize balance key to public key hex for both P2PK and P2PKH."""
        if tx.is_p2pk:
            return tx.sender_pubkey if is_sender else tx.recipient_pubkey
        else:
            addr = tx.sender_address if is_sender else tx.recipient_address
            if addr == "SYSTEM":
                return "SYSTEM"
            wallet_obj = self.wallets_map.get(addr)
            return wallet_obj.get_public_key_hex() if wallet_obj else addr

    def calculate_balances(self):
        balances = {}
        for block in self.chain:
            for tx in block.transactions:
                sender_id = self.id_for_balance(tx, True)
                recipient_id = self.id_for_balance(tx, False)

                if sender_id != "SYSTEM":
                    balances[sender_id] = balances.get(sender_id, 0) - tx.amount
                balances[recipient_id] = balances.get(recipient_id, 0) + tx.amount
        return balances

    def add_transaction(self, transaction: Transaction, wallets_map=None):
        if not transaction.verify_signature(wallets_map):
            raise ValueError("Transaction signature invalid")

        balances = self.calculate_balances()
        sender_id = self.id_for_balance(transaction, True)

        if sender_id != "SYSTEM":
            sender_balance = balances.get(sender_id, 0)
            pending_spent = sum(
                tx.amount for tx in self.unconfirmed_transactions
                if self.id_for_balance(tx, True) == sender_id
            )
            if sender_balance - pending_spent < transaction.amount:
                raise ValueError(f"Sender balance too low ({sender_balance - pending_spent}) for amount {transaction.amount}")

        self.unconfirmed_transactions.append(transaction)

    def mine_pending_transactions(self, miner_pubkey_hex):
        if not self.unconfirmed_transactions:
            print("No transactions to mine.")
            return False

        # Reward transaction as P2PK type with sender_pubkey = SYSTEM
        reward_tx = Transaction(sender_pubkey="SYSTEM", recipient_pubkey=miner_pubkey_hex, amount=10, is_p2pk=True)
        self.unconfirmed_transactions.append(reward_tx)

        new_block = Block(len(self.chain), self.unconfirmed_transactions, self.last_block().hash, self.difficulty)
        print(f"Mining block {new_block.index} with {len(new_block.transactions)} transactions...")
        new_block.mine()

        self.chain.append(new_block)
        self.unconfirmed_transactions = []
        print(f"Block {new_block.index} mined with hash: {new_block.hash[:15]}...")
        return True
