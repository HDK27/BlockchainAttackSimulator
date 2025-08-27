import random
import time
import json
from wallet import Wallet
from transaction import Transaction
from blockchain import Blockchain
from ecdsa_custom import SigningKey  # Your custom SigningKey

def main():
    NUM_WALLETS = 5
    MAX_TX_PER_BLOCK = 4
    TIME_GAP_SECONDS = 1
    OUTPUT_FILE = "blockchain_output.json"
    NUM_BLOCKS = 10  # Stop after 10 blocks for testing

    wallets = []
    fixed_priv_keys = [1, 2, 3, 4, 7]  # predetermined unique keys
    for priv_key in fixed_priv_keys:
        wallets.append(Wallet(private_key=SigningKey(priv_key)))

    wallets_map = {w.get_address(): w for w in wallets}
    chain = Blockchain(difficulty=2, wallets_map=wallets_map)
    blockchain_log = []

    # Seed initial coins using P2PK transactions
    for w in wallets:
        init_tx = Transaction(sender_pubkey="SYSTEM", recipient_pubkey=w.get_public_key_hex(), amount=100, is_p2pk=True)
        chain.unconfirmed_transactions.append(init_tx)
    chain.mine_pending_transactions(wallets[0].get_public_key_hex())

    block_num = 1
    while block_num <= NUM_BLOCKS:
        balances = chain.calculate_balances()
        tx_count = random.randint(1, MAX_TX_PER_BLOCK)

        for _ in range(tx_count):
            is_p2pk = random.choice([True, False])
            sender_wallet = random.choice(wallets)

            # Correct balance lookup for P2PK vs regular address
            if is_p2pk:
                sender_balance = balances.get(sender_wallet.get_public_key_hex(), 0)
            else:
                sender_balance = balances.get(sender_wallet.get_address(), 0)

            if sender_balance <= 0:
                continue

            amount = random.randint(1, sender_balance)
            recipient_wallet = random.choice(wallets)
            while recipient_wallet == sender_wallet:
                recipient_wallet = random.choice(wallets)

            if is_p2pk:
                tx = Transaction(
                    sender_pubkey=sender_wallet.get_public_key_hex(),
                    recipient_pubkey=recipient_wallet.get_public_key_hex(),
                    amount=amount,
                    is_p2pk=True
                )
            else:
                tx = Transaction(
                    sender_address=sender_wallet.get_address(),
                    recipient_address=recipient_wallet.get_address(),
                    amount=amount,
                    is_p2pk=False
                )

            tx.sign_transaction(sender_wallet)

            try:
                chain.add_transaction(tx, wallets_map=wallets_map)
            except ValueError as e:
                print(f"Invalid transaction: {e}")
                continue

        chain.mine_pending_transactions(wallets[0].get_public_key_hex())
        block_obj = chain.last_block()

        print(f"\n--- Block {block_num} mined ---")
        print(block_obj.detailed_str())

        block_data = {
            "index": block_obj.index,
            "hash": block_obj.hash,
            "previous_hash": block_obj.previous_hash,
            "timestamp": block_obj.timestamp,
            "nonce": block_obj.nonce,
            "difficulty": block_obj.difficulty,
            "transactions": []
        }
        for tx in block_obj.transactions:
            tx_dict = tx.to_dict()
            tx_dict["signature"] = tx.signature or ""
            tx_dict["is_p2pk"] = tx.is_p2pk
            block_data["transactions"].append(tx_dict)

        blockchain_log.append(block_data)
        with open(OUTPUT_FILE, "w") as f:
            json.dump(blockchain_log, f, indent=2)

        balances = chain.calculate_balances()
        print("\nWallet balances:")
        for i, w in enumerate(wallets):
            bal = balances.get(w.get_public_key_hex(), 0)
            print(f"  Wallet {i}: {bal} coins")

        block_num += 1
        time.sleep(TIME_GAP_SECONDS)

if __name__ == "__main__":
    main()
