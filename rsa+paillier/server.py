import socket
import json
from phe import paillier
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generate Paillier keypair
public_key, private_key = paillier.generate_paillier_keypair()

# Generate RSA keypair for digital signatures
rsa_key = RSA.generate(2048)
private_rsa_key = rsa_key
public_rsa_key = rsa_key.publickey()

# Data structure to hold transaction summary
transaction_summary = {}

def sign_data(data, priv_key):
    h = SHA256.new(data.encode('utf-8'))
    signature = pkcs1_15.new(priv_key).sign(h)
    return signature.hex()

def verify_signature(data, signature_hex, pub_key):
    h = SHA256.new(data.encode('utf-8'))
    signature = bytes.fromhex(signature_hex)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def process_transaction(seller_name, transactions):
    # Encrypt each transaction amount and add homomorphically
    encrypted_transactions = []
    for amt in transactions:
        enc = public_key.encrypt(amt)
        encrypted_transactions.append(enc)

    # Homomorphic addition
    encrypted_total = encrypted_transactions[0]
    for enc_amt in encrypted_transactions[1:]:
        encrypted_total += enc_amt

    decrypted_total = private_key.decrypt(encrypted_total)

    # Save summary
    transaction_summary[seller_name] = {
        'individual_transaction_amounts': transactions,
        'encrypted_transaction_amounts': [str(enc.ciphertext()) for enc in encrypted_transactions],
        'decrypted_transaction_amounts': transactions,  # Since individual decrypted is known
        'total_encrypted_transaction_amount': str(encrypted_total.ciphertext()),
        'total_decrypted_transaction_amount': decrypted_total,
    }

def prepare_summary():
    summary = ""
    for seller, details in transaction_summary.items():
        summary += f"Seller: {seller}\n"
        summary += f"Individual Amounts: {details['individual_transaction_amounts']}\n"
        summary += f"Encrypted Amounts: {details['encrypted_transaction_amounts']}\n"
        summary += f"Total Encrypted: {details['total_encrypted_transaction_amount']}\n"
        summary += f"Total Decrypted: {details['total_decrypted_transaction_amount']}\n"
        summary += "\n"
    return summary

def main():
    host = '127.0.0.1'
    port = 65432

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen()

    print(f"Server listening on {host}:{port}")

    while True:
        conn, addr = s.accept()
        print(f"Connection from {addr}")

        data = conn.recv(4096).decode('utf-8')
        if not data:
            conn.close()
            continue

        payload = json.loads(data)
        seller = payload['seller']
        transactions = payload['transactions']

        # Process transactions (encrypt + sum)
        process_transaction(seller, transactions)

        # Prepare full summary text
        summary = prepare_summary()

        # Sign summary with RSA private key
        signature = sign_data(summary, private_rsa_key)

        # Verify signature for demonstration
        verification_result = verify_signature(summary, signature, public_rsa_key)

        # Include signature info in final output
        transaction_summary[seller]['digital_signature'] = signature
        transaction_summary[seller]['signature_verification'] = verification_result

        # Build response
        response = {
            'transaction_summary': transaction_summary,
            'signature': signature,
            'signature_verification': verification_result
        }

        conn.sendall(json.dumps(response).encode('utf-8'))
        conn.close()

if __name__ == "__main__":
    main()
