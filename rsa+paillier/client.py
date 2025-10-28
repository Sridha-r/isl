import socket
import json

def send_transactions(seller_name, transactions):
    import socket
    import json
    
    host = '127.0.0.1'
    port = 65432

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    data = {
        'seller': seller_name,
        'transactions': transactions
    }
    s.sendall(json.dumps(data).encode('utf-8'))

    # Receive all data in chunks
    chunks = []
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
    s.close()
    
    complete_data = b''.join(chunks).decode('utf-8')
    return json.loads(complete_data)


def main():
    # Simulate two sellers each with multiple transactions
    sellers_data = {
        "Seller1": [100, 200],
        "Seller2": [150, 250, 50]
    }

    for seller, transactions in sellers_data.items():
        print(f"Sending data for {seller}: {transactions}")
        result = send_transactions(seller, transactions)
        print("Transaction Summary Received:")
        for sel, vals in result['transaction_summary'].items():
            print(f"Seller: {sel}")
            print(f" Individual Amounts: {vals['individual_transaction_amounts']}")
            print(f" Encrypted Amounts: {vals['encrypted_transaction_amounts']}")
            print(f" Total Encrypted: {vals['total_encrypted_transaction_amount']}")
            print(f" Total Decrypted: {vals['total_decrypted_transaction_amount']}")
            print(f" Digital Signature: {vals.get('digital_signature')}")
            print(f" Signature Verified: {vals.get('signature_verification')}")
            print("")

if __name__ == "__main__":
    main()
