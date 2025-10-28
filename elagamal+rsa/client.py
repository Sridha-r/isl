import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def verify_signature(data, sig_hex, pub_key):
    h = SHA256.new(data.encode('utf-8'))
    signature = bytes.fromhex(sig_hex)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except:
        return False

def send_transactions(seller, transactions):
    host = '127.0.0.1'
    port = 65432
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    payload = {"seller": seller, "transactions": transactions}
    s.sendall(json.dumps(payload).encode())
    response = b""
    while True:
        part = s.recv(8192)
        if not part:
            break
        response += part
    s.close()
    return json.loads(response.decode())

def main():
    sellers_transactions = {
        "Seller1": [2, 5],
        "Seller2": [3, 4, 2]
    }

    for seller, transactions in sellers_transactions.items():
        print(f"Sending transactions for {seller}: {transactions}")
        response = send_transactions(seller, transactions)
        print("Received transaction summary:")
        for s, details in response["transaction_summary"].items():
            print(f" Seller: {s}")
            print(f" Transactions: {details['transactions']}")
            print(f" Total decrypted: {details['total_decrypted']}")
            print(f" Digital Signature: {details.get('signature')}")
            print(f" Signature Verified: {details.get('signature_verified')}")

            pub_key = RSA.import_key(response["public_key"])
signed_summary = response["signed_summary"]

valid = verify_signature(signed_summary, details.get('signature'), pub_key)
print(f" Client-side Signature Verification (using exact signed summary): {valid}")


if __name__ == "__main__":
    main()
