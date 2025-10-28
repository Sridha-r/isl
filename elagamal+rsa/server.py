import socket
import json
from Crypto.Random import random
from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ElGamal class with homomorphic multiplication
class ElGamal:
    def __init__(self, bits=256):
        self.p = number.getPrime(bits)
        self.g = random.randint(2, self.p - 1)
        self.x = random.randint(2, self.p - 2)
        self.h = pow(self.g, self.x, self.p)

    def encrypt(self, m):
        k = random.randint(2, self.p - 2)
        c1 = pow(self.g, k, self.p)
        c2 = (m * pow(self.h, k, self.p)) % self.p
        return (c1, c2)

    def decrypt(self, ciphertext):
        c1, c2 = ciphertext
        s = pow(c1, self.x, self.p)
        s_inv = pow(s, -1, self.p)
        return (c2 * s_inv) % self.p

    def multiply(self, ct1, ct2):
        # Multiply ciphertexts homomorphically
        c1 = (ct1[0] * ct2[0]) % self.p
        c2 = (ct1[1] * ct2[1]) % self.p
        return (c1, c2)

# Generate ElGamal and RSA keypairs
elgamal = ElGamal(bits=256)
rsa_key = RSA.generate(2048)
private_rsa_key = rsa_key
public_rsa_key = rsa_key.publickey()

transaction_summary = {}

def sign_data(data, priv_key):
    h = SHA256.new(data.encode('utf-8'))
    signature = pkcs1_15.new(priv_key).sign(h)
    return signature.hex()

def verify_signature(data, sig_hex, pub_key):
    h = SHA256.new(data.encode('utf-8'))
    signature = bytes.fromhex(sig_hex)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except:
        return False

def process_transactions(seller_name, transactions):
    encrypted_transactions = [elgamal.encrypt(m) for m in transactions]
    total_encrypted = encrypted_transactions[0]
    for ct in encrypted_transactions[1:]:
        total_encrypted = elgamal.multiply(total_encrypted, ct)
    decrypted_total = elgamal.decrypt(total_encrypted)
    transaction_summary[seller_name] = {
        "transactions": transactions,
        "encrypted_transactions": [(str(ct[0]), str(ct[1])) for ct in encrypted_transactions],
        "total_encrypted": (str(total_encrypted[0]), str(total_encrypted[1])),
        "total_decrypted": decrypted_total,
    }

def prepare_summary():
    summary = ""
    for seller, details in transaction_summary.items():
        summary += f"Seller: {seller}\n"
        summary += f"Transactions: {details['transactions']}\n"
        summary += f"Total decrypted: {details['total_decrypted']}\n\n"
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
        try:
            data = conn.recv(8192).decode()
            if not data:
                conn.close()
                continue

            payload = json.loads(data)
            seller = payload["seller"]
            transactions = payload["transactions"]

            process_transactions(seller, transactions)

            summary = prepare_summary()
            signature = sign_data(summary, private_rsa_key)
            transaction_summary[seller]["signature"] = signature
            transaction_summary[seller]["signature_verified"] = verify_signature(summary, signature, public_rsa_key)

            response = {
                "transaction_summary": transaction_summary,
                "signature": signature,
                "signature_verified": transaction_summary[seller]["signature_verified"],
                "public_key": public_rsa_key.export_key().decode()
            }

            conn.sendall(json.dumps(response).encode())
        except Exception as e:
            print("Error:", e)
        finally:
            conn.close()

if __name__ == "__main__":
    main()
