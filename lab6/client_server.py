import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import time

HOST = 'localhost'
PORT = 65433

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key_pem, message, signature):
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    print("[Server] Listening for connections...")

    conn, addr = server_sock.accept()
    print(f"[Server] Connected by {addr}")

    def recv_all(n):
        data = b''
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    # Receive public key
    pubkey_len = int.from_bytes(recv_all(4), 'big')
    public_key_pem = recv_all(pubkey_len)

    # Receive message
    msg_len = int.from_bytes(recv_all(4), 'big')
    message = recv_all(msg_len)

    # Receive signature
    sig_len = int.from_bytes(recv_all(4), 'big')
    signature = recv_all(sig_len)

    print("[Server] Received public key, message, and signature.")
    print(f"[Server] Message:\n{message.decode()}")

    valid = verify_signature(public_key_pem, message, signature)
    if valid:
        print("[Server] Signature is VALID. Message is authentic and signed by client.")
    else:
        print("[Server] Signature is INVALID! Message may be tampered.")

    conn.close()
    server_sock.close()

def client():
    time.sleep(1)  # Wait for server to start

    # Generate keys and sign
    private_key, public_key = generate_rsa_keys()
    print("[Client] RSA key pair generated.")

    message = b"Legal Document: This is Alice's signed document."

    signature = sign_message(private_key, message)
    print(f"[Client] Message signed. Signature length: {len(signature)} bytes.")

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((HOST, PORT))
    print("[Client] Connected to server.")

    def send_with_len(data):
        client_sock.send(len(data).to_bytes(4, 'big'))
        client_sock.send(data)

    send_with_len(public_key_pem)
    send_with_len(message)
    send_with_len(signature)

    print("[Client] Sent public key, message, and signature to server.")
    client_sock.close()

if __name__ == "__main__":
    server_thread = threading.Thread(target=server)
    client_thread = threading.Thread(target=client)

    server_thread.start()
    client_thread.start()

    server_thread.join()
    client_thread.join()
