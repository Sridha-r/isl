import time
import random
from Crypto.Util import number
from phe import paillier

# ElGamal implementation as in 1a (reuse class here)
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

# Generate datasets of random integers
data = [random.randint(1, 1000) for _ in range(50)]

# Paillier Benchmark
public_key, private_key = paillier.generate_paillier_keypair(n_length=512)

start = time.time()
paillier_encrypted = [public_key.encrypt(x) for x in data]
end = time.time()
paillier_encrypt_time = end - start

# ElGamal Benchmark
elgamal = ElGamal()

start = time.time()
elgamal_encrypted = [elgamal.encrypt(x) for x in data]
end = time.time()
elgamal_encrypt_time = end - start

print(f"Paillier encryption time for 50 items: {paillier_encrypt_time:.4f} seconds")
print(f"ElGamal encryption time for 50 items: {elgamal_encrypt_time:.4f} seconds")

# Collision detection is not relevant here directly, as these are probabilistic encryption outputs.
# For hash collisions or signature collisions, separate cryptographic tests would be needed.
