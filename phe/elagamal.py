from Crypto.Random import random
from Crypto.Util import number

class ElGamal:
    def __init__(self, bits=256):
        self.p = number.getPrime(bits)
        self.g = random.randint(2, self.p - 1)
        self.x = random.randint(2, self.p - 2)  # Private key
        self.h = pow(self.g, self.x, self.p)   # Public key

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
        # Homomorphic multiplication on ciphertexts
        c1 = (ct1[0] * ct2[0]) % self.p
        c2 = (ct1[1] * ct2[1]) % self.p
        return (c1, c2)

# Demo:
elgamal = ElGamal()
m1, m2 = 7, 3

enc1 = elgamal.encrypt(m1)
enc2 = elgamal.encrypt(m2)

print("Encrypted m1:", enc1)
print("Encrypted m2:", enc2)

enc_mul = elgamal.multiply(enc1, enc2)
print("Encrypted multiplication:", enc_mul)

dec_mul = elgamal.decrypt(enc_mul)
print("Decrypted multiplication result:", dec_mul)  # Should be 21 (7*3)
