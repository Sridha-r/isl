import random
from hashlib import sha256

# ---------- Common helpers ----------

def hash_message(m):
    return int(sha256(m.encode()).hexdigest(), 16)

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


# ---------- ElGamal Digital Signature ----------

class ElGamalDS:
    def __init__(self, p, g):
        self.p = p  # large prime modulus
        self.g = g  # generator

        # Private key x in [1, p-2]
        self.x = random.randint(1, p - 2)
        # Public key y = g^x mod p
        self.y = pow(g, self.x, p)

    def sign(self, message):
        H = hash_message(message) % self.p
        while True:
            k = random.randint(1, self.p - 2)
            if gcd(k, self.p - 1) == 1:
                break
        r = pow(self.g, k, self.p)
        k_inv = modinv(k, self.p - 1)
        s = (k_inv * (H - self.x * r)) % (self.p - 1)
        return (r, s)

    def verify(self, message, signature):
        r, s = signature
        if not (0 < r < self.p):
            return False
        H = hash_message(message) % self.p
        v1 = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p
        v2 = pow(self.g, H, self.p)
        return v1 == v2


# ---------- Schnorr Digital Signature ----------

class SchnorrDS:
    def __init__(self, p, q, g):
        self.p = p  # large prime modulus
        self.q = q  # large prime divisor of p-1
        self.g = g  # generator of order q

        # Private key x in [1, q-1]
        self.x = random.randint(1, q - 1)
        # Public key y = g^x mod p
        self.y = pow(g, self.x, p)

    def sign(self, message):
        k = random.randint(1, self.q - 1)
        R = pow(self.g, k, self.p)
        e = hash_message(message + str(R)) % self.q
        s = (k + self.x * e) % self.q
        return (e, s)

    def verify(self, message, signature):
        e, s = signature
        R_prime = (pow(self.g, s, self.p) * pow(self.y, self.q - e, self.p)) % self.p
        e_prime = hash_message(message + str(R_prime)) % self.q
        return e == e_prime


# ----------- Example usage -------------

def main():
    # ElGamal example with small primes (for demo only)
    print("ElGamal Digital Signature:")
    p = 467
    g = 2
    elgamal = ElGamalDS(p, g)
    message1 = "Hello, this is Alice."
    signature1 = elgamal.sign(message1)
    print(f"Message: {message1}")
    print(f"Signature: {signature1}")
    print(f"Verification: {elgamal.verify(message1, signature1)}\n")

    # Schnorr example with small primes (for demo only)
    print("Schnorr Digital Signature:")
    p = 467
    q = 233
    g = 2
    schnorr = SchnorrDS(p, q, g)
    message2 = "Hello, this is Bob."
    signature2 = schnorr.sign(message2)
    print(f"Message: {message2}")
    print(f"Signature: {signature2}")
    print(f"Verification: {schnorr.verify(message2, signature2)}")

if __name__ == "__main__":
    main()

