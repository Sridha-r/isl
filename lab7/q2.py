import random
from math import gcd

def modinv(a, m):
    """Modular inverse using Extended Euclidean Algorithm"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def is_prime(n, k=10):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    # Check small primes
    small_primes = [2,3,5,7,11,13,17,19,23]
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0 and n != sp:
            return False

    # Find r, d such that n-1 = 2^r * d
    r, d = 0, n-1
    while d % 2 == 0:
        d //= 2
        r += 1

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime_candidate(length):
    """Generate an odd integer randomly"""
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1  # Ensure high bit and low bit set
    return p

def generate_prime_number(length=512):
    p = generate_prime_candidate(length)
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

class RSA:
    def __init__(self, bit_length=512):
        self.p = generate_prime_number(bit_length)
        self.q = generate_prime_number(bit_length)
        while self.q == self.p:
            self.q = generate_prime_number(bit_length)

        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)

        # Choose e coprime with phi
        self.e = 65537  # common choice
        if gcd(self.e, self.phi) != 1:
            # Find another e
            self.e = 3
            while gcd(self.e, self.phi) != 1:
                self.e += 2

        self.d = modinv(self.e, self.phi)

    def encrypt(self, m):
        if not (0 <= m < self.n):
            raise ValueError("Message out of range")
        return pow(m, self.e, self.n)

    def decrypt(self, c):
        return pow(c, self.d, self.n)

# Demo
rsa = RSA(bit_length=128)  # smaller bits for speed

m1 = 7
m2 = 3

c1 = rsa.encrypt(m1)
c2 = rsa.encrypt(m2)

print(f"Ciphertext of {m1}: {c1}")
print(f"Ciphertext of {m2}: {c2}")

# Multiply ciphertexts (homomorphic multiplication)
c_mul = (c1 * c2) % rsa.n
print(f"Encrypted product (ciphertext): {c_mul}")

# Decrypt the product
m_mul = rsa.decrypt(c_mul)
print(f"Decrypted product: {m_mul}")

assert m_mul == m1 * m2, "Decrypted product does not match original product!"
print("Verification passed: decrypted product matches the product of the original integers.")
