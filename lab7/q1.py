import random
from math import gcd

def lcm(a, b):
    return abs(a*b) // gcd(a, b)

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

def L(u, n):
    return (u - 1) // n

def generate_prime_candidate(length):
    """Generate an odd integer randomly"""
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1  # Ensure high bit and low bit set
    return p

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

def generate_prime_number(length=512):
    p = generate_prime_candidate(length)
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

class Paillier:
    def __init__(self, bit_length=512):
        self.p = generate_prime_number(bit_length)
        self.q = generate_prime_number(bit_length)
        while self.q == self.p:
            self.q = generate_prime_number(bit_length)

        self.n = self.p * self.q
        self.n_sq = self.n * self.n
        self.g = self.n + 1  # common choice for g

        self.lambda_param = lcm(self.p - 1, self.q - 1)
        self.mu = modinv(L(pow(self.g, self.lambda_param, self.n_sq), self.n), self.n)

    def encrypt(self, m):
        """Encrypt integer m"""
        if not (0 <= m < self.n):
            raise ValueError('Message must be in Z_n')
        r = random.randint(1, self.n - 1)
        while gcd(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        c = (pow(self.g, m, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        return c

    def decrypt(self, c):
        """Decrypt ciphertext c"""
        u = pow(c, self.lambda_param, self.n_sq)
        l = L(u, self.n)
        m = (l * self.mu) % self.n
        return m

    def add_ciphertexts(self, c1, c2):
        """Homomorphic addition of two ciphertexts"""
        return (c1 * c2) % self.n_sq


# Demo
paillier = Paillier(bit_length=128)  # smaller bits for faster demo

m1 = 15
m2 = 25

c1 = paillier.encrypt(m1)
c2 = paillier.encrypt(m2)

print(f"Ciphertext of {m1}: {c1}")
print(f"Ciphertext of {m2}: {c2}")

c_sum = paillier.add_ciphertexts(c1, c2)
print(f"Encrypted sum (ciphertext): {c_sum}")

m_sum = paillier.decrypt(c_sum)
print(f"Decrypted sum: {m_sum}")

assert m_sum == m1 + m2, "Decrypted sum does not match original sum!"
print("Verification passed: decrypted sum matches the sum of the original integers.")
