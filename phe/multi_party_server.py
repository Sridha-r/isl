from phe import paillier

# Key generation (usually server)
public_key, private_key = paillier.generate_paillier_keypair(n_length=512)

# Simulate 3 parties encrypting private inputs
party_inputs = [10, 15, 21]

encrypted_inputs = [public_key.encrypt(x) for x in party_inputs]

# Server performs homomorphic addition without seeing plaintexts
enc_total = encrypted_inputs[0]
for ct in encrypted_inputs[1:]:
    enc_total += ct

# Server decrypts the total only
decrypted_total = private_key.decrypt(enc_total)

print("Encrypted inputs:", [ct.ciphertext() for ct in encrypted_inputs])
print("Encrypted total:", enc_total.ciphertext())
print("Decrypted total:", decrypted_total)  # Should be sum of inputs: 46
