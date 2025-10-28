from phe import paillier

# Party A generates keys
public_key, private_key = paillier.generate_paillier_keypair(n_length=512)

# Two parties encrypt their private values
party1_val = 5
party2_val = 2

enc1 = public_key.encrypt(party1_val)
enc2 = public_key.encrypt(party2_val)

# Combine encrypted data homomorphically (addition)
enc_sum = enc1 + enc2

# Decrypt combined result (only party with private key can)
decrypted_sum = private_key.decrypt(enc_sum)

print("Party 1 encrypted value:", enc1.ciphertext())
print("Party 2 encrypted value:", enc2.ciphertext())
print("Encrypted sum:", enc_sum.ciphertext())
print("Decrypted sum:", decrypted_sum)  # Should be 46
