import base64
from phe import paillier

# Dataset
documents = {
    1: "apple orange banana",
    2: "banana fruit apple",
    3: "fruit salad apple",
    4: "orange juice",
    5: "banana smoothie",
    6: "salad dressing",
    7: "juice orange apple",
    8: "smoothie banana fruit",
    9: "dressing salad fruit",
    10: "apple banana orange smoothie"
}

# Key generation
public_key, private_key = paillier.generate_paillier_keypair()

def encrypt_number(n):
    return public_key.encrypt(n)

def decrypt_number(c):
    return private_key.decrypt(c)

def encode_ciphertext(c):
    # Convert encrypted number to base64 string for readable output
    return base64.b64encode(c.ciphertext().to_bytes((c.ciphertext().bit_length() + 7) // 8, 'big')).decode()

# Build inverted index
inverted_index = {}
for doc_id, text in documents.items():
    for word in text.split():
        inverted_index.setdefault(word, set()).add(doc_id)

# Encrypt inverted index
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    encrypted_doc_ids = [encrypt_number(doc_id) for doc_id in doc_ids]
    encrypted_index[word] = encrypted_doc_ids

# Show a sample of encrypted index (only first 3 words for brevity)
print("Encrypted Inverted Index Sample (word -> encrypted doc IDs):\n")
for i, (word, enc_ids) in enumerate(encrypted_index.items()):
    print(f"{word}:")
    for c in enc_ids:
        print(f"  {encode_ciphertext(c)}")
    print()
    if i >= 2:  # show only 3 words
        break

# Search function with detailed steps
def search(query):
    print(f"\nSearching for '{query}':")
    # Query encrypted? For words, we keep plaintext keys as before.
    print(f"Query word (plaintext): {query}")

    if query in encrypted_index:
        encrypted_doc_ids = encrypted_index[query]
        print("\nEncrypted document IDs:")
        for c in encrypted_doc_ids:
            print(f"  {encode_ciphertext(c)}")

        doc_ids = [decrypt_number(c) for c in encrypted_doc_ids]

        print("\nDecrypted document IDs:")
        print(f"  {doc_ids}")

        results = {doc_id: documents[doc_id] for doc_id in doc_ids}
        print("\nDocuments matching the query:")
        for doc_id, text in results.items():
            print(f"  Document {doc_id}: {text}")

        return results
    else:
        print("No matching documents found.")
        return {}

# Interactive search for demonstration
while True:
    query = input("\nEnter a word to search (or 'exit' to quit): ").strip().lower()
    if query == "exit":
        print("Goodbye!")
        break
    search(query)
