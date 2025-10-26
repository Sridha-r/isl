import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ===============================
# 1a. DATASET CREATION / UPLOAD
# ===============================
def create_dataset():
    print("Create or upload 10 text documents.")
    folder = "documents"
    os.makedirs(folder, exist_ok=True)

    for i in range(1, 11):
        path = os.path.join(folder, f"doc{i}.txt")
        if not os.path.exists(path):
            content = input(f"Enter text for document {i}: ")
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
    print("\nDocuments stored in 'documents/' folder.\n")

    documents = {}
    for i in range(1, 11):
        with open(os.path.join(folder, f"doc{i}.txt"), "r", encoding="utf-8") as f:
            documents[f"doc{i}"] = f.read()
    return documents

# ===============================
# 1b. ENCRYPTION & DECRYPTION
# ===============================
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv, ciphertext

def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# ===============================
# 1c. CREATE ENCRYPTED INVERTED INDEX
# ===============================
def create_encrypted_index(documents, key):
    index = {}

    # Create plaintext inverted index
    for doc_id, text in documents.items():
        words = text.lower().split()
        for word in words:
            word_hash = hashlib.sha256(word.encode()).hexdigest()
            if word_hash not in index:
                index[word_hash] = []
            index[word_hash].append(doc_id)

    # Encrypt the index
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        iv, enc_word = encrypt_data(key, word_hash)
        enc_doc_ids = []
        for doc_id in doc_ids:
            iv2, enc_id = encrypt_data(key, doc_id)
            enc_doc_ids.append((iv2, enc_id))
        encrypted_index[(iv, enc_word)] = enc_doc_ids

    return encrypted_index

# ===============================
# 1d. SEARCH FUNCTION
# ===============================
def search(encrypted_index, query, key, documents):
    query_hash = hashlib.sha256(query.lower().encode()).hexdigest()
    iv_query, enc_query = encrypt_data(key, query_hash)

    found_docs = []

    for (iv_word, enc_word), enc_doc_list in encrypted_index.items():
        dec_word = decrypt_data(key, iv_word, enc_word)
        if dec_word == query_hash:
            for iv_id, enc_id in enc_doc_list:
                doc_id = decrypt_data(key, iv_id, enc_id)
                found_docs.append(doc_id)

    if found_docs:
        print(f"\n🔍 Documents containing '{query}':")
        for doc_id in found_docs:
            print(f"\n📄 {doc_id}:")
            print("------------------------")
            print(documents[doc_id])
    else:
        print(f"\nNo documents found containing '{query}'.")

# ===============================
# MAIN PROGRAM
# ===============================
def main():
    print("\n🔒 Searchable Encryption System\n")
    documents = create_dataset()
    key = get_random_bytes(16)

    print("Encrypting index...")
    encrypted_index = create_encrypted_index(documents, key)
    print("Index encryption complete!\n")

    while True:
        query = input("Enter a search term (or 'exit' to quit): ")
        if query.lower() == "exit":
            break
        search(encrypted_index, query, key, documents)

if __name__ == "__main__":
    main()
