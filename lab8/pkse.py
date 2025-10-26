import os
import pickle
from phe import paillier

# ---------- STEP 1: Dataset creation ----------
def create_documents():
    if not os.path.exists("documents"):
        os.makedirs("documents")

    docs = {
        1: "apple orange banana",
        2: "banana fruit apple",
        3: "fruit salad apple",
        4: "orange juice",
        5: "banana smoothie",
        6: "salad dressing",
        7: "juice orange apple",
        8: "apple pie fruit",
        9: "fresh orange juice",
        10: "fruit basket apple banana"
    }

    for doc_id, text in docs.items():
        with open(f"documents/doc{doc_id}.txt", "w") as f:
            f.write(text)

    print("✅ Documents created in 'documents/' folder.")


# ---------- STEP 2: Load or generate Paillier keys ----------
def save_keys(public_key, private_key):
    with open("paillier_keys.pkl", "wb") as f:
        pickle.dump((public_key, private_key), f)

def load_keys():
    if os.path.exists("paillier_keys.pkl"):
        with open("paillier_keys.pkl", "rb") as f:
            return pickle.load(f)
    return None, None


# ---------- STEP 3: Build inverted index ----------
def build_index(doc_folder):
    index = {}
    for file_name in os.listdir(doc_folder):
        if file_name.endswith(".txt"):
            doc_id = int(file_name.replace("doc", "").replace(".txt", ""))
            with open(os.path.join(doc_folder, file_name), "r") as f:
                words = f.read().lower().split()
                for w in words:
                    index.setdefault(w, set()).add(doc_id)
    return index


# ---------- STEP 4: Deterministic encryption for words ----------
def det_encrypt_word(word, pubkey):
    # For demo, use hash-based deterministic “encryption”
    # (Paillier not meant for text; this keeps mapping stable)
    return hash(word) % (10 ** 8)


# ---------- STEP 5: Encrypt document IDs using Paillier ----------
def encrypt_index(index, public_key):
    enc_index = {}
    for word, doc_ids in index.items():
        enc_word = det_encrypt_word(word, public_key)
        enc_doc_ids = [public_key.encrypt(doc_id) for doc_id in doc_ids]
        enc_index[enc_word] = enc_doc_ids
    return enc_index


# ---------- STEP 6: Search ----------
def search(enc_index, query, public_key, private_key):
    enc_query = det_encrypt_word(query, public_key)
    if enc_query not in enc_index:
        return []

    encrypted_doc_ids = enc_index[enc_query]
    return [private_key.decrypt(x) for x in encrypted_doc_ids]


# ---------- MAIN ----------
def main():
    # Create dataset if not already there
    if not os.path.exists("documents") or not os.listdir("documents"):
        create_documents()
    else:
        print("Loaded existing documents from 'documents/'.")

    # Load or create Paillier keys
    public_key, private_key = load_keys()
    if public_key is None:
        print("🔑 Generating Paillier keypair (this may take a moment)...")
        public_key, private_key = paillier.generate_paillier_keypair()
        save_keys(public_key, private_key)
        print("✅ Keys generated and saved.")
    else:
        print("🔐 Loaded existing Paillier keypair from file.")

    # Build and encrypt index
    print("Building encrypted index...")
    index = build_index("documents")
    enc_index = encrypt_index(index, public_key)
    print(f"🔒 Encrypted index contains {len(enc_index)} unique words.\n")

    # Search loop
    print("=== PKSE Search Demo ===")
    print("Type a word to search (e.g., 'apple', 'orange'). Type 'exit' to quit.\n")

    while True:
        query = input("Search> ").strip().lower()
        if query == "exit":
            print("Exiting search.")
            break
        results = search(enc_index, query, public_key, private_key)
        if results:
            print(f"✅ Word '{query}' found in documents: {sorted(results)}\n")
        else:
            print(f"❌ No documents found containing '{query}'.\n")


if __name__ == "__main__":
    main()
