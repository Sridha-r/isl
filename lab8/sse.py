from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

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

# AES setup
key = get_random_bytes(16)

def encrypt(data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ct_bytes

def decrypt(data):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# Build inverted index
inverted_index = {}
for doc_id, text in documents.items():
    for word in text.split():
        inverted_index.setdefault(word, set()).add(doc_id)

# Encrypt inverted index
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    enc_word = encrypt(word)
    enc_doc_ids = encrypt(",".join(map(str, doc_ids)))
    encrypted_index[enc_word] = enc_doc_ids

# Search function
def search(query):
    enc_query = encrypt(query)
    for enc_word, enc_doc_ids in encrypted_index.items():
        if decrypt(enc_word) == query:
            doc_ids = map(int, decrypt(enc_doc_ids).split(","))
            return {doc_id: documents[doc_id] for doc_id in doc_ids}
    return {}

# Main loop for user interaction
print("Welcome to the encrypted document search!")
print("Type 'exit' to quit.\n")

while True:
    query = input("Enter a word to search: ").strip().lower()
    if query == "exit":
        print("Goodbye!")
        break

    results = search(query)
    if results:
        print(f"\nFound {len(results)} document(s) containing '{query}':")
        for doc_id, text in sorted(results.items()):
            print(f"Document {doc_id}: {text}")
    else:
        print(f"No documents found containing '{query}'.")
    print()  # blank line for readability
