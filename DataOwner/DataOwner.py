import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Initializer.kzg_core import KZG
from EdgeNode.EdgeNode import EdgeNode


BLOCK_SIZE = 32 
AES_KEY_SIZE = 32 

class DataOwner:
    def __init__(self, secret_key=None, edge_node=None):
        self.aes_key = secret_key if secret_key else get_random_bytes(AES_KEY_SIZE)
        self.kzg = KZG(degree=1024) 
        self.edge_node = edge_node if edge_node else EdgeNode(self.kzg)

    def encrypt_file(self, content: bytes):
        """
        Encrypts content using AES-CBC.
        Returns: iv, ciphertext
        """
        iv = get_random_bytes(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(content, AES.block_size))
        return iv, ciphertext

    def decrypt_file(self, iv, ciphertext):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    def prepare_upload(self, file_path):
        """
        Reads file, encrypts it, chunks it, and builds Verkle Root.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError("File not found.")

        with open(file_path, "rb") as f:
            content = f.read()

        print(f"Original File Size: {len(content)} bytes")
        
        iv, ciphertext = self.encrypt_file(content)
        print(f"Encrypted Size: {len(ciphertext)} bytes")

        chunk_size = 31
        chunks = []
        for i in range(0, len(ciphertext), chunk_size):
            chunk_bytes = ciphertext[i:i+chunk_size]
            chunk_int = int.from_bytes(chunk_bytes, 'big')
            chunks.append(chunk_int)
        
        print(f"Total Blocks/Chunks: {len(chunks)}")

        root_commitment = self.edge_node.generate_tags_and_root(chunks)
        
        return {
            "root": root_commitment,
            "chunks": chunks,
            "iv": iv,
            "ciphertext": ciphertext
        }

if __name__ == "__main__":
    do = DataOwner()
    

    with open("test_file.txt", "w") as f:
        f.write("Hello Verkle World! This is a secure file storage test." * 10)
        
    data = do.prepare_upload("test_file.txt")
    print("Root generated:", data["root"])
    

