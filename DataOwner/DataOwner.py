import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Initializer.kzg_core import KZG
from EdgeNode.EdgeNode import EdgeNode

AES_KEY_SIZE = 32

class DataOwner:
    def __init__(self, secret_key=None, edge_node=None):
        self.aes_key = secret_key if secret_key else get_random_bytes(AES_KEY_SIZE)
        self.kzg = KZG(degree=1024)
        self.edge_node = edge_node if edge_node else EdgeNode(self.kzg)

    def encrypt_file(self, content: bytes):
        iv = get_random_bytes(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(content, AES.block_size))
        return iv, ciphertext

    def decrypt_file(self, iv, ciphertext):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)

    def prepare_upload(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError("File not found.")
        with open(file_path, "rb") as f:
            content = f.read()
        iv, ciphertext = self.encrypt_file(content)
        chunk_size = 31
        chunks = []
        for i in range(0, len(ciphertext), chunk_size):
            chunks.append(int.from_bytes(ciphertext[i:i+chunk_size], 'big'))
            
        root_commitment, tree_levels = self.edge_node.generate_tags_and_root(chunks)
        return {
            "root": root_commitment,
            "chunks": chunks,
            "tree_levels": tree_levels,
            "iv": iv,
            "ciphertext": ciphertext
        }
