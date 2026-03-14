from Initializer.kzg_core import KZG
from Initializer.verkle_tree import VerkleTree

class EdgeNode:
    def __init__(self, kzg_instance=None, width=16):
        self.kzg = kzg_instance if kzg_instance else KZG(degree=1024)
        self.vt = VerkleTree(self.kzg, width=width)

    def generate_tags_and_root(self, chunks):
        print("[Edge Node] Received chunks. Computing Verkle Root...")
        return self.vt.build_tree(chunks)

    def initiate_audit(self, file_id, challenge_indices):
        return {"file_id": file_id, "indices": challenge_indices}
