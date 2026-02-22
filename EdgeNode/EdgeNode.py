from Initializer.kzg_core import KZG

class EdgeNode:
    def __init__(self, kzg_instance=None):
        """Initializes Edge Node with SRS"""
        if kzg_instance:
            self.kzg = kzg_instance
        else:
            self.kzg = KZG(degree=1024)

    def generate_tags_and_root(self, chunks):
        """Computes the Vector Commitment (Verkle Root)"""
        print("[Edge Node] Received chunks. Computing Verkle Root...")
        root = self.kzg.commit(chunks)
        return root

    def initiate_audit(self, file_id, challenge_indices):
        """Constructs an Audit Challenge"""
        return {
            "file_id": file_id,
            "indices": challenge_indices
        }
