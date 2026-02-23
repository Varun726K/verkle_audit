import os
from Initializer.kzg_core import KZG
from py_ecc.optimized_bn128 import normalize

class CloudProvider:
    def __init__(self, degree=1024):
        self.storage = {}

    def load_kzg(self, kzg_instance):
        self.kzg = kzg_instance

    def store_file(self, file_id, chunks):
        """Stores the encrypted file chunks to disk for demo modification"""
        import json
        filename = "Stored_chunks.json"
        
        with open(filename, "w") as f:
            json.dump([str(c) for c in chunks], f, indent=4)
            
        self.storage[file_id] = filename
        print(f"[CSP] Stored {len(chunks)} blocks to local disk as '{filename}'")

    def respond_to_challenge(self, file_id, challenge_indices):
        """Generates a KZG Proof for the requested indices reading from disk"""
        if file_id not in self.storage:
            return None
        
        filename = self.storage[file_id]
        import json
        with open(filename, "r") as f:
            chunks = [int(c) for c in json.load(f)]
            
        proofs = []
        
        for idx in challenge_indices:
            z = idx
            proof, y = self.kzg.generate_proof(chunks, z)
            proofs.append({
                "z": z,
                "y": y,
                "proof": proof
            })
            
        return proofs
