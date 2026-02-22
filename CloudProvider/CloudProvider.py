import os
from Initializer.kzg_core import KZG
from py_ecc.optimized_bn128 import normalize

class CloudProvider:
    def __init__(self, degree=1024):
        pass

    def load_kzg(self, kzg_instance):
        self.kzg = kzg_instance

    def store_file(self, file_id, chunks):
        """Stores the encrypted file chunks"""
        self.storage = {file_id: chunks}
        print(f"[CSP] Stored {len(chunks)} blocks for file {file_id}")

    def respond_to_challenge(self, file_id, challenge_indices):
        """Generates a KZG Proof for the requested indices"""
        if file_id not in self.storage:
            return None
        
        chunks = self.storage[file_id]
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
