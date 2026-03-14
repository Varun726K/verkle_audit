import os
import json
from Initializer.kzg_core import KZG
from Initializer.verkle_tree import VerkleTree

class CloudProvider:
    def __init__(self, degree=1024, width=16):
        self.storage = {}
        self.width = width

    def load_kzg(self, kzg_instance):
        self.kzg = kzg_instance
        self.vt = VerkleTree(self.kzg, width=self.width)

    def store_file(self, file_id, tree_levels):
        filename = "Stored_chunks.json"
        
        serialized_levels = []
        for level in tree_levels:
             serialized_levels.append([str(c) for c in level])
             
        with open(filename, "w") as f:
            json.dump(serialized_levels, f, indent=4)
            
        self.storage[file_id] = filename
        print(f"[CSP] Stored {len(tree_levels[0])} leaf blocks to local disk as '{filename}'")

    def respond_to_challenge(self, file_id, challenge_indices):
        if file_id not in self.storage:
            return None
            
        filename = self.storage[file_id]
        with open(filename, "r") as f:
            serialized_levels = json.load(f)
            
        tree_levels = []
        for level in serialized_levels:
            tree_levels.append([int(c) for c in level])
            
        paths = []
        for idx in challenge_indices:
            path = self.vt.prove_path(tree_levels, idx)
            paths.append(path)
            
        return paths
