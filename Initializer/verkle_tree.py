import hashlib
from Initializer.kzg_core import KZG, Order, lagrange_interpolate

def hash_commitment(C):
    if not C:
        return 0
    x = int(C[0])
    y = int(C[1])
    data = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
    return int.from_bytes(hashlib.sha256(data).digest(), 'big') % Order

class VerkleTree:
    def __init__(self, kzg: KZG, width=16):
        self.kzg = kzg
        self.width = width

    def build_tree(self, data_chunks):
        if not data_chunks:
            return None, []
            
        tree_levels = []
        current_layer_scalars = list(data_chunks)
        
        while len(current_layer_scalars) % self.width != 0:
            current_layer_scalars.append(0)
            
        tree_levels.append(current_layer_scalars)
        
        while len(current_layer_scalars) > 1:
            next_layer_scalars = []
            
            for i in range(0, len(current_layer_scalars), self.width):
                block = current_layer_scalars[i:i+self.width]
                x_vals = list(range(len(block)))
                poly = lagrange_interpolate(x_vals, block)
                C = self.kzg.commit(poly)
                next_layer_scalars.append(hash_commitment(C))
                
            if len(next_layer_scalars) > 1:
                while len(next_layer_scalars) % self.width != 0:
                    next_layer_scalars.append(0)
                    
            tree_levels.append(next_layer_scalars)
            current_layer_scalars = next_layer_scalars
            
        if len(tree_levels) > 1:
            root_block = tree_levels[-2]
            x_vals = list(range(len(root_block)))
            root_poly = lagrange_interpolate(x_vals, root_block)
            root_commitment = self.kzg.commit(root_poly)
        else:
            x_vals = list(range(len(tree_levels[0])))
            root_poly = lagrange_interpolate(x_vals, tree_levels[0])
            root_commitment = self.kzg.commit(root_poly)
            
        return root_commitment, tree_levels

    def prove_path(self, tree_levels, global_index):
        path = []
        curr_idx = global_index
        depth = len(tree_levels) - 1 if len(tree_levels) > 1 else 1
        
        for level in range(depth):
            layer_scalars = tree_levels[level]
            block_idx = curr_idx // self.width
            z = curr_idx % self.width
            start = block_idx * self.width
            block = layer_scalars[start:start+self.width]
            
            x_vals = list(range(len(block)))
            poly = lagrange_interpolate(x_vals, block)
            y = block[z]
            C = self.kzg.commit(poly)
            pi, evaluated_y = self.kzg.generate_proof(poly, z)
            
            assert y == evaluated_y, f"Interpolation mismatched at {z}: {y} != {evaluated_y}"
            
            path.append({
                "level": level,
                "commitment": C,
                "z": z,
                "y": y,
                "proof": pi
            })
            curr_idx = block_idx
            
        return path

    def verify_path(self, path, root_commitment):
        depth = len(path)
        for i in range(depth):
            step = path[i]
            C = step['commitment']
            pi = step['proof']
            z = step['z']
            y = step['y']
            
            if i == depth - 1:
                if C != root_commitment:
                    print("Root mismatch:", C, root_commitment)
                    return False
            
            if i > 0:
                prev_C = path[i-1]['commitment']
                expected_hash = hash_commitment(prev_C)
                if y != expected_hash:
                    print(f"Hash link broken at level {i}:", y, expected_hash)
                    return False
            
            valid = self.kzg.verify(C, pi, z, y)
            if not valid:
                print(f"KZG Verify failed at level {i}")
                return False
                
        return True
