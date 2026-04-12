import hashlib

def hash_data(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()

class MerkleTree:
    def __init__(self):
        pass

    def build_tree(self, data_chunks):
        if not data_chunks:
            return b'\x00'*32, []
        
        # Base layer: hash each chunk
        current_layer = [hash_data(str(chunk).encode('utf-8')) if not isinstance(chunk, bytes) else hash_data(chunk) for chunk in data_chunks]
        
        tree_levels = [current_layer]
        
        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                if i + 1 < len(current_layer):
                    right = current_layer[i+1]
                else:
                    right = left # pad odd nodes by duplicating
                next_layer.append(hash_node(left, right))
            
            tree_levels.append(next_layer)
            current_layer = next_layer
            
        root = tree_levels[-1][0]
        return root, tree_levels

    def prove_path(self, tree_levels, global_index):
        siblings = []
        flags = []
        curr_idx = global_index
        
        depth = len(tree_levels) - 1
        for level in range(depth):
            layer = tree_levels[level]
            
            if curr_idx % 2 == 0:
                is_left = True
                sibling_idx = curr_idx + 1
            else:
                is_left = False
                sibling_idx = curr_idx - 1
                
            if sibling_idx < len(layer):
                siblings.append(layer[sibling_idx])
            else:
                siblings.append(layer[curr_idx])
                
            flags.append(is_left)
            curr_idx = curr_idx // 2
            
        return siblings, flags

    def verify_path(self, root, leaf, siblings, flags):
        current_hash = hash_data(str(leaf).encode('utf-8')) if not isinstance(leaf, bytes) else hash_data(leaf)
        
        for i in range(len(siblings)):
            sibling = siblings[i]
            is_left = flags[i]
            if is_left:
                current_hash = hash_node(current_hash, sibling)
            else:
                current_hash = hash_node(sibling, current_hash)
                
        return current_hash == root
