from Initializer.kzg_core import KZG

class EdgeNode:
    def __init__(self, kzg_instance=None):
        """
        In a real scenario, Edge Node is a powerful server.
        It has the public parameters (SRS).
        """
        # For simulation, we share the KZG instance (SRS)
        if kzg_instance:
            self.kzg = kzg_instance
        else:
            self.kzg = KZG(degree=1024)

    def generate_tags_and_root(self, chunks):
        """
        Receives blinded/encrypted blocks from Data Owner.
        Computes the Vector Commitment (Verkle Root).
        """
        print("[Edge Node] Received chunks. Computing Verkle Root...")
        root = self.kzg.commit(chunks)
        
        # In the full paper, 'Tags' are individual authenticators per block.
        # But efficiently, the KZG commitment *is* the root authenticator for the polynomial.
        # We return the Root.
        return root

    def initiate_audit(self, file_id, challenge_indices):
        """
        The Edge Node can also act as the 'Auditor' or trigger the Smart Contract.
        This method constructs the Challenge.
        """
        # Challenge = (FileID, BlockIndices, RandomValues)
        # For KZG, the challenge is evaluating the polynomial at these indices.
        return {
            "file_id": file_id,
            "indices": challenge_indices
        }
