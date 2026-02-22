import os
from DataOwner.DataOwner import DataOwner
from CloudProvider.CloudProvider import CloudProvider
from EdgeNode.EdgeNode import EdgeNode

def test_system_flow():
    print("=== PPD-CL-DIA System Flow Verification ===")
    
    print("[1] Initializing Edge Node (KGC/Helper)...")
    edge_node = EdgeNode()
    
    print("[2] Initializing Data Owner (linked to Edge Node)...")
    do = DataOwner(edge_node=edge_node)
    
    print("[3] Initializing Cloud Provider...")
    csp = CloudProvider()
    csp.load_kzg(edge_node.kzg)
    
    print("\n[4] Data Owner: Processing File...")
    test_filename = "system_test_file.txt"
    with open(test_filename, "w") as f:
        f.write("A" * 100 + "B" * 100 + "C" * 50)
    
    upload_data = do.prepare_upload(test_filename)
    root = upload_data["root"]
    chunks = upload_data["chunks"]
    print(f"    -> Root Generated: {root}")
    print(f"    -> Total Chunks: {len(chunks)}")
    
    print("\n[5] Cloud Provider: Storing File...")
    file_id = b"FILE_001"
    csp.store_file(file_id, chunks)
    
    print("\n[6] Auditor: Challenging Random Blocks...")
    challenge_indices = [0, 2, 5]
    print(f"    -> Challenge Indices: {challenge_indices}")
    
    proofs = csp.respond_to_challenge(file_id, challenge_indices)
    
    print("\n[7] Auditor: Verifying Proofs...")
    
    all_valid = True
    for p in proofs:
        z = p["z"]
        y = p["y"]
        proof_pi = p["proof"]
        
        is_valid = edge_node.kzg.verify(root, proof_pi, z, y)
        print(f"    -> Index {z}: Value {y} | Valid? {is_valid}")
        
        if not is_valid:
            all_valid = False

    if all_valid:
        print("\nSYSTEM TEST PASSED: All proofs verified.")
    else:
        print("\nSYSTEM TEST FAILED: Verification failed.")

    if os.path.exists(test_filename):
        os.remove(test_filename)

if __name__ == "__main__":
    try:
        test_system_flow()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"CRITICAL SYSTEM FAILURE: {e}")
