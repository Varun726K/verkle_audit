from DataOwner import DataOwner
from CloudProvider import CloudProvider
from EdgeNode import EdgeNode
import os

def test_system_flow():
    print("=== PPD-CL-DIA System Flow Verification ===")
    
    # 1. Initialize Components
    # In reality, KGC generates params. Here, Edge Node initializes KZG 
    # and we share that instance.
    print("[1] Initializing Edge Node (KGC/Helper)...")
    edge_node = EdgeNode() # Generates SRS internally
    
    print("[2] Initializing Data Owner (linked to Edge Node)...")
    do = DataOwner(edge_node=edge_node)
    
    print("[3] Initializing Cloud Provider...")
    csp = CloudProvider()
    # Share the public parameters (SRS) from EdgeNode's KZG instance
    csp.load_kzg(edge_node.kzg)
    
    # 2. Prepare Data (Data Owner + Edge Node)
    print("\n[4] Data Owner: Processing File...")
    test_filename = "system_test_file.txt"
    with open(test_filename, "w") as f:
        f.write("A" * 100 + "B" * 100 + "C" * 50) # 250 bytes
    
    upload_data = do.prepare_upload(test_filename)
    root = upload_data["root"]
    chunks = upload_data["chunks"]
    print(f"    -> Root Generated: {root}")
    print(f"    -> Total Chunks: {len(chunks)}")
    
    # 3. Upload to Cloud (Cloud Provider)
    print("\n[5] Cloud Provider: Storing File...")
    file_id = b"FILE_001"
    csp.store_file(file_id, chunks)
    
    # 4. Audit Challenge (Simulated Auditor/Edge Node)
    print("\n[6] Auditor: Challenging Random Blocks...")
    # Challenge indices 0, 2, and 5
    challenge_indices = [0, 2, 5]
    print(f"    -> Challenge Indices: {challenge_indices}")
    
    proofs = csp.respond_to_challenge(file_id, challenge_indices)
    
    # 5. Verify Proofs (Simulated Auditor)
    print("\n[7] Auditor: Verifying Proofs...")
    
    all_valid = True
    for i, p in enumerate(proofs):
        z = p["z"]
        y = p["y"]
        proof_pi = p["proof"]
        
        # Verify: e(pi, [s-z]_2) = e(C - [y]_1, [1]_2)
        # Using the verify function from EdgeNode's kzg instance (acting as Auditor)
        is_valid =  edge_node.kzg.verify(root, proof_pi, z, y)
        print(f"    -> Index {z}: Value {y} | Valid? {is_valid}")
        
        if not is_valid:
            all_valid = False

    if all_valid:
        print("\n✅ SYSTEM TEST PASSED: All proofs verified.")
    else:
        print("\n❌ SYSTEM TEST FAILED: Verification failed.")

    # Cleanup
    if os.path.exists(test_filename):
        os.remove(test_filename)

if __name__ == "__main__":
    try:
        test_system_flow()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"CRITICAL SYSTEM FAILURE: {e}")
