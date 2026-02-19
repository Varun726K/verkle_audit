import time
from DataOwner import DataOwner
from CloudProvider import CloudProvider
from EdgeNode import EdgeNode
from ContractInterface import ContractInterface
from kzg_core import KZG

def run_demo():
    print("\n" + "="*60)
    print("      PPD-CL-DIA: END-TO-END SYSTEM DEMO")
    print("="*60 + "\n")

    # --- Step 1: System Intialization ---
    print(">>> [Phase 1: Initialization]")
    print("(*) Blockchain: Initializing Auditor Smart Contract Interface...")
    # Initialize interface. If no local node, it defaults to SIMULATION.
    contract = ContractInterface(check_connection=True)
    print(f"    -> Mode: {contract.mode}")

    # Check for shared secret from deployment
    srs_secret = getattr(contract, "srs_secret", None)
    
    print("(*) KGC/Edge Node: Generating System Parameters (SRS)...")
    if srs_secret:
        print(f"    -> Loaded SRS Secret from existing deployment: {srs_secret}")
        edge_node = EdgeNode(kzg_instance=KZG(secret=srs_secret))
    else:
        print("    -> Generating NEW SRS (Mock Mode)")
        edge_node = EdgeNode() # This acts as our Trusted Setup source for the demo
    
    # IMPORTANT: Share the Trusted Setup with the Mock Blockchain for valid verification
    contract.set_simulation_kzg(edge_node.kzg)
    
    # Deploy the contract (Mock or Real)
    if contract.mode == "BLOCKCHAIN" and not contract.contract:
         # If connected but no contract loaded (shouldn't happen if initialized correctly)
         pass 
    
    contract_addr = contract.contract.address if contract.contract else contract.deploy()
    print(f"(*) Contract Deployed/Simulated at: {contract_addr}")
    
    # --- Step 2: Data Outsourcing ---
    print("\n>>> [Phase 2: Data Outsourcing]")
    demo_file = "demo_secret.txt"
    with open(demo_file, "w") as f:
        f.write("Confidential Cloud Data " * 20)
    
    # Data Owner is initialized with the edge node (shared SRS)
    do = DataOwner(edge_node=edge_node)
    
    print(f"(*) Data Owner: Preparing '{demo_file}'...")
    upload_pkg = do.prepare_upload(demo_file)
    root = upload_pkg["root"]
    chunks = upload_pkg["chunks"]
    file_id = b"DOC_001"
    
    print(f"(*) Data Owner: Generated Verkle Root: {root}")
    print(f"(*) Data Owner: Uploading Metadata to Blockchain...")
    contract.upload_metadata(file_id, root)
    
    print(f"(*) Data Owner: Uploading Encrypted Chunks to Cloud...")
    csp = CloudProvider()
    # Share params
    csp.load_kzg(edge_node.kzg) 
    # In real world, Cloud doesn't need "s" (secret), just SRS. 
    # Our simple KZG implementation bundles them, but logic holds.
    
    csp.store_file(file_id, chunks)
    # Get random indices from contract (mock or real)
    indices = contract.get_challenge(file_id)
    print(f"(*) Blockchain: Issued Challenge For Indices: {indices}")

    # --- Step 3: Auditing ---
    print("\n>>> [Phase 3: Integrity Auditing]")
    
    # 2. CSP Generates Proof
    print("(*) Cloud Provider: Generating KZG Proofs...")
    proofs = csp.respond_to_challenge(file_id, indices)
    
    # 3. Submit Proofs to Blockchain
    print("(*) Cloud Provider: Submitting Proofs to Blockchain...")
    
    all_passed = True
    for p in proofs:
        idx = p["z"]
        val = p["y"]
        pi = p["proof"]
        
        # Verify via contract
        print(f"    > Verifying Chunk {idx} with Value {val}...")
        result = contract.verify_proof(file_id, idx, val, pi)
        
        status = "PASSED" if result else "FAILED"
        print(f"    > Result: {status}")
        
        if not result:
            all_passed = False
            
    print("\n" + "="*60)
    if all_passed:
        print("      DEMO RESULT: SUCCESS (Data Integrity Verified)")
    else:
        print("      DEMO RESULT: FAILED (Tampering Detected)")
    print("="*60 + "\n")
    
    # Cleanup
    import os
    if os.path.exists(demo_file):
        os.remove(demo_file)

if __name__ == "__main__":
    try:
        run_demo()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"DEMO CRASHED: {e}")
