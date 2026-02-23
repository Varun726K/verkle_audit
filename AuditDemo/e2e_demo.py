import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import time
from DataOwner.DataOwner import DataOwner
from CloudProvider.CloudProvider import CloudProvider
from EdgeNode.EdgeNode import EdgeNode
from Blockchain.ContractInterface import ContractInterface
from Initializer.kzg_core import KZG

def run_demo():
    print("\n" + "="*60)
    print("      PPD-CL-DIA: END-TO-END SYSTEM DEMO")
    print("="*60 + "\n")

    print(">>> [Phase 1: Initialization]")
    print("(*) Blockchain: Initializing Auditor Smart Contract Interface...")
    contract = ContractInterface(check_connection=True)
    print(f"    -> Mode: {contract.mode}")

    srs_secret = getattr(contract, "srs_secret", None)
    
    print("(*) KGC/Edge Node: Generating System Parameters (SRS)...")
    if srs_secret:
        print(f"    -> Loaded SRS Secret from existing deployment: {srs_secret}")
        edge_node = EdgeNode(kzg_instance=KZG(secret=srs_secret))
    else:
        print("    -> Generating NEW SRS (Mock Mode)")
        edge_node = EdgeNode()
    
    contract.set_simulation_kzg(edge_node.kzg)
    
    if contract.mode == "BLOCKCHAIN" and not contract.contract:
         pass 
    
    contract_addr = contract.deploy()
    print(f"(*) Contract Deployed/Simulated at: {contract_addr}")
    
    input("\n Contract initialized! Press Enter to proceed to Phase 2 (Data Outsourcing)...")
    
    print("\n>>> [Phase 2: Data Outsourcing]")
    demo_file = "demo_secret.txt"
    with open(demo_file, "w") as f:
        f.write("Confidential Cloud Data " * 20)
    
    do = DataOwner(edge_node=edge_node)
    
    print(f"(*) Data Owner: Preparing '{demo_file}'...")
    upload_pkg = do.prepare_upload(demo_file)
    root = upload_pkg["root"]
    chunks = upload_pkg["chunks"]
    import random
    file_id = f"DOC_{random.randint(1000, 9999)}".encode('utf-8')
    
    print(f"(*) Data Owner: Generated Verkle Root: {root}")
    print(f"(*) Data Owner: Uploading Metadata to Blockchain...")
    contract.upload_metadata(file_id, root)
    
    print(f"(*) Data Owner: Uploading Encrypted Chunks to Cloud...")
    csp = CloudProvider()
    csp.load_kzg(edge_node.kzg) 
    csp.store_file(file_id, chunks)
    
    input("\n Data Owner upload complete! Press Enter to proceed to Phase 3 (Integrity Challenge)...")

    indices = contract.get_challenge(file_id)
    print(f"(*) Blockchain: Issued Challenge For Indices: {indices}")

    print("\n>>> [Phase 3: Integrity Auditing]")
    
    print("(*) Cloud Provider: Generating KZG Proofs...")
    proofs = csp.respond_to_challenge(file_id, indices)
    
    tamper_cmd = input("\n Press Enter to verify normally, or type 'TAMPER' to corrupt a proof: ").strip().upper()
    if tamper_cmd == 'TAMPER':
        print("\n[!!!] MALICIOUS ACTOR TAMPERING WITH PROOF [!!!]")
        print(f"    -> Corrupting polynomial evaluation for chunk {proofs[0]['z']}...")
        proofs[0]['y'] = proofs[0]['y'] + 1
    
    print("\n(*) Cloud Provider: Submitting Proofs to Blockchain...")
    
    all_passed = True
    for p in proofs:
        idx = p["z"]
        val = p["y"]
        pi = p["proof"]
        
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
    
if __name__ == "__main__":
    try:
        run_demo()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"DEMO CRASHED: {e}")
