import sys
import os
import random
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from DataOwner.DataOwner import DataOwner
from CloudProvider.CloudProvider import CloudProvider
from EdgeNode.EdgeNode import EdgeNode
from Blockchain.ContractInterface import ContractInterface
from Initializer.kzg_core import KZG

def run_demo():
    print("\n>>> Phase 1: Initialization")
    contract = ContractInterface(check_connection=True)
    srs_secret = getattr(contract, "srs_secret", None)
    edge_node = EdgeNode(kzg_instance=KZG(secret=srs_secret)) if srs_secret else EdgeNode()
    contract.set_simulation_kzg(edge_node.kzg)
    contract_addr = contract.deploy()
    input("\n Contract initialized! Press Enter to proceed to Phase 2 (Data Outsourcing)...")
    
    print("\n>>> Phase 2: Data Outsourcing")
    demo_file = "demo_secret.txt"
    with open(demo_file, "w") as f:
        f.write("Confidential Cloud Data " * 20)
    
    do = DataOwner(edge_node=edge_node)
    upload_pkg = do.prepare_upload(demo_file)
    file_id = f"DOC_{random.randint(1000, 9999)}".encode('utf-8')
    contract.upload_metadata(file_id, upload_pkg["root"])
    
    csp = CloudProvider()
    csp.load_kzg(edge_node.kzg) 
    csp.store_file(file_id, upload_pkg["tree_levels"])
    
    input("\n Data Owner upload complete! Press Enter to proceed to Phase 3 (Integrity Challenge)...")

    indices = contract.get_challenge(file_id)
    print(f"\n>>> Phase 3: Integrity Auditing (Challenges: {indices})")
    paths = csp.respond_to_challenge(file_id, indices)
    
    tamper_cmd = input("\n Press Enter to verify normally, type 'TAMPER' to corrupt a proof: ").strip().upper()
    if tamper_cmd == 'TAMPER':
        paths[0][0]['y'] = (paths[0][0]['y'] + 1) % int(KZG(degree=1).s) # just corrupt something
    
    all_passed = True
    for path in paths:
        idx = path[0]["z"]  # The leaf index
        val = path[0]["y"]  # The leaf value
        print(f"    > Verifying Path for Chunk {idx} with Value {val}...")
        result = contract.verify_proof(file_id, path)
        print(f"    > Result: {'PASSED' if result else 'FAILED'}")
        if not result:
            all_passed = False

    print("\n" + "="*60)
    print("      DEMO RESULT: SUCCESS" if all_passed else "      DEMO RESULT: FAILED (Tampering Detected)")
    print("="*60 + "\n")

if __name__ == "__main__":
    try:
        run_demo()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"CRASHED: {e}")
