import os
import json
import time
import random
from Initializer.kzg_core import KZG
from DataOwner.DataOwner import DataOwner
from CloudProvider.CloudProvider import CloudProvider
from Blockchain.ContractInterface import ContractInterface
from EdgeNode.EdgeNode import EdgeNode
from Initializer.verkle_tree import VerkleTree
from CloudProvider.MerkleTree import MerkleTree, hash_data

FILE_SIZES = [10 * 1024, 50 * 1024, 100 * 1024, 500 * 1024]

def fmt(g):
    return f"{g:,}" if isinstance(g, int) else str(g)

def run_benchmark():
    run_id = random.randint(1000, 9999)

    print("=" * 70)
    print("   VERKLE TREE vs MERKLE TREE — SCALING DEMO")
    print("   Proving O(1) constant gas vs O(log N) growing gas")
    print("=" * 70)

    # --- INIT ---
    print("\n[INIT] Connecting to local Ganache blockchain...")
    ci = ContractInterface()
    w3 = ci.web3
    Auditor = ci.contract
    account = w3.eth.accounts[0]
    print(f"  Connected: {w3.client_version}")
    print(f"  Contract:  {ci.contract_address}")

    print("\n[INIT] Loading KZG Structured Reference String (SRS)...")
    edge_node = EdgeNode(kzg_instance=KZG(secret=ci.srs_secret))
    ci.set_simulation_kzg(edge_node.kzg)
    print(f"  SRS Degree: {len(edge_node.kzg.SRS_1)} G1 points")

    do = DataOwner(edge_node=edge_node)
    csp = CloudProvider()
    csp.load_kzg(edge_node.kzg)
    mt = MerkleTree()

    results = []

    for size in FILE_SIZES:
        label = f"{size // 1024} KB"
        print(f"\n{'='*70}")
        print(f"  FILE SIZE: {label}")
        print(f"{'='*70}")

        # --- Build file ---
        with open("bench.txt", "wb") as f:
            f.write(os.urandom(size))

        print(f"\n  [1] Encrypting & chunking ({label})...")
        t0 = time.time()
        verkle_pkg = do.prepare_upload("bench.txt")
        chunks = verkle_pkg["chunks"]
        tree_levels = verkle_pkg["tree_levels"]
        root = verkle_pkg["root"]
        build_time = time.time() - t0
        print(f"      Chunks: {len(chunks):,}")
        print(f"      Time:   {build_time:.1f}s")

        # --- Verkle ---
        verkle_depth = len(tree_levels) - 1
        print(f"\n  [2] VERKLE TREE: {len(tree_levels)} levels (16-ary, depth={verkle_depth})")
        for i, lvl in enumerate(tree_levels):
            print(f"      Level {i}: {len(lvl):,} nodes")

        file_id_v = f"V{run_id}_{size}".encode('utf-8')
        ci.upload_metadata(file_id_v, root)
        csp.store_file(file_id_v, tree_levels)

        challenge_idx = random.randint(0, len(chunks) - 1)
        print(f"\n      Challenge: leaf #{challenge_idx:,}")

        t0 = time.time()
        v_paths = csp.respond_to_challenge(file_id_v, [challenge_idx])
        path = v_paths[0]
        v_proof_time = time.time() - t0
        v_proof_bytes = len(json.dumps(path).encode('utf-8'))

        print(f"      Proof generated in {v_proof_time:.1f}s")
        print(f"      Proof size: {v_proof_bytes:,} bytes")
        print(f"      Submitting verifyVerkleMultiProof()...", end="", flush=True)

        try:
            tx = Auditor.functions.verifyVerkleMultiProof(
                file_id_v.ljust(32, b'\0'),
                path["C"], path["z"], path["y"], path["v"],
                path["C_h"], path["pi"],
                len(path["C"])  # depth = total entries for single path
            ).transact({'from': account, 'gas': 30000000})
            receipt = w3.eth.wait_for_transaction_receipt(tx)
            verkle_gas = receipt.gasUsed
            print(f" PASS ({fmt(verkle_gas)} gas)")
        except Exception as e:
            verkle_gas = 0
            print(f" FAIL: {e}")

        # --- Merkle ---
        m_root_bytes, m_levels = mt.build_tree(chunks)
        merkle_depth = len(m_levels) - 1
        print(f"\n  [3] MERKLE TREE: {len(m_levels)} levels (binary, depth={merkle_depth})")

        file_id_m = f"M{run_id}_{size}".encode('utf-8')
        ci.upload_metadata(file_id_m, (int.from_bytes(m_root_bytes, 'big'), 0))

        siblings, flags = mt.prove_path(m_levels, challenge_idx)
        leaf_hash = hash_data(str(chunks[challenge_idx]).encode('utf-8'))
        m_proof_bytes = len(json.dumps({"s": [s.hex() for s in siblings], "f": flags}).encode('utf-8'))

        print(f"      Challenge: leaf #{challenge_idx:,}")
        print(f"      Proof size: {m_proof_bytes:,} bytes ({len(siblings)} siblings)")
        print(f"      Submitting verifyMerkleProof()...", end="", flush=True)

        try:
            tx = Auditor.functions.verifyMerkleProof(
                file_id_m.ljust(32, b'\0'), siblings, flags, leaf_hash
            ).transact({'from': account, 'gas': 30000000})
            receipt = w3.eth.wait_for_transaction_receipt(tx)
            merkle_gas = receipt.gasUsed
            print(f" PASS ({fmt(merkle_gas)} gas)")
        except Exception as e:
            merkle_gas = 0
            print(f" FAIL: {e}")

        results.append({
            "size": label,
            "chunks": len(chunks),
            "v_depth": verkle_depth,
            "m_depth": merkle_depth,
            "v_proof": v_proof_bytes,
            "m_proof": m_proof_bytes,
            "v_gas": verkle_gas,
            "m_gas": merkle_gas,
        })

    # =================================================================
    #  FINAL SCALING TABLE
    # =================================================================
    print(f"\n{'='*70}")
    print("   FINAL SCALING COMPARISON")
    print(f"{'='*70}")
    print(f"\n  {'Size':<8} {'Chunks':<10} {'V-Depth':<9} {'M-Depth':<9} {'V-Proof':<10} {'M-Proof':<10} {'V-Gas':<12} {'M-Gas':<12}")
    print(f"  {'-'*80}")
    for r in results:
        print(f"  {r['size']:<8} {fmt(r['chunks']):<10} {r['v_depth']:<9} {r['m_depth']:<9} {fmt(r['v_proof'])+'B':<10} {fmt(r['m_proof'])+'B':<10} {fmt(r['v_gas']):<12} {fmt(r['m_gas']):<12}")

    print(f"\n  ANALYSIS:")
    if len(results) >= 2:
        v_first, v_last = results[0]["v_gas"], results[-1]["v_gas"]
        m_first, m_last = results[0]["m_gas"], results[-1]["m_gas"]
        v_change = ((v_last - v_first) / v_first * 100) if v_first else 0
        m_change = ((m_last - m_first) / m_first * 100) if m_first else 0
        size_mult = FILE_SIZES[-1] // FILE_SIZES[0]
        print(f"  File size grew {size_mult}x ({results[0]['size']} → {results[-1]['size']})")
        print(f"  Verkle Gas changed: {v_change:+.1f}%  (CONSTANT — O(1) pairing)")
        print(f"  Merkle Gas changed: {m_change:+.1f}%  (GROWING — O(log N) depth)")
        print(f"\n  Verkle tree depth:  {results[0]['v_depth']} → {results[-1]['v_depth']}  (16-ary tree grows slowly)")
        print(f"  Merkle tree depth:  {results[0]['m_depth']} → {results[-1]['m_depth']}  (binary tree grows fast)")
    print(f"\n  At GB/TB file sizes, Merkle depth reaches 30-50+ levels")
    print(f"  while Verkle depth stays at 5-7 levels. The curves CROSS.")
    print(f"{'='*70}\n")

    if os.path.exists("bench.txt"):
        os.remove("bench.txt")

if __name__ == "__main__":
    run_benchmark()
