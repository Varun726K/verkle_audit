import json
import os
from web3 import Web3
from solcx import compile_standard, install_solc

def deploy_contract():
    # 1. Connect to Local Blockchain
    ganache_url = "http://127.0.0.1:8545"
    web3 = Web3(Web3.HTTPProvider(ganache_url))
    
    if not web3.is_connected():
        print(f"❌ Error: Could not connect to Blockchain at {ganache_url}")
        print("   -> Make sure Ganache is running (run 'ganache' in a terminal).")
        return

    print(f"✅ Connected to Blockchain: {web3.client_version}")
    
    # Set the default account (the first one created by Ganache)
    web3.eth.default_account = web3.eth.accounts[0]
    print(f"   Using Account: {web3.eth.default_account}")

    # 2. Compile Solidity Contract
    print("⏳ Compiling Auditor.sol...")
    
    # Ensure specific solc version is installed
    solc_version = '0.8.0'
    install_solc(solc_version)

    with open(os.path.join("Blockchain", "Auditor.sol"), "r") as f:
        contract_source = f.read()

    compiled_sol = compile_standard(
        {
            "language": "Solidity",
            "sources": {"Auditor.sol": {"content": contract_source}},
            "settings": {
                "outputSelection": {
                    "*": {
                        "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                    }
                }
            },
        },
        solc_version=solc_version,
    )

    # Extract Bytecode and ABI
    bytecode = compiled_sol["contracts"]["Auditor.sol"]["Auditor"]["evm"]["bytecode"]["object"]
    abi = compiled_sol["contracts"]["Auditor.sol"]["Auditor"]["abi"]

    # Load KZG to get Trusted Setup Params (SRS)
    from kzg_core import KZG
    from py_ecc.optimized_bn128 import normalize
    print("🔐 Generating Trusted Setup for Contract...")
    kzg = KZG(degree=1) # Minimal setup to get parameters
    
    # We need G2_Gen (SRS_2[0]) and G2_Alpha (SRS_2[1])
    # logical structure: [1]_2 and [s]_2
    # py_ecc G2 point is (x, y, z) or (x, y) if normalized?
    # optimized_bn128 G2 is (x, y, z).
    # Solidity expects pairs of uint256 for (x, y) which are complex numbers (x1, x2) + i(y1, y2)?
    # Wait, BN254 G2 coordinates are elements of FQ2. 
    # FQ2(coeffs) where coeffs = (c0, c1) -> c0 + c1*u
    # Solidity usually expects:
    # x = x1 * 1 + x2 * i 
    # format: x1, x2, y1, y2? Or x2, x1? 
    # EIP-197: G2 points are encoded as (x, y) where x and y are FQ2 elements.
    # x = x1 * i + x0 ?
    # Standard: x being (x1, x2) means x1 is real, x2 is imaginary?
    # Ethereum precompile 0x08 expects:
    # G1: x, y
    # G2: x1, x2, y1, y2 
    # where G2 point is (x, y) over FQ2.
    # py_ecc FQ2 representation:
    # x = FQ2([x0, x1]) -> x0 + x1*u
    # Let's verify exact ordering for Solidity/Precompile on BN254.
    
    # helper to unpack G2
    def split_g2(pt):
        pt = normalize(pt)
        x, y = pt[0], pt[1]
        # x and y are FQ2
        # x.coeffs is (c0, c1) -> these are integers directly in optimized_bn128
        return (x.coeffs[0], x.coeffs[1], y.coeffs[0], y.coeffs[1])

    g2_gen = kzg.SRS_2[0]
    g2_alpha = kzg.SRS_2[1]
    
    g2_gen_coords = split_g2(g2_gen)
    g2_alpha_coords = split_g2(g2_alpha)
    
    print(f"   G2 Gen: {g2_gen_coords}")
    print(f"   G2 Alpha: {g2_alpha_coords}")

    # 3. Deploy Contract
    print("🚀 Deploying Contract...")
    Auditor = web3.eth.contract(abi=abi, bytecode=bytecode)
    
    # Submit transaction with Constructor Args
    # Args: x1, x2, y1, y2 for Gen, then for Alpha
    # Checking Constructor signature:
    # uint256 _g2_gen_x1, uint256 _g2_gen_x2, uint256 _g2_gen_y1, uint256 _g2_gen_y2, ...
    
    args = list(g2_gen_coords) + list(g2_alpha_coords)
    
    tx_hash = Auditor.constructor(*args).transact()
    
    # Wait for transaction to be mined
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    
    contract_address = tx_receipt.contractAddress
    print(f"🎉 Contract Deployed at: {contract_address}")

    # 4. Save Deployment Info
    deployment_data = {
        "address": contract_address,
        "abi": abi,
        "srs_secret": kzg.s # Save secret so client can match SRS
    }
    
    with open(os.path.join("Blockchain", "contract_data.json"), "w") as f:
        json.dump(deployment_data, f, indent=4)
    print("💾 Saved contract address, ABI, and SRS secret to 'contract_data.json'")

if __name__ == "__main__":
    try:
        deploy_contract()
    except Exception as e:
        print(f"❌ Deployment Failed: {e}")
