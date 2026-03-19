import json
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from web3 import Web3
from solcx import compile_standard, install_solc

def deploy_contract():
    ganache_url = "http://127.0.0.1:8545"
    web3 = Web3(Web3.HTTPProvider(ganache_url))
    
    if not web3.is_connected():
        print(f"Error: Could not connect to Blockchain at {ganache_url}")
        return

    print(f"Connected to Blockchain: {web3.client_version}")
    web3.eth.default_account = web3.eth.accounts[0]
    print(f"   Using Account: {web3.eth.default_account}")

    print("Compiling Auditor.sol...")
    solc_version = '0.8.0'
    install_solc(solc_version)

    with open(os.path.join("Blockchain", "Auditor.sol"), "r") as f:
        contract_source = f.read()

    compiled_sol = compile_standard(
        {
            "language": "Solidity",
            "sources": {"Auditor.sol": {"content": contract_source}},
            "settings": {
                "optimizer": {
                    "enabled": True,
                    "runs": 200
                },
                "outputSelection": {
                    "*": {
                        "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                    }
                }
            },
        },
        solc_version=solc_version,
    )

    bytecode = compiled_sol["contracts"]["Auditor.sol"]["Auditor"]["evm"]["bytecode"]["object"]
    abi = compiled_sol["contracts"]["Auditor.sol"]["Auditor"]["abi"]

    from Initializer.kzg_core import KZG
    from py_ecc.optimized_bn128 import normalize
    print("Generating Trusted Setup for Contract...")
    kzg = KZG(degree=1)
    
    def split_g2(pt):
        pt = normalize(pt)
        x, y = pt[0], pt[1]
        return (x.coeffs[0], x.coeffs[1], y.coeffs[0], y.coeffs[1])

    g2_gen = kzg.SRS_2[0]
    g2_alpha = kzg.SRS_2[1]
    
    g2_gen_coords = split_g2(g2_gen)
    g2_alpha_coords = split_g2(g2_alpha)
    
    print(f"   G2 Gen: {g2_gen_coords}")
    print(f"   G2 Alpha: {g2_alpha_coords}")

    print("Deploying Contract...")
    Auditor = web3.eth.contract(abi=abi, bytecode=bytecode)
    
    args = list(g2_gen_coords) + list(g2_alpha_coords)
    tx_hash = Auditor.constructor(*args).transact()
    
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress
    print(f"Contract Deployed at: {contract_address}")

    deployment_data = {
        "address": contract_address,
        "abi": abi,
        "srs_secret": kzg.s
    }
    
    with open(os.path.join("Blockchain", "contract_data.json"), "w") as f:
        json.dump(deployment_data, f, indent=4)
    print("Saved contract address, ABI, and SRS secret to 'contract_data.json'")

if __name__ == "__main__":
    try:
        deploy_contract()
    except Exception as e:
        if hasattr(e, 'stdout_data'):
            try:
                err_dict = json.loads(e.stdout_data)
                print(f"\nSOLC ERROR:\n{err_dict['errors'][0]['formattedMessage']}")
            except:
                print(f"Deployment Failed with Solc Error:\n{e.stdout_data}")
        else:
            import traceback
            traceback.print_exc()
            print(f"Deployment Failed: {e}")
