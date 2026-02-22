import json
import random
from web3 import Web3
from Initializer.kzg_core import KZG
from EdgeNode.EdgeNode import EdgeNode

class ContractInterface:
    def __init__(self, node_url="http://127.0.0.1:8545", check_connection=True):
        self.web3 = Web3(Web3.HTTPProvider(node_url))
        self.mode = "SIMULATION"
        self.contract = None
        self.contract_address = None
        
        if check_connection and self.web3.is_connected():
            print(f"[ContractInterface] Connected to Blockchain at {node_url}")
            self.mode = "BLOCKCHAIN"
            try:
                with open("Blockchain/contract_data.json") as f:
                    data = json.load(f)
                    self.contract_address = data["address"]
                    self.abi = data["abi"]
                    self.srs_secret = data.get("srs_secret")
                    self.contract = self.web3.eth.contract(address=self.contract_address, abi=self.abi)
                    self.web3.eth.default_account = self.web3.eth.accounts[0]
            except FileNotFoundError:
                print("[ContractInterface] 'contract_data.json' not found. Please run 'deploy.py' first.")
                self.mode = "SIMULATION"
                self.mock_chain = MockBlockchain()
        else:
            print("[ContractInterface] No Blockchain Node detected. Switching to SIMULATION mode.")
            self.mock_chain = MockBlockchain()

    def set_simulation_kzg(self, kzg_instance):
        if self.mode != "BLOCKCHAIN":
             self.mock_chain.verifier = kzg_instance

    def deploy(self, abi=None, bytecode=None):
        if self.mode == "BLOCKCHAIN":
            return self.contract_address
        else:
            print("[ContractInterface] Deploying Mock Auditor Contract...")
            return self.mock_chain.deploy()

    def upload_metadata(self, file_id, root):
        """DO uploads the file metadata (Root)"""
        if self.mode == "BLOCKCHAIN":
            root_x = int(root[0])
            root_y = int(root[1])
            
            if isinstance(file_id, str):
                file_id = file_id.encode('utf-8')
            if len(file_id) < 32:
                file_id = file_id.ljust(32, b'\0')
            
            file_size = 1024 
            
            tx_hash = self.contract.functions.uploadMetadata(file_id, root_x, root_y, file_size).transact()
            self.web3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"[Blockchain] Metadata uploaded for {file_id.rstrip(b'0')}")
            return True
        else:
            return self.mock_chain.upload_metadata(file_id, root)

    def verify_proof(self, file_id, challenge_index, y, proof):
        """Verify a KZG Proof submitted by CSP"""
        if self.mode == "BLOCKCHAIN":
             proof_x = int(proof[0])
             proof_y = int(proof[1])
             
             if isinstance(file_id, str):
                file_id = file_id.encode('utf-8')
             if len(file_id) < 32:
                file_id = file_id.ljust(32, b'\0')

             try:
                 result = self.contract.functions.verifyProof(file_id, proof_x, proof_y, challenge_index, y).call()
                 return result
             except Exception as e:
                 print(f"[Blockchain] Verification Error: {e}")
                 return False
        else:
            return self.mock_chain.verify_proof(file_id, challenge_index, y, proof)
            
    def get_challenge(self, file_id):
         """Get random challenge indices"""
         if isinstance(file_id, str):
            file_id = file_id.encode('utf-8')

         if self.mode == "BLOCKCHAIN":
             return [random.randint(0, 100) for _ in range(3)]
         else:
             return self.mock_chain.get_challenge(file_id)

class MockBlockchain:
    def __init__(self, kzg_instance=None):
        self.files = {}
        if kzg_instance:
            self.verifier = kzg_instance
        else:
            print("[MockChain] Warning: No KZG instance provided. Basic verification might fail if SRS mismatches.")
            self.verifier = EdgeNode().kzg 

    def deploy(self):
        print("[MockChain] Auditor Contract Deployed at 0xMOCK...")
        return "0xMOCK"

    def upload_metadata(self, file_id, root):
        if file_id in self.files:
            raise Exception("File ID already exists")
        self.files[file_id] = root
        print(f"[MockChain] Event: FileUploaded(ID={file_id}, Root={root})")
        return True

    def get_challenge(self, file_id):
        return [random.randint(0, 100) for _ in range(3)]

    def verify_proof(self, file_id, index, y, proof):
        if file_id not in self.files:
            print("[MockChain] Error: File not found.")
            return False
        
        root = self.files[file_id]
        is_valid = self.verifier.verify(root, proof, index, y)
        status = "Success" if is_valid else "Failure"
        print(f"[MockChain] Event: AuditResult(ID={file_id}, Chunk={index}, Result={status})")
        return is_valid
