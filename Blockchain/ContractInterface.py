import json
import random
from web3 import Web3
from Initializer.kzg_core import KZG
from EdgeNode.EdgeNode import EdgeNode
from Initializer.verkle_tree import VerkleTree

class ContractInterface:
    def __init__(self, node_url="http://127.0.0.1:8545", check_connection=True):
        self.web3 = Web3(Web3.HTTPProvider(node_url))
        self.mode = "SIMULATION"
        self.contract = None
        self.contract_address = None
        if check_connection and self.web3.is_connected():
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
                self.mode = "SIMULATION"
                self.mock_chain = MockBlockchain()
        else:
            self.mock_chain = MockBlockchain()

    def set_simulation_kzg(self, kzg_instance):
        if self.mode != "BLOCKCHAIN":
             self.mock_chain.verifier = kzg_instance

    def deploy(self, abi=None, bytecode=None):
        if self.mode == "BLOCKCHAIN":
            return self.contract_address
        return self.mock_chain.deploy()

    def upload_metadata(self, file_id, root):
        if self.mode == "BLOCKCHAIN":
            root_x, root_y = int(root[0]), int(root[1])
            if isinstance(file_id, str): file_id = file_id.encode('utf-8')
            if len(file_id) < 32: file_id = file_id.ljust(32, b'\0')
            tx_hash = self.contract.functions.uploadMetadata(file_id, root_x, root_y, 1024).transact()
            self.web3.eth.wait_for_transaction_receipt(tx_hash)
            return True
        return self.mock_chain.upload_metadata(file_id, root)

    def verify_proof(self, file_id, bgm_payload):
        if self.mode == "BLOCKCHAIN":
             if isinstance(file_id, str): file_id = file_id.encode('utf-8')
             if len(file_id) < 32: file_id = file_id.ljust(32, b'\0')
             
             C_list = bgm_payload["C"]
             z_arr = bgm_payload["z"]
             y_arr = bgm_payload["y"]
             v_arr = bgm_payload["v"]
             v_h   = bgm_payload["v_h"]
             C_h = bgm_payload["C_h"]
             pi = bgm_payload["pi"]
             depth = bgm_payload.get("depth", len(C_list))
             
             try:
                 tx_hash = self.contract.functions.verifyVerkleMultiProof(
                     file_id, C_list, z_arr, y_arr, v_arr, v_h, C_h, pi, depth
                 ).transact({'gas': 30000000})
                 receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                 return receipt.status == 1
             except Exception as e:
                 print(f"[ContractInterface] Smart Contract Error: {e}")
                 return False
        return True # Mock skipped for BGM
            
    def get_challenge(self, file_id):
         if isinstance(file_id, str): file_id = file_id.encode('utf-8')
         if self.mode == "BLOCKCHAIN": return [random.randint(0, 10) for _ in range(3)]
         return self.mock_chain.get_challenge(file_id)

class MockBlockchain:
    def __init__(self, kzg_instance=None):
        self.files = {}
        self.verifier = kzg_instance if kzg_instance else EdgeNode().kzg 
        self.vt = VerkleTree(self.verifier)

    def deploy(self):
        return "0xMOCK"

    def upload_metadata(self, file_id, root):
        if file_id in self.files: raise Exception("File ID already exists")
        self.files[file_id] = root
        return True

    def get_challenge(self, file_id):
        return [random.randint(0, 10) for _ in range(3)]

    def verify_proof(self, file_id, path):
        if file_id not in self.files: return False
        root = self.files[file_id]
        return self.vt.verify_path(path, root)
