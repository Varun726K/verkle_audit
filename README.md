# PPD-CL-DIA: Privacy-Preserving and Dynamic Data Integrity Auditing

This project implements a decentralized auditing scheme for cloud storage using **Verkle Trees** (KZG Commitments) and **Ethereum Smart Contracts**. It allows a Data Owner to outsource encrypted files to a Cloud Provider and verify their integrity efficiently ($O(1)$ proof size) without a trusted third party.

## Prerequisites

*   **Python 3.8+**
*   **Node.js & npm** (for Ganache)

## Installation

1.  **Clone / Navigate to the directory**:
    ```bash
    cd k:/Code/CIP
    ```

2.  **Install Python Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Install Ganache (Local Blockchain)**:
    ```bash
    npm install -g ganache
    ```

## Running the Demo (Local Blockchain)

For the full experience with a real local blockchain state:

### Step 1: Start the Blockchain
Open a terminal and run:
```bash
ganache
```
*Keep this terminal running.*

### Step 2: Deploy the Smart Contract
Open a **new** terminal and run:
```bash
python -m Initializer.deploy
```
This script will:
*   Compile `Auditor.sol`.
*   Generate the Trusted Setup (SRS) parameters.
*   Deploy the contract to your local Ganache node.
*   Save the deployment details to `contract_data.json`.

### Step 3: Run the End-to-End Demo
In the same terminal, run:
```bash
python -m AuditDemo.e2e_demo
```

## What's Happening?

1.  **Initialization**: The system loads the Trusted Setup and connects to the deployed Smart Contract.
2.  **Data Outsourcing**:
    *   **Data Owner** encrypts `demo_secret.txt` (AES-256).
    *   Generates a **Verkle Root** (Vector Commitment) for the file chunks.
    *   Uploads the **Root** to the Smart Contract.
    *   Uploads the **Encrypted Chunks** to the Cloud Provider.
3.  **Auditing**:
    *   The **Auditor** (simulated via script) requests a randomized challenge.
    *   The **Cloud Provider** generates an $O(1)$ sized **KZG Proof**.
    *   The **Smart Contract** verifies the proof on-chain using pairing cryptography.
    *   **Result**: The script reports `SUCCESS` if the data is intact.

## Project Structure

*   `Blockchain/Auditor.sol`: Solidity smart contract for on-chain verification.
*   `Blockchain/ContractInterface.py`: Bridge between Python and Ethereum (Web3.py).
*   `Initializer/kzg_core.py`: Python implementation of KZG commitments and pairing checks.
*   `Initializer/deploy.py`: Deployment script.
*   `DataOwner/DataOwner.py`: Client-side encryption and tree root generation.
*   `CloudProvider/CloudProvider.py`: Server-side storage and proof generation.
*   `EdgeNode/EdgeNode.py`: Node handling heavy cryptography logic like Verkle Tree root tag generation.
*   `AuditDemo/e2e_demo.py`: Main demonstration script.
*   `AuditDemo/SystemTest.py`: Testing script for the full system flow.
