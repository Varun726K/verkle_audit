// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Auditor {
    event ChallengeGenerated(bytes32 indexed fileId, bytes32 challengeHash, uint256[] indices);
    event AuditResult(bytes32 indexed fileId, bool success);
    event DebugPairingFailed(uint256[] data);

    struct FileInfo {
        address owner;
        uint256 root_x;
        uint256 root_y;
        uint256 fileSize;
        bool exists;
    }

    mapping(bytes32 => FileInfo) public files;

    struct G2Point {
        uint256 x1;
        uint256 x2;
        uint256 y1;
        uint256 y2;
    }
    
    G2Point public G2_Gen;
    G2Point public G2_Alpha;

    constructor(
        uint256 _g2_gen_x1, uint256 _g2_gen_x2, uint256 _g2_gen_y1, uint256 _g2_gen_y2,
        uint256 _g2_alpha_x1, uint256 _g2_alpha_x2, uint256 _g2_alpha_y1, uint256 _g2_alpha_y2
    ) {
        G2_Gen = G2Point(_g2_gen_x1, _g2_gen_x2, _g2_gen_y1, _g2_gen_y2);
        G2_Alpha = G2Point(_g2_alpha_x1, _g2_alpha_x2, _g2_alpha_y1, _g2_alpha_y2);
    }
    
    /**
     * @notice DO uploads the file metadata (Root)
     */
    function uploadMetadata(bytes32 fileId, uint256 root_x, uint256 root_y, uint256 fileSize) external {
        require(!files[fileId].exists, "File ID already exists");
        files[fileId] = FileInfo({
            owner: msg.sender,
            root_x: root_x,
            root_y: root_y,
            fileSize: fileSize,
            exists: true
        });
    }

    /**
     * @notice Verify a KZG Proof submitted by CSP
     */
    function verifyProof(
        bytes32 fileId,
        uint256 proof_x,
        uint256 proof_y,
        uint256 z,
        uint256 y
    ) external returns (bool) {
        require(files[fileId].exists, "File does not exist");

        uint256[12] memory input;
        
        // --- First Pairing: e(pi, [s]_2) ---
        input[0] = proof_x;
        input[1] = proof_y;
        input[2] = G2_Alpha.x2; // EIP-197 encodes G2 as [imag, real]
        input[3] = G2_Alpha.x1;
        input[4] = G2_Alpha.y2;
        input[5] = G2_Alpha.y1;

        // --- Second Pairing: e(y*G1 - C - z*pi, G2_Gen) ---
        // Block scope to clear intermediate variables from the stack
        {
            // 1. tx, ty = y * G1
            (uint256 tx, uint256 ty) = g1Mul(1, 2, y);
            
            // 2. cx, cy = -C (Negative Verkle Root)
            (uint256 cx, uint256 cy) = g1Neg(files[fileId].root_x, files[fileId].root_y);
            
            // 3. tx, ty = (y * G1) + (-C)
            (tx, ty) = g1Add(tx, ty, cx, cy);

            // 4. cx, cy = z * pi
            (cx, cy) = g1Mul(proof_x, proof_y, z);
            
            // 5. cx, cy = -z * pi
            (cx, cy) = g1Neg(cx, cy);

            // 6. Calculate final P2 and assign directly to the pairing input array
            (input[6], input[7]) = g1Add(tx, ty, cx, cy);
        }

        // Add G2_Gen to the input array (EIP-197 encoding)
        input[8] = G2_Gen.x2;
        input[9] = G2_Gen.x1;
        input[10] = G2_Gen.y2;
        input[11] = G2_Gen.y1;

        // --- Execute the Pairing Precompile ---
        bool success = ecPairing(input);
        require(success, "KZG Proof Verification Failed: Data Corrupted or Fake Proof");

        emit AuditResult(fileId, true);
        return true;
    }

    event PrecompilePayload(uint256[] payload);

    function ecPairing(uint256[12] memory input) internal returns (bool) {
        uint256[1] memory out;
        
        uint256[] memory emitArr = new uint256[](12);
        for(uint i=0; i<12; i++) emitArr[i] = input[i];
        emit PrecompilePayload(emitArr);

        bool success;
        assembly {
            // staticcall to precompile 0x08 (ecPairing)
            success := staticcall(sub(gas(), 2000), 8, input, 384, out, 32)
        }
        if (!success) {
            uint256[] memory dynInput = new uint256[](12);
            for(uint i=0; i<12; i++) dynInput[i] = input[i];
            emit DebugPairingFailed(dynInput);
            return false;
        }
        return out[0] == 1;
    }

    function g1Mul(uint256 x, uint256 y, uint256 s) internal returns (uint256, uint256) {
        (bool success, bytes memory ret) = address(0x07).staticcall(abi.encode(x, y, s));
        if (!success) {
            uint256[] memory err = new uint256[](1);
            err[0] = 777; // Indicate G1Mul failed
            emit DebugPairingFailed(err);
            return (0, 0);
        }
        return abi.decode(ret, (uint256, uint256));
    }
    
    function g1Add(uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal returns (uint256, uint256) {
        (bool success, bytes memory ret) = address(0x06).staticcall(abi.encode(x1, y1, x2, y2));
        if (!success) {
            uint256[] memory err = new uint256[](1);
            err[0] = 666; // Indicate G1Add failed
            emit DebugPairingFailed(err);
            return (0, 0);
        }
        return abi.decode(ret, (uint256, uint256));
    }
    
    function g1Neg(uint256 x, uint256 y) internal pure returns (uint256, uint256) {
        uint256 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (y == 0) return (x, y);
        return (x, p - y);
    }
}
