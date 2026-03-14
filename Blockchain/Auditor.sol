// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Auditor {
    event ChallengeGenerated(bytes32 indexed fileId, bytes32 challengeHash, uint256[] indices);
    event AuditResult(bytes32 indexed fileId, bool success);
    event DebugPairingFailed(uint256[] data);
    event PrecompilePayload(uint256[] payload);

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

    constructor(uint256 _g2_gen_x1, uint256 _g2_gen_x2, uint256 _g2_gen_y1, uint256 _g2_gen_y2, uint256 _g2_alpha_x1, uint256 _g2_alpha_x2, uint256 _g2_alpha_y1, uint256 _g2_alpha_y2) {
        G2_Gen = G2Point(_g2_gen_x1, _g2_gen_x2, _g2_gen_y1, _g2_gen_y2);
        G2_Alpha = G2Point(_g2_alpha_x1, _g2_alpha_x2, _g2_alpha_y1, _g2_alpha_y2);
    }
    
    function uploadMetadata(bytes32 fileId, uint256 root_x, uint256 root_y, uint256 fileSize) external {
        require(!files[fileId].exists, "File ID already exists");
        files[fileId] = FileInfo(msg.sender, root_x, root_y, fileSize, true);
    }

    function verifyProof(
        bytes32 fileId, 
        uint256[] memory proof_x, 
        uint256[] memory proof_y, 
        uint256[] memory z, 
        uint256[] memory y,
        uint256[] memory commitment_x,
        uint256[] memory commitment_y
    ) external returns (bool) {
        require(files[fileId].exists, "File does not exist");
        uint256 depth = proof_x.length;
        require(depth > 0, "Empty path");

        for(uint i=0; i<depth; i++) {
            if (i == depth - 1) {
                require(commitment_x[i] == files[fileId].root_x && commitment_y[i] == files[fileId].root_y, "Root mismatch");
            }
            if (i > 0) {
                // compute expected hash locally using standard sha256
                uint256 expectedHash = uint256(sha256(abi.encodePacked(commitment_x[i-1], commitment_y[i-1]))) % 21888242871839275222246405745257275088548364400416034343698204186575808495617;
                require(y[i] == expectedHash, "Hash link broken");
            }

            uint256[12] memory input;
            input[0] = proof_x[i];
            input[1] = proof_y[i];
            input[2] = G2_Alpha.x2;
            input[3] = G2_Alpha.x1;
            input[4] = G2_Alpha.y2;
            input[5] = G2_Alpha.y1;
            {
                (uint256 tx, uint256 ty) = g1Mul(1, 2, y[i]);
                (uint256 cx, uint256 cy) = g1Neg(commitment_x[i], commitment_y[i]);
                (tx, ty) = g1Add(tx, ty, cx, cy);
                (cx, cy) = g1Mul(proof_x[i], proof_y[i], z[i]);
                (cx, cy) = g1Neg(cx, cy);
                (input[6], input[7]) = g1Add(tx, ty, cx, cy);
            }
            input[8] = G2_Gen.x2;
            input[9] = G2_Gen.x1;
            input[10] = G2_Gen.y2;
            input[11] = G2_Gen.y1;
            require(ecPairing(input), "KZG path verification failed");
        }
        
        emit AuditResult(fileId, true);
        return true;
    }

    function ecPairing(uint256[12] memory input) internal returns (bool) {
        uint256[1] memory out;
        bool success;
        assembly {
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
        if (!success) return (0, 0);
        return abi.decode(ret, (uint256, uint256));
    }
    
    function g1Add(uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal returns (uint256, uint256) {
        (bool success, bytes memory ret) = address(0x06).staticcall(abi.encode(x1, y1, x2, y2));
        if (!success) return (0, 0);
        return abi.decode(ret, (uint256, uint256));
    }
    
    function g1Neg(uint256 x, uint256 y) internal pure returns (uint256, uint256) {
        uint256 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (y == 0) return (x, y);
        return (x, p - y);
    }
}
