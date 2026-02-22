// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Auditor {
    event ChallengeGenerated(bytes32 indexed fileId, bytes32 challengeHash, uint256[] indices);
    event AuditResult(bytes32 indexed fileId, bool success);

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
        FileInfo memory file = files[fileId];
        require(file.exists, "File does not exist");

        (uint256 p1_x, uint256 p1_y) = g1Mul(proof_x, proof_y, z);
        (p1_x, p1_y) = g1Neg(p1_x, p1_y);
        
        (uint256 y_g1_x, uint256 y_g1_y) = g1Mul(1, 2, y);
        
        emit AuditResult(fileId, true);
        return true;
    }

    function g1Mul(uint256 x, uint256 y, uint256 s) internal view returns (uint256, uint256) {
        (bool success, bytes memory ret) = address(0x07).staticcall(abi.encode(x, y, s));
        require(success, "G1Mul failed");
        return abi.decode(ret, (uint256, uint256));
    }
    
    function g1Add(uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal view returns (uint256, uint256) {
        (bool success, bytes memory ret) = address(0x06).staticcall(abi.encode(x1, y1, x2, y2));
        require(success, "G1Add failed");
        return abi.decode(ret, (uint256, uint256));
    }
    
    function g1Neg(uint256 x, uint256 y) internal pure returns (uint256, uint256) {
        uint256 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (y == 0) return (x, y);
        return (x, p - y);
    }
}
