// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Auditor {
    event ChallengeGenerated(bytes32 indexed fileId, bytes32 challengeHash, uint256[] indices);
    event AuditResult(bytes32 indexed fileId, bool success);
    event DebugPairingFailed(uint256[] data);
    event PrecompilePayload(uint256[] payload);

    uint256 constant ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

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

    function computeAggregates(
        uint256[2][] calldata C,
        uint256[] calldata v,
        uint256 rho,
        uint256[2] calldata C_h,
        uint256 v_h
    ) internal returns (uint256[3] memory aggs) {
        uint256 rho_power = 1;
        uint256 depth = C.length;
        for (uint i = 0; i < depth; i++) {
            (uint256 tempX, uint256 tempY) = g1Mul(C[i][0], C[i][1], rho_power);
            (aggs[0], aggs[1]) = g1Add(aggs[0], aggs[1], tempX, tempY);
            aggs[2] = addmod(aggs[2], mulmod(v[i], rho_power, ORDER), ORDER);
            rho_power = mulmod(rho_power, rho, ORDER);
        }
        (uint256 hX, uint256 hY) = g1Mul(C_h[0], C_h[1], rho_power);
        (aggs[0], aggs[1]) = g1Add(aggs[0], aggs[1], hX, hY);
        aggs[2] = addmod(aggs[2], mulmod(v_h, rho_power, ORDER), ORDER);
    }

    function computeRHS(
        uint256 aggC_X,
        uint256 aggC_Y,
        uint256 aggV,
        uint256[2] calldata pi,
        uint256 t
    ) internal returns (uint256 rhsX, uint256 rhsY) {
        (uint256 vg1X, uint256 vg1Y) = g1Mul(1, 2, aggV); // V_agg * G1
        (uint256 nvg1X, uint256 nvg1Y) = g1Neg(vg1X, vg1Y); // -V_agg * G1
        (uint256 cx, uint256 cy) = g1Add(aggC_X, aggC_Y, nvg1X, nvg1Y); // C_agg - V_agg*G1
        (uint256 tPiX, uint256 tPiY) = g1Mul(pi[0], pi[1], t); // t * pi
        return g1Add(cx, cy, tPiX, tPiY); // Final RHS
    }

    function checkPairing(
        uint256 rhsX,
        uint256 rhsY,
        uint256[2] calldata pi
    ) internal returns (bool) {
        uint256[12] memory input;
        input[0] = pi[0];
        input[1] = pi[1];
        input[2] = G2_Alpha.x2;
        input[3] = G2_Alpha.x1;
        input[4] = G2_Alpha.y2;
        input[5] = G2_Alpha.y1;
        
        (uint256 negRhsX, uint256 negRhsY) = g1Neg(rhsX, rhsY);
        input[6] = negRhsX;
        input[7] = negRhsY;
        input[8] = G2_Gen.x2;
        input[9] = G2_Gen.x1;
        input[10] = G2_Gen.y2;
        input[11] = G2_Gen.y1;

        return ecPairing(input);
    }
    function validateRoots(
        bytes32 fileId,
        uint256[2][] calldata C,
        uint256 depth
    ) internal view {
        for (uint i = depth - 1; i < C.length; i += depth) {
            require(C[i][0] == files[fileId].root_x && C[i][1] == files[fileId].root_y, "Root mismatch");
        }
    }

    // Computes [r, t, rho] challenges matching Python hash_to_scalar flat-bytes encoding
    function _computeChallenges(
        uint256[2][] calldata C,
        uint256[] calldata z,
        uint256[] calldata y,
        uint256[] calldata v,
        uint256 v_h,
        uint256[2] calldata C_h
    ) internal pure returns (uint256[3] memory chals) {
        // r = sha256(C[0].x || C[0].y || ... || z[0] || ... || y[0] || ...)
        bytes memory buf;
        for (uint i = 0; i < C.length; i++) {
            buf = abi.encodePacked(buf, C[i][0], C[i][1]);
        }
        for (uint i = 0; i < z.length; i++) {
            buf = abi.encodePacked(buf, z[i]);
        }
        for (uint i = 0; i < y.length; i++) {
            buf = abi.encodePacked(buf, y[i]);
        }
        chals[0] = uint256(sha256(buf)) % ORDER;

        // t = sha256(r || C_h.x || C_h.y)
        chals[1] = uint256(sha256(abi.encodePacked(chals[0], C_h[0], C_h[1]))) % ORDER;

        // rho = sha256(t || v[0] || ... || v_h)
        bytes memory rhoBuf = abi.encodePacked(chals[1]);
        for (uint i = 0; i < v.length; i++) {
            rhoBuf = abi.encodePacked(rhoBuf, v[i]);
        }
        rhoBuf = abi.encodePacked(rhoBuf, v_h);
        chals[2] = uint256(sha256(rhoBuf)) % ORDER;
    }

    function _doVerify(
        uint256[2][] calldata C,
        uint256[] calldata v,
        uint256 rho,
        uint256 v_h,
        uint256[2] calldata C_h,
        uint256[2] calldata pi,
        uint256 t
    ) internal returns (bool) {
        uint256[3] memory aggs = computeAggregates(C, v, rho, C_h, v_h);
        (uint256 rhsX, uint256 rhsY) = computeRHS(aggs[0], aggs[1], aggs[2], pi, t);
        return checkPairing(rhsX, rhsY, pi);
    }

    function verifyVerkleMultiProof(
        bytes32 fileId,
        uint256[2][] calldata C,
        uint256[] calldata z,
        uint256[] calldata y,
        uint256[] calldata v,
        uint256 v_h,
        uint256[2] calldata C_h,
        uint256[2] calldata pi,
        uint256 depth
    ) external returns (bool) {
        require(files[fileId].exists, "File does not exist");
        validateRoots(fileId, C, depth);
        uint256[3] memory chals = _computeChallenges(C, z, y, v, v_h, C_h);
        require(_doVerify(C, v, chals[2], v_h, C_h, pi, chals[1]), "Multiproof verification failed");
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

    function modExp(uint256 base, uint256 exp, uint256 mod) internal view returns (uint256) {
        uint256[6] memory input;
        input[0] = 32; input[1] = 32; input[2] = 32;
        input[3] = base; input[4] = exp; input[5] = mod;
        uint256[1] memory out;
        bool success;
        assembly { success := staticcall(sub(gas(), 2000), 5, input, 192, out, 32) }
        require(success, "modExp failed");
        return out[0];
    }

    function verifyMerkleProof(
        bytes32 fileId,
        bytes32[] calldata siblings,
        bool[] calldata flags,
        bytes32 leaf
    ) external returns (bool) {
        require(files[fileId].exists, "File does not exist");
        bytes32 currentHash = leaf;
        
        for (uint i = 0; i < siblings.length; i++) {
            if (flags[i]) {
                currentHash = sha256(abi.encodePacked(currentHash, siblings[i]));
            } else {
                currentHash = sha256(abi.encodePacked(siblings[i], currentHash));
            }
        }
        
        require(uint256(currentHash) == files[fileId].root_x, "Merkle Root mismatch");
        return true;
    }
}
