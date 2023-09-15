// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

address constant VM_ADDR = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;

function vmsign(uint256 pk, bytes32 digest) pure returns (uint8 v, bytes32 r, bytes32 s) {
    return Vm(VM_ADDR).sign(pk, digest);
}

/// @title CheckNSignaturesFoundryHelper
/// @author zeroknots
contract CheckNSignaturesFoundryHelper {
    function sign(
        uint256 signerPrivKey,
        bytes memory packedData
    )
        public
        pure
        returns (bytes memory signature)
    {
        bytes32 dataHash = keccak256(packedData);
        (uint8 v, bytes32 r, bytes32 s) = vmsign(signerPrivKey, dataHash);

        signature = abi.encodePacked(r, s, v);
    }

    function sign(
        uint256[] memory signerPrivKeys,
        bytes memory packedData
    )
        public
        pure
        returns (bytes memory signatures)
    {
        uint8 v;
        bytes32 r;
        bytes32 s;

        bytes32 dataHash = keccak256(packedData);

        for (uint256 i; i < signerPrivKeys.length; i++) {
            uint256 privKey = signerPrivKeys[i];
            (v, r, s) = vmsign(privKey, dataHash);
            signatures = abi.encodePacked(signatures, abi.encodePacked(r, s, v));
        }
    }
}
