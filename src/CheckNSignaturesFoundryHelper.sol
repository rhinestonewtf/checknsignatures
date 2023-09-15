// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

/// @title CheckNSignaturesFoundryHelper
/// @author zeroknots
contract CheckNSignaturesFoundryHelper is Test {
    function sign(
        uint256 signerPrivKey,
        bytes memory packedData
    )
        public
        pure
        returns (bytes memory signature)
    {
        bytes32 dataHash = keccak256(packedData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivKey, dataHash);

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
            (v, r, s) = vm.sign(privKey, dataHash);
            signatures = abi.encodePacked(signatures, abi.encodePacked(r, s, v));
        }
    }
}
