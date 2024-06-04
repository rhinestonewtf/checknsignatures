// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { Vm } from "forge-std/Test.sol";

// The address of the VM contract
address constant VM_ADDR = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;

/**
 * Sign data with a private key outside of a foundry test
 *
 * @param pk The private key to sign with
 * @param digest The data to sign
 *
 * @return v The recovery id
 * @return r The r value of the signature
 * @return s The s value of the signature
 */
function vmsign(uint256 pk, bytes32 digest) pure returns (uint8 v, bytes32 r, bytes32 s) {
    return Vm(VM_ADDR).sign(pk, digest);
}

/**
 * @title CheckNSignaturesFoundryHelper
 * @dev Helper contract to sign data
 * @author Rhinestone
 */
contract CheckNSignaturesFoundryHelper {
    /**
     * Sign data with a private key
     *
     * @param signerPrivKey The private key to sign with
     * @param packedData The data to sign
     *
     * @return signature The signature
     */
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

    /**
     * Sign data with multiple private keys
     *
     * @param signerPrivKeys The private keys to sign with
     * @param packedData The data to sign
     *
     * @return signatures The signatures
     */
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
