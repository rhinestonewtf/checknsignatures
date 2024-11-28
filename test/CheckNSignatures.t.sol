// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import "../src/CheckNSignatures.sol";

import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { CheckNSignaturesFoundryHelper } from "../src/CheckNSignaturesFoundryHelper.sol";

/// @title CheckNSignaturesTest
/// @author zeroknots
contract ERC1271 is ISignatureValidator {
    function isValidSignature(
        bytes32 _dataHash,
        bytes memory _signature
    )
        public
        view
        virtual
        override
        returns (bytes4)
    {
        if (keccak256(_signature) == keccak256(abi.encodePacked("SIGNATURE"))) {
            return EIP1271_MAGIC_VALUE;
        }
        return 0;
    }
}

contract CheckNSignaturesTest is Test, CheckNSignaturesFoundryHelper {
    function setUp() public { }

    function testCheckSignature() public {
        (address signer1, uint256 signerPk1) = makeAddrAndKey("signer1");
        (address signer2, uint256 signerPk2) = makeAddrAndKey("signer2");

        console2.log("signer1", signer1);
        console2.log("signer2", signer2);
        console2.log("this", address(this));

        bytes memory data = abi.encodePacked("DATA TO SIGN");

        bytes32 dataHash = keccak256(data);

        bytes memory signatures;
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(signerPk1, dataHash);
        address signer = address(uint160(uint256(r)));
        console2.log("signerDecode", signer);
        signatures = abi.encodePacked(r, s, v);
        (v, r, s) = vm.sign(signerPk2, dataHash);
        signatures = abi.encodePacked(signatures, abi.encodePacked(r, s, v));

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 2);

        assertEq(signer1, recovered[0]);
        assertEq(signer2, recovered[1]);
    }

    function test_WithHelper(uint256 privKey, bytes memory data) public {
        vm.assume(privKey < 2 ** 18);
        vm.assume(privKey > 0);
        bytes memory signature = sign(privKey, data);

        bytes32 dataHash = keccak256(data);

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signature, 1);

        address signer = vm.addr(privKey);

        assertEq(signer, recovered[0]);
    }

    function test_WithHelper(
        uint256 privKey1,
        uint256 privKey2,
        uint256 privKey3,
        bytes memory data
    )
        public
    {
        vm.assume(privKey1 < 2 ** 18);
        vm.assume(privKey1 > 0);

        vm.assume(privKey2 < 2 ** 18);
        vm.assume(privKey2 > 0);

        vm.assume(privKey3 < 2 ** 18);
        vm.assume(privKey3 > 0);
        uint256[] memory privKeys = new uint256[](3);
        privKeys[0] = privKey1;
        privKeys[1] = privKey2;
        privKeys[2] = privKey3;
        bytes memory signature = sign(privKeys, data);

        bytes32 dataHash = keccak256(data);

        address[] memory recovered =
            CheckSignatures.recoverNSignatures(dataHash, signature, privKeys.length);

        for (uint256 i; i < privKeys.length; i++) {
            address signer = vm.addr(privKeys[i]);
            assertEq(signer, recovered[i]);
        }
    }

    function test_ERC1271(bytes memory data) public {
        ERC1271 erc1271Signer = new ERC1271();
        bytes32 dataHash = keccak256(data);

        bytes memory contractSignature = abi.encodePacked("SIGNATURE");

        // Store signature at position after base signature length
        uint256 signatureOffset = 65;

        // Format: <owner address 20> <offset to contract signature 32> <signature type 1> <contract
        // signature>
        bytes32 r = bytes32(uint256(uint160(address(erc1271Signer)))); // owner
        bytes32 s = bytes32(signatureOffset); // offset
        uint8 v = 0; // contract signature type

        bytes memory signatures =
            abi.encodePacked(r, s, v, bytes32(contractSignature.length), contractSignature);

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 1);
        assertEq(address(erc1271Signer), recovered[0]);
    }

    function testSkippedValidSignature() public {
        (address signer1, uint256 pk1) = makeAddrAndKey("signer1");
        (address signer2, uint256 pk2) = makeAddrAndKey("signer2");
        (address signer3, uint256 pk3) = makeAddrAndKey("signer3");

        bytes memory data = abi.encodePacked("DATA TO SIGN");
        bytes32 dataHash = keccak256(data);

        // Create signatures in order [valid, invalid, valid]
        // First valid signature
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pk1, dataHash);
        bytes memory signatures = abi.encodePacked(r1, s1, v1);

        // Invalid signature (using wrong hash)
        bytes32 wrongHash = keccak256("WRONG DATA");
        (v1, r1, s1) = vm.sign(pk2, wrongHash);
        signatures = abi.encodePacked(signatures, r1, s1, v1);

        // Second valid signature
        (v1, r1, s1) = vm.sign(pk3, dataHash);
        signatures = abi.encodePacked(signatures, r1, s1, v1);

        // Try to get 2 valid signatures
        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 2);

        // Should get both valid signatures (first and third)
        assertEq(recovered.length, 3);
        assert(recovered[0] == signer1);
        assert(
            recovered[1] != signer2 && recovered[1] != signer3 && recovered[1] != address(0)
                && recovered[1] != signer1
        );
        assert(recovered[2] == signer3);
    }

    function testMixedSignatureTypes() public {
        (address signer1, uint256 pk1) = makeAddrAndKey("signer1");
        (address signer2, uint256 pk2) = makeAddrAndKey("signer2");
        ERC1271 erc1271Signer = new ERC1271();

        bytes memory data = abi.encodePacked("DATA TO SIGN");
        bytes32 dataHash = keccak256(data);

        // First valid ECDSA signature
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pk1, dataHash);
        bytes memory signatures = abi.encodePacked(r1, s1, v1);

        // Invalid ECDSA signature
        (v1, r1, s1) = vm.sign(pk2, bytes32(uint256(dataHash) + 1));
        signatures = abi.encodePacked(signatures, r1, s1, v1);

        // Valid ERC1271 contract signature
        bytes memory contractSignature = abi.encodePacked("SIGNATURE");
        uint256 signatureOffset = signatures.length + 65; // offset after current signatures plus
            // one more signature slot

        r1 = bytes32(uint256(uint160(address(erc1271Signer))));
        s1 = bytes32(signatureOffset);
        v1 = 0;

        signatures = abi.encodePacked(
            signatures, r1, s1, v1, bytes32(contractSignature.length), contractSignature
        );

        assembly {
            mstore(add(add(signatures, signatureOffset), 0x20), mload(contractSignature))
        }

        // Try to get 2 valid signatures
        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 2);

        // Should get both valid signatures (first ECDSA and last ERC1271)
        assertEq(recovered.length, 3);
        assertEq(recovered[0], signer1);
        assert(
            recovered[1] != signer1 && recovered[1] != address(0)
                && recovered[1] != address(erc1271Signer) && recovered[1] != signer2
        );
        assertEq(recovered[2], address(erc1271Signer));
    }
}
