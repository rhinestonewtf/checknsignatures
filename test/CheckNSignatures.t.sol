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
        return EIP1271_MAGIC_VALUE;
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

        uint256 length = contractSignature.length;

        uint8 v = 0;
        console2.log("signer contract", address(erc1271Signer));
        bytes32 encodedAddr = bytes32(uint256(uint160(address(erc1271Signer))) << 96);
        bytes32 r = encodedAddr;
        bytes32 s = bytes32(uint256(30));
        bytes memory signatures = abi.encodePacked(v, s, r);
        signatures = abi.encodePacked(signatures, contractSignature);

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 1);
        assertEq(address(erc1271Signer), recovered[0]);
    }
}
