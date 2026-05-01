// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import "../src/CheckNSignatures.sol";

import { ECDSA } from "solady/utils/ECDSA.sol";
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

contract ERC1271Rejecting is ISignatureValidator {
    function isValidSignature(
        bytes32,
        bytes memory
    )
        public
        view
        virtual
        override
        returns (bytes4)
    {
        return 0xffffffff;
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

        bytes32 r = bytes32(uint256(uint160(address(erc1271Signer))));
        bytes32 s = bytes32(uint256(65));
        uint8 v = 0;

        bytes memory signatures = abi.encodePacked(r, s, v);
        signatures =
            abi.encodePacked(signatures, uint256(contractSignature.length), contractSignature);

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 1);
        assertEq(address(erc1271Signer), recovered[0]);
    }

    function _ecdsaStatic(uint256 pk, bytes32 dataHash) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, dataHash);
        return abi.encodePacked(r, s, v);
    }

    function _contractStatic(
        address signer,
        uint256 dynamicOffset
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes32 r = bytes32(uint256(uint160(signer)));
        bytes32 s = bytes32(dynamicOffset);
        uint8 v = 0;
        return abi.encodePacked(r, s, v);
    }

    function _contractDynamic(bytes memory contractSignature) internal pure returns (bytes memory) {
        return abi.encodePacked(uint256(contractSignature.length), contractSignature);
    }

    function recoverNSignaturesExternal(
        bytes32 dataHash,
        bytes memory signatures,
        uint256 requiredSignatures
    )
        external
        view
        returns (address[] memory)
    {
        return CheckSignatures.recoverNSignatures(dataHash, signatures, requiredSignatures);
    }

    function test_EthSignFlow() public {
        (address signer, uint256 pk) = makeAddrAndKey("ethSignSigner");

        bytes32 dataHash = keccak256("eth_sign payload");
        bytes32 prefixed = ECDSA.toEthSignedMessageHash(dataHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, prefixed);
        bytes memory signatures = abi.encodePacked(r, s, v + 4);

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 1);
        assertEq(signer, recovered[0]);
    }

    function test_ContractAndECDSA() public {
        ERC1271 contractSigner = new ERC1271();
        (address eoa, uint256 pk) = makeAddrAndKey("eoa");

        bytes32 dataHash = keccak256("contract+ecdsa");
        bytes memory contractSig = abi.encodePacked("CONTRACT_SIG");

        bytes memory signatures = _contractStatic(address(contractSigner), 130);
        signatures = abi.encodePacked(signatures, _ecdsaStatic(pk, dataHash));
        signatures = abi.encodePacked(signatures, _contractDynamic(contractSig));

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 2);
        assertEq(address(contractSigner), recovered[0]);
        assertEq(eoa, recovered[1]);
    }

    function test_ECDSAAndContract() public {
        (address eoa, uint256 pk) = makeAddrAndKey("eoa");
        ERC1271 contractSigner = new ERC1271();

        bytes32 dataHash = keccak256("ecdsa+contract");
        bytes memory contractSig = abi.encodePacked("CONTRACT_SIG");

        bytes memory signatures = _ecdsaStatic(pk, dataHash);
        signatures = abi.encodePacked(signatures, _contractStatic(address(contractSigner), 130));
        signatures = abi.encodePacked(signatures, _contractDynamic(contractSig));

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 2);
        assertEq(eoa, recovered[0]);
        assertEq(address(contractSigner), recovered[1]);
    }

    function test_TwoContractSigs() public {
        ERC1271 contractA = new ERC1271();
        ERC1271 contractB = new ERC1271();

        bytes32 dataHash = keccak256("two contracts");
        bytes memory sigA = abi.encodePacked("AAAA");
        bytes memory sigB = abi.encodePacked("BBBBBBBB");

        uint256 offsetA = 130;
        uint256 offsetB = offsetA + 32 + sigA.length;

        bytes memory signatures = _contractStatic(address(contractA), offsetA);
        signatures = abi.encodePacked(signatures, _contractStatic(address(contractB), offsetB));
        signatures = abi.encodePacked(signatures, _contractDynamic(sigA));
        signatures = abi.encodePacked(signatures, _contractDynamic(sigB));

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 2);
        assertEq(address(contractA), recovered[0]);
        assertEq(address(contractB), recovered[1]);
    }

    function test_MixedECDSAContractECDSA() public {
        (address eoa1, uint256 pk1) = makeAddrAndKey("eoa1");
        ERC1271 contractSigner = new ERC1271();
        (address eoa2, uint256 pk2) = makeAddrAndKey("eoa2");

        bytes32 dataHash = keccak256("ecdsa+contract+ecdsa");
        bytes memory contractSig = abi.encodePacked("MIDDLE");

        bytes memory signatures = _ecdsaStatic(pk1, dataHash);
        signatures = abi.encodePacked(signatures, _contractStatic(address(contractSigner), 195));
        signatures = abi.encodePacked(signatures, _ecdsaStatic(pk2, dataHash));
        signatures = abi.encodePacked(signatures, _contractDynamic(contractSig));

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 3);
        assertEq(eoa1, recovered[0]);
        assertEq(address(contractSigner), recovered[1]);
        assertEq(eoa2, recovered[2]);
    }

    function test_TwoContractsTwoECDSA() public {
        ERC1271 contractA = new ERC1271();
        (address eoa1, uint256 pk1) = makeAddrAndKey("eoa1");
        ERC1271 contractB = new ERC1271();
        (address eoa2, uint256 pk2) = makeAddrAndKey("eoa2");

        bytes32 dataHash = keccak256("2x2 mix");
        bytes memory sigA = abi.encodePacked("AAA");
        bytes memory sigB = abi.encodePacked("BBBBB");

        uint256 staticLen = 65 * 4;
        uint256 offsetA = staticLen;
        uint256 offsetB = offsetA + 32 + sigA.length;

        bytes memory signatures = _contractStatic(address(contractA), offsetA);
        signatures = abi.encodePacked(signatures, _ecdsaStatic(pk1, dataHash));
        signatures = abi.encodePacked(signatures, _contractStatic(address(contractB), offsetB));
        signatures = abi.encodePacked(signatures, _ecdsaStatic(pk2, dataHash));
        signatures = abi.encodePacked(signatures, _contractDynamic(sigA));
        signatures = abi.encodePacked(signatures, _contractDynamic(sigB));

        address[] memory recovered = CheckSignatures.recoverNSignatures(dataHash, signatures, 4);
        assertEq(address(contractA), recovered[0]);
        assertEq(eoa1, recovered[1]);
        assertEq(address(contractB), recovered[2]);
        assertEq(eoa2, recovered[3]);
    }

    function test_RevertWhen_InsufficientSignatures() public {
        bytes32 dataHash = keccak256("not enough");
        bytes memory signatures = new bytes(64);

        vm.expectRevert(InvalidSignature.selector);
        this.recoverNSignaturesExternal(dataHash, signatures, 1);
    }

    function test_RevertWhen_ContractSignatureRejects() public {
        ERC1271Rejecting rejecting = new ERC1271Rejecting();

        bytes32 dataHash = keccak256("rejected");
        bytes memory contractSig = abi.encodePacked("BAD");

        bytes memory signatures = _contractStatic(address(rejecting), 65);
        signatures = abi.encodePacked(signatures, _contractDynamic(contractSig));

        vm.expectRevert(abi.encodeWithSelector(WrongContractSignature.selector, contractSig));
        this.recoverNSignaturesExternal(dataHash, signatures, 1);
    }

    function test_RevertWhen_ContractSignaturePointerInsideStatic() public {
        ERC1271 contractSigner = new ERC1271();

        bytes32 dataHash = keccak256("pointer in static");
        bytes memory contractSig = abi.encodePacked("X");

        bytes memory signatures = _contractStatic(address(contractSigner), 64);
        signatures = abi.encodePacked(signatures, _contractDynamic(contractSig));

        vm.expectRevert(abi.encodeWithSelector(WrongContractSignatureFormat.selector, 64, 0, 0));
        this.recoverNSignaturesExternal(dataHash, signatures, 1);
    }

    function test_RevertWhen_ContractSignatureLengthOOB() public {
        ERC1271 contractSigner = new ERC1271();

        bytes32 dataHash = keccak256("length oob");
        bytes memory contractSig = abi.encodePacked("DATA");

        bytes memory signatures = _contractStatic(address(contractSigner), 65);
        signatures = abi.encodePacked(signatures, uint256(999), contractSig);

        uint256 totalLen = signatures.length;
        vm.expectRevert(
            abi.encodeWithSelector(WrongContractSignatureFormat.selector, 65, 999, totalLen)
        );
        this.recoverNSignaturesExternal(dataHash, signatures, 1);
    }
}
