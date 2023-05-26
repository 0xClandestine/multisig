// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {Counter} from "./Counter.sol";
import "../src/Factory.sol";

contract MultisigTest is Test {
    /// -----------------------------------------------------------------------
    /// Testing Storage
    /// -----------------------------------------------------------------------

    Factory factory;
    Multisig multisig;
    Counter target;

    address addr0;
    uint256 pk0;

    address addr1;
    uint256 pk1;

    address addr2;
    uint256 pk2;

    uint256 constant value = 1 ether;
    uint256 constant deadline = 0;
    uint256 constant nonce = 0;
    uint256 constant quorum = 2;

    /// -----------------------------------------------------------------------
    /// Setup
    /// -----------------------------------------------------------------------

    function setUp() public {
        (addr0, pk0) = makeAddrAndKey("addr0");
        (addr1, pk1) = makeAddrAndKey("addr1");
        (addr2, pk2) = makeAddrAndKey("addr2");

        address[] memory signers = new address[](3);

        signers[0] = addr0;
        signers[1] = addr1;
        signers[2] = addr2;

        uint256 quorum = 2;

        factory = new Factory();
        multisig = new Multisig(signers, quorum);
        target = new Counter();
    }

    /// -----------------------------------------------------------------------
    /// Helpers
    /// -----------------------------------------------------------------------

    function getSignatures_3_of_3(bytes32 digest)
        internal
        view
        returns (bytes[] memory signatures)
    {
        signatures = new bytes[](3);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk0, digest);
        signatures[0] = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(pk1, digest);
        signatures[1] = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(pk2, digest);
        signatures[2] = abi.encodePacked(r, s, v);
    }

    function getSignatures_2_of_3(bytes32 digest)
        internal
        view
        returns (bytes[] memory signatures)
    {
        signatures = getSignatures_3_of_3(digest);
        signatures[0] = abi.encodePacked(addr0);
    }

    function getSignatures_1_of_3(bytes32 digest)
        internal
        view
        returns (bytes[] memory signatures)
    {
        signatures = getSignatures_2_of_3(digest);
        signatures[1] = abi.encodePacked(addr1);
    }

    /// -----------------------------------------------------------------------
    /// Tests
    /// -----------------------------------------------------------------------

    function testFactory_CreateMultisig() public {
        address[] memory signers = new address[](3);

        signers[0] = addr0;
        signers[1] = addr1;
        signers[2] = addr2;

        factory.createMultisig(signers, 2, bytes32(0));
    }

    function _computeDigestForCall(
        address target,
        uint256 value,
        bytes memory data,
        uint256 deadline,
        uint256 nonce
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                multisig.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(CALL_TYPEHASH, target, value, keccak256(data), deadline, nonce)
                )
            )
        );
    }

    function testCall_CanSendAndReceiveEther() public {
        deal(address(multisig), 1 ether);

        bytes memory data;

        bytes32 digest = _computeDigestForCall(address(target), value, data, deadline, nonce);

        multisig.call(address(target), value, deadline, quorum, data, getSignatures_2_of_3(digest));

        assertEq(address(target).balance, 1 ether);
    }

    function testCall_CannotReplaySignature() public {
        deal(address(multisig), 2 ether);

        bytes memory data;

        bytes32 digest = _computeDigestForCall(address(target), value, data, deadline, nonce);

        multisig.call(address(target), value, deadline, quorum, data, getSignatures_2_of_3(digest));

        vm.expectRevert(0x439cc0cd); // VerificationFailed
        multisig.call(address(target), value, deadline, quorum, data, getSignatures_2_of_3(digest));

        assertEq(multisig.nonce(), 1);
        assertEq(address(target).balance, 1 ether);
        assertEq(address(multisig).balance, 1 ether);
    }

    function testCall_CannotChangeTarget() public {
        deal(address(multisig), 1 ether);

        bytes memory data;

        bytes32 digest = _computeDigestForCall(address(0xbad), value, data, deadline, nonce);

        vm.expectRevert(0x439cc0cd); // VerificationFailed
        multisig.call(address(target), value, deadline, quorum, data, getSignatures_2_of_3(digest));
    }

    function testCall_CannotChangeValue() public {
        deal(address(multisig), 1 ether);

        bytes memory data;

        bytes32 digest = _computeDigestForCall(address(target), 0.99 ether, data, deadline, nonce);

        vm.expectRevert(0x439cc0cd); // VerificationFailed
        multisig.call(address(target), value, deadline, quorum, data, getSignatures_2_of_3(digest));
    }

    function testCall_CannotChangeData() public {
        deal(address(multisig), 1 ether);

        bytes memory data = abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = _computeDigestForCall(address(target), value, "", deadline, nonce);

        vm.expectRevert(0x439cc0cd); // VerificationFailed
        multisig.call(address(target), value, deadline, quorum, data, getSignatures_2_of_3(digest));
    }

    function testCall_CannotChangeNonce() public {
        deal(address(multisig), 1 ether);
        
        bytes memory data;

        bytes32 digest = _computeDigestForCall(address(target), value, data, deadline, nonce + 1);

        vm.expectRevert(0x439cc0cd); // VerificationFailed
        multisig.call(address(target), value, deadline, quorum, data, getSignatures_2_of_3(digest));
    }

    function testCall_CannotChangeQuorum() public {
        deal(address(multisig), 1 ether);
        
        bytes memory data;

        bytes32 digest = _computeDigestForCall(address(target), value, data, deadline, nonce);

        vm.expectRevert(0x439cc0cd); // VerificationFailed
        multisig.call(address(target), value, deadline, 1, data, getSignatures_1_of_3(digest));
    }

    function testCall_CannotCallWithInsufficientSigners() public {
        deal(address(multisig), 1 ether);

        bytes memory data;

        bytes32 digest = _computeDigestForCall(address(target), value, data, deadline, nonce);

        vm.expectRevert(0xc2ee9b9e); // InsufficientSigners
        multisig.call(address(target), value, deadline, quorum, data, getSignatures_1_of_3(digest));
    }
}
