// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Yulsig} from "../src/Yulsig.sol";
import {Counter} from "./Counter.sol";

contract YulsigTest is Test {
    /// -----------------------------------------------------------------------
    /// Testing Storage
    /// -----------------------------------------------------------------------

    Yulsig ms;
    Counter target;

    address addr0;
    uint256 pk0;

    address addr1;
    uint256 pk1;

    address addr2;
    uint256 pk2;

    /// -----------------------------------------------------------------------
    /// Setup
    /// -----------------------------------------------------------------------

    function setUp() public {
        (addr0, pk0) = makeAddrAndKey("addr0");
        (addr1, pk1) = makeAddrAndKey("addr1");
        (addr2, pk2) = makeAddrAndKey("addr2");

        ms = new Yulsig(keccak256(abi.encode(addr0, addr1, addr2)), 2);
        target = new Counter();
    }

    /// -----------------------------------------------------------------------
    /// Helpers
    /// -----------------------------------------------------------------------

    function getSignatures_3_of_3(bytes32 digest)
        internal
        returns (bytes32[] memory sigs)
    {
        sigs = new bytes32[](3*4);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk0, digest);
        sigs[0] = 0;
        sigs[1] = bytes32(uint256(v));
        sigs[2] = bytes32(r);
        sigs[3] = bytes32(s);

        (v, r, s) = vm.sign(pk1, digest);
        sigs[4] = 0;
        sigs[5] = bytes32(uint256(v));
        sigs[6] = bytes32(r);
        sigs[7] = bytes32(s);

        (v, r, s) = vm.sign(pk2, digest);
        sigs[8] = 0;
        sigs[9] = bytes32(uint256(v));
        sigs[10] = bytes32(r);
        sigs[11] = bytes32(s);
    }

    function getSignatures_1_of_3(bytes32 digest)
        internal
        returns (bytes32[] memory sigs)
    {
        sigs = new bytes32[](3*4);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk0, digest);
        sigs[0] = 0;
        sigs[1] = bytes32(uint256(v));
        sigs[2] = bytes32(r);
        sigs[3] = bytes32(s);

        (v, r, s) = vm.sign(pk1, digest);
        sigs[4] = bytes32(uint256(uint160(addr1)));
        sigs[5] = bytes32(0);
        sigs[6] = bytes32(0);
        sigs[7] = bytes32(0);

        (v, r, s) = vm.sign(pk2, digest);
        sigs[8] = bytes32(uint256(uint160(addr2)));
        sigs[9] = bytes32(0);
        sigs[10] = bytes32(0);
        sigs[11] = bytes32(0);
    }

    function getDigest(
        address _target,
        uint256 _value,
        bytes memory _payload,
        uint256 _nonce
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes32(
                    0x0000000000000000000000000000000000000000000000000000000000001901
                ),
                keccak256(
                    abi.encode(
                        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                        0xcd4046335c6490bc800b62dfe4e32b5bbe64545e84e866aba69afbf5ce39f2df,
                        0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6,
                        block.chainid,
                        address(ms)
                    )
                ),
                keccak256(
                    abi.encodePacked(
                        bytes32(
                            0xaa3a4d0cd4c47557a58609818667017c466f80079033a1aa81f16097da102d43
                        ),
                        _target,
                        _value,
                        _payload,
                        _nonce
                    )
                )
            )
        );
    }

    /// -----------------------------------------------------------------------
    /// Tests
    /// -----------------------------------------------------------------------

    function testSendEther() public {
        deal(address(ms), 1 ether);
        assertEq(address(ms).balance, 1 ether);

        bytes32 digest = getDigest(address(target), 1 ether, hex"", 0);

        bytes memory transaction =
            abi.encode(target, 1 ether, hex"", getSignatures_3_of_3(digest));

        address(ms).call(transaction);

        // assertEq(ms.nonce(), 1);
        assertEq(address(target).balance, 1 ether);
    }

    function testAttemptReplayAttack() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, payload, 0);

        bytes memory transaction =
            abi.encode(target, 0, payload, getSignatures_3_of_3(digest));

        address(ms).call(transaction);

        vm.expectRevert();
        address(ms).call(transaction);

        // assertEq(ms.nonce(), 1);
        assertEq(target.number(), 420);
    }

    function testAttemptDoubleSignatureAttack() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, payload, 0);

        bytes32[] memory signatures = getSignatures_3_of_3(digest);

        signatures[0] = signatures[4];
        signatures[1] = signatures[5];
        signatures[2] = signatures[6];
        signatures[3] = signatures[7];

        bytes memory transaction = abi.encode(target, 0, payload, signatures);

        vm.expectRevert();
        address(ms).call(transaction);
    }

    function testAttemptBadTarget() public {
        Counter badTarget = new Counter();

        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, payload, 0);

        bytes memory transaction =
            abi.encode(badTarget, 0, payload, getSignatures_3_of_3(digest));

        vm.expectRevert();
        address(ms).call(transaction);
    }

    function testAttemptBadValue() public {
        deal(address(ms), 1 ether);

        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, payload, 0);

        bytes memory transaction =
            abi.encode(target, 1 ether, payload, getSignatures_3_of_3(digest));

        vm.expectRevert();
        address(ms).call(transaction);
    }

    function testAttemptBadPayload() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes memory badPayload =
            abi.encodeWithSelector(target.setNumber.selector, 69);

        bytes32 digest = getDigest(address(target), 0, payload, 0);

        bytes memory transaction =
            abi.encode(target, 0, badPayload, getSignatures_3_of_3(digest));

        vm.expectRevert();
        address(ms).call(transaction);
    }

    function testAttemptBadNonce() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, payload, 1);

        bytes memory transaction =
            abi.encode(target, 0, payload, getSignatures_3_of_3(digest));

        vm.expectRevert();
        address(ms).call(transaction);
    }

    function testAttemptInsufficientSigners() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, payload, 0);

        bytes memory transaction =
            abi.encode(target, 0, payload, getSignatures_1_of_3(digest));

        vm.expectRevert();
        address(ms).call(transaction);
    }
}
