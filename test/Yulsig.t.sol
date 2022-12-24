// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "./Counter.sol";
import "../src/Yulsig.sol";

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

        bytes32 hashOfSigners;

        assembly {
            mstore(mload(0x40), sload(addr0.slot))
            mstore(add(mload(0x40), 0x20), sload(addr1.slot))
            mstore(add(mload(0x40), 0x40), sload(addr2.slot))

            hashOfSigners := keccak256(mload(0x40), 0x60)
        }

        ms = new Yulsig(hashOfSigners, 2);
        target = new Counter();
    }

    /// -----------------------------------------------------------------------
    /// Helpers
    /// -----------------------------------------------------------------------

    function getSignatures_3_of_3(bytes32 digest) internal returns (bytes32[] memory sigs) {
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

    function getDigest(address _target, uint256 _value, bytes memory _payload, uint256 _nonce)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                bytes32(0x0000000000000000000000000000000000000000000000000000000000001901),
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
                        bytes32(0xaa3a4d0cd4c47557a58609818667017c466f80079033a1aa81f16097da102d43),
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

        bytes32 digest = getDigest(address(target), 1 ether, hex'', 0);

        bytes memory transaction = abi.encode(
            target, 1 ether, hex'', getSignatures_3_of_3(digest)
        );

        address(ms).call(transaction);

        // assertEq(ms.nonce(), 1);
        assertEq(address(target).balance, 1 ether);
    }

    function testAttemptReplayAttack() public {
        bytes memory payload = abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, payload, 0);

        bytes memory transaction = abi.encode(
            target, 0, payload, getSignatures_3_of_3(digest)
        );

        address(ms).call(transaction);

        vm.expectRevert();
        address(ms).call(transaction);

        assertEq(target.number(), 420);
        // assertEq(ms.nonce(), 1);
    }
}
