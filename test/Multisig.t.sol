// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "./Counter.sol";
import "../src/Multisig.sol";

contract MultisigMock is Multisig {
    constructor(bytes32 signerHash, uint256 required)
        Multisig(signerHash, required)
    {}

    function _computeDigest(bytes32 digest) external view returns (bytes32) {
        return computeDigest(digest);
    }
}

contract MultisigTest is Test {
    /// -----------------------------------------------------------------------
    /// Testing Storage
    /// -----------------------------------------------------------------------

    MultisigMock ms;
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

        address[] memory signers = new address[](3);

        signers[0] = addr0;
        signers[1] = addr1;
        signers[2] = addr2;

        bytes32 hashOfSigners = keccak256(abi.encodePacked(signers));

        ms = new MultisigMock(hashOfSigners, 2);
        target = new Counter();
    }

    /// -----------------------------------------------------------------------
    /// Helpers
    /// -----------------------------------------------------------------------

    function getSignatures_3_of_3(bytes32 digest)
        internal
        returns (
            // view
            Signature[] memory sigs
        )
    {
        sigs = new Signature[](3);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk0, digest);
        sigs[0] = Signature(address(0), v, r, s);

        (v, r, s) = vm.sign(pk1, digest);
        sigs[1] = Signature(address(0), v, r, s);

        (v, r, s) = vm.sign(pk2, digest);
        sigs[2] = Signature(address(0), v, r, s);
    }

    function getSignatures_2_of_3(bytes32 digest)
        internal
        returns (
            // view
            Signature[] memory sigs
        )
    {
        sigs = getSignatures_3_of_3(digest);
        sigs[0].signer = addr0;
    }

    function getSignatures_1_of_3(bytes32 digest)
        internal
        returns (
            // view
            Signature[] memory sigs
        )
    {
        sigs = getSignatures_2_of_3(digest);
        sigs[1].signer = addr1;
    }

    /// -----------------------------------------------------------------------
    /// Tests
    /// -----------------------------------------------------------------------

    function testBasic() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = ms._computeDigest(
            keccak256(
                abi.encodePacked(
                    address(target), uint256(0), payload, uint256(0)
                )
            )
        );

        Tx memory t = Tx(
            payable(address(target)), 0, payload, getSignatures_2_of_3(digest)
        );

        ms.execute(t);

        assertEq(target.number(), 420);
    }
}
