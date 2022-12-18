// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Counter.sol";
import "../src/Multisig.sol";

contract MultisigTest is Test {
    /// -----------------------------------------------------------------------
    /// Testing Storage
    /// -----------------------------------------------------------------------

    Multisig ms;

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

        ms = new Multisig(signers);
        target = new Counter();
    }

    /// -----------------------------------------------------------------------
    /// Helpers
    /// -----------------------------------------------------------------------

    function getSigners() internal view returns (address[] memory addrs) {
        addrs = new address[](3);

        addrs[0] = addr0;

        addrs[1] = addr1;

        addrs[2] = addr2;
    }

    function getSignatures(bytes32 digest)
        internal
        view
        returns (Signature[] memory sigs)
    {
        sigs = new Signature[](3);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk0, digest);

        sigs[0] = Signature(v, r, s);

        (v, r, s) = vm.sign(pk1, digest);

        sigs[1] = Signature(v, r, s);

        (v, r, s) = vm.sign(pk2, digest);

        sigs[2] = Signature(v, r, s);
    }

    /// -----------------------------------------------------------------------
    /// Tests
    /// -----------------------------------------------------------------------

    function testBasic() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);
        bytes32 nullifier = 0x00;
        bytes32 digest =
            keccak256(abi.encode(address(target), 0, payload, nullifier));

        address[] memory signers = getSigners();
        Signature[] memory sigs = getSignatures(digest);

        Tx memory t =
            Tx(payable(address(target)), 0, signers, sigs, payload, nullifier);

        ms.execute(t);

        assertEq(target.number(), 420);
    }
}
