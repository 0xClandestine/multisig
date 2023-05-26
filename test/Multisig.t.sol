// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {Counter} from "./Counter.sol";
import "../src/Multisig.sol";

contract MockMultisig is Multisig {
    constructor(address[] memory signers, uint256 quorum) Multisig(signers, quorum) {}

    function computeCallDigest(
        address target,
        uint256 value,
        bytes memory data,
        uint256 deadline,
        uint256 nonce
    ) external view returns (bytes32) {
        return _hashTypedData(
            keccak256(abi.encode(CALL_TYPEHASH, target, value, data, deadline, nonce))
        );
    }
}

contract MultisigTest is Test {
    /// -----------------------------------------------------------------------
    /// Testing Storage
    /// -----------------------------------------------------------------------

    MockMultisig multisig;
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

        uint256 quorum = 2;

        multisig = new MockMultisig(signers, quorum);
        target = new Counter();
    }

    /// -----------------------------------------------------------------------
    /// Helpers
    /// -----------------------------------------------------------------------

    function getSignatures_3_of_3(bytes32 digest) internal view returns (bytes[] memory sigs) {
        sigs = new bytes[](3);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk0, digest);
        sigs[0] = abi.encode(v, r, s);

        (v, r, s) = vm.sign(pk1, digest);
        sigs[1] = abi.encode(v, r, s);

        (v, r, s) = vm.sign(pk2, digest);
        sigs[2] = abi.encode(v, r, s);
    }

    function getSignatures_2_of_3(bytes32 digest) internal view returns (bytes[] memory sigs) {
        sigs = getSignatures_3_of_3(digest);
        sigs[0] = abi.encodePacked(addr0);
    }

    function getSignatures_1_of_3(bytes32 digest) internal view returns (bytes[] memory sigs) {
        sigs = getSignatures_2_of_3(digest);
        sigs[1] = abi.encodePacked(addr1);
    }

    /// -----------------------------------------------------------------------
    /// Tests
    /// -----------------------------------------------------------------------

    function testSendEther() public {
        deal(address(multisig), 1 ether);

        bytes memory data;

        uint256 value = 1 ether;
        uint256 deadline = block.timestamp;
        uint256 nonce = 0;
        uint256 quorum = 2;

        bytes32 digest =
            multisig.computeCallDigest(address(target), value, data, deadline, nonce);

        multisig.call(address(target), value, deadline, quorum, data, getSignatures_2_of_3(digest));

        assertEq(multisig.nonce(), 1);
        assertEq(address(target).balance, 1 ether);
    }

    // function testAttemptReplayAttack() public {
    //     bytes memory data = abi.encodeWithSelector(target.setNumber.selector, 420);

    //     bytes32 digest = getDigest(address(target), 0, false, data, 0);

    //     Tx memory t = Tx({
    //         target: payable(address(target)),
    //         value: 0,
    //         delegate: false,
    //         data: data,
    //         quorum: 2,
    //         signatures: getSignatures_2_of_3(digest)
    //     });

    //     multisig.execute(t);

    //     vm.expectRevert(VerificationFailed.selector);
    //     multisig.execute(t);

    //     assertEq(target.number(), 420);
    //     assertEq(multisig.nonce(), 1);
    // }

    // function testAttemptDoubleSignatureAttack() public {
    //     bytes memory data = abi.encodeWithSelector(target.setNumber.selector, 420);

    //     bytes32 digest = getDigest(address(target), 0, false, data, 0);

    //     Signature[] memory signatures = getSignatures_3_of_3(digest);
    //     signatures[1] = signatures[0];

    //     Tx memory t = Tx({
    //         target: payable(address(target)),
    //         value: 0,
    //         delegate: false,
    //         data: data,
    //         quorum: 2,
    //         signatures: signatures
    //     });

    //     vm.expectRevert(VerificationFailed.selector);
    //     multisig.execute(t);
    // }

    // function testAttemptBadTarget() public {
    //     Counter badTarget = new Counter();

    //     bytes memory data = abi.encodeWithSelector(target.setNumber.selector, 420);

    //     bytes32 digest = getDigest(address(target), 0, false, data, 0);

    //     Tx memory t = Tx({
    //         target: payable(address(badTarget)),
    //         value: 0,
    //         delegate: false,
    //         data: data,
    //         quorum: 2,
    //         signatures: getSignatures_2_of_3(digest)
    //     });

    //     vm.expectRevert(VerificationFailed.selector);
    //     multisig.execute(t);
    // }

    // function testAttemptBadValue() public {
    //     deal(address(multisig), 1 ether);

    //     bytes memory data = abi.encodeWithSelector(target.setNumber.selector, 420);

    //     bytes32 digest = getDigest(address(target), 0, false, data, 0);

    //     Tx memory t = Tx({
    //         target: payable(address(target)),
    //         value: 1 ether,
    //         delegate: false,
    //         data: data,
    //         quorum: 2,
    //         signatures: getSignatures_2_of_3(digest)
    //     });

    //     vm.expectRevert(VerificationFailed.selector);
    //     multisig.execute(t);
    // }

    // function testAttemptBadPayload() public {
    //     bytes memory data = abi.encodeWithSelector(target.setNumber.selector, 420);

    //     bytes32 digest = getDigest(address(target), 0, false, data, 0);

    //     Tx memory t = Tx({
    //         target: payable(address(target)),
    //         value: 0,
    //         delegate: false,
    //         data: new bytes(0),
    //         quorum: 2,
    //         signatures: getSignatures_2_of_3(digest)
    //     });

    //     vm.expectRevert(VerificationFailed.selector);
    //     multisig.execute(t);
    // }

    // function testAttemptBadNonce() public {
    //     bytes memory data = abi.encodeWithSelector(target.setNumber.selector, 420);

    //     bytes32 digest = getDigest(address(target), 0, false, data, 1);

    //     Tx memory t = Tx({
    //         target: payable(address(target)),
    //         value: 0,
    //         delegate: false,
    //         data: data,
    //         quorum: 2,
    //         signatures: getSignatures_2_of_3(digest)
    //     });

    //     vm.expectRevert(VerificationFailed.selector);
    //     multisig.execute(t);
    // }

    // function testAttemptInsufficientSigners() public {
    //     bytes memory data = abi.encodeWithSelector(target.setNumber.selector, 420);

    //     bytes32 digest = getDigest(address(target), 0, false, data, 0);

    //     Tx memory t = Tx({
    //         target: payable(address(target)),
    //         value: 0,
    //         delegate: false,
    //         data: data,
    //         quorum: 2,
    //         signatures: getSignatures_1_of_3(digest)
    //     });

    //     vm.expectRevert(InsufficientSigners.selector);
    //     multisig.execute(t);
    // }
}
