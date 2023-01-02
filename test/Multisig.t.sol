// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Counter} from "./Counter.sol";
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

        uint256 quorum = 2;

        bytes32 verificationHash = keccak256(abi.encodePacked(signers, quorum));

        ms = new Multisig(verificationHash);
        target = new Counter();
    }

    /// -----------------------------------------------------------------------
    /// Helpers
    /// -----------------------------------------------------------------------

    function getSignatures_3_of_3(bytes32 digest)
        internal
        view
        returns (Signature[] memory sigs)
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
        view
        returns (Signature[] memory sigs)
    {
        sigs = getSignatures_3_of_3(digest);
        sigs[0].signer = addr0;
    }

    function getSignatures_1_of_3(bytes32 digest)
        internal
        view
        returns (Signature[] memory sigs)
    {
        sigs = getSignatures_2_of_3(digest);
        sigs[1].signer = addr1;
    }

    function getDigest(
        address _target,
        uint256 _value,
        bool _delegate,
        bytes memory _payload,
        uint256 _nonce
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                keccak256(
                    abi.encode(
                        DOMAIN_TYPEHASH,
                        HASHED_DOMAIN_NAME,
                        HASHED_DOMAIN_VERSION,
                        block.chainid,
                        address(ms)
                    )
                ),
                keccak256(
                    abi.encodePacked(
                        keccak256(
                            "execute(address target,uint256 value,bool delegate,bytes payload,uint256 nonce)"
                        ),
                        _target,
                        _value,
                        _delegate,
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

        bytes memory payload;

        bytes32 digest = getDigest(address(target), 1 ether, false, payload, 0);

        Tx memory t = Tx({
            target: payable(address(target)),
            value: 1 ether,
            delegate: false,
            payload: payload,
            quorum: 2,
            signatures: getSignatures_2_of_3(digest)
        });

        ms.execute(t);

        vm.expectRevert(VerificationFailed.selector);
        ms.execute(t);

        assertEq(ms.nonce(), 1);
        assertEq(address(target).balance, 1 ether);
    }

    function testAttemptReplayAttack() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, false, payload, 0);

        Tx memory t = Tx({
            target: payable(address(target)),
            value: 0,
            delegate: false,
            payload: payload,
            quorum: 2,
            signatures: getSignatures_2_of_3(digest)
        });

        ms.execute(t);

        vm.expectRevert(VerificationFailed.selector);
        ms.execute(t);

        assertEq(target.number(), 420);
        assertEq(ms.nonce(), 1);
    }

    function testAttemptDoubleSignatureAttack() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, false, payload, 0);

        Signature[] memory signatures = getSignatures_3_of_3(digest);
        signatures[1] = signatures[0];

        Tx memory t = Tx({
            target: payable(address(target)),
            value: 0,
            delegate: false,
            payload: payload,
            quorum: 2,
            signatures: signatures
        });

        vm.expectRevert(VerificationFailed.selector);
        ms.execute(t);
    }

    function testAttemptBadTarget() public {
        Counter badTarget = new Counter();

        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, false, payload, 0);

        Tx memory t = Tx({
            target: payable(address(badTarget)),
            value: 0,
            delegate: false,
            payload: payload,
            quorum: 2,
            signatures: getSignatures_2_of_3(digest)
        });

        vm.expectRevert(VerificationFailed.selector);
        ms.execute(t);
    }

    function testAttemptBadValue() public {
        deal(address(ms), 1 ether);

        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, false, payload, 0);

        Tx memory t = Tx({
            target: payable(address(target)),
            value: 1 ether,
            delegate: false,
            payload: payload,
            quorum: 2,
            signatures: getSignatures_2_of_3(digest)
        });

        vm.expectRevert(VerificationFailed.selector);
        ms.execute(t);
    }

    function testAttemptBadPayload() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, false, payload, 0);

        Tx memory t = Tx({
            target: payable(address(target)),
            value: 0,
            delegate: false,
            payload: new bytes(0),
            quorum: 2,
            signatures: getSignatures_2_of_3(digest)
        });

        vm.expectRevert(VerificationFailed.selector);
        ms.execute(t);
    }

    function testAttemptBadNonce() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, false, payload, 1);

        Tx memory t = Tx({
            target: payable(address(target)),
            value: 0,
            delegate: false,
            payload: payload,
            quorum: 2,
            signatures: getSignatures_2_of_3(digest)
        });

        vm.expectRevert(VerificationFailed.selector);
        ms.execute(t);
    }

    function testAttemptInsufficientSigners() public {
        bytes memory payload =
            abi.encodeWithSelector(target.setNumber.selector, 420);

        bytes32 digest = getDigest(address(target), 0, false, payload, 0);

        Tx memory t = Tx({
            target: payable(address(target)),
            value: 0,
            delegate: false,
            payload: payload,
            quorum: 2,
            signatures: getSignatures_1_of_3(digest)
        });

        vm.expectRevert(InsufficientSigners.selector);
        ms.execute(t);
    }
}
