// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "solbase/utils/EIP712.sol";

/// @dev If signer is non-zero we assume this signer has not signed the current tx.
struct Signature {
    address signer;
    uint8 v;
    bytes32 r;
    bytes32 s;
}

struct Tx {
    address payable target;
    uint256 value;
    bytes payload;
    Signature[] signatures;
}

error InvalidSignerHash();
error InvalidMinSigners();
error InvalidCall();

contract Multisig is EIP712("Multisig", "1") {
    /// -----------------------------------------------------------------------
    /// Mutables
    /// -----------------------------------------------------------------------

    uint256 public nonce;

    /// -----------------------------------------------------------------------
    /// Immutables
    /// -----------------------------------------------------------------------

    bytes32 public immutable VERIFICATION_HASH;

    uint256 public immutable MIN_SIGNERS;

    constructor(bytes32 _HASH_OF_SIGNERS, uint256 _MIN_SIGNERS) {
        VERIFICATION_HASH = _HASH_OF_SIGNERS;
        MIN_SIGNERS = _MIN_SIGNERS;
    }

    /// -----------------------------------------------------------------------
    /// Multisig Logic
    /// -----------------------------------------------------------------------

    receive() external payable virtual {}

    function execute(Tx calldata t) external virtual {
        uint256 nonSigners;

        uint256 totalSigners = t.signatures.length;

        address[] memory signers = new address[](totalSigners);

        unchecked {
            bytes32 digest = computeDigest(
                keccak256(
                    abi.encodePacked(
                        keccak256(
                            "Order(address target,uint256 value,bytes payload,uint256 nonce)"
                        ),
                        t.target,
                        t.value,
                        t.payload,
                        nonce++
                    )
                )
            );

            for (uint256 i; i < totalSigners; ++i) {
                address signer = t.signatures[i].signer;

                if (signer == address(0)) {
                    signers[i] = ecrecover(
                        digest,
                        t.signatures[i].v,
                        t.signatures[i].r,
                        t.signatures[i].s
                    );
                } else {
                    signers[i] = signer;

                    ++nonSigners;
                }
            }

            // assert m-of-n signers are required for tx to execute
            if (totalSigners - nonSigners < MIN_SIGNERS) {
                revert InvalidMinSigners();
            }

            // assert hash of all signers is equal to VERIFICATION_HASH
            if (keccak256(abi.encodePacked(signers)) != VERIFICATION_HASH) {
                revert InvalidSignerHash();
            }

            // call target contract with tx value and payload
            (bool success,) = t.target.call{value: t.value}(t.payload);

            // assert call is successful
            if (!success) revert InvalidCall();
        }
    }
}
