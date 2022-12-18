// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "solbase/utils/EIP712.sol";

struct Signature {
    uint8 v;
    bytes32 r;
    bytes32 s;
}

struct Tx {
    address payable target;
    uint256 value;
    address[] signers;
    Signature[] signatures;
    bytes payload;
    bytes32 nullifier;
}

contract Multisig is EIP712("Multisig", "1") {
    /// -----------------------------------------------------------------------
    /// Multisig Storage
    /// -----------------------------------------------------------------------

    uint256 public totalSigners;

    uint256 public minimumConfirmations;

    mapping(address => bool) public isSigner;

    mapping(bytes32 => bool) public isExecuted;

    /// -----------------------------------------------------------------------
    /// Construction
    /// -----------------------------------------------------------------------

    constructor(address[] memory signers) {
        unchecked {
            for (uint256 i; i < signers.length; ++i) {
                ++totalSigners;

                isSigner[signers[i]] = true;

                emit SignersChanged(signers[i], true);
            }
        }
    }

    /// -----------------------------------------------------------------------
    /// Multisig Logic
    /// -----------------------------------------------------------------------

    // TODO salted contract deployment function

    event SignersChanged(address account, bool signer);

    function updateSigner(address account, bool signer) external virtual {
        if (msg.sender != address(this)) revert();

        if (isSigner[account] == signer) revert();

        unchecked {
            if (signer) ++totalSigners;
        }

        isSigner[account] = signer;

        emit SignersChanged(account, signer);
    }

    event MinimumConfirmationsChanged(uint256 minConfirmations);

    function setMinimumConfirmations(uint256 minConfirmations)
        external
        virtual
    {
        if (msg.sender != address(this)) revert();

        minimumConfirmations = minConfirmations;

        emit MinimumConfirmationsChanged(minConfirmations);
    }

    error InvalidSignature(address signer);

    function execute(Tx calldata t) external virtual {
        uint256 signers = t.signers.length;

        if (signers != t.signatures.length) revert();

        if (signers < minimumConfirmations) revert();

        bytes32 digest =
            keccak256(abi.encode(t.target, t.value, t.payload, t.nullifier));

        if (isExecuted[digest]) revert();

        // Incrementing cannot reasonably overflow.
        unchecked {
            for (uint256 i; i < signers; ++i) {
                if (
                    ecrecover(
                        digest,
                        t.signatures[i].v,
                        t.signatures[i].r,
                        t.signatures[i].s
                    ) != t.signers[i] || !isSigner[t.signers[i]]
                ) {
                    revert InvalidSignature(t.signers[i]);
                }
            }
        }

        isExecuted[digest] = true;

        (bool success,) = t.target.call{value: t.value}(t.payload);

        if (!success) revert();
    }
}
