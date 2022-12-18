// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "solbase/utils/EIP712.sol";

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
    bytes32 nullifier;
    bool delegate;
    Signature[] signatures;
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

    constructor(address[] memory signers, uint256 _minimumConfirmations) {
        unchecked {
            uint256 _totalSigners = signers.length;

            for (uint256 i; i < _totalSigners; ++i) {
                ++totalSigners;

                isSigner[signers[i]] = true;
            }

            minimumConfirmations = _minimumConfirmations;
        }
    }

    /// -----------------------------------------------------------------------
    /// Multisig Logic
    /// -----------------------------------------------------------------------

    error InvalidSignature(address signer);

    function execute(Tx calldata t) external virtual {
        uint256 signers = t.signatures.length;

        if (signers < minimumConfirmations) revert();

        bytes32 digest = keccak256(
            abi.encodePacked(t.target, t.value, t.payload, t.nullifier)
        );

        if (isExecuted[digest]) revert();

        // Incrementing cannot reasonably overflow.
        unchecked {
            for (uint256 i; i < signers; ++i) {
                address signer = t.signatures[i].signer;
                if (
                    ecrecover(
                        digest,
                        t.signatures[i].v,
                        t.signatures[i].r,
                        t.signatures[i].s
                    ) != signer || !isSigner[signer]
                ) {
                    revert InvalidSignature(signer);
                }
            }
        }

        isExecuted[digest] = true;

        bool success;
        
        if (t.delegate) {
            (success,) = t.target.delegatecall(t.payload);
        } else {
            (success,) = t.target.call{value: t.value}(t.payload);
        }

        if (!success) revert();
    }

    event SignersChanged(address account, bool signer);

    function setSigner(address account, bool signer) external virtual {
        if (msg.sender != address(this)) revert();

        if (isSigner[account] == signer) revert();

        unchecked {
            if (signer) {
                ++totalSigners;
            } else {
                --totalSigners;
            }
        }

        if (totalSigners < minimumConfirmations) revert();

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
}
