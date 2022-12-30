// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {EIP712} from "solbase/utils/EIP712.sol";

struct Signature {
    address signer;
    uint8 v;
    bytes32 r;
    bytes32 s;
}

error VerificationFailed();
error InsufficientSigners();
error ExecutionReverted();

contract CheaperExecutionModule is EIP712 {
    /// -----------------------------------------------------------------------
    /// Mutables
    /// -----------------------------------------------------------------------

    bytes32 public verificationHash; // order matters

    uint256 public nonce;

    /// -----------------------------------------------------------------------
    /// Immutables
    /// -----------------------------------------------------------------------

    Safe public immutable safe;

    constructor(Safe _safe, address[] memory signers, uint256 quorum)
        EIP712("Cheaper Execution Module", "1")
    {
        safe = _safe;

        verificationHash = keccak256(abi.encodePacked(signers, quorum));
    }

    /// -----------------------------------------------------------------------
    /// Safe Module Logic
    /// -----------------------------------------------------------------------

    receive() external payable virtual {
        payable(address(safe)).transfer(address(this).balance);
    }

    // TODO support contract signatures
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Safe.Operation operation,
        uint256 quorum,
        Signature[] memory signatures
    ) external virtual {
        unchecked {
            address[] memory signers = new address[](signatures.length);

            uint256 totalSigners = signatures.length;

            uint256 nonSigners;

            bytes32 digest = computeDigest(
                keccak256(
                    abi.encodePacked(
                        keccak256(
                            "Execute(address to,uint256 value,bytes data,Operation operation,uint256 quorum,uint256 nonce)"
                        ),
                        to,
                        value,
                        data,
                        operation,
                        quorum,
                        nonce++
                    )
                )
            );

            for (uint256 i; i < totalSigners; ++i) {
                address signer = signatures[i].signer;

                if (signer == address(0)) {
                    signers[i] = ecrecover(
                        digest,
                        signatures[i].v,
                        signatures[i].r,
                        signatures[i].s
                    );
                } else {
                    signers[i] = signer;

                    ++nonSigners;
                }
            }

            // assert hash of all signers and quorum is equal to VERIFICATION_HASH
            if (
                keccak256(abi.encodePacked(signers, quorum)) != verificationHash
            ) {
                revert VerificationFailed();
            }

            // assert m-of-n signers are required for tx to execute
            if (totalSigners - nonSigners < quorum) {
                revert InsufficientSigners();
            }

            if (!safe.execTransactionFromModule(to, value, data, operation)) {
                revert ExecutionReverted();
            }
        }
    }
}

abstract contract Safe {
    enum Operation {
        Call,
        DelegateCall
    }

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Operation operation
    ) external virtual returns (bool success);
}
