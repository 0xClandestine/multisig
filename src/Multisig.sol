// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "solady/utils/EIP712.sol";
import "solady/utils/ECDSA.sol";

error VerificationFailed();
error InsufficientSigners();
error ExecutionReverted();

// keccak256("Tx(address target,uint256 value,bool delegate,bytes payload,uint256 deadline,uint256 nonce)");
bytes32 constant TX_TYPEHASH = 0xafe0c581cad4b7c13925ee4d470d0dba861dfb871cb796cdb711c2f4449bf69d;

/// @notice Minimal and gas efficient multi-signature wallet.
/// @author 0xClandestine
abstract contract Multisig is EIP712 {
    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    event SignersAndQuorumSet(address[] signers, uint256 quorum);

    /// -----------------------------------------------------------------------
    /// Storage
    /// -----------------------------------------------------------------------

    bytes32 public signersAndQuorumHash;

    uint256 public nonce;

    /// -----------------------------------------------------------------------
    /// Construction
    /// -----------------------------------------------------------------------

    constructor(address[] memory signers, uint256 quorum) {
        _setSignersAndQuorum(signers, quorum);
    }

    /// -----------------------------------------------------------------------
    /// Setters
    /// -----------------------------------------------------------------------

    function _setSignersAndQuorum(address[] memory signers, uint256 quorum) internal virtual {
        signersAndQuorumHash = keccak256(abi.encodePacked(signers, quorum));

        emit SignersAndQuorumSet(signers, quorum);
    }

    function setSignersAndQuorum(address[] memory signers, uint256 quorum) external virtual {
        if (msg.sender != address(this)) revert VerificationFailed();

        signersAndQuorumHash = keccak256(abi.encodePacked(signers, quorum));

        emit SignersAndQuorumSet(signers, quorum);
    }

    /// -----------------------------------------------------------------------
    /// Execution
    /// -----------------------------------------------------------------------

    /// @notice Executes a transaction.
    /// @param target The target address of the transaction.
    /// @param value The value of the transaction.
    /// @param delegate A flag indicating whether to delegate the call or not.
    /// @param deadline The deadline for the transaction.
    /// @param quorum The quorum required for the transaction.
    /// @param payload The payload data of the transaction.
    /// @param signatures The signatures of the signers.
    /// @dev Signatures must be in order and must be replaced with the relevant signer's address if they're not signing.
    function execute(
        address target,
        uint256 value,
        bool delegate,
        uint256 deadline,
        uint256 quorum,
        bytes calldata payload,
        bytes[] calldata signatures
    ) external payable virtual {
        unchecked {
            address[] memory signers = new address[](signatures.length);

            bytes32 digest = _hashTypedData(
                keccak256(
                    abi.encode(TX_TYPEHASH, target, value, delegate, payload, deadline, nonce++)
                )
            );

            uint256 totalNonSigners;

            for (uint256 i; i < signatures.length; ++i) {
                if (signatures[i].length != 20) {
                    (uint8 v, bytes32 r, bytes32 s) =
                        abi.decode(signatures[i], (uint8, bytes32, bytes32));

                    signers[i] = ecrecover(digest, v, r, s);
                } else {
                    signers[i] = address(bytes20(signatures[i]));

                    ++totalNonSigners;
                }
            }

            // Assert the recovered list of signers and quorum are correct.
            if (keccak256(abi.encodePacked(signers, quorum)) != signersAndQuorumHash) {
                revert VerificationFailed();
            }

            // Assert m-of-n of the signers have signed.
            if (signatures.length - totalNonSigners < quorum) {
                revert InsufficientSigners();
            }

            (bool success,) =
                delegate ? target.delegatecall(payload) : target.call{value: value}(payload);

            // Assert the transaction succeeded.
            if (!success) {
                revert ExecutionReverted();
            }
        }
    }

    /// -----------------------------------------------------------------------
    /// EIP712
    /// -----------------------------------------------------------------------

    function _domainNameAndVersion()
        internal
        pure
        virtual
        override
        returns (string memory name, string memory version)
    {
        return ("Multisig", "1");
    }
}
