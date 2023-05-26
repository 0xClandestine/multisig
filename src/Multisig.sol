// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "solady/utils/EIP712.sol";

error VerificationFailed();
error InsufficientSigners();
error ExecutionReverted();

// keccak256("Call(address target,uint256 value,bytes data,uint256 deadline,uint256 nonce)");
bytes32 constant CALL_TYPEHASH = 0xd4149930d6ff08a361ca75aaedd2a3496dc25f7489b21179b7408a9d78d15b96;

// keccak256("Delegate(address target,bytes data,uint256 deadline,uint256 nonce)");
bytes32 constant DELEGATE_CALL_TYPEHASH =
    0x1a6fe3733e53c3d6a401b5c27d307e2a02d06a855ba7175032d8a686c37617d1;

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

        _setSignersAndQuorum(signers, quorum);
    }

    /// -----------------------------------------------------------------------
    /// Execution
    /// -----------------------------------------------------------------------

    function _verify(bytes32 digest, uint256 quorum, bytes[] calldata signatures)
        internal
        virtual
    {
        address[] memory signers = new address[](signatures.length);

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

        // Assert the list of signers and quorum are correct.
        if (keccak256(abi.encodePacked(signers, quorum)) != signersAndQuorumHash) {
            revert VerificationFailed();
        }

        // Assert m-of-n of the signers have signed.
        if (signatures.length - totalNonSigners < quorum) {
            revert InsufficientSigners();
        }
    }

    function call(
        address target,
        uint256 value,
        uint256 deadline,
        uint256 quorum,
        bytes calldata data,
        bytes[] calldata signatures
    ) external payable virtual {
        unchecked {
            bytes32 digest = _hashTypedData(
                keccak256(abi.encode(CALL_TYPEHASH, target, value, data, deadline, nonce++))
            );

            _verify(digest, quorum, signatures);

            (bool success,) = target.call{value: value}(data);

            if (!success) revert ExecutionReverted();
        }
    }

    function delegatecall(
        address target,
        uint256 deadline,
        uint256 quorum,
        bytes calldata data,
        bytes[] calldata signatures
    ) external payable virtual {
        unchecked {
            bytes32 digest = _hashTypedData(
                keccak256(abi.encode(DELEGATE_CALL_TYPEHASH, target, data, deadline, nonce++))
            );

            _verify(digest, quorum, signatures);

            (bool success,) = target.delegatecall(data);

            if (!success) revert ExecutionReverted();
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
