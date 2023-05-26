// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "solady/utils/ECDSA.sol";
import "solady/utils/EIP712.sol";

error Initialized();
error VerificationFailed();
error InsufficientSigners();
error ExecutionReverted();

// keccak256("Call(address target,uint256 value,bytes32 dataHash,uint256 deadline,uint256 nonce)");
bytes32 constant CALL_TYPEHASH = 0x4e885c46927d6b127eac2c84c43441f25504c49f72e87e9f0de0eb4dedb8e719;

// keccak256("Delegate(address target,bytes32 dataHash,uint256 deadline,uint256 nonce)");
bytes32 constant DELEGATE_CALL_TYPEHASH =
    0x4905d9a8afc9807f420f1bfff786e56d59f8df3cf6b84eb4559d5a3f922488c6;

/// @notice Minimal and gas efficient multi-signature wallet.
/// @author 0xClandestine
contract Multisig is EIP712 {
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

    function initialize(address[] memory signers, uint256 quorum) external virtual {
        if (signersAndQuorumHash != bytes32(0)) revert Initialized();

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
                signers[i] = ECDSA.recover(digest, signatures[i]);
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
            _verify(
                _hashTypedData(
                    keccak256(
                        abi.encode(CALL_TYPEHASH, target, value, keccak256(data), deadline, nonce++)
                    )
                ),
                quorum,
                signatures
            );

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
            _verify(
                _hashTypedData(
                    keccak256(
                        abi.encode(
                            DELEGATE_CALL_TYPEHASH, target, keccak256(data), deadline, nonce++
                        )
                    )
                ),
                quorum,
                signatures
            );

            (bool success,) = target.delegatecall(data);

            if (!success) revert ExecutionReverted();
        }
    }

    /// -----------------------------------------------------------------------
    /// EIP712
    /// -----------------------------------------------------------------------

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

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
