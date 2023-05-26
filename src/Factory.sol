// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "solady/utils/LibClone.sol";
import "solady/utils/SafeTransferLib.sol";

import "./Multisig.sol";

/// @notice Minimal and gas efficient multi-signature wallet factory.
/// @author 0xClandestine
contract Factory {
    /// -----------------------------------------------------------------------
    /// Dependencies
    /// -----------------------------------------------------------------------

    using LibClone for address;
    using SafeTransferLib for address;

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    event Deployment(address instance, address[] signers, uint256 quorum);

    /// -----------------------------------------------------------------------
    /// Immutable Storage
    /// -----------------------------------------------------------------------

    address internal immutable implementation;

    /// -----------------------------------------------------------------------
    /// Construction
    /// -----------------------------------------------------------------------

    constructor() {
        implementation = address(new Multisig(new address[](0), 0));
    }

    /// -----------------------------------------------------------------------
    /// Management Actions
    /// -----------------------------------------------------------------------

    function createMultisig(address[] memory signers, uint256 quorum, bytes32 salt)
        external
        payable
        virtual
        returns (address instance)
    {
        instance = implementation.cloneDeterministic(salt);

        Multisig(instance).initialize(signers, quorum);

        if (msg.value > 0) implementation.safeTransferETH(msg.value);

        emit Deployment(instance, signers, quorum);
    }

    /// -----------------------------------------------------------------------
    /// Read-only Clone Helper Logic
    /// -----------------------------------------------------------------------

    function predictDeterministicAddress(bytes32 salt) external view virtual returns (address) {
        return implementation.predictDeterministicAddress(salt, address(this));
    }

    function predictInitCodeHash(
        address underlyingAsset,
        uint96 quoteBondAmount,
        uint64 quoteDisputeWindow,
        uint64 emergencyWindow
    ) external view virtual returns (bytes32) {
        return implementation.initCodeHash();
    }
}
