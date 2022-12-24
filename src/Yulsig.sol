// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/// @notice Minimal and gas effecient multi-signature wallet.
/// @author 0xClandestine
contract Yulsig {
    /// -----------------------------------------------------------------------
    /// Mutables
    /// -----------------------------------------------------------------------

    bytes32 private verificationHash;

    uint256 private minimumSigners;

    uint256 private nonce;

    /// -----------------------------------------------------------------------
    /// Construction
    /// -----------------------------------------------------------------------

    constructor(bytes32 _hashOfSigners, uint256 _minimumSigners) {
        verificationHash = _hashOfSigners;
        minimumSigners = _minimumSigners;
    }

    /// -----------------------------------------------------------------------
    /// Multisig Logic
    /// -----------------------------------------------------------------------

    receive() external payable virtual {}

    fallback() external virtual payable {        
        assembly {
            if calldatasize() {
                let freeMemoryPointer := mload(0x40)
                /// -----------------------------------------------------------------------
                /// 1) Compute EIP-712 Domain Separator
                /// -----------------------------------------------------------------------

                // keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(name), keccak256(version), chainid, address))

                // First we copy each parameter of the separator into memory, starting at
                // 0, then each additional variable is offset by 32*n bytes. Since we've got
                // 5 words to store we start at pos 0x00 (0) and end at pos 0xa0 (32*5=160).

                // 0x00                 DOMAIN_TYPEHASH
                // 0x20                 keccak256(name)
                // 0x40                 keccak256(version)
                // 0x60                 block.chainid
                // 0x80                 address(this)

                // 0x00 -> DOMAIN_TYPEHASH
                mstore(0x00, 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f)
                // 0x20 -> keccak256(name)
                mstore(0x20, 0xcd4046335c6490bc800b62dfe4e32b5bbe64545e84e866aba69afbf5ce39f2df)
                // 0x40 -> keccak256(version)
                mstore(0x40, 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6)
                // 0x60 -> block.chainid
                mstore(0x60, chainid())
                // 0x80 -> address(this)
                mstore(0x80, address())

                // Then we hash the 5 variables, and store the output at pos 0x20 (32).
                // We store the value at 0x20 in order to leave space for the eip712 prefix
                // at pos 0x00 (0), which is needed for the the final eip712 hashed digest.

                // 0x00                 DOMAIN_TYPEHASH
                // 0x20                 DOMAIN_SEPARATOR() <------ Overwrote keccak256(name)
                // 0x40                 keccak256(version)
                // 0x60                 block.chainid
                // 0x80                 address(this)

                // 0x20 -> DOMAIN_SEPARATOR()
                mstore(0x20, keccak256(0x00, 0xa0))

                /// -----------------------------------------------------------------------
                /// 2) Compute EIP-712 Message Digest
                /// -----------------------------------------------------------------------

                // 0x00                 DOMAIN_TYPEHASH
                // 0x20                 DOMAIN_SEPARATOR()
                // 0x40                 keccak256(version)
                // 0x60                 ORDER_TYPEHASH     <------ Overwrote block.chainid
                // 0x80                 address(this)

                // 0x60 -> ORDER_TYPEHASH
                mstore(0x60, 0xaa3a4d0cd4c47557a58609818667017c466f80079033a1aa81f16097da102d43)

                // 0x00                 tx payload length PL  <------ Overwrote DOMAIN_TYPEHASH
                // 0x20                 DOMAIN_SEPARATOR()
                // 0x40                 keccak256(version)
                // 0x60                 ORDER_TYPEHASH     <------ Overwrote block.chainid
                // 0x80                 tx target          <------ Overwrote address(this)
                // 0x94 (0x80 + 20)     tx value
                // 0xb4 (0x94 + 32)     tx payload (start)

                // 0x80 -> target
                calldatacopy(0x80, 12, 0x14)
                // 0x94 -> value
                calldatacopy(0x94, 32, 0x20)
                // 0x00 -> payload length
                calldatacopy(0x00, 128, 0x20)
                // 0xb4 -> payload
                calldatacopy(0xb4, 160, mload(0x00))

                // 0x00                 tx payload length PL
                // 0x20                 DOMAIN_SEPARATOR()
                // 0x40                 message digest <------ Overwrote keccak256(version)
                // 0x60                 ORDER_TYPEHASH
                // 0x80                 tx target
                // 0x94 (0x80 + 20)     tx value
                // 0xb4 (0x94 + 32)     tx payload (start)
                // ???? (0xb4 + PL)     current nonce

                let nonceOffset := add(0xb4, mload(0x00))

                // nonceOffset -> current nonce
                mstore(nonceOffset, sload(nonce.slot))
                // nonce.slot -> current nonce + 1
                sstore(nonce.slot, add(mload(nonceOffset), 0x1))
                // 0x40 -> hashed message digest
                mstore(0x40, keccak256(0x60, add(0x74, mload(0x00))))

                /// -----------------------------------------------------------------------
                /// 3) Compute EIP-712 Digest
                /// -----------------------------------------------------------------------

                // 0x00 -> eip712 prefix
                mstore(0x00, 0x1901)
                // 0x00 -> eip712 digest
                mstore(0x00, keccak256(0x00, 0x60))

                /// -----------------------------------------------------------------------
                /// 4) Signer verification
                /// -----------------------------------------------------------------------

                calldatacopy(0x40, 0x80, 0x20) // payload length

                let payloadLength := mload(0x40)

                let payloadTotalWords :=
                    add(div(payloadLength, 0x20), iszero(iszero(mod(payloadLength, 0x20))))

                let totalSignersCalldataOffset := add(160, mul(payloadTotalWords, 0x20))

                calldatacopy(0x60, totalSignersCalldataOffset, 0x20) // elements

                let totalSigners := div(mload(0x60), 0x4)

                let totalNonSigners := 0

                // construct hash of signer addresses
                for { let i } lt(i, totalSigners) { i := add(i, 1) } {
                    let pos := add(0x200, mul(i, 32))

                    // copy next 4 words (signer, v, r, s)
                    calldatacopy(0x100, add(add(totalSignersCalldataOffset, 32), mul(i, 128)), 128)

                    let signer := mload(0x100)
                    let v := mload(0x120)
                    let r := mload(0x140)
                    let s := mload(0x160)

                    // if signer is zero
                    switch iszero(signer)
                    case true {
                        // note: yoinked from solady :P
                        // If `s` in lower half order, such that the signature is not malleable.
                        if iszero(
                            gt(
                                s,
                                0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
                            )
                        ) {
                            mstore(0x20, v)
                            mstore(0x40, r)
                            mstore(0x60, s)
                            pop(
                                staticcall(
                                    gas(), // Amount of gas left for the transaction.
                                    0x01, // Address of `ecrecover`.
                                    0x00, // Start of input.
                                    0x80, // Size of input.
                                    0x40, // Start of output.
                                    0x20 // Size of output.
                                )
                            )

                            // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                            let result := mload(sub(0x60, returndatasize()))

                            mstore(pos, result)
                        }
                    }
                    case false { totalNonSigners := add(totalNonSigners, 1) }
                }

                if iszero(eq(sload(verificationHash.slot), keccak256(0x200, 0x60))) { revert(0, 0) }

                if gt(sload(minimumSigners.slot), sub(totalSigners, totalNonSigners)) {
                    revert(0, 0)
                }

                /// -----------------------------------------------------------------------
                /// 5) External Call
                /// -----------------------------------------------------------------------

                // 0x60 -> payload length
                calldatacopy(0x60, 0x80, 0x20)
                // 0x80 -> target
                calldatacopy(0x80, 0x0, 0x20)
                // 0xa0 -> value
                calldatacopy(0xa0, 0x20, 0x20)
                // 0xc0 -> payload
                calldatacopy(0xc0, 0xa0, mload(0x60))

                let success := call(gas(), mload(0x80), mload(0xa0), 0xc0, mload(0x60), 0x0, 0x0)

                if iszero(success) { revert(0, 0) }

                // Restore the free memory pointer.
                mstore(0x40, freeMemoryPointer)
                // Restore the zero slot.
                mstore(0x60, 0x00)
            }
        }
    }
}
