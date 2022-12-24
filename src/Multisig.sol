// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

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

error VerificationFailed();

error InsufficientSigners();

error ExecutionReverted();

/// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
bytes32 constant DOMAIN_TYPEHASH =
    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

bytes32 constant HASHED_DOMAIN_NAME = keccak256(bytes("Multisig"));

bytes32 constant HASHED_DOMAIN_VERSION = keccak256(bytes("1"));

/// @notice Minimal and gas effecient multi-signature wallet.
/// @author 0xClandestine
contract Multisig {
    /// -----------------------------------------------------------------------
    /// Mutables
    /// -----------------------------------------------------------------------

    uint256 public nonce;

    /// -----------------------------------------------------------------------
    /// Immutables
    /// -----------------------------------------------------------------------

    bytes32 public immutable VERIFICATION_HASH;

    uint256 public immutable MINIMUM_SIGNERS;

    constructor(bytes32 _HASH_OF_SIGNERS, uint256 _MINIMUM_SIGNERS) {
        VERIFICATION_HASH = _HASH_OF_SIGNERS;
        MINIMUM_SIGNERS = _MINIMUM_SIGNERS;
    }

    /// -----------------------------------------------------------------------
    /// Multisig Logic
    /// -----------------------------------------------------------------------

    receive() external payable virtual {}

    function execute(Tx calldata t) external virtual {
        unchecked {
            uint256 nonSigners;

            uint256 totalSigners = t.signatures.length;

            address[] memory signers = new address[](totalSigners);

            bytes32 digest = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    keccak256(
                        abi.encode(
                            DOMAIN_TYPEHASH,
                            HASHED_DOMAIN_NAME,
                            HASHED_DOMAIN_VERSION,
                            block.chainid,
                            address(this)
                        )
                    ),
                    keccak256(
                        abi.encodePacked(
                            keccak256(
                                "execute(address target,uint256 value,bytes payload,uint256 nonce)"
                            ),
                            t.target,
                            t.value,
                            t.payload,
                            nonce++
                        )
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
            if (totalSigners - nonSigners < MINIMUM_SIGNERS) {
                revert InsufficientSigners();
            }

            // assert hash of all signers is equal to VERIFICATION_HASH
            if (keccak256(abi.encodePacked(signers)) != VERIFICATION_HASH) {
                revert VerificationFailed();
            }

            // call target contract with tx value and payload
            (bool success,) = t.target.call{value: t.value}(t.payload);

            // assert call is successful
            if (!success) revert ExecutionReverted();
        }
    }
}
