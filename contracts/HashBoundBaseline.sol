// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title HashBoundBaseline - conventional hash-bound approval anchoring (comparison baseline)
/// @notice An authorized validator signs only the data hash; the contract anchors any record
///         whose submitted hash carries a valid authorized signature, once per record.
///         No version registry, record context, deadline, plant assignment, or rejection trail.
contract HashBoundBaseline is EIP712 {
    bytes32 public constant HASH_APPROVAL_TYPEHASH = keccak256("HashApproval(bytes32 dataHash,address validator)");

    address public immutable admin;
    mapping(address => bool) public authorizedValidator;
    mapping(bytes32 => bool) public anchored;
    mapping(bytes32 => bytes32) public anchoredDataHash;

    error NOT_ADMIN();
    error ALREADY_ANCHORED();
    error INVALID_APPROVAL_SIGNATURE();
    error UNAUTHORIZED_VALIDATOR();

    event RecordAnchored(bytes32 indexed recordId, bytes32 dataHash, address validator);

    constructor() EIP712("HashBoundBaseline", "1") { admin = msg.sender; }

    function setValidator(address validator, bool status) external {
        if (msg.sender != admin) revert NOT_ADMIN();
        authorizedValidator[validator] = status;
    }

    function anchorRecord(bytes32 recordId, bytes32 dataHash, address validator, bytes calldata signature) external {
        if (anchored[recordId]) revert ALREADY_ANCHORED();
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(HASH_APPROVAL_TYPEHASH, dataHash, validator)));
        (address signer, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, signature);
        if (err != ECDSA.RecoverError.NoError || signer != validator) revert INVALID_APPROVAL_SIGNATURE();
        if (!authorizedValidator[signer]) revert UNAUTHORIZED_VALIDATOR();
        anchored[recordId] = true;
        anchoredDataHash[recordId] = dataHash;
        emit RecordAnchored(recordId, dataHash, signer);
    }

    function verifyRecord(bytes32 recordId, bytes32 recomputedHash) external view returns (bool) {
        return anchored[recordId] && anchoredDataHash[recordId] == recomputedHash;
    }
}
