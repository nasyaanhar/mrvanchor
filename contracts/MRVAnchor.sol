// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title MRVAnchor (v2) - approval-bound anchoring of carbon MRV records
/// @notice A record version can be anchored only with an unexpired EIP-712 approval
///         from a validator assigned to the plant, bound to the exact registered record context.
contract MRVAnchor is EIP712 {
    struct Decision {            // shared by approvals and rejections
        bytes32 recordId;
        uint32 version;
        bytes32 plantId;
        uint32 reportingPeriod;
        bytes32 dataHash;
        address validator;
        uint64 deadline;
    }

    struct RecordMeta { bytes32 plantId; uint32 period; bool exists; }

    bytes32 public constant MRV_APPROVAL_TYPEHASH = keccak256(
        "MRVApproval(bytes32 recordId,uint32 version,bytes32 plantId,uint32 reportingPeriod,bytes32 dataHash,address validator,uint64 deadline)"
    );
    bytes32 public constant MRV_REJECTION_TYPEHASH = keccak256(
        "MRVRejection(bytes32 recordId,uint32 version,bytes32 plantId,uint32 reportingPeriod,bytes32 dataHash,address validator,uint64 deadline,bytes32 reasonHash)"
    );

    address public immutable admin;

    // Role registry
    mapping(bytes32 => address) public plantOperator;                          // plantId => operator
    mapping(bytes32 => mapping(address => bool)) public assignedValidator;     // plantId => validator => assigned

    // Version registry
    mapping(bytes32 => RecordMeta) public recordMeta;
    mapping(bytes32 => mapping(uint32 => bytes32)) public registeredHash;      // recordId => version => dataHash
    mapping(bytes32 => uint32) public currentVersion;
    mapping(bytes32 => mapping(uint32 => bool)) public rejected;
    mapping(bytes32 => bool) public anchored;
    mapping(bytes32 => uint32) public anchoredVersion;
    mapping(bytes32 => bytes32) public anchoredDataHash;

    error NOT_ADMIN();
    error ZERO_VALUE();
    error NOT_PLANT_OPERATOR();
    error RECORD_EXISTS();
    error INVALID_VERSION();
    error RECORD_NOT_REGISTERED();
    error ALREADY_ANCHORED();
    error STALE_VERSION();
    error RECORD_CONTEXT_MISMATCH();
    error DATA_HASH_MISMATCH();
    error APPROVAL_EXPIRED();
    error RECORD_REJECTED();
    error INVALID_APPROVAL_SIGNATURE();
    error VALIDATOR_NOT_ASSIGNED();
    error SELF_APPROVAL_NOT_ALLOWED();
    error RECORD_NOT_ANCHORED();

    event PlantOperatorSet(bytes32 indexed plantId, address operator);
    event ValidatorAssigned(bytes32 indexed plantId, address indexed validator, bool status);
    event RecordVersionRegistered(bytes32 indexed recordId, uint32 version, bytes32 plantId, uint32 period, bytes32 dataHash);
    event RecordRejected(bytes32 indexed recordId, uint32 version, bytes32 dataHash, bytes32 reasonHash, address validator);
    event RecordAnchored(bytes32 indexed recordId, uint32 version, bytes32 dataHash, address validator, address submitter);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NOT_ADMIN();
        _;
    }

    constructor() EIP712("MRVAnchor", "2") { admin = msg.sender; }

    // ---------------- Algorithm 1: roles and record versions ----------------
    function setPlantOperator(bytes32 plantId, address operator) external onlyAdmin {
        if (operator == address(0)) revert ZERO_VALUE();
        plantOperator[plantId] = operator;
        emit PlantOperatorSet(plantId, operator);
    }

    function assignValidator(bytes32 plantId, address validator, bool status) external onlyAdmin {
        if (validator == address(0)) revert ZERO_VALUE();
        assignedValidator[plantId][validator] = status;
        emit ValidatorAssigned(plantId, validator, status);
    }

    function registerRecordVersion(bytes32 recordId, uint32 version, bytes32 plantId, uint32 period, bytes32 dataHash) external {
        if (msg.sender != plantOperator[plantId]) revert NOT_PLANT_OPERATOR();
        if (dataHash == bytes32(0)) revert ZERO_VALUE();
        if (anchored[recordId]) revert ALREADY_ANCHORED();
        RecordMeta storage m = recordMeta[recordId];
        if (version == 1) {
            if (m.exists) revert RECORD_EXISTS();
            recordMeta[recordId] = RecordMeta(plantId, period, true);
        } else {
            if (!m.exists || m.plantId != plantId || m.period != period) revert RECORD_CONTEXT_MISMATCH();
            if (version != currentVersion[recordId] + 1) revert INVALID_VERSION();
        }
        registeredHash[recordId][version] = dataHash;
        currentVersion[recordId] = version;
        emit RecordVersionRegistered(recordId, version, plantId, period, dataHash);
    }

    // ---------------- Algorithm 2: approval-bound anchoring ----------------
    /// @dev Callable by any party (operator or validator), so an operator cannot withhold a valid approval.
    function anchorRecord(Decision calldata a, bytes calldata signature) external {
        _checkDecision(a);                                                                      // checks 1-6
        if (rejected[a.recordId][a.version]) revert RECORD_REJECTED();                          // check 7
        address signer = _recover(_hashTypedDataV4(_approvalStruct(a)), signature);
        _checkSigner(a, signer);                                                                // checks 8-10

        anchored[a.recordId] = true;
        anchoredVersion[a.recordId] = a.version;
        anchoredDataHash[a.recordId] = a.dataHash;
        emit RecordAnchored(a.recordId, a.version, a.dataHash, signer, msg.sender);
    }

    /// @notice Records a signed validator rejection on-chain so regulators keep a rejection trail.
    function recordRejection(Decision calldata r, bytes32 reasonHash, bytes calldata signature) external {
        _checkDecision(r);
        if (rejected[r.recordId][r.version]) revert RECORD_REJECTED();
        address signer = _recover(_hashTypedDataV4(_rejectionStruct(r, reasonHash)), signature);
        _checkSigner(r, signer);
        rejected[r.recordId][r.version] = true;
        emit RecordRejected(r.recordId, r.version, r.dataHash, reasonHash, signer);
    }

    function verifyRecord(bytes32 recordId, bytes32 recomputedHash) external view returns (bool) {
        if (!anchored[recordId]) revert RECORD_NOT_ANCHORED();
        return anchoredDataHash[recordId] == recomputedHash;
    }

    // ---------------- internal checks ----------------
    function _checkDecision(Decision calldata a) internal view {
        if (registeredHash[a.recordId][a.version] == bytes32(0)) revert RECORD_NOT_REGISTERED();  // 1
        if (anchored[a.recordId]) revert ALREADY_ANCHORED();                                     // 2
        if (a.version != currentVersion[a.recordId]) revert STALE_VERSION();                     // 3
        RecordMeta storage m = recordMeta[a.recordId];
        if (a.plantId != m.plantId || a.reportingPeriod != m.period) revert RECORD_CONTEXT_MISMATCH(); // 4
        if (a.dataHash != registeredHash[a.recordId][a.version]) revert DATA_HASH_MISMATCH();    // 5
        if (block.timestamp > a.deadline) revert APPROVAL_EXPIRED();                             // 6
    }

    function _checkSigner(Decision calldata a, address signer) internal view {
        if (signer == address(0) || signer != a.validator) revert INVALID_APPROVAL_SIGNATURE();   // 8
        if (!assignedValidator[a.plantId][signer]) revert VALIDATOR_NOT_ASSIGNED();              // 9
        if (signer == plantOperator[a.plantId]) revert SELF_APPROVAL_NOT_ALLOWED();               // 10
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        (address signer, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, signature);
        return err == ECDSA.RecoverError.NoError ? signer : address(0);
    }

    function _approvalStruct(Decision calldata a) internal pure returns (bytes32) {
        return keccak256(abi.encode(MRV_APPROVAL_TYPEHASH, a.recordId, a.version, a.plantId,
                                    a.reportingPeriod, a.dataHash, a.validator, a.deadline));
    }

    function _rejectionStruct(Decision calldata r, bytes32 reasonHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(MRV_REJECTION_TYPEHASH, r.recordId, r.version, r.plantId,
                                    r.reportingPeriod, r.dataHash, r.validator, r.deadline, reasonHash));
    }
}
