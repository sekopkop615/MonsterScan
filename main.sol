// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// @title MonsterScan/// @notice On-chain registry for token and address scans; reporters submit risk scores and flags; keeper manages config and vault receives protocol fees./// @dev Scanner keeper and report vault are set at construction. ReentrancyGuard and Pausable for mainnet. All role addresses are immutable.////// ## Roles/// - scannerKeeper: register tokens, add/remove whitelist/blacklist, set risk thresholds, register/revoke reporters, pause./// - reportVault: receives ETH via receive() and can withdraw with withdrawVault()./// - reporters: addresses registered by keeper; only they can submitScan / submitScanBatch.////// ## Flow/// 1. Keeper registers tokens (registerToken) and optionally categories (registerCategory)./// 2. Keeper registers reporters (registerReporter)./// 3. Reporters submit scans (submitScan or submitScanWithCategory) with target address, risk tier (0-10), and flags hash./// 4. Keeper can whitelist/blacklist addresses; views expose isWhitelisted, isBlacklisted, addressStatus./// 5. Risk thresholds per tier are configurable (setRiskThreshold); exceedsThreshold(scanId, tier) for checks.////// ## Constants/// MSC_MAX_RISK_TIER = 10, MSC_MAX_SCANS = 50000, MSC_BATCH_LIMIT = 64, MSC_VIEW_BATCH = 96./// Domain/role constants use keccak256 for EIP compatibility.////// ## Integration/// Frontends can paginate scans via getScanIdsPaginated(offset, limit) or getScanIdsRange(from, to)./// For a given address use addressStatus(target) for whitelist/blacklist and scan count; targetScanCount(target) and getTargetScanAt(target, i) for scan ids./// Risk thresholds are per tier (0-10); setRiskThreshold(tier, value) and exceedsThreshold(scanId, tier) for alerts./// Categories are optional: registerCategory(nameHash), then submitScanWithCategory(..., categoryId)./// Token registry: registerToken(tokenScanId, tokenAddress, symbolHash); query via getTokenAt(index), getTokenAddress(tokenScanId), tokenRegistered(tokenScanId).////// ## Security/// ReentrancyGuard on submitScan, submitScanBatch, withdrawVault. Pausable for keeper. No upgrade; deploy new instance to change logic./// Reporter registration is keeper-only; only registered reporters can submit scans. Vault address is immutable and the only one that can withdraw.import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/ReentrancyGuard.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/Pausable.sol";
contract MonsterScan is ReentrancyGuard, Pausable {
    // -------------------------------------------------------------------------
    // EVENTS
    // -------------------------------------------------------------------------    event TokenRegistered(bytes32 indexed tokenScanId, address indexed token, bytes32 symbolHash, uint256 atBlock);
    event AddressScanned(bytes32 indexed scanId, address indexed target, uint8 riskTier, uint256 atBlock);
    event ScanResultSubmitted(bytes32 indexed scanId, address indexed reporter, uint8 riskTier, bytes32 flagsHash, uint256 atBlock);
    event AddressFlagged(address indexed target, uint8 flagType, address indexed reporter, uint256 atBlock);
    event AddressCleared(address indexed target, uint8 flagType, address indexed by, uint256 atBlock);
    event WhitelistAdded(address indexed target, address indexed by, uint256 atBlock);
    event WhitelistRemoved(address indexed target, address indexed by, uint256 atBlock);
    event BlacklistAdded(address indexed target, address indexed by, uint256 atBlock);
    event BlacklistRemoved(address indexed target, address indexed by, uint256 atBlock);
    event ThresholdUpdated(uint8 riskTier, uint256 previousValue, uint256 newValue, uint256 atBlock);
    event ReporterRegistered(address indexed reporter, uint256 atBlock);
    event ReporterRevoked(address indexed reporter, uint256 atBlock);
    event ScannerPaused(address indexed by, uint256 atBlock);
    event ScannerUnpaused(address indexed by, uint256 atBlock);
    event VaultWithdrawn(address indexed to, uint256 amountWei, uint256 atBlock);
    event FeeCollected(address indexed from, uint256 amountWei, uint256 atBlock);
    event BatchScansSubmitted(uint256 count, address indexed reporter, uint256 atBlock);
    // -------------------------------------------------------------------------
    // ERRORS
    // -------------------------------------------------------------------------    error MSC_ZeroAddress();
    error MSC_ZeroScanId();
    error MSC_NotKeeper();
    error MSC_NotReporter();
    error MSC_NotVault();
    error MSC_ScanAlreadyExists();
    error MSC_ScanNotFound();
    error MSC_InvalidRiskTier();
    error MSC_AlreadyWhitelisted();
    error MSC_NotWhitelisted();
    error MSC_AlreadyBlacklisted();
    error MSC_NotBlacklisted();
    error MSC_TransferFailed();
    error MSC_Paused();
    error MSC_ArrayLengthMismatch();
    error MSC_BatchTooLarge();
    error MSC_WithdrawZero();
    error MSC_MaxScansReached();
    error MSC_InvalidThreshold();
    error MSC_ReporterAlreadyRegistered();
    error MSC_ReporterNotRegistered();
    error MSC_ZeroToken();
    error MSC_InvalidCategory();
    error MSC_CategoryLimitReached();
    error MSC_ZeroSymbolHash();
    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------    uint256 public constant MSC_MAX_RISK_TIER = 10;    uint256 public constant MSC_MAX_SCANS = 50_000;    uint256 public constant MSC_BATCH_LIMIT = 64;    uint256 public constant MSC_VIEW_BATCH = 96;    uint256 public constant MSC_FLAG_WHITELIST = 1;    uint256 public constant MSC_FLAG_BLACKLIST = 2;    uint256 public constant MSC_FLAG_SUSPICIOUS = 3;    bytes32 public constant MSC_SCAN_DOMAIN = keccak256("MonsterScan.MSC_SCAN_DOMAIN");
    bytes32 public constant MSC_REPORTER_ROLE = keccak256("MonsterScan.MSC_REPORTER_ROLE");
    bytes32 public constant MSC_TOKEN_NAMESPACE = keccak256("MonsterScan.MSC_TOKEN_NAMESPACE");
    uint256 public constant MSC_MAX_CATEGORIES = 16;    uint256 public constant MSC_CATEGORY_NAME_LEN = 32;    // -------------------------------------------------------------------------
    // IMMUTABLES
    // -------------------------------------------------------------------------    address public immutable scannerKeeper;    address public immutable reportVault;    uint256 public immutable deployBlock;    // -------------------------------------------------------------------------
    // STATE
    // -------------------------------------------------------------------------    mapping(bytes32 => bool) private _scanExists;    mapping(bytes32 => address) private _scanTarget;    mapping(bytes32 => uint8) private _scanRiskTier;    mapping(bytes32 => bytes32) private _scanFlagsHash;    mapping(bytes32 => address) private _scanReporter;    mapping(bytes32 => uint256) private _scanBlock;    bytes32[] private _scanIds;    uint256 public scanCount;    mapping(address => bytes32[]) private _targetScanIds;    mapping(address => uint256) private _targetScanCount;    mapping(address => bool) private _whitelist;    mapping(address => bool) private _blacklist;    address[] private _whitelistArr;    address[] private _blacklistArr;    mapping(address => bool) private _reporter;    uint256 public reporterCount;    mapping(uint8 => uint256) private _riskThreshold;    mapping(bytes32 => bool) private _tokenRegistered;    mapping(bytes32 => address) private _tokenAddress;    bytes32[] private _tokenScanIds;    uint256 public tokenCount;    uint256 private _vaultBalance;    uint256 public categoryCount;    mapping(uint256 => bytes32) private _categoryName;    mapping(bytes32 => uint256) private _scanCategory;    mapping(uint256 => bytes32[]) private _categoryScanIds;    mapping(uint256 => uint256) private _categoryScanCount;    // -------------------------------------------------------------------------
    // CONSTRUCTOR
    // -------------------------------------------------------------------------    constructor() {        scannerKeeper = msg.sender;        reportVault = address(0x9D1e4F7a2C8b0E5d3A6f9c1B4e7D2a0F8C5b3E6);
        deployBlock = block.number;        _riskThreshold[1] = 100;        _riskThreshold[2] = 200;        _riskThreshold[3] = 500;        _riskThreshold[5] = 1000;        _riskThreshold[8] = 2000;    }    modifier whenNotPaused() {        if (paused()) revert MSC_Paused();
        _;    }    modifier onlyKeeper() {        if (msg.sender != scannerKeeper) revert MSC_NotKeeper();
        _;    }    modifier onlyReporter() {        if (!_reporter[msg.sender]) revert MSC_NotReporter();
        _;    }
    // -------------------------------------------------------------------------
    // REGISTRATION & SCANNING
    // -------------------------------------------------------------------------
    /// @param nameHash keccak256 of category name    /// @return categoryId index of the new category (0-based)    function registerCategory(bytes32 nameHash) external whenNotPaused onlyKeeper returns (uint256 categoryId) {        if (categoryCount >= MSC_MAX_CATEGORIES) revert MSC_CategoryLimitReached();
        categoryId = categoryCount;        _categoryName[categoryId] = nameHash;        categoryCount++;
    }
    /// @param tokenScanId unique id for the token (e.g. keccak256(symbol))    /// @param token contract address of the token    /// @param symbolHash keccak256 of symbol string    function registerToken(bytes32 tokenScanId, address token, bytes32 symbolHash) external whenNotPaused onlyKeeper {        if (token == address(0)) revert MSC_ZeroToken();
        if (tokenScanId == bytes32(0)) revert MSC_ZeroScanId();
        if (symbolHash == bytes32(0)) revert MSC_ZeroSymbolHash();
        if (_tokenRegistered[tokenScanId]) revert MSC_ScanAlreadyExists();
        if (tokenCount >= MSC_MAX_SCANS) revert MSC_MaxScansReached();
        _tokenRegistered[tokenScanId] = true;        _tokenAddress[tokenScanId] = token;        _tokenScanIds.push(tokenScanId);
        tokenCount++;        emit TokenRegistered(tokenScanId, token, symbolHash, block.number);
    }
    /// @param scanId unique scan identifier    /// @param target address that was scanned    /// @param riskTier 0-10 risk level    /// @param flagsHash hash of flag bits or metadata    function submitScan(bytes32 scanId, address target, uint8 riskTier, bytes32 flagsHash) external whenNotPaused onlyReporter nonReentrant {        _submitScanOne(scanId, target, riskTier, flagsHash, type(uint256).max);
    }
    function submitScanWithCategory(bytes32 scanId, address target, uint8 riskTier, bytes32 flagsHash, uint256 categoryId) external whenNotPaused onlyReporter nonReentrant {        if (categoryId >= categoryCount) revert MSC_InvalidCategory();
        _submitScanOne(scanId, target, riskTier, flagsHash, categoryId);
    }
    function _submitScanOne(bytes32 scanId, address target, uint8 riskTier, bytes32 flagsHash, uint256 categoryId) internal {        if (scanId == bytes32(0)) revert MSC_ZeroScanId();
        if (target == address(0)) revert MSC_ZeroAddress();
        if (riskTier > MSC_MAX_RISK_TIER) revert MSC_InvalidRiskTier();
        if (_scanExists[scanId]) revert MSC_ScanAlreadyExists();
        if (scanCount >= MSC_MAX_SCANS) revert MSC_MaxScansReached();
        _scanExists[scanId] = true;        _scanTarget[scanId] = target;        _scanRiskTier[scanId] = riskTier;        _scanFlagsHash[scanId] = flagsHash;        _scanReporter[scanId] = msg.sender;        _scanBlock[scanId] = block.number;        _scanIds.push(scanId);
        if (categoryId != type(uint256).max) {            _scanCategory[scanId] = categoryId;            _categoryScanIds[categoryId].push(scanId);
            _categoryScanCount[categoryId]++;        }        if (_targetScanIds[target].length == 0) {            _targetScanIds[target].push(scanId);
            _targetScanCount[target] = 1;        } else {            _targetScanIds[target].push(scanId);
            _targetScanCount[target]++;        }        scanCount++;        emit AddressScanned(scanId, target, riskTier, block.number);
        emit ScanResultSubmitted(scanId, msg.sender, riskTier, flagsHash, block.number);
    }
    function submitScanBatch(bytes32[] calldata scanIds, address[] calldata targets, uint8[] calldata riskTiers, bytes32[] calldata flagsHashes)        external        whenNotPaused        onlyReporter        nonReentrant    {        if (scanIds.length != targets.length || scanIds.length != riskTiers.length || scanIds.length != flagsHashes.length) revert MSC_ArrayLengthMismatch();
        if (scanIds.length > MSC_BATCH_LIMIT) revert MSC_BatchTooLarge();
        if (scanCount + scanIds.length > MSC_MAX_SCANS) revert MSC_MaxScansReached();
        for (uint256 i = 0; i < scanIds.length; i++) {            bytes32 sid = scanIds[i];            address target = targets[i];            uint8 rt = riskTiers[i];            if (sid == bytes32(0) || target == address(0)) continue;            if (_scanExists[sid] || rt > MSC_MAX_RISK_TIER) continue;            _scanExists[sid] = true;            _scanTarget[sid] = target;            _scanRiskTier[sid] = rt;            _scanFlagsHash[sid] = flagsHashes[i];            _scanReporter[sid] = msg.sender;            _scanBlock[sid] = block.number;            _scanIds.push(sid);
            _targetScanIds[target].push(sid);
            _targetScanCount[target]++;            scanCount++;            emit ScanResultSubmitted(sid, msg.sender, rt, flagsHashes[i], block.number);
        }        emit BatchScansSubmitted(scanIds.length, msg.sender, block.number);
    }
    function addToWhitelistBatch(address[] calldata targets) external whenNotPaused onlyKeeper {        if (targets.length > MSC_BATCH_LIMIT) revert MSC_BatchTooLarge();
        for (uint256 i = 0; i < targets.length; i++) {            address t = targets[i];            if (t == address(0)) continue;            if (!_whitelist[t]) {                _whitelist[t] = true;                _whitelistArr.push(t);
                emit WhitelistAdded(t, msg.sender, block.number);
            }        }    }
    function addToBlacklistBatch(address[] calldata targets) external whenNotPaused onlyKeeper {        if (targets.length > MSC_BATCH_LIMIT) revert MSC_BatchTooLarge();
        for (uint256 i = 0; i < targets.length; i++) {            address t = targets[i];            if (t == address(0)) continue;            if (!_blacklist[t]) {                _blacklist[t] = true;                _blacklistArr.push(t);
                emit BlacklistAdded(t, msg.sender, block.number);
            }        }    }
    function addToWhitelist(address target) external whenNotPaused onlyKeeper {        if (target == address(0)) revert MSC_ZeroAddress();
        if (_whitelist[target]) revert MSC_AlreadyWhitelisted();
        _whitelist[target] = true;        _whitelistArr.push(target);
        emit WhitelistAdded(target, msg.sender, block.number);
    }
    function removeFromWhitelist(address target) external onlyKeeper {        if (!_whitelist[target]) revert MSC_NotWhitelisted();
