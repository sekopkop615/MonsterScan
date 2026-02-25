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
        _whitelist[target] = false;        emit WhitelistRemoved(target, msg.sender, block.number);
    }
    function addToBlacklist(address target) external whenNotPaused onlyKeeper {        if (target == address(0)) revert MSC_ZeroAddress();
        if (_blacklist[target]) revert MSC_AlreadyBlacklisted();
        _blacklist[target] = true;        _blacklistArr.push(target);
        emit BlacklistAdded(target, msg.sender, block.number);
    }
    function removeFromBlacklist(address target) external onlyKeeper {        if (!_blacklist[target]) revert MSC_NotBlacklisted();
        _blacklist[target] = false;        emit BlacklistRemoved(target, msg.sender, block.number);
    }
    function setRiskThreshold(uint8 riskTier, uint256 value) external onlyKeeper {        if (riskTier > MSC_MAX_RISK_TIER) revert MSC_InvalidRiskTier();
        uint256 prev = _riskThreshold[riskTier];        _riskThreshold[riskTier] = value;        emit ThresholdUpdated(riskTier, prev, value, block.number);
    }
    function registerReporter(address reporter) external onlyKeeper {        if (reporter == address(0)) revert MSC_ZeroAddress();
        if (_reporter[reporter]) revert MSC_ReporterAlreadyRegistered();
        _reporter[reporter] = true;        reporterCount++;        emit ReporterRegistered(reporter, block.number);
    }
    function revokeReporter(address reporter) external onlyKeeper {        if (!_reporter[reporter]) revert MSC_ReporterNotRegistered();
        _reporter[reporter] = false;        reporterCount--;        emit ReporterRevoked(reporter, block.number);
    }
    function pause() external onlyKeeper {        _pause();
        emit ScannerPaused(msg.sender, block.number);
    }
    function unpause() external onlyKeeper {        _unpause();
        emit ScannerUnpaused(msg.sender, block.number);
    }
    function withdrawVault() external nonReentrant {        if (msg.sender != reportVault) revert MSC_NotVault();
        uint256 amt = _vaultBalance;        if (amt == 0) revert MSC_WithdrawZero();
        _vaultBalance = 0;        (bool ok,) = reportVault.call{value: amt}("");
        if (!ok) revert MSC_TransferFailed();
        emit VaultWithdrawn(reportVault, amt, block.number);
    }    receive() external payable {        _vaultBalance += msg.value;        emit FeeCollected(msg.sender, msg.value, block.number);
    }
    // -------------------------------------------------------------------------
    // VIEWS
    // -------------------------------------------------------------------------    function getScan(bytes32 scanId)        external        view        returns (address target, uint8 riskTier, bytes32 flagsHash, address reporter, uint256 atBlock, bool exists)    {        return (            _scanTarget[scanId],            _scanRiskTier[scanId],            _scanFlagsHash[scanId],            _scanReporter[scanId],            _scanBlock[scanId],            _scanExists[scanId]        );
    }
    function getScanTarget(bytes32 scanId) external view returns (address) { return _scanTarget[scanId]; }
    function getScanRiskTier(bytes32 scanId) external view returns (uint8) { return _scanRiskTier[scanId]; }
    function getScanFlagsHash(bytes32 scanId) external view returns (bytes32) { return _scanFlagsHash[scanId]; }
    function getScanReporter(bytes32 scanId) external view returns (address) { return _scanReporter[scanId]; }
    function getScanBlock(bytes32 scanId) external view returns (uint256) { return _scanBlock[scanId]; }
    function scanExists(bytes32 scanId) external view returns (bool) { return _scanExists[scanId]; }
    function targetScanCount(address target) external view returns (uint256) { return _targetScanCount[target]; }
    function getTargetScanAt(address target, uint256 index) external view returns (bytes32) { return _targetScanIds[target][index]; }
    function isWhitelisted(address target) external view returns (bool) { return _whitelist[target]; }
    function isBlacklisted(address target) external view returns (bool) { return _blacklist[target]; }
    function isReporter(address addr) external view returns (bool) { return _reporter[addr]; }
    function getRiskThreshold(uint8 riskTier) external view returns (uint256) { return _riskThreshold[riskTier]; }
    function vaultBalance() external view returns (uint256) { return _vaultBalance; }
    function scanIdsLength() external view returns (uint256) { return _scanIds.length; }
    function getScanIdAt(uint256 index) external view returns (bytes32) { return _scanIds[index]; }
    function getTokenAt(uint256 index) external view returns (bytes32 tokenScanId, address token) {        if (index >= _tokenScanIds.length) return (bytes32(0), address(0));
        bytes32 tid = _tokenScanIds[index];        return (tid, _tokenAddress[tid]);
    }
    function tokenRegistered(bytes32 tokenScanId) external view returns (bool) { return _tokenRegistered[tokenScanId]; }
    function getTokenAddress(bytes32 tokenScanId) external view returns (address) { return _tokenAddress[tokenScanId]; }
    function getScanIdsPaginated(uint256 offset, uint256 limit) external view returns (bytes32[] memory out) {        uint256 total = _scanIds.length;        if (offset >= total) return out;        if (limit > MSC_VIEW_BATCH) limit = MSC_VIEW_BATCH;        uint256 end = offset + limit;        if (end > total) end = total;        uint256 n = end - offset;        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _scanIds[offset + i];    }
    function getScansBatch(bytes32[] calldata scanIds)        external        view        returns (            address[] memory targets,            uint8[] memory riskTiers,            bytes32[] memory flagsHashes,            address[] memory reporters,            uint256[] memory atBlocks,            bool[] memory exists        )    {        uint256 n = scanIds.length;        if (n > MSC_VIEW_BATCH) n = MSC_VIEW_BATCH;        targets = new address[](n);
        riskTiers = new uint8[](n);
        flagsHashes = new bytes32[](n);
        reporters = new address[](n);
        atBlocks = new uint256[](n);
        exists = new bool[](n);
        for (uint256 i = 0; i < n; i++) {            targets[i] = _scanTarget[scanIds[i]];            riskTiers[i] = _scanRiskTier[scanIds[i]];            flagsHashes[i] = _scanFlagsHash[scanIds[i]];            reporters[i] = _scanReporter[scanIds[i]];            atBlocks[i] = _scanBlock[scanIds[i]];            exists[i] = _scanExists[scanIds[i]];        }    }
    function exceedsThreshold(bytes32 scanId, uint8 riskTier) external view returns (bool) {        if (!_scanExists[scanId]) return false;        uint256 thresh = _riskThreshold[riskTier];        return uint256(_scanRiskTier[scanId]) >= thresh;    }
    function addressStatus(address target) external view returns (bool whitelisted, bool blacklisted, uint256 scanCount_) {        return (_whitelist[target], _blacklist[target], _targetScanCount[target]);
    }
    function whitelistLength() external view returns (uint256) { return _whitelistArr.length; }
    function blacklistLength() external view returns (uint256) { return _blacklistArr.length; }
    function getWhitelistAt(uint256 index) external view returns (address) { return _whitelistArr[index]; }
    function getBlacklistAt(uint256 index) external view returns (address) { return _blacklistArr[index]; }
    function getScanCategory(bytes32 scanId) external view returns (uint256) { return _scanCategory[scanId]; }
    function getCategoryName(uint256 categoryId) external view returns (bytes32) { return _categoryName[categoryId]; }
    function getCategoryScanCount(uint256 categoryId) external view returns (uint256) { return _categoryScanCount[categoryId]; }
    function getCategoryScanAt(uint256 categoryId, uint256 index) external view returns (bytes32) { return _categoryScanIds[categoryId][index]; }
    function deployBlockNumber() external view returns (uint256) { return deployBlock; }
    function getKeeper() external view returns (address) { return scannerKeeper; }
    function getVault() external view returns (address) { return reportVault; }
    function getTargetScansPaginated(address target, uint256 offset, uint256 limit) external view returns (bytes32[] memory out) {        uint256 total = _targetScanCount[target];        if (offset >= total) return out;        if (limit > MSC_VIEW_BATCH) limit = MSC_VIEW_BATCH;        uint256 end = offset + limit;        if (end > total) end = total;        uint256 n = end - offset;        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _targetScanIds[target][offset + i];    }
    function isHighRisk(bytes32 scanId) external view returns (bool) {        if (!_scanExists[scanId]) return false;        uint256 thresh = _riskThreshold[8];        return thresh > 0 && uint256(_scanRiskTier[scanId]) >= thresh;    }
    function getGlobalStats() external view returns (uint256 totalScans, uint256 totalTokens, uint256 totalReporters, uint256 whitelistLen, uint256 blacklistLen, uint256 vaultBal) {        return (_scanIds.length, tokenCount, reporterCount, _whitelistArr.length, _blacklistArr.length, _vaultBalance);
    }
    function hasAnyFlag(address target) external view returns (bool) {        return _whitelist[target] || _blacklist[target];    }
    function tokenScanIdsLength() external view returns (uint256) { return _tokenScanIds.length; }
    function getTokenScanIdAt(uint256 index) external view returns (bytes32) { return _tokenScanIds[index]; }
    function getScanSummary(bytes32 scanId) external view returns (address target, uint8 riskTier, bool exists, uint256 atBlock) {        return (_scanTarget[scanId], _scanRiskTier[scanId], _scanExists[scanId], _scanBlock[scanId]);
    }
    function getMaxRiskTier() external pure returns (uint256) { return MSC_MAX_RISK_TIER; }
    function getMaxScans() external pure returns (uint256) { return MSC_MAX_SCANS; }
    function getBatchLimit() external pure returns (uint256) { return MSC_BATCH_LIMIT; }
    function getViewBatch() external pure returns (uint256) { return MSC_VIEW_BATCH; }
    function getScanDomain() external pure returns (bytes32) { return MSC_SCAN_DOMAIN; }
    function getReporterRole() external pure returns (bytes32) { return MSC_REPORTER_ROLE; }
    function getTokenNamespace() external pure returns (bytes32) { return MSC_TOKEN_NAMESPACE; }
    function getMaxCategories() external pure returns (uint256) { return MSC_MAX_CATEGORIES; }
    function isLive() external view returns (bool) { return !paused(); }
    function getScanIdsRange(uint256 fromIdx, uint256 toIdx) external view returns (bytes32[] memory) {        uint256 total = _scanIds.length;        if (fromIdx >= total) return new bytes32[](0);
        if (toIdx > total) toIdx = total;        if (fromIdx >= toIdx) return new bytes32[](0);
        uint256 n = toIdx - fromIdx;        if (n > MSC_VIEW_BATCH) n = MSC_VIEW_BATCH;        bytes32[] memory out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _scanIds[fromIdx + i];        return out;    }
    function getWhitelistPaginated(uint256 offset, uint256 limit) external view returns (address[] memory out) {        uint256 total = _whitelistArr.length;        if (offset >= total) return out;        if (limit > MSC_VIEW_BATCH) limit = MSC_VIEW_BATCH;        uint256 end = offset + limit;        if (end > total) end = total;        uint256 n = end - offset;        out = new address[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _whitelistArr[offset + i];    }
    function getBlacklistPaginated(uint256 offset, uint256 limit) external view returns (address[] memory out) {        uint256 total = _blacklistArr.length;        if (offset >= total) return out;        if (limit > MSC_VIEW_BATCH) limit = MSC_VIEW_BATCH;        uint256 end = offset + limit;        if (end > total) end = total;        uint256 n = end - offset;        out = new address[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _blacklistArr[offset + i];    }
    function getTokenScanIdsPaginated(uint256 offset, uint256 limit) external view returns (bytes32[] memory out) {        uint256 total = _tokenScanIds.length;        if (offset >= total) return out;        if (limit > MSC_VIEW_BATCH) limit = MSC_VIEW_BATCH;        uint256 end = offset + limit;        if (end > total) end = total;        uint256 n = end - offset;        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _tokenScanIds[offset + i];    }
    function allScanIds() external view returns (bytes32[] memory) { return _scanIds; }
    function allTokenScanIds() external view returns (bytes32[] memory) { return _tokenScanIds; }
    function getScansByReporter(address reporter, uint256 offset, uint256 limit) external view returns (bytes32[] memory out) {        uint256 total = _scanIds.length;        uint256 count = 0;        for (uint256 i = 0; i < total; i++) {            if (_scanReporter[_scanIds[i]] == reporter) count++;        }        if (offset >= count) return out;        if (limit > MSC_VIEW_BATCH) limit = MSC_VIEW_BATCH;        uint256 end = offset + limit;        if (end > count) end = count;        uint256 n = end - offset;        out = new bytes32[](n);
        uint256 written = 0;        uint256 outIdx = 0;        for (uint256 i = 0; i < total && outIdx < n; i++) {            if (_scanReporter[_scanIds[i]] == reporter) {                if (written >= offset) {                    out[outIdx] = _scanIds[i];                    outIdx++;                }                written++;            }        }    }
    function getRiskTierCounts() external view returns (uint256[] memory counts) {        counts = new uint256[](MSC_MAX_RISK_TIER + 1);
        for (uint256 i = 0; i < _scanIds.length; i++) {            uint8 t = _scanRiskTier[_scanIds[i]];            if (t <= MSC_MAX_RISK_TIER) counts[t]++;        }    }
    function getScanIdsByRiskTier(uint8 riskTier, uint256 offset, uint256 limit) external view returns (bytes32[] memory out) {        if (riskTier > MSC_MAX_RISK_TIER) return out;        uint256 total = _scanIds.length;        uint256 count = 0;        for (uint256 i = 0; i < total; i++) {            if (_scanRiskTier[_scanIds[i]] == riskTier) count++;        }        if (offset >= count) return out;        if (limit > MSC_VIEW_BATCH) limit = MSC_VIEW_BATCH;        uint256 end = offset + limit;        if (end > count) end = count;        uint256 n = end - offset;        out = new bytes32[](n);
        uint256 written = 0;        uint256 outIdx = 0;        for (uint256 i = 0; i < total && outIdx < n; i++) {            if (_scanRiskTier[_scanIds[i]] == riskTier) {                if (written >= offset) {                    out[outIdx] = _scanIds[i];                    outIdx++;                }                written++;            }        }    }
    function totalScansForTarget(address target) external view returns (uint256) { return _targetScanCount[target]; }
    function scanReporter(bytes32 scanId) external view returns (address) { return _scanReporter[scanId]; }
    function scanFlags(bytes32 scanId) external view returns (bytes32) { return _scanFlagsHash[scanId]; }
    function scanRisk(bytes32 scanId) external view returns (uint8) { return _scanRiskTier[scanId]; }
    function scanAtBlock(bytes32 scanId) external view returns (uint256) { return _scanBlock[scanId]; }
    function scanTarget(bytes32 scanId) external view returns (address) { return _scanTarget[scanId]; }
    function categoryScanIdsLength(uint256 categoryId) external view returns (uint256) { return _categoryScanCount[categoryId]; }
    function categoryNameHash(uint256 categoryId) external view returns (bytes32) { return _categoryName[categoryId]; }
    function scanCategoryId(bytes32 scanId) external view returns (uint256) { return _scanCategory[scanId]; }
    function getCategoryScanIdAt(uint256 categoryId, uint256 index) external view returns (bytes32) { return _categoryScanIds[categoryId][index]; }    /// @notice Returns scan id at index (alias for getScanIdAt)    function scanIdAtIndex(uint256 index) external view returns (bytes32) { return _scanIds[index]; }    /// @notice Returns whether scan exists by id    function exists(bytes32 scanId) external view returns (bool) { return _scanExists[scanId]; }    /// @notice Returns vault balance in wei    function getVaultBalance() external view returns (uint256) { return _vaultBalance; }    /// @notice Returns deploy block number    function getDeployBlock() external view returns (uint256) { return deployBlock; }    /// @notice Returns current scan count    function getScanCount() external view returns (uint256) { return scanCount; }    /// @notice Returns token count    function getTokenCount() external view returns (uint256) { return tokenCount; }    /// @notice Returns reporter count    function getReporterCount() external view returns (uint256) { return reporterCount; }    /// @notice Returns category count    function getCategoryCount() external view returns (uint256) { return categoryCount; }    /// @notice Returns whitelist length    function getWhitelistLength() external view returns (uint256) { return _whitelistArr.length; }    /// @notice Returns blacklist length    function getBlacklistLength() external view returns (uint256) { return _blacklistArr.length; }    /// @notice Returns token scan ids array length    function getTokenScanIdsLength() external view returns (uint256) { return _tokenScanIds.length; }    /// @notice Batch get scan targets for given scan ids    function getTargetsForScans(bytes32[] calldata scanIds) external view returns (address[] memory targets) {        uint256 n = scanIds.length;        if (n > MSC_VIEW_BATCH) n = MSC_VIEW_BATCH;        targets = new address[](n);
        for (uint256 i = 0; i < n; i++) targets[i] = _scanTarget[scanIds[i]];    }
    /// @notice Batch get risk tiers for given scan ids    function getRiskTiersForScans(bytes32[] calldata scanIds) external view returns (uint8[] memory tiers) {        uint256 n = scanIds.length;        if (n > MSC_VIEW_BATCH) n = MSC_VIEW_BATCH;        tiers = new uint8[](n);
        for (uint256 i = 0; i < n; i++) tiers[i] = _scanRiskTier[scanIds[i]];    }
    /// @notice Batch check existence for given scan ids    function getExistsForScans(bytes32[] calldata scanIds) external view returns (bool[] memory exists_) {        uint256 n = scanIds.length;        if (n > MSC_VIEW_BATCH) n = MSC_VIEW_BATCH;        exists_ = new bool[](n);
        for (uint256 i = 0; i < n; i++) exists_[i] = _scanExists[scanIds[i]];    }
    /// @notice Returns scan id at index in range [from, to)    function getScanIdsInRange(uint256 fromIndex, uint256 toIndex) external view returns (bytes32[] memory out) {        uint256 total = _scanIds.length;        if (fromIndex >= total) return new bytes32[](0);
        if (toIndex > total) toIndex = total;        if (fromIndex >= toIndex) return new bytes32[](0);
        uint256 n = toIndex - fromIndex;        if (n > MSC_VIEW_BATCH) n = MSC_VIEW_BATCH;        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _scanIds[fromIndex + i];    }
    /// @notice Returns true if target is whitelisted (alias)    function checkWhitelist(address target) external view returns (bool) { return _whitelist[target]; }    /// @notice Returns true if target is blacklisted (alias)    function checkBlacklist(address target) external view returns (bool) { return _blacklist[target]; }    /// @notice Returns true if address is registered reporter (alias)    function checkReporter(address addr) external view returns (bool) { return _reporter[addr]; }    /// @notice Returns token address for token scan id    function tokenAddress(bytes32 tokenScanId) external view returns (address) { return _tokenAddress[tokenScanId]; }    /// @notice Returns whether token is registered (alias)    function isTokenRegistered(bytes32 tokenScanId) external view returns (bool) { return _tokenRegistered[tokenScanId]; }
    function getMultipleAddressStatuses(address[] calldata targets) external view returns (bool[] memory whitelisted, bool[] memory blacklisted, uint256[] memory scanCounts) {        uint256 n = targets.length;        if (n > MSC_VIEW_BATCH) n = MSC_VIEW_BATCH;        whitelisted = new bool[](n);
        blacklisted = new bool[](n);
        scanCounts = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {            address t = targets[i];            whitelisted[i] = _whitelist[t];            blacklisted[i] = _blacklist[t];            scanCounts[i] = _targetScanCount[t];        }    }
    function getThresholdsBatch(uint8[] calldata tiers) external view returns (uint256[] memory values) {        uint256 n = tiers.length;        if (n > MSC_MAX_RISK_TIER + 1) n = MSC_MAX_RISK_TIER + 1;        values = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {            if (tiers[i] <= MSC_MAX_RISK_TIER) values[i] = _riskThreshold[tiers[i]];        }    }
    function getAllThresholds() external view returns (uint256[] memory values) {        values = new uint256[](MSC_MAX_RISK_TIER + 1);
        for (uint8 i = 0; i <= uint8(MSC_MAX_RISK_TIER); i++) values[i] = _riskThreshold[i];    }
    function getScanIdsForTargetSlice(address target, uint256 offset, uint256 limit) external view returns (bytes32[] memory) {        return this.getTargetScansPaginated(target, offset, limit);
    }
    function countScansByReporter(address reporter) external view returns (uint256 count) {        for (uint256 i = 0; i < _scanIds.length; i++) {            if (_scanReporter[_scanIds[i]] == reporter) count++;        }    }
    function countScansByRiskTier(uint8 riskTier) external view returns (uint256 count) {        if (riskTier > MSC_MAX_RISK_TIER) return 0;        for (uint256 i = 0; i < _scanIds.length; i++) {            if (_scanRiskTier[_scanIds[i]] == riskTier) count++;        }    }
    function getFirstScanIdForTarget(address target) external view returns (bytes32) {        if (_targetScanCount[target] == 0) return bytes32(0);
        return _targetScanIds[target][0];    }
    function getLastScanIdForTarget(address target) external view returns (bytes32) {        uint256 c = _targetScanCount[target];        if (c == 0) return bytes32(0);
        return _targetScanIds[target][c - 1];    }
    function getTokenByScanId(bytes32 tokenScanId) external view returns (address) { return _tokenAddress[tokenScanId]; }
    function totalScans() external view returns (uint256) { return _scanIds.length; }
    function totalTokensRegistered() external view returns (uint256) { return tokenCount; }
    function totalReporters() external view returns (uint256) { return reporterCount; }
    function totalCategories() external view returns (uint256) { return categoryCount; }
    function getScannerKeeper() external view returns (address) { return scannerKeeper; }
    function getReportVault() external view returns (address) { return reportVault; }
    function pausedState() external view returns (bool) { return paused(); }
    function getScanIdsFromIndex(uint256 start, uint256 num) external view returns (bytes32[] memory out) {        uint256 total = _scanIds.length;        if (start >= total || num == 0) return out;        if (num > MSC_VIEW_BATCH) num = MSC_VIEW_BATCH;        uint256 end = start + num;        if (end > total) end = total;        uint256 n = end - start;        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _scanIds[start + i];    }
    function getWhitelistFromIndex(uint256 start, uint256 num) external view returns (address[] memory out) {        uint256 total = _whitelistArr.length;        if (start >= total || num == 0) return out;        if (num > MSC_VIEW_BATCH) num = MSC_VIEW_BATCH;        uint256 end = start + num;        if (end > total) end = total;        uint256 n = end - start;        out = new address[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _whitelistArr[start + i];    }
    function getBlacklistFromIndex(uint256 start, uint256 num) external view returns (address[] memory out) {        uint256 total = _blacklistArr.length;        if (start >= total || num == 0) return out;        if (num > MSC_VIEW_BATCH) num = MSC_VIEW_BATCH;        uint256 end = start + num;        if (end > total) end = total;        uint256 n = end - start;        out = new address[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _blacklistArr[start + i];    }
    function getTokenScanIdsFromIndex(uint256 start, uint256 num) external view returns (bytes32[] memory out) {        uint256 total = _tokenScanIds.length;        if (start >= total || num == 0) return out;        if (num > MSC_VIEW_BATCH) num = MSC_VIEW_BATCH;        uint256 end = start + num;        if (end > total) end = total;        uint256 n = end - start;        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _tokenScanIds[start + i];    }
    function getCategoryScanIdsFromIndex(uint256 categoryId, uint256 start, uint256 num) external view returns (bytes32[] memory out) {        uint256 total = _categoryScanCount[categoryId];        if (start >= total || num == 0) return out;        if (num > MSC_VIEW_BATCH) num = MSC_VIEW_BATCH;        uint256 end = start + num;        if (end > total) end = total;        uint256 n = end - start;        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _categoryScanIds[categoryId][start + i];    }
    function scanTargetAddress(bytes32 scanId) external view returns (address) { return _scanTarget[scanId]; }
    function scanTier(bytes32 scanId) external view returns (uint8) { return _scanRiskTier[scanId]; }
    function scanBlockNumber(bytes32 scanId) external view returns (uint256) { return _scanBlock[scanId]; }
    function scanReporterAddress(bytes32 scanId) external view returns (address) { return _scanReporter[scanId]; }
    function scanFlagsHash(bytes32 scanId) external view returns (bytes32) { return _scanFlagsHash[scanId]; }
    function whitelistAddressAt(uint256 index) external view returns (address) { return _whitelistArr[index]; }
    function blacklistAddressAt(uint256 index) external view returns (address) { return _blacklistArr[index]; }
    function tokenScanIdAt(uint256 index) external view returns (bytes32) { return _tokenScanIds[index]; }
    function tokenAtTokenScanId(bytes32 tokenScanId) external view returns (address) { return _tokenAddress[tokenScanId]; }
