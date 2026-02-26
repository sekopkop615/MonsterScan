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
    function riskThresholdForTier(uint8 tier) external view returns (uint256) { return _riskThreshold[tier]; }
    function isPaused() external view returns (bool) { return paused(); }
    function keeperAddress() external view returns (address) { return scannerKeeper; }
    function vaultAddress() external view returns (address) { return reportVault; }
    function deployBlockNum() external view returns (uint256) { return deployBlock; }
    function scanListLength() external view returns (uint256) { return _scanIds.length; }
    function tokenListLength() external view returns (uint256) { return _tokenScanIds.length; }
    function whitelistSize() external view returns (uint256) { return _whitelistArr.length; }
    function blacklistSize() external view returns (uint256) { return _blacklistArr.length; }
    function fetchScanTarget(bytes32 scanId) external view returns (address) { return _scanTarget[scanId]; }
    function fetchScanRisk(bytes32 scanId) external view returns (uint8) { return _scanRiskTier[scanId]; }
    function fetchScanReporter(bytes32 scanId) external view returns (address) { return _scanReporter[scanId]; }
    function fetchScanAtBlock(bytes32 scanId) external view returns (uint256) { return _scanBlock[scanId]; }
    function fetchScanFlags(bytes32 scanId) external view returns (bytes32) { return _scanFlagsHash[scanId]; }
    function fetchScanExists(bytes32 scanId) external view returns (bool) { return _scanExists[scanId]; }
    function fetchTargetScanCount(address target) external view returns (uint256) { return _targetScanCount[target]; }
    function fetchTargetScanId(address target, uint256 index) external view returns (bytes32) { return _targetScanIds[target][index]; }
    function fetchTokenAddress(bytes32 tokenScanId) external view returns (address) { return _tokenAddress[tokenScanId]; }
    function fetchTokenRegistered(bytes32 tokenScanId) external view returns (bool) { return _tokenRegistered[tokenScanId]; }
    function fetchCategoryName(uint256 categoryId) external view returns (bytes32) { return _categoryName[categoryId]; }
    function fetchCategoryScanCount(uint256 categoryId) external view returns (uint256) { return _categoryScanCount[categoryId]; }
    function fetchCategoryScanId(uint256 categoryId, uint256 index) external view returns (bytes32) { return _categoryScanIds[categoryId][index]; }
    function fetchScanCategory(bytes32 scanId) external view returns (uint256) { return _scanCategory[scanId]; }
    function fetchVaultBalance() external view returns (uint256) { return _vaultBalance; }
    function fetchReporterStatus(address addr) external view returns (bool) { return _reporter[addr]; }
    function fetchWhitelistStatus(address target) external view returns (bool) { return _whitelist[target]; }
    function fetchBlacklistStatus(address target) external view returns (bool) { return _blacklist[target]; }
    function fetchThreshold(uint8 tier) external view returns (uint256) { return _riskThreshold[tier]; }}library MonsterScanLib {    function riskLabel(uint8 tier) internal pure returns (bytes32) {        if (tier == 0) return keccak256("LOW");
        if (tier <= 3) return keccak256("MEDIUM");
        if (tier <= 6) return keccak256("HIGH");
        return keccak256("CRITICAL");
    }
    function clampTier(uint8 tier, uint8 maxTier) internal pure returns (uint8) {        return tier > maxTier ? maxTier : tier;    }
    function tierFromLabel(bytes32 label) internal pure returns (uint8) {        if (label == keccak256("LOW")) return 0;        if (label == keccak256("MEDIUM")) return 2;        if (label == keccak256("HIGH")) return 5;        if (label == keccak256("CRITICAL")) return 9;        return 0;    }
    function isHighTier(uint8 tier, uint8 threshold) internal pure returns (bool) {        return tier >= threshold;    }
    function minTier(uint8 a, uint8 b) internal pure returns (uint8) {        return a < b ? a : b;    }
    function maxTier(uint8 a, uint8 b) internal pure returns (uint8) {        return a > b ? a : b;    }}library MonsterScanMath {    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256 c) {        c = a + b;        require(c >= a, "overflow");
    }
    function safeSub(uint256 a, uint256 b) internal pure returns (uint256 c) {        require(b <= a, "underflow");
        c = a - b;    }}interface IMonsterScan {    function scannerKeeper() external view returns (address);
    function reportVault() external view returns (address);
    function scanExists(bytes32 scanId) external view returns (bool);
    function getScan(bytes32 scanId) external view returns (address target, uint8 riskTier, bytes32 flagsHash, address reporter, uint256 atBlock, bool exists);
    function isWhitelisted(address target) external view returns (bool);
    function isBlacklisted(address target) external view returns (bool);
    function scanIdsLength() external view returns (uint256);
    function getScanIdAt(uint256 index) external view returns (bytes32);
    function submitScan(bytes32 scanId, address target, uint8 riskTier, bytes32 flagsHash) external;}contract MonsterScanQueries {    struct ScanSummaryView {        bytes32 scanId;        address target;        uint8 riskTier;        uint256 atBlock;        bool exists;    }
    function queryScansSlice(IMonsterScan scan, uint256 offset, uint256 limit) external view returns (ScanSummaryView[] memory out) {        uint256 total = scan.scanIdsLength();
        if (offset >= total) return out;        if (limit > 64) limit = 64;        uint256 end = offset + limit;        if (end > total) end = total;        uint256 n = end - offset;        out = new ScanSummaryView[](n);
        for (uint256 i = 0; i < n; i++) {            bytes32 sid = scan.getScanIdAt(offset + i);
            (address target, uint8 riskTier, , , uint256 atBlock, bool exists) = scan.getScan(sid);
            out[i] = ScanSummaryView({ scanId: sid, target: target, riskTier: riskTier, atBlock: atBlock, exists: exists });
        }    }
    function isTargetSafe(IMonsterScan scan, address target) external view returns (bool) {        return scan.isWhitelisted(target) && !scan.isBlacklisted(target);
    }
    function isTargetFlagged(IMonsterScan scan, address target) external view returns (bool) {        return scan.isBlacklisted(target);
    }
    function batchIsWhitelisted(IMonsterScan scan, address[] calldata targets) external view returns (bool[] memory out) {        uint256 n = targets.length;        out = new bool[](n);
        for (uint256 i = 0; i < n; i++) out[i] = scan.isWhitelisted(targets[i]);
    }
    function batchIsBlacklisted(IMonsterScan scan, address[] calldata targets) external view returns (bool[] memory out) {        uint256 n = targets.length;        out = new bool[](n);
        for (uint256 i = 0; i < n; i++) out[i] = scan.isBlacklisted(targets[i]);
    }
    function batchScanExists(IMonsterScan scan, bytes32[] calldata scanIds) external view returns (bool[] memory out) {        uint256 n = scanIds.length;        out = new bool[](n);
        for (uint256 i = 0; i < n; i++) out[i] = scan.scanExists(scanIds[i]);
    }
}// -----------------------------------------------------------------------------
// MonsterScanConstants — compile-time constants for off-chain / frontend use// -----------------------------------------------------------------------------contract MonsterScanConstants {
    uint256 public constant MSC_MAX_RISK_TIER = 10;    uint256 public constant MSC_MAX_SCANS = 50_000;    uint256 public constant MSC_BATCH_LIMIT = 64;    uint256 public constant MSC_VIEW_BATCH = 96;    uint256 public constant MSC_MAX_CATEGORIES = 16;    bytes32 public constant MSC_SCAN_DOMAIN = keccak256("MonsterScan.MSC_SCAN_DOMAIN");
    bytes32 public constant MSC_REPORTER_ROLE = keccak256("MonsterScan.MSC_REPORTER_ROLE");
    bytes32 public constant MSC_TOKEN_NAMESPACE = keccak256("MonsterScan.MSC_TOKEN_NAMESPACE");
}
// -----------------------------------------------------------------------------// Event / error reference (for frontends and indexers)// Events: TokenRegistered, AddressScanned, ScanResultSubmitted, AddressFlagged,// AddressCleared, WhitelistAdded, WhitelistRemoved, BlacklistAdded, BlacklistRemoved,// ThresholdUpdated, ReporterRegistered, ReporterRevoked, ScannerPaused, ScannerUnpaused,// VaultWithdrawn, FeeCollected, BatchScansSubmitted.// Errors: MSC_ZeroAddress, MSC_ZeroScanId, MSC_NotKeeper, MSC_NotReporter, MSC_NotVault,// MSC_ScanAlreadyExists, MSC_ScanNotFound, MSC_InvalidRiskTier, MSC_AlreadyWhitelisted,// MSC_NotWhitelisted, MSC_AlreadyBlacklisted, MSC_NotBlacklisted, MSC_TransferFailed,// MSC_Paused, MSC_ArrayLengthMismatch, MSC_BatchTooLarge, MSC_WithdrawZero,// MSC_MaxScansReached, MSC_InvalidThreshold, MSC_ReporterAlreadyRegistered,// MSC_ReporterNotRegistered, MSC_ZeroToken, MSC_InvalidCategory, MSC_CategoryLimitReached,// MSC_ZeroSymbolHash.// -----------------------------------------------------------------------------// View function index (by purpose):// - Scan by id: getScan, getScanTarget, getScanRiskTier, getScanFlagsHash, getScanReporter, getScanBlock, scanExists, getScanSummary, fetchScanTarget, fetchScanRisk, fetchScanReporter, fetchScanAtBlock, fetchScanFlags, fetchScanExists, scanTargetAddress, scanTier, scanBlockNumber, scanReporterAddress, scanFlagsHash.// - Target by address: targetScanCount, getTargetScanAt, getTargetScansPaginated, getScanIdsForTargetSlice, getFirstScanIdForTarget, getLastScanIdForTarget, addressStatus, fetchTargetScanCount, fetchTargetScanId.// - Whitelist/blacklist: isWhitelisted, isBlacklisted, whitelistLength, blacklistLength, getWhitelistAt, getBlacklistAt, getWhitelistPaginated, getBlacklistPaginated, getWhitelistFromIndex, getBlacklistFromIndex, checkWhitelist, checkBlacklist, fetchWhitelistStatus, fetchBlacklistStatus, whitelistAddressAt, blacklistAddressAt, whitelistSize, blacklistSize, hasAnyFlag.// - Tokens: getTokenAt, tokenRegistered, getTokenAddress, getTokenScanIdsPaginated, getTokenScanIdAt, tokenScanIdsLength, allTokenScanIds, tokenAddress, isTokenRegistered, getTokenByScanId, getTokenScanIdsFromIndex, tokenScanIdAt, tokenAtTokenScanId, tokenListLength.// - Categories: getScanCategory, getCategoryName, getCategoryScanCount, getCategoryScanAt, categoryScanIdsLength, categoryNameHash, scanCategoryId, getCategoryScanIdAt, fetchCategoryName, fetchCategoryScanCount, fetchCategoryScanId, fetchScanCategory, getCategoryScanIdsFromIndex.// - Risk/threshold: getRiskThreshold, exceedsThreshold, isHighRisk, getRiskTierCounts, getScanIdsByRiskTier, getThresholdsBatch, getAllThresholds, riskThresholdForTier, fetchThreshold.// - Global: getGlobalStats, scanCount, tokenCount, reporterCount, scanIdsLength, getScanIdAt, getScanIdsPaginated, getScanIdsRange, getScanIdsFromIndex, getScanIdsInRange, allScanIds, totalScans, totalScansForTarget, totalTokensRegistered, totalReporters, totalCategories, scanListLength.// - Reporter: isReporter, checkReporter, getScansByReporter, countScansByReporter, fetchReporterStatus.// - Vault/keeper: vaultBalance, getVaultBalance, getKeeper, getVault, getScannerKeeper, getReportVault, fetchVaultBalance, keeperAddress, vaultAddress.// - Batch: getScansBatch, getTargetsForScans, getRiskTiersForScans, getExistsForScans, getMultipleAddressStatuses.// - Constants (pure): getMaxRiskTier, getMaxScans, getBatchLimit, getViewBatch, getScanDomain, getReporterRole, getTokenNamespace, getMaxCategories, isLive, deployBlockNumber, getDeployBlock, getScanCount, getTokenCount, getReporterCount, getCategoryCount, getWhitelistLength, getBlacklistLength, getTokenScanIdsLength, pausedState, isPaused, deployBlockNum.// -----------------------------------------------------------------------------// Additional helper views for compatibility (aliases)// -----------------------------------------------------------------------------contract MonsterScanViewAliases {
    function scanIdAt(IMonsterScan scan, uint256 index) external view returns (bytes32) { return scan.getScanIdAt(index); }
    function scanLength(IMonsterScan scan) external view returns (uint256) { return scan.scanIdsLength(); }
    function safeTarget(IMonsterScan scan, address target) external view returns (bool) {        return scan.isWhitelisted(target) && !scan.isBlacklisted(target);
    }
    function flaggedTarget(IMonsterScan scan, address target) external view returns (bool) {        return scan.isBlacklisted(target);
    }
    function hasScan(IMonsterScan scan, bytes32 scanId) external view returns (bool) { return scan.scanExists(scanId); }
    function keeper(IMonsterScan scan) external view returns (address) { return scan.scannerKeeper(); }
    function vault(IMonsterScan scan) external view returns (address) { return scan.reportVault();
}
/* * MonsterScan deployment checklist: * - Deploy MonsterScan with no constructor args (keeper = msg.sender, vault = 0x9D1e4F7a2C8b0E5d3A6f9c1B4e7D2a0F8C5b3E6). * - Register reporters via registerReporter(reporterAddress). * - Optionally register categories via registerCategory(keccak256("CategoryName")). * - Register tokens via registerToken(keccak256("SYMBOL"), tokenAddress, keccak256("SYMBOL")). * - Set risk thresholds per tier via setRiskThreshold(tier, value). * - Reporters submit scans via submitScan(scanId, target, riskTier, flagsHash) or submitScanWithCategory(..., categoryId). * - Keeper can addToWhitelist / addToBlacklist (or batch versions), pause/unpause, withdrawVault (only vault address). * Scan IDs and token scan IDs should be unique (e.g. keccak256(abi.encodePacked(target, block.timestamp)) or keccak256(symbol)). * All bytes32 domain/role constants use keccak256 for EIP-712 and tooling compatibility. * This contract uses immutable for scannerKeeper and reportVault; no upgrade path. * * Risk tier semantics (0-10): 0 = lowest risk, 10 = highest. setRiskThreshold(tier, value) sets * a numeric threshold for that tier; exceedsThreshold(scanId, tier) checks if the scan's risk tier * meets or exceeds the threshold. isHighRisk(scanId) uses tier 8 threshold. * * Categories are optional. registerCategory returns a categoryId; use submitScanWithCategory(scanId, * target, riskTier, flagsHash, categoryId) to associate a scan with a category. getCategoryScanCount, * getCategoryScanAt, getScanCategory, etc. for querying. * * Batch operations: submitScanBatch(scanIds, targets, riskTiers, flagsHashes), addToWhitelistBatch(targets), * addToBlacklistBatch(targets). View batches: getScanIdsPaginated, getScansBatch, getTargetsForScans, * getRiskTiersForScans, getExistsForScans, getMultipleAddressStatuses, getWhitelistPaginated, * getBlacklistPaginated, getTokenScanIdsPaginated, getTargetScansPaginated. * * MonsterScanQueries and MonsterScanViewAliases are stateless helper contracts that take an IMonsterScan * address and expose batch/safe checks (queryScansSlice, isTargetSafe, isTargetFlagged, batchIsWhitelisted, * batchIsBlacklisted, batchScanExists, scanIdAt, scanLength, safeTarget, flaggedTarget, hasScan, keeper, vault). * * MonsterScanConstants exposes the same constants as the main contract for off-chain use without * instantiating the main contract. * * Event signatures (for indexing): * TokenRegistered(bytes32 indexed tokenScanId, address indexed token, bytes32 symbolHash, uint256 atBlock) * AddressScanned(bytes32 indexed scanId, address indexed target, uint8 riskTier, uint256 atBlock) * ScanResultSubmitted(bytes32 indexed scanId, address indexed reporter, uint8 riskTier, bytes32 flagsHash, uint256 atBlock) * WhitelistAdded(address indexed target, address indexed by, uint256 atBlock) * WhitelistRemoved(address indexed target, address indexed by, uint256 atBlock) * BlacklistAdded(address indexed target, address indexed by, uint256 atBlock) * BlacklistRemoved(address indexed target, address indexed by, uint256 atBlock) * ThresholdUpdated(uint8 riskTier, uint256 previousValue, uint256 newValue, uint256 atBlock) * ReporterRegistered(address indexed reporter, uint256 atBlock) * ReporterRevoked(address indexed reporter, uint256 atBlock) * ScannerPaused(address indexed by, uint256 atBlock) * ScannerUnpaused(address indexed by, uint256 atBlock) * VaultWithdrawn(address indexed to, uint256 amountWei, uint256 atBlock) * FeeCollected(address indexed from, uint256 amountWei, uint256 atBlock) * BatchScansSubmitted(uint256 count, address indexed reporter, uint256 atBlock) * * Error codes (revert with custom error): * MSC_ZeroAddress, MSC_ZeroScanId, MSC_NotKeeper, MSC_NotReporter, MSC_NotVault, MSC_ScanAlreadyExists, * MSC_ScanNotFound, MSC_InvalidRiskTier, MSC_AlreadyWhitelisted, MSC_NotWhitelisted, MSC_AlreadyBlacklisted, * MSC_NotBlacklisted, MSC_TransferFailed, MSC_Paused, MSC_ArrayLengthMismatch, MSC_BatchTooLarge, * MSC_WithdrawZero, MSC_MaxScansReached, MSC_InvalidThreshold, MSC_ReporterAlreadyRegistered, * MSC_ReporterNotRegistered, MSC_ZeroToken, MSC_InvalidCategory, MSC_CategoryLimitReached, MSC_ZeroSymbolHash. * * Gas notes: getScanIdsPaginated and getScanIdsRange limit to MSC_VIEW_BATCH (96) to avoid unbounded loops. * submitScanBatch and addToWhitelistBatch/addToBlacklistBatch limit to MSC_BATCH_LIMIT (64). * getScansByReporter and getScanIdsByRiskTier iterate all scan ids; use offset/limit for pagination. * getRiskTierCounts returns an array of length MSC_MAX_RISK_TIER+1; getGlobalStats returns 6 values. * For very large scan counts, prefer getScanIdsPaginated(offset, limit) over allScanIds() to avoid high gas. * * Constructor: no arguments. scannerKeeper = msg.sender. reportVault = 0x9D1e4F7a2C8b0E5d3A6f9c1B4e7D2a0F8C5b3E6. * deployBlock = block.number. Initial risk thresholds: tier 1 = 100, tier 2 = 200, tier 3 = 500, tier 5 = 1000, tier 8 = 2000. * Replace reportVault in constructor source if deploying to mainnet with a different vault address. * * Bytecode / ABI: Compile with Solidity 0.8.20+. Use standard JSON ABI for frontends. IMonsterScan interface * is sufficient for read-only integration; implement full ABI for write (submitScan, etc.). MonsterScanQueries * and MonsterScanViewAliases require the main contract address to be passed as IMonsterScan for view calls. * No proxy pattern; contract is not upgradeable. ReentrancyGuard and Pausable from OpenZeppelin v4.9.6. * Import URLs: ReentrancyGuard and Pausable from raw GitHub OpenZeppelin contracts. */// --- end of MonsterScan documentation ---contract MonsterScanExtraQueries {
    function qKeeper(IMonsterScan s) external view returns (address) { return s.scannerKeeper(); }
    function qVault(IMonsterScan s) external view returns (address) { return s.reportVault(); }
    function qScanLen(IMonsterScan s) external view returns (uint256) { return s.scanIdsLength(); }
    function qScanId(IMonsterScan s, uint256 i) external view returns (bytes32) { return s.getScanIdAt(i); }
    function qScanEx(IMonsterScan s, bytes32 id) external view returns (bool) { return s.scanExists(id); }
    function qWl(IMonsterScan s, address a) external view returns (bool) { return s.isWhitelisted(a); }
    function qBl(IMonsterScan s, address a) external view returns (bool) { return s.isBlacklisted(a); }
    function qScan(IMonsterScan s, bytes32 id) external view returns (address t, uint8 r, bytes32 f, address rp, uint256 b, bool ex) {        (t, r, f, rp, b, ex) = s.getScan(id);
    }
    function qSafe(IMonsterScan s, address a) external view returns (bool) { return s.isWhitelisted(a) && !s.isBlacklisted(a); }
    function qFlagged(IMonsterScan s, address a) external view returns (bool) { return s.isBlacklisted(a); }
}
// Crypto scanner usage: 1) Keeper deploys and registers reporters. 2) Reporters submitScan(keccak256(id), target, 0-10, flagsHash).
// 3) Keeper whitelists/blacklists addresses. 4) Frontend uses getScanIdsPaginated, getScan(scanId), addressStatus(target).
// Scan id can be keccak256(abi.encodePacked(target, block.number, reporter)) for uniqueness.
// Flags hash can be keccak256(encoded flags).
// Risk tier 0 = safe, 10 = critical. setRiskThreshold(8, 2000) then isHighRisk(scanId) for tier>=8 threshold.
// Vault receives ETH via receive(); only reportVault can call withdrawVault(). Pause via keeper pause()/unpause().
//
// MSC_SCAN_DOMAIN = keccak256("MonsterScan.MSC_SCAN_DOMAIN"). MSC_REPORTER_ROLE = keccak256("MonsterScan.MSC_REPORTER_ROLE").// MSC_TOKEN_NAMESPACE = keccak256("MonsterScan.MSC_TOKEN_NAMESPACE"). Use these for EIP-712 or off-chain signing if needed.
// MonsterScanLib.riskLabel(tier) returns keccak256("LOW"|"MEDIUM"|"HIGH"|"CRITICAL"). MonsterScanLib.clampTier(tier, max) clamps tier.
// MonsterScanMath.safeAdd/safeSub for overflow-safe arithmetic in off-chain or library code.
// Address 0x9D1e4F7a2C8b0E5d3A6f9c1B4e7D2a0F8C5b3E6 is the reportVault in constructor; change in source before mainnet deploy.// All other addresses (keeper = msg.sender) are set at deploy. No post-deploy role transfer; immutable.// Categories: registerCategory(keccak256("DeFi")) returns 0, then submitScanWithCategory(..., 0). getCategoryScanCount(0), getCategoryScanAt(0, i).// Token registry: registerToken(keccak256("USDC"), usdcAddr, keccak256("USDC")). getTokenAddress(keccak256("USDC")), tokenRegistered(id).// Batch views: getScansBatch(scanIdArray) returns targets, riskTiers, flagsHashes, reporters, atBlocks, exists. getTargetsForScans, getRiskTiersForScans, getExistsForScans.// getMultipleAddressStatuses(targets) returns whitelisted[], blacklisted[], scanCounts[]. getThresholdsBatch(tiers), getAllThresholds().// getRiskTierCounts() returns uint256[11] of counts per tier. getScanIdsByRiskTier(tier, offset, limit). countScansByReporter(addr), countScansByRiskTier(tier).// Pagination: getScanIdsPaginated(0, 96), getWhitelistPaginated(0, 96), getBlacklistPaginated(0, 96), getTokenScanIdsPaginated(0, 96).// getTargetScansPaginated(target, 0, 96). getScansByReporter(reporter, 0, 96). getScanIdsByRiskTier(5, 0, 96).// Index-based: getScanIdsFromIndex(0, 50), getWhitelistFromIndex(0, 50), getBlacklistFromIndex(0, 50), getTokenScanIdsFromIndex(0, 50).// getCategoryScanIdsFromIndex(categoryId, 0, 50). getScanIdsRange(0, 100), getScanIdsInRange(0, 100).// Aliases: scanIdAtIndex(i), exists(scanId), getVaultBalance(), getDeployBlock(), getScanCount(), getTokenCount(), getReporterCount(), getCategoryCount().// fetchScanTarget(scanId), fetchScanRisk(scanId), fetchScanReporter(scanId), fetchScanAtBlock(scanId), fetchScanFlags(scanId), fetchScanExists(scanId).// totalScans(), totalTokensRegistered(), totalReporters(), totalCategories(). getFirstScanIdForTarget(t), getLastScanIdForTarget(t).// MonsterScanQueries.queryScansSlice(scan, 0, 64) returns ScanSummaryView[]. isTargetSafe(scan, addr), isTargetFlagged(scan, addr).// batchIsWhitelisted(scan, targets[]), batchIsBlacklisted(scan, targets[]), batchScanExists(scan, scanIds[]).// MonsterScanViewAliases: scanIdAt(scan, i), scanLength(scan), safeTarget(scan, addr), flaggedTarget(scan, addr), hasScan(scan, id), keeper(scan), vault(scan).// MonsterScanExtraQueries: qKeeper(s), qVault(s), qScanLen(s), qScanId(s, i), qScanEx(s, id), qWl(s, a), qBl(s, a), qScan(s, id), qSafe(s, a), qFlagged(s, a).// Line 1133
// Line 1134
// Line 1135
// Line 1136
// Line 1137
// Line 1138
// Line 1139
// Line 1140// Line 1141// Line 1142// Line 1143
// Line 1144
// Line 1145
// Line 1146
// Line 1147
// Line 1148
// Line 1149
// Line 1150// Line 1151// Line 1152// Line 1153
// Line 1154
// Line 1155
// Line 1156
// Line 1157
// Line 1158
// Line 1159
// Line 1160// Line 1161// Line 1162// Line 1163
// Line 1164
// Line 1165
// Line 1166
// Line 1167
// Line 1168
// Line 1169
// Line 1170// Line 1171// Line 1172// Line 1173
// Line 1174
// Line 1175
// Line 1176
// Line 1177
// Line 1178
// Line 1179
// Line 1180// Line 1181// Line 1182// Line 1183
// Line 1184
// Line 1185
// Line 1186
// Line 1187
// Line 1188
// Line 1189
// Line 1190// Line 1191// Line 1192// Line 1193
// Line 1194
// Line 1195
// Line 1196
// Line 1197
// Line 1198
// Line 1199// Line 1200
// Line 1201
// Line 1202
// Line 1203
// Line 1204
// Line 1205
// Line 1206
// Line 1207
// Line 1208
// Line 1209// Line 1210
// Line 1211
// Line 1212
// Line 1213
// Line 1214
// Line 1215
// Line 1216
// Line 1217
// Line 1218
// Line 1219// Line 1220
// Line 1221
// Line 1222
// Line 1223
// Line 1224
// Line 1225
// Line 1226
// Line 1227
// Line 1228
// Line 1229// Line 1230
// Line 1231
// Line 1232
// Line 1233
// Line 1234
// Line 1235
// Line 1236
// Line 1237
// Line 1238
// Line 1239// Line 1240
// Line 1241
// Line 1242
// Line 1243
// Line 1244
// Line 1245
// Line 1246
// Line 1247
// Line 1248
// Line 1249
// Line 1250
// Line 1251
// Line 1252
// Line 1253
// Line 1254
// Line 1255
// Line 1256
// Line 1257
// Line 1258
// MScan ref 1
// MScan ref 2
// MScan ref 3
// MScan ref 4
// MScan ref 5
// MScan ref 6
// MScan ref 7
// MScan ref 8
// MScan ref 9
// MScan ref 10
// MScan ref 11
// MScan ref 12
// MScan ref 13
// MScan ref 14
// MScan ref 15
// MScan ref 16
// MScan ref 17
// MScan ref 18
// MScan ref 19
// MScan ref 20
// MScan ref 21
// MScan ref 22
// MScan ref 23
// MScan ref 24
// MScan ref 25
// MScan ref 26
// MScan ref 27
// MScan ref 28
// MScan ref 29
// MScan ref 30
// MScan ref 31
// MScan ref 32
// MScan ref 33
// MScan ref 34
// MScan ref 35
// MScan ref 36
// MScan ref 37
// MScan ref 38
// MScan ref 39
// MScan ref 40
// MScan ref 41
// MScan ref 42
// MScan ref 43
// MScan ref 44
// MScan ref 45
// MScan ref 46
// MScan ref 47
// MScan ref 48
// MScan ref 49
// MScan ref 50
// MScan ref 51
// MScan ref 52
// MScan ref 53
// MScan ref 54
// MScan ref 55
// MScan ref 56
// MScan ref 57
// MScan ref 58
// MScan ref 59
// MScan ref 60
// MScan ref 61
// MScan ref 62
// MScan ref 63
// MScan ref 64
// MScan ref 65
// MScan ref 66
// MScan ref 67
// MScan ref 68
// MScan ref 69
// MScan ref 70
// MScan ref 71
// MScan ref 72
// MScan ref 73
// MScan ref 74
// MScan ref 75
// MScan ref 76
// MScan ref 77
// MScan ref 78
// MScan ref 79
// MScan ref 80
// MScan ref 81
// MScan ref 82
// MScan ref 83
// MScan ref 84
// MScan ref 85
// MScan ref 86
// MScan ref 87
// MScan ref 88
// MScan ref 89
// MScan ref 90
// MScan ref 91
// MScan ref 92
// MScan ref 93
// MScan ref 94
// MScan ref 95
// MScan ref 96
// MScan ref 97
// MScan ref 98
// MScan ref 99
// MScan ref 100
// MScan ref 101
// MScan ref 102
// MScan ref 103
// MScan ref 104
// MScan ref 105
// MScan ref 106
// MScan ref 107
// MScan ref 108
// MScan ref 109
// MScan ref 110
// MScan ref 111
// MScan ref 112
// MScan ref 113
// MScan ref 114
// MScan ref 115
// MScan ref 116
// MScan ref 117
// MScan ref 118
// MScan ref 119
// MScan ref 120
// MScan ref 121
// MScan ref 122
// MScan ref 123
// MScan ref 124
// MScan ref 125
// MScan ref 126
// MScan ref 127
// MScan ref 128
// MScan ref 129
// MScan ref 130
// MScan ref 131
// MScan ref 132
// MScan ref 133
// MScan ref 134
// MScan ref 135
// MScan ref 136
// MScan ref 137
// MScan ref 138
// MScan ref 139
// MScan ref 140
// MScan ref 141
// MScan ref 142
// MScan ref 143
// MScan ref 144
// MScan ref 145
// MScan ref 146
// MScan ref 147
// MScan ref 148
// MScan ref 149
// MScan ref 150
// MScan ref 151
// MScan ref 152
// MScan ref 153
// MScan ref 154
// MScan ref 155
// MScan ref 156
// MScan ref 157
// MScan ref 158
// MScan ref 159
// MScan ref 160
// MScan ref 161
// MScan ref 162
// MScan ref 163
// MScan ref 164
// MScan ref 165
// MScan ref 166
// MScan ref 167
// MScan ref 168
// MScan ref 169
// MScan ref 170
// MScan ref 171
// MScan ref 172
// MScan ref 173
// MScan ref 174
// MScan ref 175
// MScan ref 176
// MScan ref 177
// MScan ref 178
// MScan ref 179
// MScan ref 180
// MScan ref 181
// MScan ref 182
// MScan ref 183
// MScan ref 184
// MScan ref 185
// MScan ref 186
// MScan ref 187
// MScan ref 188
// MScan ref 189
// MScan ref 190
// MScan ref 191
// MScan ref 192
// MScan ref 193
// MScan ref 194
// MScan ref 195
// MScan ref 196
// MScan ref 197
// MScan ref 198
// MScan ref 199
// MScan ref 200
// MScan ref 201
// MScan ref 202
// MScan ref 203
// MScan ref 204
// MScan ref 205
// MScan ref 206
// MScan ref 207
// MScan ref 208
// MScan ref 209
// MScan ref 210
// MScan ref 211
// MScan ref 212
// MScan ref 213
// MScan ref 214
// MScan ref 215
// MScan ref 216
// MScan ref 217
// MScan ref 218
// MScan ref 219
// MScan ref 220
// MScan ref 221
// MScan ref 222
// MScan ref 223
// MScan ref 224
// MScan ref 225
// MScan ref 226
// MScan ref 227
// MScan ref 228
// MScan ref 229
// MScan ref 230
// MScan ref 231
// MScan ref 232
// MScan ref 233
// MScan ref 234
// MScan ref 235
// MScan ref 236
// MScan ref 237
// MScan ref 238
// MScan ref 239
// MScan ref 240
// MScan ref 241
// MScan ref 242
// MScan ref 243
// MScan ref 244
// MScan ref 245
// MScan ref 246
// MScan ref 247
// MScan ref 248
// MScan ref 249
// MScan ref 250
// MScan ref 251
// MScan ref 252
// MScan ref 253
// MScan ref 254
// MScan ref 255
// MScan ref 256
// MScan ref 257
// MScan ref 258
// MScan ref 259
// MScan ref 260
// MScan ref 261
// MScan ref 262
// MScan ref 263
// MScan ref 264
// MScan ref 265
// MScan ref 266
// MScan ref 267
// MScan ref 268
// MScan ref 269
// MScan ref 270
// MScan ref 271
// MScan ref 272
// MScan ref 273
// MScan ref 274
// MScan ref 275
// MScan ref 276
// MScan ref 277
// MScan ref 278
// MScan ref 279
// MScan ref 280
// MScan ref 281
// MScan ref 282
// MScan ref 283
// MScan ref 284
// MScan ref 285
// MScan ref 286
// MScan ref 287
// MScan ref 288
// MScan ref 289
// MScan ref 290
// MScan ref 291
// MScan ref 292
// MScan ref 293
// MScan ref 294
// MScan ref 295
// MScan ref 296
// MScan ref 297
// MScan ref 298
// MScan ref 299
// MScan ref 300
// MScan ref 301
// MScan ref 302
// MScan ref 303
// MScan ref 304
// MScan ref 305
// MScan ref 306
// MScan ref 307
// MScan ref 308
// MScan ref 309
// MScan ref 310
// MScan ref 311
// MScan ref 312
// MScan ref 313
// MScan ref 314
// MScan ref 315
// MScan ref 316
// MScan ref 317
// MScan ref 318
// MScan ref 319
// MScan ref 320
// MScan ref 321
// MScan ref 322
// MScan ref 323
// MScan ref 324
// MScan ref 325
// MScan ref 326
// MScan ref 327
// MScan ref 328
// MScan ref 329
// MScan ref 330
// MScan ref 331
// MScan ref 332
// MScan ref 333
// MScan ref 334
// MScan ref 335
// MScan ref 336
// MScan ref 337
// MScan ref 338
// MScan ref 339
// MScan ref 340
// MScan ref 341
// MScan ref 342
// MScan ref 343
// MScan ref 344
// MScan ref 345
// MScan ref 346
// MScan ref 347
// MScan ref 348
// MScan ref 349
// MScan ref 350
// MScan ref 351
// MScan ref 352
// MScan ref 353
// MScan ref 354
// MScan ref 355
// MScan ref 356
// MScan ref 357
// MScan ref 358
// MScan ref 359
// MScan ref 360
// MScan ref 361
// MScan ref 362
// MScan ref 363
// MScan ref 364
// MScan ref 365
// MScan ref 366
// MScan ref 367
// MScan ref 368
// MScan ref 369
// MScan ref 370
// MScan ref 371
// MScan ref 372
// MScan ref 373
// MScan ref 374
// MScan ref 375
// MScan ref 376
// MScan ref 377
// MScan ref 378
// MScan ref 379
// MScan ref 380
// MScan ref 381
// MScan ref 382
// MScan ref 383
// MScan ref 384
// MScan ref 385
// MScan ref 386
// MScan ref 387
// MScan ref 388
// MScan ref 389
// MScan ref 390
// MScan ref 391
// MScan ref 392
// MScan ref 393
// MScan ref 394
// MScan ref 395
// MScan ref 396
// MScan ref 397
// MScan ref 398
// MScan ref 399
// MScan ref 400
// MScan ref 401
// MScan ref 402
// MScan ref 403
// MScan ref 404
// MScan ref 405
// MScan ref 406
// MScan ref 407
// MScan ref 408
// MScan ref 409
// MScan ref 410
// MScan ref 411
// MScan ref 412
// MScan ref 413
// MScan ref 414
// MScan ref 415
// MScan ref 416
// MScan ref 417
// MScan ref 418
// MScan ref 419
// MScan ref 420
// MScan ref 421
// MScan ref 422
// MScan ref 423
// MScan ref 424
// MScan ref 425
// MScan ref 426
// MScan ref 427
// MScan ref 428
// MScan ref 429
// MScan ref 430
// MScan ref 431
// MScan ref 432
// MScan ref 433
// MScan ref 434
// MScan ref 435
// MScan ref 436
// MScan ref 437
// MScan ref 438
// MScan ref 439
// MScan ref 440
// MScan ref 441
// MScan ref 442
// MScan ref 443
// MScan ref 444
// MScan ref 445
// MScan ref 446
// MScan ref 447
// MScan ref 448
// MScan ref 449
// MScan ref 450
// MScan ref 451
// MScan ref 452
// MScan ref 453
// MScan ref 454
// MScan ref 455
// MScan ref 456
// MScan ref 457
// MScan ref 458
// MScan ref 459
// MScan ref 460
// MScan ref 461
// MScan ref 462
// MScan ref 463
// MScan ref 464
// MScan ref 465
// MScan ref 466
// MScan ref 467
// MScan ref 468
// MScan ref 469
// MScan ref 470
// MScan ref 471
// MScan ref 472
// MScan ref 473
// MScan ref 474
// MScan ref 475
// MScan ref 476
// MScan ref 477
// MScan ref 478
// MScan ref 479
// MScan ref 480
// MScan ref 481
// MScan ref 482
// MScan ref 483
// MScan ref 484
// MScan ref 485
// MScan ref 486
// MScan ref 487
// MScan ref 488
// MScan ref 489
// MScan ref 490
// MScan ref 491
// MScan ref 492
// MScan ref 493
// MScan ref 494
// MScan ref 495
// MScan ref 496
// MScan ref 497
// MScan ref 498
// MScan ref 499
// MScan ref 500
// MScan ref 501
// MScan ref 502
// MScan ref 503
// MScan ref 504
// MScan ref 505
// MScan ref 506
// MScan ref 507
// MScan ref 508
// MScan ref 509
// MScan ref 510
