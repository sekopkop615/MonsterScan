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
