// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {PolicyEngine} from "./core/PolicyEngine.sol";
import {IERC165} from "./interfaces/IERC165.sol";
import {IPolicyEngine} from "./interfaces/IPolicyEngine.sol";
import {ISafe} from "./interfaces/ISafe.sol";
import {ISafeModuleGuard} from "./interfaces/ISafeModuleGuard.sol";
import {ISafeTransactionGuard} from "./interfaces/ISafeTransactionGuard.sol";
import {Operation} from "./interfaces/Operation.sol";
import {SignatureExtension} from "./libraries/SignatureExtension.sol";

/**
 * @title Safe Policy Guard
 * @dev Apply security policy to all Safe transactions.
 */
abstract contract SafePolicyGuardBase is PolicyEngine, ISafeModuleGuard, ISafeTransactionGuard {
    /**
     * @notice The configuration data struct for a policy.
     * @custom:member target The target address for the policy.
     * @custom:member selector The selector for the policy.
     * @custom:member operation The operation for the policy.
     * @custom:member policy The policy address. Zero removes the entry, so the operation fallback applies, if any.
     * @custom:member data The data for the policy.
     */
    struct Configuration {
        address target;
        bytes4 selector;
        Operation operation;
        address policy;
        bytes data;
    }

    /**
     * @dev `keccak256("guard_manager.guard.address")` — Safe's `GuardManager.GUARD_STORAGE_SLOT`.
     */
    bytes32 private constant _GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /**
     * @dev `keccak256("module_manager.module_guard.address")` — Safe's
     *      `ModuleManager.MODULE_GUARD_STORAGE_SLOT`.
     */
    bytes32 private constant _MODULE_GUARD_STORAGE_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    /**
     * @dev `keccak256("SafePolicyGuard.PolicyContext.v1")` — the {SignatureExtension} type carrying
     *      policy context in the Safe `signatures` tail.
     */
    bytes32 private constant _CONTEXT_TYPE_HASH = 0x5aa463b48748f9162d63ae93151d31fed6a96b34cd2ae84ef33d25b0bdea62e4;

    struct ConfigurationRequest {
        uint256 validFrom;
        uint256 expiry;
    }

    // Zero expiry marks an absent request, including on chains that can have timestamp zero.
    mapping(address safe => mapping(bytes32 root => ConfigurationRequest)) private _requests;

    /**
     * @notice Error indicating the root is already configured.
     * @param root The root that is already configured.
     */
    error RootAlreadyConfigured(bytes32 root);

    /**
     * @notice Error indicating non zero gas price is not allowed.
     */
    error NonZeroGasPrice();

    /**
     * @notice Error indicating non zero safe transaction gas is not allowed.
     */
    error NonZeroSafeTxGas();

    /**
     * @notice Error indicating the root is not configured.
     * @param root The root that is not configured.
     */
    error RootNotConfigured(bytes32 root);

    /**
     * @notice Error indicating the policy root configuration is pending.
     */
    error RootConfigurationPending();

    /**
     * @notice Error indicating the policy root configuration is past its application window.
     */
    error RootConfigurationExpired();

    /**
     * @notice Error indicating this contract is already installed as a guard on the caller.
     */
    error GuardAlreadyEnabled();

    /**
     * @notice Error indicating the guarded transaction failed to execute.
     */
    error ExecutionFailed();

    /**
     * @notice Error indicating the guarded module transaction failed to execute.
     */
    error ModuleExecutionFailed();

    /**
     * @notice Zero expiry would leave an empty application window.
     */
    error ZeroExpiryNotAllowed();

    /**
     * @notice Emitted when a configuration is requested.
     * @param safe The address of the Safe.
     * @param root The requested configuration root.
     * @param timestamp The timestamp when the request matures.
     */
    event RootConfigured(address indexed safe, bytes32 indexed root, uint256 timestamp);

    /**
     * @notice Emitted when a configuration request is invalidated.
     * @param safe The address of the Safe.
     * @param root The invalidated configuration root.
     */
    event RootInvalidated(address indexed safe, bytes32 indexed root);

    /**
     * @notice Emitted when a configuration is applied.
     * @param safe The address of the Safe.
     * @param root The applied configuration root.
     */
    event RootApplied(address indexed safe, bytes32 indexed root);

    /**
     * @inheritdoc IERC165
     */
    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return
            interfaceId == type(IPolicyEngine).interfaceId || // 0x04a9e3cd
            interfaceId == type(ISafeModuleGuard).interfaceId || // 0x58401ed8
            interfaceId == type(ISafeTransactionGuard).interfaceId || // 0xe6d7a83a
            interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
    }

    /**
     * @dev Permits the Safe to reach the configuration entry points with no policy configured, so a
     *      Safe can never lock itself out of managing its own policies. Each call is pinned exactly
     *      — this contract as target, zero value, `CALL`, and a configuration selector — and none of
     *      them can apply a configuration outside the delay: `configureImmediately` is deliberately
     *      absent, and is separately rejected once the guard is installed.
     */
    function _allowedCalls(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) internal view virtual override returns (bool) {
        return
            to == address(this) &&
            value == 0 &&
            operation == Operation.CALL &&
            _isConfigurationSelector(_decodeSelector(data));
    }

    function _isConfigurationSelector(bytes4 selector) internal pure virtual returns (bool) {
        return
            selector == this.requestConfiguration.selector ||
            selector == this.applyConfiguration.selector ||
            selector == this.invalidateRoot.selector;
    }

    /**
     * @inheritdoc ISafeTransactionGuard
     */
    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures,
        address executor
    ) external override {
        // Gas refunds are deliberately unsupported: they are another way to move funds out of a
        // Safe, are rarely used, and are not worth covering in the policy interface. With
        // `gasPrice == 0` the Safe skips `handlePayment` entirely, so `baseGas`, `gasToken` and
        // `refundReceiver` cannot move value and need no policy check.
        require(gasPrice == 0, NonZeroGasPrice());

        // A non-zero `safeTxGas` lets a Safe transaction whose inner call fails complete without
        // reverting. Once policy checks can mutate state, that would commit any state a policy
        // staged during the pre-check against a failed action. Forbid it so a failed execution
        // always reverts atomically, keeping policy state in sync with execution outcome.
        require(safeTxGas == 0, NonZeroSafeTxGas());

        // An owner transaction has no authorizing module.
        _enterCheck(msg.sender, address(0));
        checkTransaction(msg.sender, to, value, data, operation, _decodeContext(signatures));
        _afterOwnerPolicyCheck(
            to,
            value,
            data,
            operation,
            safeTxGas,
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            signatures,
            executor
        );
        _exitCheck();
    }

    /**
     * @inheritdoc ISafeTransactionGuard
     * @dev The hook still runs on a successful transaction; what it cannot observe while
     *      `safeTxGas == 0` and `gasPrice == 0` are enforced is a *failure*, because the Safe
     *      reverts before calling it. Kept so atomicity is enforced locally rather than assumed of
     *      the Safe version in use.
     */
    function checkAfterExecution(bytes32 txHash, bool success) external override {
        require(success, ExecutionFailed());
        _afterOwnerExecution(txHash);
    }

    /**
     * @inheritdoc ISafeModuleGuard
     */
    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address module
    ) external override returns (bytes32 moduleTxHash) {
        // The module travels out-of-band so policies receive it authenticated; passing it through
        // `context` let any executor forge a module identity from the Safe `signatures`.
        _enterCheck(msg.sender, module);
        checkTransaction(msg.sender, to, value, data, operation, _emptyContext());
        _afterModulePolicyCheck(to, value, data, operation, module);
        _exitCheck();
        return bytes32(0);
    }

    /**
     * @inheritdoc ISafeModuleGuard
     * @dev Checks are pre-execution only, so any state a policy wrote during the check commits with
     *      the transaction. The module path has no `safeTxGas` equivalent —
     *      `execTransactionFromModule` returns `false` instead of reverting — so without this a
     *      policy's writes would commit against an action that never took effect.
     */
    function checkAfterModuleExecution(bytes32, bool success) external pure override {
        require(success, ModuleExecutionFailed());
    }

    /* solhint-disable no-empty-blocks */
    /// @dev Runs with the policy reentrancy gate held and the original caller.
    function _afterOwnerPolicyCheck(
        address,
        uint256,
        bytes calldata,
        Operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes calldata,
        address
    ) internal virtual {}

    /// @dev Extensions that write state must bind cleanup to a live record for the caller and hash.
    function _afterOwnerExecution(bytes32) internal virtual {}

    /// @dev Runs with the policy reentrancy gate held and the original caller.
    function _afterModulePolicyCheck(address, uint256, bytes calldata, Operation, address) internal virtual {}
    /* solhint-enable no-empty-blocks */

    /**
     * @dev Decodes additional context to pass to the policy from the signatures bytes.
     *      Absence is not an error, so signatures carrying no context (plain ECDSA owner signatures)
     *      work for policies that do not need any. A blob that claims the type but is malformed does
     *      revert, which denies the transaction rather than silently yielding empty context.
     */
    function _decodeContext(bytes calldata signatures) internal pure returns (bytes calldata) {
        if (!SignatureExtension.has(signatures, _CONTEXT_TYPE_HASH)) {
            return _emptyContext();
        }

        return SignatureExtension.payload(signatures, _CONTEXT_TYPE_HASH);
    }

    /**
     * @dev `signatures` without the policy context extension, if one is present. Its owner
     *      signatures, including any dynamic contract-signature data, are left unchanged.
     */
    function _ownerSignatures(bytes calldata signatures) internal pure returns (bytes calldata) {
        if (!SignatureExtension.has(signatures, _CONTEXT_TYPE_HASH)) {
            return signatures;
        }

        bytes calldata context = SignatureExtension.payload(signatures, _CONTEXT_TYPE_HASH);
        uint256 ownerLength;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            ownerLength := sub(context.offset, signatures.offset)
        }
        return signatures[:ownerLength];
    }

    function _emptyContext() internal pure returns (bytes calldata) {
        return msg.data[0:0];
    }

    /**
     * @dev Whether this contract is installed on `safe` as either its transaction or module guard.
     */
    function _isGuardEnabled(address safe) internal view returns (bool) {
        return
            _readGuardSlot(safe, _GUARD_STORAGE_SLOT) == address(this) ||
            _readGuardSlot(safe, _MODULE_GUARD_STORAGE_SLOT) == address(this);
    }

    /**
     * @dev Reads a guard address out of `safe`'s storage. Returns `address(0)` when `safe` does not
     *      answer `getStorageAt` as a Safe would, so that non-Safe callers keep working rather than
     *      reverting on a failed decode.
     */
    function _readGuardSlot(address safe, bytes32 slot) private view returns (address guard) {
        (bool success, bytes memory returnData) = safe.staticcall(
            abi.encodeCall(ISafe.getStorageAt, (uint256(slot), 1))
        );

        // A Safe answers with `bytes` holding a single word, ABI-encoded as
        // 32 offset + 32 length + 32 data.
        if (!success || returnData.length < 96) {
            return address(0);
        }

        // Read the data word directly rather than via `abi.decode`, which would revert on a caller
        // that answers with a malformed encoding instead of leaving it to the length check above.
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            guard := and(mload(add(returnData, 0x60)), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    /**
     * @notice The timestamp at which a configuration request matures.
     * @dev Returns zero for an absent request. See {rootExpiry} to distinguish a request at timestamp zero.
     */
    function rootConfigured(address safe, bytes32 root) external view returns (uint256) {
        return _requests[safe][root].validFrom;
    }

    /**
     * @notice The snapshotted application window in seconds. Zero denotes an absent request.
     */
    function rootExpiry(address safe, bytes32 root) public view returns (uint256) {
        return _requests[safe][root].expiry;
    }

    function _expired(ConfigurationRequest storage request) private view returns (bool) {
        uint256 expiry = request.expiry;
        uint256 validFrom = request.validFrom;
        return expiry != type(uint256).max && block.timestamp >= validFrom && block.timestamp - validFrom >= expiry;
    }

    /// @notice The delay and application window in seconds for new requests by `safe`.
    /// @dev Expiry must be nonzero. The maximum uint256 represents an unlimited window.
    function configurationTiming(address safe) public view virtual returns (uint256 delay, uint256 expiry);

    /**
     * @notice Configures and confirms multiple policies for an address, bypassing the delay.
     * @param configurations The array of configurations to be applied.
     * @dev Only usable before this contract is installed as a guard, which is what keeps the delay
     *      unavoidable afterwards. Relying on the guard check to reject the call is not sufficient:
     *      any policy permitting a `CALL` to this contract (a permissive fallback, for example)
     *      would let it through and defeat the timelock, including for guard removal.
     */
    function configureImmediately(Configuration[] calldata configurations) external virtual {
        require(!_isGuardEnabled(msg.sender), GuardAlreadyEnabled());
        _confirmConfigurations(configurations);
    }

    /**
     * @notice Requests a configuration change using the caller's current timing.
     * @param configureRoot The root of the configuration to be applied.
     */
    function requestConfiguration(bytes32 configureRoot) external virtual {
        ConfigurationRequest storage request = _requests[msg.sender][configureRoot];
        // An expired request is spent, so the same root may be requested afresh without having to
        // be invalidated first.
        require(request.expiry == 0 || _expired(request), RootAlreadyConfigured(configureRoot));
        (uint256 delay, uint256 expiry) = configurationTiming(msg.sender);
        uint256 validFrom = block.timestamp + delay;
        request.validFrom = validFrom;
        request.expiry = expiry;
        emit RootConfigured(msg.sender, configureRoot, validFrom);
    }

    /**
     * @notice Invalidates a policy configuration change.
     * @param configureRoot The root of the configuration to be invalidated.
     * @dev A Safe can discard any outstanding request immediately.
     */
    function invalidateRoot(bytes32 configureRoot) public virtual {
        require(_requests[msg.sender][configureRoot].expiry != 0, RootNotConfigured(configureRoot));
        delete _requests[msg.sender][configureRoot];
        emit RootInvalidated(msg.sender, configureRoot);
    }

    /**
     * @notice Applies a policy configuration change.
     * @param configurations The array of configurations to be applied.
     * @dev This can be used to set multiple policies at once. {RootApplied} is emitted before the
     *      individual {PolicyConfirmed} logs, so an indexer can attribute them to the root.
     */
    function applyConfiguration(Configuration[] calldata configurations) external virtual {
        _consumeRequest(keccak256(abi.encode(configurations)));
        _confirmConfigurations(configurations);
    }

    function _confirmConfigurations(Configuration[] calldata configurations) internal {
        for (uint256 i = 0; i < configurations.length; i++) {
            _confirmPolicy(
                msg.sender,
                configurations[i].target,
                configurations[i].selector,
                configurations[i].operation,
                configurations[i].policy,
                configurations[i].data
            );
        }
    }

    function _consumeRequest(bytes32 configureRoot) internal {
        ConfigurationRequest storage request = _requests[msg.sender][configureRoot];
        require(request.expiry != 0, RootNotConfigured(configureRoot));
        require(block.timestamp >= request.validFrom, RootConfigurationPending());
        require(!_expired(request), RootConfigurationExpired());
        delete _requests[msg.sender][configureRoot];
        emit RootApplied(msg.sender, configureRoot);
    }
}
