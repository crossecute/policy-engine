// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {SafePolicyGuardBase} from "./SafePolicyGuardBase.sol";

/// @notice A policy guard with one immutable timing for all Safes.
contract SafePolicyGuard is SafePolicyGuardBase {
    uint256 public immutable DELAY;
    uint256 public immutable EXPIRY;

    constructor(uint256 delay, uint256 expiry) {
        require(expiry != 0, ZeroExpiryNotAllowed());
        DELAY = delay;
        EXPIRY = expiry;
    }

    /// @inheritdoc SafePolicyGuardBase
    function configurationTiming(address) public view override returns (uint256 delay, uint256 expiry) {
        return (DELAY, EXPIRY);
    }
}
