ArbitraryExecution

medium

# No storage gap in inherited contracts

## Summary
There is no storage gap on [contracts](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L5-L6) (ex. `TellerV2.sol`, `TellerV2Storage.sol`, `ProtocolFee.sol`) and can make upgrading much more difficult and expensive in the future.

This applies to all contracts in scope.

## Vulnerability Detail
When contracts do not have a storage gap, it can make upgrading to a new version difficult and expensive if the storage layout changes.

## Impact
Can make upgrading in the future very expensive and difficult

## Code Snippet

## Tool used
Manual Review

## Recommendation
Add a variable to each of the inherited contracts that takes up a large number of storage slots. Then when performing upgrades in the future subtract the number of additional storage slots used in the new version from the original number of set storage slots. For example, you could deploy a version 1 with `uint256[50] __gap;`. If in version 2 you use an additional 5 storage slots, you would then modify `__gap` to `uint256[45] __gap;`.
