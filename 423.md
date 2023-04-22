tsvetanovv

medium

# Must approve by zero first

## Summary
The protocol currently uses any tokens:

> ERC20: any

Some ERC20 tokens (like USDT) do not work when changing the allowance from an existing non-zero allowance value. For example Tether (USDT)'s `approve()` function will revert if the current approval is not zero, to protect against front-running changes of approvals.

## Vulnerability Detail
Some tokens will revert when updating allowance. They must first be approved by zero and then the actual allowance must be approved.

## Impact
The protocol will impossible to use USDT.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L332-L335

```solidity
CollateralManager.sol

332: IERC20Upgradeable(collateralInfo._collateralAddress).approve( 
333:                escrowAddress,
334:                collateralInfo._amount
335:            );
```

## Tool used

Manual Review

## Recommendation
It is recommended to set the allowance to zero before increasing the allowance.

Change this:
```solidity
332: IERC20Upgradeable(collateralInfo._collateralAddress).approve( 
333:                escrowAddress,
334:                collateralInfo._amount
335:            );
```

To this:
```solidity
 IERC20Upgradeable(collateralInfo._collateralAddress).approve( 
                escrowAddress,
                0
            );

 IERC20Upgradeable(collateralInfo._collateralAddress).approve( 
                escrowAddress,
                collateralInfo._amount
            );
```