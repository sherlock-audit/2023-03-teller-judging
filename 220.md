Inspex

high

# Use `safeTransfer()` instead of `transfer()`


## Summary
The `transfer()` function of the `IERC20Upgradeable` interface return a boolean value that indicates a success status. However, some tokens do not implement the EIP20 standard correctly, and the `transfer()` function return void instead.


## Vulnerability Detail
After the lender accepts the borrower's bid, the borrower's collateral is deposited into the `CollateralEscrowV1` contract using the `SafeERC20Upgradeable.safeTransferFrom()` function.

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L119-L124


However, when users withdraw funds from the `CollateralEscrowV1` contract, such as when liquidating or fully repaying a loan, the token is transferred using the `IERC20Upgradeable.transfer()` function. This can cause issues with tokens that are not implemented according to the EIP20 standard, such as `USDT` token on the mainnet network, as they may be reverted.

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L166-L169

Therefore, if users use tokens that are not implemented according to the EIP20 standard, such as the `USDT` token, it can prevent the loan from being repaid or liquidated, potentially resulting in the loss of the user's collateral.

## Impact
Users of the Teller platform may be at risk of losing their collateral if they use non-EIP20 standard tokens such as the `USDT` token, which results in the token being reverted. This can cause the loan to become unrecoverable and result in the loss of the user's collateral.

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L166-L169

## Tool used

Manual Review

## Recommendation
We recommend adding the implementation of the OpenZeppelin's `SafeERC20` library, which replaces the usage of the `transfer()` function with the `safeTransfer()` function.