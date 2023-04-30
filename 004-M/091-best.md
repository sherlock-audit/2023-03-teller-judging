nobody2018

medium

# If the collateral is a fee-on-transfer token, repayment will be blocked

## Summary

As we all know, some tokens will deduct fees when transferring token. In this way, **the actual amount of token received by the receiver will be less than the amount sent**. If the collateral is this type of token, the amount of collateral recorded in the contract will bigger than the actual amount. **When the borrower repays the loan, the amount of collateral withdrawn will be insufficient, causing tx revert**.

## Vulnerability Detail

The `_bidCollaterals` mapping of `CollateralManager` records the `CollateralInfo` of each bidId. This structure records the collateral information provided by the user when creating a bid for a loan. A lender can accept a loan by calling  `TellerV2.lenderAcceptBid` that will eventually transfer the user's collateral from the user address to the CollateralEscrowV1 contract corresponding to the loan. The whole process will deduct fee twice.

```solidity
//CollateralManager.sol
function _deposit(uint256 _bidId, Collateral memory collateralInfo)
        internal
        virtual
    {
        ......
        // Pull collateral from borrower & deposit into escrow
        if (collateralInfo._collateralType == CollateralType.ERC20) {
            IERC20Upgradeable(collateralInfo._collateralAddress).transferFrom(	//transferFrom first time
                borrower,
                address(this),
                collateralInfo._amount
            );
            IERC20Upgradeable(collateralInfo._collateralAddress).approve(
                escrowAddress,
                collateralInfo._amount
            );
            collateralEscrow.depositAsset(		//transferFrom second time
                CollateralType.ERC20,
                collateralInfo._collateralAddress,
                collateralInfo._amount,			//this value is from user's input
                0
            );
        }
        ......
    }
```

The amount of collateral recorded by the CollateralEscrowV1 contract is equal to the amount originally submitted by the user.

When the borrower repays the loan, `collateralManager.withdraw` will be triggered. This function internally calls `CollateralEscrowV1.withdraw`. Since the balance of the collateral in the CollateralEscrowV1 contract is less than the amount to be withdrawn, the entire transaction reverts.

```solidity
//CollateralEscrowV1.sol
function _withdrawCollateral(
        Collateral memory _collateral,
        address _collateralAddress,
        uint256 _amount,
        address _recipient
    ) internal {
        // Withdraw ERC20
        if (_collateral._collateralType == CollateralType.ERC20) {
            IERC20Upgradeable(_collateralAddress).transfer(   //revert
                _recipient,
                _collateral._amount	//_collateral.balanceOf(address(this)) < _collateral._amount
            );
        }
    ......
    }
```

## Impact

The borrower's collateral is stuck in the instance of CollateralEscrowV1. Non-professional users will never know that they need to manually transfer some collateral into CollateralEscrowV1 to successfully repay.

- This issue blocked the user's repayment, causing the loan to be liquidated.
- The liquidator will not succeed by calling `TellerV2.liquidateLoanFull`.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L323-L326

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L432-L434

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L510

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L327-L341

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L73

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L166-L169

## Tool used

Manual Review

## Recommendation

Two ways to fix this issue.

- The `afterBalance-beforeBalance` method should be used when recording the amount of collateral.
- 
   ```diff
            --- a/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol
            +++ b/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol
            @@ -165,7 +165,7 @@ contract CollateralEscrowV1 is OwnableUpgradeable, ICollateralEscrowV1 {
                     if (_collateral._collateralType == CollateralType.ERC20) {
                         IERC20Upgradeable(_collateralAddress).transfer(
                             _recipient,
            -                _collateral._amount
            +                IERC20Upgradeable(_collateralAddress).balanceOf(address(this))
                         );
                     }
    ```