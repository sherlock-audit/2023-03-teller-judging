RaymondFam

medium

# repayLoanMinimum() and repayLoan() do not check if loan has been defaulted and collaterals claimed by the lender

## Summary
A loan that has defaulted where its collaterals already claimed by the lender does not prevent the borrower from making payments, leading to the borrower incur additional losses.

## Vulnerability Detail
Here is a typical scenario:

1. Alice’s loan has defaulted and her lender, Bob has a day to see if Alice is still going to make her payment.
2. True enough Alice is kind of glad noticing she still has a chance to keep her loan intact and proceeds to making a [minimum payment](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L580-L599).
3. Bob, upon seeing this in the mempool, front runs Alice to [claim the collaterals](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L250-L260).
4. Next, Alice’s transaction executes successfully by paying Bob additional payment although her collaterals in the escrow have been fully drained.

## Impact
Alice could have incurred more added loss had she made a larger payment by calling [repayLoan()](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L629-L655) instead. 

(Note: The call would have reverted at [CollateralEscrowV1.withdraw()](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L92) (due to collateral._amount < _amount) had Alice resorted to calling repayLoanFull(). But given her financial situation this would be less likely to happen.)

Additionally, Alice might naively continue making all future payments since the function logic would fully permit that till the last payment was going to revert though.

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L580-L599

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L629-L655

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L250-L260

## Tool used

Manual Review

## Recommendation
Consider adding a reverting check on the affected repay functions if the loan collaterals already equal zero due to an earlier default.
