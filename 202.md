T1MOH

high

# Lender force Loan become default

## Summary
in `_repayLoan()` directly transfer the debt token to Lender, but did not consider that Lender can not accept the token (in contract blacklist), resulting in `_repayLoan()` always revert, and finally the Loan will be default.

## Vulnerability Detail
The only way for the borrower to get the collateral token back is to repay the amount owed via _repayLoan(). Currently in the _repayLoan() method transfers the principal token directly to the Lender.
This has a problem:
if the Lender is blacklisted by the principal token now, the debtToken.transferFrom() method will fail and the _repayLoan() method will always fail and finally the Loan will default.

See also https://github.com/sherlock-audit/2023-01-cooler-judging/issues/23
## Impact
Lender forced Loan become default for get collateral, borrower lost collateral

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L747

## Tool used

Manual Review

## Recommendation
Instead of transferring the debt token directly, put the debt token into the protocol and set like: withdrawBalance[token][lender] += amount, and provide the method withdraw(address token, address receiver) for lender to get principal token back