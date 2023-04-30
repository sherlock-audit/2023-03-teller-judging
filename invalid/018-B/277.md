foxb868

medium

# Late Payment Calculation based on Next Due Date.

## Summary
The `isPaymentLate()` function calculates whether a payment is late or not, the function checks whether the current `timestamp` is greater than the next due date of the payment, which is calculated using the `calculateNextDueDate()` function, and the issue arises when the function does not consider the time zone while calculating the next due date, leading to the calculation of the due date in a different time zone, this can result in incorrect calculations of the due date and may cause the payment to be marked as late even if it is not late.

## Vulnerability Detail
In the `isPaymentLate()` function, below is the line that calculates whether a payment is late, and the function checks whether the current `timestamp` is greater than the next due date of the payment. If it is, the payment is considered late.

Affected line of the [isPaymentLate(): #L916](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L916)
```solidity
return uint32(block.timestamp) > calculateNextDueDate(_bidId);
```
Affected Code Block of the [isPaymentLate: [](#L914-L917](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L914-L917)
```solidity
    function isPaymentLate(uint256 _bidId) public view override returns (bool) {
        if (bids[_bidId].state != BidState.ACCEPTED) return false;
        return uint32(block.timestamp) > calculateNextDueDate(_bidId);
    }
```

## Impact
When the wrong calculation happen, it can cause the payment to be marked as late even if it is not late, it could cause disputes between borrowers and lenders, and may cause borrowers to default on their loans, leading to loss of funds for the lenders.

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L916
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L914-L917

## Tool used

Manual Review

## Recommendation
The contract should use a standardized time zone to calculate the due date, and if possible the contract should also allow the borrower to specify their time zone to avoid any discrepancies.

Additionally, the contract should ensure that the due date is calculated accurately and should consider all relevant factors, including weekends and holidays, when calculating the due date.

The contract should also have a mechanism to allow borrowers to dispute any late payment claims and to provide evidence to support their claim.
