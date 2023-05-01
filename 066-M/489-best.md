ArbitraryExecution

high

# Reentrancy in `repayLoan`

## Summary
The `liquidateLoanFull` [function](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L690-L697) does not follow the checks, effects, interactions coding pattern.

## Vulnerability Detail
The `LIQUIDATED` state is only updated on a bid after an external message call is made transferring the tokens. Malicious or reentrant tokens can abuse this and reenter the `liquidateLoanFull` function

## Impact
Can lead to a position being liquidated multiple times.

## Code Snippet
```solidity
        _repayLoan(
            _bidId,
            Payment({ principal: owedPrincipal, interest: interest }),
            owedPrincipal + interest,
            false
        );

        bid.state = BidState.LIQUIDATED;
```

## Tool used
Manual Review

## Recommendation
Consider using the OpenZeppelin reentrant modifier.
