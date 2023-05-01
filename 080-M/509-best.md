carrotsmuggler

medium

# Loss of precision during interest calculation

## Summary

Interest free loans can be taken out due to insufficient precision in interest calculations.

## Vulnerability Detail

The interest owed is calculated using in the function `calculateAmountOwed` in the V2Calculations library. The interesting part is quoted here.

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol#L89-L91

The value `owedPrincipal_` is in the native token decimals, say 6 for USDC. Thus `interestOwedInAYear` is also calculated in 6 decimals. `owedTime` is the difference in seconds, which can be as little as the block times, so around 10 seconds. `daysInYear` is the seconds in a year. For 365 days, it is 31536000.

Thus the contract multiplies 6 decimals with a small number (block time) and then divides by a huge number (seconds in year). Since solidity does not support floating point numbers, this can lead to rounding down of the interest amount to 0.

For example, lets say the interest owed in an year is 10 USDC. Thus in native token decimals, thats 10 _ 10^6, or 10^7. If the `owedTime` is 3 seconds, then the interest owed is 10^7 _ 3 / 31536000 = 0. This is an extreme case which shows an interest free loan for small values, but for larger values and normal numbers, this translates to large amounts of interests being rounded down. This issue is also dependent on the decimals of the token, thus for tokens with 2 decimals this can lead to much larger losses. Since the protocol is meant to work with tokens of all decimals, this creates an issue here.

## Impact

Loss of interest.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol#L89-L91

## Tool used

Manual Review

## Recommendation

Revert on 0 interest payments.
