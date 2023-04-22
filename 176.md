0x52

medium

# LenderCommitmentForwarder#updateCommitment can be front-run by malicious borrower to cause lender to over-commit funds

## Summary

This is the same idea as approve vs increaseAlllowance. updateCommitment is a bit worse though because there are more reason why a user may wish to update their commitment (expiration, collateral ratio, interest rate, etc).

## Vulnerability Detail

[LenderCommitmentForwarder.sol#L212-L222](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L212-L222)

        require(
            _commitment.principalTokenAddress ==
                commitments[_commitmentId].principalTokenAddress,
            "Principal token address cannot be updated."
        );
        require(
            _commitment.marketId == commitments[_commitmentId].marketId,
            "Market Id cannot be updated."
        );

        commitments[_commitmentId] = _commitment;

LenderCommitmentForwarder#updateCommitment overwrites ALL of the commitment data. This means that even if a user is calling it to update even one value the maxPrincipal will reset, opening up the following attack vector:

1) User A creates a commitment for 100e6 USDC lending against ETH
2) User A's commitment is close to expiry so they call to update their commitment with a new expiration
3) User B sees this update and front-runs it with a loan against the commitment for 100e6 USDC
4) User A's commitment is updated and the amount is set back to 100e6 USDC
5) User B takes out another loan for 100e6 USDC
6) User A has now loaned out 200e6 USDC when they only meant to loan 100e6 USDC

## Impact

Commitment is abused to over-commit lender

## Code Snippet

[LenderCommitmentForwarder.sol#L208-L233](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L208-L233)

## Tool used

Manual Review

## Recommendation

Create a function that allows users to extend expiry while keeping amount unchanged. Additionally create a function similar to increaseApproval which increase amount instead of overwriting amount.