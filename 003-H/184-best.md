0x52

high

# Malicious user can poison bids before they exist

## Summary

Bids can be committed to before they even exist allowing bids to be poisoned with malicious ERC20 tokens making bids created and fulfilled by the LenderCommitmentForwarder extremely dangerous.

## Vulnerability Detail

In the readme it states:
`If a rebasing/weird token breaks just the loan that it is in, we want to know about it but that is bad but largely OK (not hyper critical) since the borrower and lender both agreed to that asset manually beforehand and, really, shouldnt have.`

The second part of that statement isn't true because the bids can be poisoned beforehand. 

[CollateralManager.sol#L117-L130](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L117-L130)

    function commitCollateral(
        uint256 _bidId,
        Collateral[] calldata _collateralInfo
    ) public returns (bool validation_) {
        address borrower = tellerV2.getLoanBorrower(_bidId);
        (validation_, ) = checkBalances(borrower, _collateralInfo); <- @audit-issue no access control

        if (validation_) {
            for (uint256 i; i < _collateralInfo.length; i++) {
                Collateral memory info = _collateralInfo[i];
                _commitCollateral(_bidId, info);
            }
        }
    }

This happens because commitCollateral never checks that the borrower != address(0) (i.e. that the bid doesn't exist). BidId's are assigned sequentially, which makes this very problematic for bids created and fulfilled by the LenderCommitmentForwarder. It makes the assumption that the agreed upon collateral is the only collateral in the contract. Since they can be easily poisoned (bids are assigned sequentially) this creates a serious issue for those loans.

A malicious user can easily poison a large number of bidIds with a malicious token and trap any users who use LenderCommitmentForwarder to open a loan

## Impact

Bids created and fulfilled by LenderCommitmentForwarder are highly dangerous since they can easily be poisoned

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L138-L147

## Tool used

Manual Review

## Recommendation

Cause CollateralManager#commitCollateral to revert if borrower == address(0)