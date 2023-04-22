cducrest-brainbot

medium

# Borrower/lender will not be able to withdraw any collateral when partially blacklisted

## Summary

The function to withdraw collateral directly sends each collateral token either to the loan borrower (when loan is repaid) or to the lender (when loan is defaulted).

If the borrower committed multiple tokens and one of them uses a blacklist, it could be that they are blacklisted for part of the collateral and will not be able to withdraw any of the collateral.

## Vulnerability Detail

When a loan is repaid, `CollateralManager.withdraw()` allows borrower to withdraw all of their collateral:
```solidity
    function withdraw(uint256 _bidId) external {
        BidState bidState = tellerV2.getBidState(_bidId);
        if (bidState == BidState.PAID) {
            _withdraw(_bidId, tellerV2.getLoanBorrower(_bidId));
        } else if (tellerV2.isLoanDefaulted(_bidId)) {
            _withdraw(_bidId, tellerV2.getLoanLender(_bidId));
            emit CollateralClaimed(_bidId);
        } else {
            revert("collateral cannot be withdrawn");
        }
    }
```

The `_withdraw()` function loops over all the committed collateral and withdraws each one:

```solidity
    function _withdraw(uint256 _bidId, address _receiver) internal virtual {
        for (
            uint256 i;
            i < _bidCollaterals[_bidId].collateralAddresses.length();
            i++
        ) {
            // Get collateral info
            Collateral storage collateralInfo = _bidCollaterals[_bidId]
                .collateralInfo[
                    _bidCollaterals[_bidId].collateralAddresses.at(i)
                ];
            // Withdraw collateral from escrow and send it to bid lender
            ICollateralEscrowV1(_escrows[_bidId]).withdraw(
                collateralInfo._collateralAddress,
                collateralInfo._amount,
                _receiver
            );
            emit CollateralWithdrawn(
                _bidId,
                collateralInfo._collateralType,
                collateralInfo._collateralAddress,
                collateralInfo._amount,
                collateralInfo._tokenId,
                _receiver
            );
        }
    }
```

The `CollateralEscrowV1.withdraw()` function directly sends the token to withdrawer:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L84-L103
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L158-L194

## Impact

If borrower is blacklisted for one of its collateral, they will not be able to withdraw the other tokens they are not blacklisted with. This results in a loss of collateral for the borrower.

The same is true when loan is defaulted and lender wants to withdraw the collateral. However, the lender can transfer the loan to another address they own via the `LenderManager` so this is less of a problem.

I cannot tell if protocol wants to allow withdrawal of tokens held by the escrow that belonged to a blacklisted borrower, but that is also obviously impossible.

## Code Snippet

## Tool used

Manual Review

## Recommendation

If protocol wants to allow withdrawal of blacklisted tokens, allow withdrawer to specify new withdrawal address if they are the borrower and the loan has been repaid.
Otherwise, allow withdrawal of individual tokens to be able to withdraw the non-blacklisting tokens.