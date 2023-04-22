cducrest-brainbot

high

# Bid submission vulnerable to market parameters changes

## Summary

The details for the audit state: 

> Market owners should NOT be able to race-condition attack borrowers or lenders by changing market settings while bids are being submitted or accepted (while tx are in mempool). Care has been taken to ensure that this is not possible (similar in theory to sandwich attacking but worse as if possible it could cause unexpected and non-consentual interest rate on a loan) and further-auditing of this is welcome.

However, there is little protection in place to protect the submitter of a bid from changes in market parameters.

## Vulnerability Detail

In _submitBid(), certain bid parameters are taken from the `marketRegistry`:

```solidity
    function _submitBid(...)
        ...
        (bid.terms.paymentCycle, bidPaymentCycleType[bidId]) = marketRegistry
            .getPaymentCycle(_marketplaceId);

        bid.terms.APR = _APR;

        bidDefaultDuration[bidId] = marketRegistry.getPaymentDefaultDuration(
            _marketplaceId
        );

        bidExpirationTime[bidId] = marketRegistry.getBidExpirationTime(
            _marketplaceId
        );

        bid.paymentType = marketRegistry.getPaymentType(_marketplaceId);
        
        bid.terms.paymentCycleAmount = V2Calculations
            .calculatePaymentCycleAmount(
                bid.paymentType,
                bidPaymentCycleType[bidId],
                _principal,
                _duration,
                bid.terms.paymentCycle,
                _APR
            );
        ...
```

All the parameters taken from marketRegistry are controlled by the market owner:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/MarketRegistry.sol#L487-L511

## Impact

If market parameters are changed in between the borrower submitting a bid transaction and the transaction being applied, borrower may be subject to changes in `bidDefaultDuration`, `bidExpirationTime`, `paymentType`, `paymentCycle`, `bidPaymentCycleType` and `paymentCycleAmount`.

That is, the user may be committed to the bid for longer / shorter than expected. They may have a longer / shorter default duration (time for the loan being considered defaulted / eligible for liquidation). They have un-provisioned for payment type and cycle parameters.

I believe most of this will have a medium impact on borrower (mild inconveniences / resolvable by directly repaying the loan) if the market owner is not evil and adapting the parameters reasonably.

An evil market owner can set the value of `bidDefaultDuration` and `paymentCycle` very low (0) so that the loan will default immediately. It can then accept the bid, make user default immediately, and liquidate the loan to steal the user's collateral. This results in a loss of collateral for the borrower.

## Code Snippet

## Tool used

Manual Review

## Recommendation

Take every single parameters as input of `_submitBid()` (including fee percents) and compare them to the values in `marketRegistry` to make sure borrower agrees with them, revert if they differ.