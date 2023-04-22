0x52

medium

# lenderAcceptBid won't function if fee = 0 and token doesn't support zero transfers

## Summary

Whenever a bid is accepted the contract attempt to sends fee recipients their fees but if there is a low value loan or no fee it will attempt to transfer zero. This will break compatibility with tokens that don't support zero transfers.

## Vulnerability Detail

[TellerV2.sol#L512-L540](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L512-L540)

        // Transfer funds to borrower from the lender
        amountToProtocol = bid.loanDetails.principal.percent(protocolFee());
        amountToMarketplace = bid.loanDetails.principal.percent(
            marketRegistry.getMarketplaceFee(bid.marketplaceId)
        );
        amountToBorrower =
            bid.loanDetails.principal -
            amountToProtocol -
            amountToMarketplace;
        //transfer fee to protocol
        bid.loanDetails.lendingToken.safeTransferFrom(
            sender,
            owner(),
            amountToProtocol
        );

        //transfer fee to marketplace
        bid.loanDetails.lendingToken.safeTransferFrom(
            sender,
            marketRegistry.getMarketFeeRecipient(bid.marketplaceId),
            amountToMarketplace
        );

        //transfer funds to borrower
        bid.loanDetails.lendingToken.safeTransferFrom( <- @audit-issue this can fail if sending 0
            sender,
            bid.receiver,
            amountToBorrower
        );

With each accepted bid it attempts to send the fees to the fee recipients. If there is no fee then this transfer could break for tokens that don't support zero transfers 

## Impact

Loans for markets with no fees will be incompatible with zero transfer tokens

## Code Snippet

[TellerV2.sol#L470-L558](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L470-L558)

## Tool used

Manual Review

## Recommendation

Only transfer is amount > 0