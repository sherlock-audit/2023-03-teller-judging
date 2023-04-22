tallo

medium

# A malicious market owner/protocol owner can front-run calls to lenderAcceptBid and change the marketplace fee to steal lender funds

## Lines of Code
https://github.com/teller-protocol/teller-protocol-v2/blob/develop/packages/contracts/contracts/TellerV2.sol#L470
https://github.com/teller-protocol/teller-protocol-v2/blob/develop/packages/contracts/contracts/ProtocolFee.sol#L44
https://github.com/teller-protocol/teller-protocol-v2/blob/develop/packages/contracts/contracts/MarketRegistry.sol#L621

## Summary
Malicious market owners and protocol owners can arbitrary set fees to extraordinary rates to steal all of the lenders funds.

## Vulnerability Detail
A malicious market owner can front run lenders who wish to accept a bid through ```lenderAcceptBid``` by calling ```MarketRegistry.setMarketFeePercent```  to set the marketplace fee to 100%. This allows the malicious market owner to steal 100% of the funds from the lender. The same thing can be done by a malicious protocol owner by calling ```ProtocolFee.setProtocolFee``` 

## Impact
Lender loses all their funds on a bid they accept due to malicious or compromised market owner/protocol owner.

## Code Snippet
```solidity
 function lenderAcceptBid(uint256 _bidId)
        external
        override
        pendingBid(_bidId, "lenderAcceptBid")
        whenNotPaused
        returns (
            uint256 amountToProtocol,
            uint256 amountToMarketplace,
            uint256 amountToBorrower
        )
{
        //..

        //@audit here the fee amounts are calculated
        amountToProtocol = bid.loanDetails.principal.percent(protocolFee());

        //@audit this value is what is front-ran by the marketplace owner/protocol owner through MarketRegistry.setMarketFeePercent
        amountToMarketplace = bid.loanDetails.principal.percent(
            marketRegistry.getMarketplaceFee(bid.marketplaceId)
        );

        //@audit here the total amount to send to the borrower is calculated by subtracting the fees
        //from the principal value.
        amountToBorrower =
            bid.loanDetails.principal -
            amountToProtocol -
            amountToMarketplace;

        //@audit transfer fee to protocol
        bid.loanDetails.lendingToken.safeTransferFrom(
            sender,
            owner(),
            amountToProtocol
        );

        //@audit transfer fee to marketplace
        bid.loanDetails.lendingToken.safeTransferFrom(
            sender,
            marketRegistry.getMarketFeeRecipient(bid.marketplaceId),
            amountToMarketplace
        );
        //..
}
```


```solidity
    function setMarketFeePercent(uint256 _marketId, uint16 _newPercent)
        public
        ownsMarket(_marketId)
    {
        require(_newPercent >= 0 && _newPercent <= 10000, "invalid percent");
        if (_newPercent != markets[_marketId].marketplaceFeePercent) {
            //@audit here the market fee is set
            markets[_marketId].marketplaceFeePercent = _newPercent;
            emit SetMarketFee(_marketId, _newPercent);
        }
    }
```

## Tool used

Manual Review

## Recommendation
1. Add a timelock delay for setMarketFeePercent/setProtocolFee 
2. allow lenders to specify the exact fees they were expecting as a parameter to ```lenderAcceptBid```
Note: The developers seem to be aware of this attack vector but their doesn't appear to be a fix in this case

"Market owners should NOT be able to race-condition attack borrowers or lenders by changing market settings while bids are being submitted or accepted (while tx are in mempool). Care has been taken to ensure that this is not possible (similar in theory to sandwich attacking but worse as if possible it could cause unexpected and non-consentual interest rate on a loan) and further-auditing of this is welcome. The best way to defend against this is to allow borrowers and lenders to specify such loan parameters in their TX such that they are explicitly consenting to them in the tx and then reverting if the market settings conflict with those tx arguments."

