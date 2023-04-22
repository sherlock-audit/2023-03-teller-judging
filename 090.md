nobody2018

medium

# TellerV2.getLoanSummary returns incorrect lender causing tokens stuck in LenderManager

## Summary

After a lender accepts a loan bid, he can claim a loan nft by calling `TellerV2.claimLoanNFT` which will change `bid.lender` to the LenderManager contract. The `TellerV2.getLoanSummary` function directly returns bid.lender to the caller. If the caller sends tokens to this address(**maybe is the LenderManager contract**), then the token will be stuck in it and cause a significant loss of funds.

## Vulnerability Detail

Let's look at the code of `TellerV2.getLoanSummary`.

```solidity
function getLoanSummary(uint256 _bidId)
        external
        view
        returns (
            address borrower,
            address lender,
            uint256 marketId,
            address principalTokenAddress,
            uint256 principalAmount,
            uint32 acceptedTimestamp,
            BidState bidState
        )
    {
        Bid storage bid = bids[_bidId];

        borrower = bid.borrower;
        lender = bid.lender;	//here
        marketId = bid.marketplaceId;
        principalTokenAddress = address(bid.loanDetails.lendingToken);
        principalAmount = bid.loanDetails.principal;
        acceptedTimestamp = bid.loanDetails.acceptedTimestamp;
        bidState = bid.state;
    }
```

Although the contracts in the scope of the contest don't call this function, I found a contract calling this function. This is  `MarketLiquidityRewards.claimRewards` function which will transfer the reward token to the lender.

`TellerV2.getLoanSummary` is within the scope. **This will cause funds to be stuck in the contract and never be withdrawn**. I think this issue is an valid M/H.

## Impact

All functions using `TellerV2.getLoanSummary` will get the wrong lender. **The token will be sent to the LenderManager contract and stuck in it**.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L1065-L1087

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/MarketLiquidityRewards.sol#L231-L239

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/MarketLiquidityRewards.sol#L336

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/MarketLiquidityRewards.sol#L300-L301

## Tool used

Manual Review

## Recommendation

```solididty
--- a/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol
+++ b/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol
@@ -1078,7 +1078,7 @@ contract TellerV2 is
         Bid storage bid = bids[_bidId];
 
         borrower = bid.borrower;
-        lender = bid.lender;
+        lender = getLoanLender(_bidId);
         marketId = bid.marketplaceId;
         principalTokenAddress = address(bid.loanDetails.lendingToken);
```