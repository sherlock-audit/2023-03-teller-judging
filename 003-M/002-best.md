0xGoodess

medium

# lender could be forced to withdraw collateral even if he/she would rather wait for liquidation during default

## Summary
lender could be forced to withdraw collateral even if he/she would rather wait for liquidation during default

## Vulnerability Detail
CollateralManager.withdraw would pass if the loan is defaulted (the borrower does not pay interest in time); in that case, anyone can trigger an withdrawal on behalf of the lender before the liquidation delay period passes.

withdraw logic from CollateralManager.
```solidity
     * @notice Withdraws deposited collateral from the created escrow of a bid that has been successfully repaid.
     * @param _bidId The id of the bid to withdraw collateral for.
     */
    function withdraw(uint256 _bidId) external {
        BidState bidState = tellerV2.getBidState(_bidId);
        console2.log("WITHDRAW %d", uint256(bidState));
        if (bidState == BidState.PAID) {
            _withdraw(_bidId, tellerV2.getLoanBorrower(_bidId));
        } else if (tellerV2.isLoanDefaulted(_bidId)) { @> audit
            _withdraw(_bidId, tellerV2.getLoanLender(_bidId));
            emit CollateralClaimed(_bidId);
        } else {
            revert("collateral cannot be withdrawn");
        }
    }
```

## Impact
anyone can force lender to take up collateral during liquidation delay and liquidation could be something that never happen. This does not match the intention based on the spec which implies that lender has an option: ```3) When the loan is fully repaid, the borrower can withdraw the collateral. If the loan becomes defaulted instead, then the lender has a 24 hour grace period to claim the collateral (losing the principal) ```

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L250-L260

## Tool used

Manual Review

## Recommendation
check that the caller is the lender

```solidity
    function withdraw(uint256 _bidId) external {
        BidState bidState = tellerV2.getBidState(_bidId);
        console2.log("WITHDRAW %d", uint256(bidState));
        if (bidState == BidState.PAID) {
            _withdraw(_bidId, tellerV2.getLoanBorrower(_bidId));
        } else if (tellerV2.isLoanDefaulted(_bidId)) {
+++        uint256 _marketplaceId = bidState.marketplaceId; 
+++        address sender = _msgSenderForMarket(_marketplaceId); 
+++        address lender = tellerV2.getLoanLender(_bidId); 
+++        require(sender == lender, "sender must be the lender"); 
            _withdraw(_bidId, lender);
            emit CollateralClaimed(_bidId);
        } else {
            revert("collateral cannot be withdrawn");
        }
    }
```