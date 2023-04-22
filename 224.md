ctf_sec

high

# Lack of access in CollateralManager.sol#withdraw function

## Summary

Lack of access in CollateralManager.sol#withdraw function

## Vulnerability Detail

The function below lacks of access control

```solidity
/**
 * @notice Withdraws deposited collateral from the created escrow of a bid that has been successfully repaid.
 * @param _bidId The id of the bid to withdraw collateral for.
 */
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

## Impact

Impact is clear

```solidity
 if (tellerV2.isLoanDefaulted(_bidId)) {
	_withdraw(_bidId, tellerV2.getLoanLender(_bidId));
	emit CollateralClaimed(_bidId);
}
```

it is possible that when the loan default but has not been liquidated yet, meaning the debt + interest is not repaid yet.

lender can call this function to withdraw the borrower's collateral.

And bad debt is generated for the protocol.

Also when calling isLoanDefaulted, we are calling

```solidity
function isLoanDefaulted(uint256 _bidId)
	public
	view
	override
	returns (bool)
{
	return _canLiquidateLoan(_bidId, 0);
}
```

calling

```solidity
    function _canLiquidateLoan(uint256 _bidId, uint32 _liquidationDelay)
        internal
        view
        returns (bool)
    {
        Bid storage bid = bids[_bidId];

        // Make sure loan cannot be liquidated if it is not active
        if (bid.state != BidState.ACCEPTED) return false;

        if (bidDefaultDuration[_bidId] == 0) return false;

        return (uint32(block.timestamp) -
            _liquidationDelay -
            lastRepaidTimestamp(_bidId) >
            bidDefaultDuration[_bidId]);
    }
```

in normal case, the LIQUIDATION_DELAY is 86400 seconds (1 days), but because the isLoanDefaulted is calling the liquidation with liquidation check 0 (no LIQUIDATION_DELAY), the lender can remove all the collateral of borrower early when he is not supposed to do when the liquidation delay requirement is not met.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L250

## Tool used

Manual Review

## Recommendation

We recommend the protocol add access control to the function withdraw in CollateralManager.sol using the modifier onlyTellerV2 in CollateralManager.sol 
