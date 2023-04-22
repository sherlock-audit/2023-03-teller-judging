0x52

high

# Expiration is completely broken for markets that set bidExpirationTime = 0

## Summary

[TellerV2.sol#L1001-L1009](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L1001-L1009)

    function isLoanExpired(uint256 _bidId) public view returns (bool) {
        Bid storage bid = bids[_bidId];

        if (bid.state != BidState.PENDING) return false;
        if (bidExpirationTime[_bidId] == 0) return false;

        return (uint32(block.timestamp) >
            bid.loanDetails.timestamp + bidExpirationTime[_bidId]);
    }

The checks above are incorrect and should return true (i.e. the loan is expired) if the expirationTime == 0 or if the bid has been liquidated or accepted. Currently a bid that has been canceled will return that it is not expired. The bigger issue is that if the bidExpirationTime for the market is set to 0 then the bids will never expire. This can cause serious issues as users would expect their offer to expire but never does.

## Vulnerability Detail

See summary.

## Impact

User bids will never expire allowing them to be filled much longer than expected

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L1001-L1009

## Tool used

Manual Review

## Recommendation

        Bid storage bid = bids[_bidId];

    -   if (bid.state != BidState.PENDING) return false;
    -   if (bidExpirationTime[_bidId] == 0) return false;
    +   if (bid.state != BidState.PENDING) return true;
    +   if (bidExpirationTime[_bidId] == 0) return true;