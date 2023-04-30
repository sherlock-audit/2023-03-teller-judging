chaduke

medium

# Function _canLiquidateLoan() will revert when it is called near ``lastRepaidTimestamp(_bidId)``

## Summary
Function ``isLoanLiquidateable()`` will revert when it is called near ``lastRepaidTimestamp(_bidId)``. The main problem is that when the elapsed time since ``lastRepaidTimestamp(_bidId)`` is too short (< _liquidationDelay), there is an underflow with function ``_canLiquidateLoan()`` (which is called by ``isLoanLiquidateable()`` ). As a result, ``_canLiquidateLoan()`` and ``isLoanLiquidateable()`` will both revert. 

The impact is that all functions that require ``!isLoanLiquidateable(_bidId)`` will revert as well. This means, these functions will not function  as designed. 


## Vulnerability Detail

``isLoanLiquidateable()`` allows a user to check whether a loan is liquidable. It calls the ``_canLiquidateLoan(_bidId, LIQUIDATION_DELAY)`` to implement its logic where LIQUIDATION_DELAY is one day.

[https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L953-L969](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L953-L969)

When the function is called at the elapsed time since ``lastRepaidTimestamp(_bidId)`` is too short (< _liquidationDelay), the following line will have an underflow and revert: 

```javascript
 return (uint32(block.timestamp) -
            _liquidationDelay -
            lastRepaidTimestamp(_bidId) >
            bidDefaultDuration[_bidId]);
```
For example, since LIQUIDATION_DELAY is one day,  the means, if ``_canLiquidateLoan()`` is called within one day after ``lastRepaidTimestamp(_bidId)``, the underflow will occur and the function will revert. 

For those functions that require ``isLoanLiquidateable(_bidId)``, the consequence might not be serious; however, for those functions that require ``!isLoanLiquidateable(_bidId)``, the consequence is severe: none of those functions will execute successfully as they will all revert. 

## Impact

The impact is that all functions that depend on the state that the loan is not yet liquidadable will revert as well. 

## Code Snippet
See above

## Tool used
VSCode

Manual Review

## Recommendation
We should return false instead of revert when the function is called too near to ``lastRepaidTimestamp(_bidId)``.

```diff
 function _canLiquidateLoan(uint256 _bidId, uint32 _liquidationDelay)
        internal
        view
        returns (bool)
    {
        Bid storage bid = bids[_bidId];

        // Make sure loan cannot be liquidated if it is not active
        if (bid.state != BidState.ACCEPTED) return false;

        if (bidDefaultDuration[_bidId] == 0) return false;

 
+      if(uint32(block.timestamp) <  lastRepaidTimestamp(_bidId) + _liquidationDelay ) return false;


        return (uint32(block.timestamp) -
            _liquidationDelay -
            lastRepaidTimestamp(_bidId) >
            bidDefaultDuration[_bidId]);
    }
```

