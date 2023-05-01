GimelSec

high

# Users cannot renounce approval to the market forwarder

## Summary

ERC2771 has a security concern that the forwarder can forge the value of `_msgSender()`. And in TellerV2, the `TellerV2Contex.approveMarketForwarder` can help mitigate such issue. However, users can only approve the forwarder. They cannot remove the approvals. 

## Vulnerability Detail


`TellerV2Contex.approveMarketForwarder`  lets users approve the market forwarder. And the forwarder can only use their addresses if they approved the forwarder first.
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2Context.sol#L87
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2Context.sol#L116
```solidity
    function approveMarketForwarder(uint256 _marketId, address _forwarder)
        external
    {
        require(
            isTrustedMarketForwarder(_marketId, _forwarder),
            "Forwarder must be trusted by the market"
        );
        _approvedForwarderSenders[_forwarder].add(_msgSender());
        emit MarketForwarderApproved(_marketId, _forwarder, _msgSender());
    }

    function _msgSenderForMarket(uint256 _marketId)
        internal
        view
        virtual
        returns (address)
    {
        if (isTrustedMarketForwarder(_marketId, _msgSender())) {
            address sender;
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
            // Ensure the appended sender address approved the forwarder
            require(
                _approvedForwarderSenders[_msgSender()].contains(sender),
                "Sender must approve market forwarder"
            );
            return sender;
        }

        return _msgSender();
    }
```

However, there is no method to cancel the approval. The forwarder can always use the address of the user once the user has approved the forwarder.   

## Impact

A user may want to leave TellerV2 without any concern. So the approval should be able to be removed even if the forwarder is trusted.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2Context.sol#L87
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2Context.sol#L116


## Tool used

Manual Review

## Recommendation

Add a function to remove the approval. And use mapping instead of array to make removal easier.
