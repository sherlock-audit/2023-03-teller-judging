shaka

medium

# Users cannot approve forwarder for a specific market

## Summary

Users cannot approve forwarder for a specific market.

## Vulnerability Detail

`TellerV2Context.sol:approveMarketForwarder` is supposed to approve a forwarder for a specific market, as we can read in the NatSpec of the function.

```solidity
81:     /**
82:      * @notice Approves a forwarder contract to use their address as a sender for a specific market.
83:      * @notice The forwarder given must be trusted by the market given.
84:      * @param _marketId An ID for a lending market.
85:      * @param _forwarder A forwarder contract address.
86:      */
87:     function approveMarketForwarder(uint256 _marketId, address _forwarder)
88:         external
89:     {
90:         require(
91:             isTrustedMarketForwarder(_marketId, _forwarder),
92:             "Forwarder must be trusted by the market"
93:         );
94:         _approvedForwarderSenders[_forwarder].add(_msgSender());
95:         emit MarketForwarderApproved(_marketId, _forwarder, _msgSender());
96:     }
```

However, the `_approvedForwarderSenders` stores only the address of the forwarder and the address of the sender, without storing the `_marketId`.

## Impact

The forwarder will obtain approval for all markets where it is trusted, even if the user just wanted to trust it for a specific market.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2Context.sol#L81-L96

## Tool used

Manual Review

## Recommendation

Change the `_approvedForwarderSenders` mapping to store also market id.

```solidity
    // forwarder => market ID => set of pre-approved senders
    mapping(address => mapping(address => EnumerableSet.AddressSet)) 
        internal _approvedForwarderSenders;
```