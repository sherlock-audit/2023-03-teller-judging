0x52

medium

# MarketOwner can set user as trustedMarketForwarder to DOS them

## Summary

If a user is marked as a trusted forwarder the final 20 bytes of calldata should contain the address of the user they are forwarding for. If this address has not approved the forwarder then the function will revert. This can be used as a DOS by marketOwner to prevent users from being able to make transactions. Since a majority of user do not formulate their own transactions, this can allow the owner to DOS regular users during key moments (such as making a payment to keep from liquidating).

## Vulnerability Detail

[TellerV2Context.sol#L103-L123](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2Context.sol#L103-L123)

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
                _approvedForwarderSenders[_msgSender()].contains(sender), <- @audit-issue
                "Sender must approve market forwarder"
            );
            return sender;
        }

        return _msgSender();
    }

Since the marketOwner is allowed to remove and add at will they can use this power to DOS users.

## Impact

Users can be DOS'd during key moments causing unfair liquidation

## Code Snippet

[TellerV2Context.sol#L103-L123](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2Context.sol#L103-L123)

## Tool used

Manual Review

## Recommendation

Return msg.sender instead of reverting:

        if (isTrustedMarketForwarder(_marketId, _msgSender())) {
            address sender;
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
            // Ensure the appended sender address approved the forwarder
    -       require(
    -           _approvedForwarderSenders[_msgSender()].contains(sender),
    -           "Sender must approve market forwarder"
    -       );
    +      if (_approvedForwarderSenders[_msgSender()].contains(sender)) {
    +          return sender;
    +      } else {
    +          return _msgSender();
    +      }
        }

        return _msgSender();