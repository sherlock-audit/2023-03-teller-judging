0x52

high

# CollateralManager#setCollateralEscrowBeacon lacks access control allowing anyone to set the beacon implementation and steal all escrowed funds

## Summary

CollateralManager#setCollateralEscrowBeacon lacks access control allowing anyone to set the beacon implementation. After the initialize function is called initialized will be set to 1. Since CollateralManager#setCollateralEscrowBeacon has the modifier reinitialize(2) this can be called again to change the escrow implementation and steal user funds

## Vulnerability Detail

[CollateralManager.sol#L91-L96](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L91-L96)

    function setCollateralEscrowBeacon(address _collateralEscrowBeacon)
        external
        reinitializer(2)
    {
        collateralEscrowBeacon = _collateralEscrowBeacon;
    }

setCollateralEscrowBeacon can be used by anyone once to change the escrow implementation which can be used to steal all the funds in the escrow contracts.

## Impact

All escrowed funds can be stolen

## Code Snippet

[CollateralManager.sol#L91-L96](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L91-L96)

## Tool used

Manual Review

## Recommendation

Restrict upgrade to owner:

    function setCollateralEscrowBeacon(address _collateralEscrowBeacon)
        external
    +   OnlyOwner()
        reinitializer(2)
    {
        collateralEscrowBeacon = _collateralEscrowBeacon;
    }