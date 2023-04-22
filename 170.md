0x52

high

# CollateralManager#commitCollateral overwrites collateralInfo._amount if called with an existing collateral

## Summary

When duplicate collateral is committed, the collateral amount is overwritten with the new value. This allows borrowers to front-run bid acceptance to change their collateral and steal from lenders.

## Vulnerability Detail

[CollateralManager.sol#L426-L442](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L426-L442)

    function _commitCollateral(
        uint256 _bidId,
        Collateral memory _collateralInfo
    ) internal virtual {
        CollateralInfo storage collateral = _bidCollaterals[_bidId];
        collateral.collateralAddresses.add(_collateralInfo._collateralAddress);
        collateral.collateralInfo[
            _collateralInfo._collateralAddress
        ] = _collateralInfo; <- @audit-issue collateral info overwritten
        emit CollateralCommitted(
            _bidId,
            _collateralInfo._collateralType,
            _collateralInfo._collateralAddress,
            _collateralInfo._amount,
            _collateralInfo._tokenId
        );
    }

When a duplicate collateral is committed it overwrites the collateralInfo for that token, which is used to determine how much collateral to escrow from the borrower.

[TellerV2.sol#L470-L484](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L470-L484)

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
        // Retrieve bid
        Bid storage bid = bids[_bidId];

        address sender = _msgSenderForMarket(bid.marketplaceId);

TellerV2#lenderAcceptBid only allows the lender input the bidId of the bid they wish to accept, not allowing them to specify the expected collateral. This allows lenders to be honeypot and front-run causing massive loss of funds:

1) Malicious user creates and commits a bid to take a loan of 10e18 ETH against 100,000e6 USDC with 15% APR
2) Lender sees this and calls TellerV2#lenderAcceptBid
3) Malicious user front-runs transaction with commitCollateral call setting USDC to 1
4) Bid is filled sending malicious user 10e18 ETH and escrowing 1 USDC
5) Attacker doesn't repay loan and has stolen 10e18 ETH for the price of 1 USDC

## Impact

Bid acceptance can be front-run to cause massive losses to lenders

## Code Snippet

[TellerV2.sol#L470-L558](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L470-L558)

## Tool used

Manual Review

## Recommendation

Allow lender to specify collateral info and check that it matches the committed addresses and amounts