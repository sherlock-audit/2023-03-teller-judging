cccz

medium

# setLenderManager may cause some Lenders to lose their assets

## Summary
If the contract's lenderManager changes, repaid assets will be sent to the old lenderManager
## Vulnerability Detail
setLenderManager is used to change the lenderManager address of the contract
```solidity
    function setLenderManager(address _lenderManager)
        external
        reinitializer(8)
        onlyOwner
    {
        _setLenderManager(_lenderManager);
    }

    function _setLenderManager(address _lenderManager)
        internal
        onlyInitializing
    {
        require(
            _lenderManager.isContract(),
            "LenderManager must be a contract"
        );
        lenderManager = ILenderManager(_lenderManager);
    }
```
claimLoanNFT will change the bid.lender to the current lenderManager
```solidity
    function claimLoanNFT(uint256 _bidId)
        external
        acceptedLoan(_bidId, "claimLoanNFT")
        whenNotPaused
    {
        // Retrieve bid
        Bid storage bid = bids[_bidId];

        address sender = _msgSenderForMarket(bid.marketplaceId);
        require(sender == bid.lender, "only lender can claim NFT");
        // mint an NFT with the lender manager
        lenderManager.registerLoan(_bidId, sender);
        // set lender address to the lender manager so we know to check the owner of the NFT for the true lender
        bid.lender = address(lenderManager);
    }
```
In getLoanLender, if the bid.lender is the current lenderManager, the owner of the NFT will be returned as the lender, and the repaid assets will be sent to the lender.
```solidity
    function getLoanLender(uint256 _bidId)
        public
        view
        returns (address lender_)
    {
        lender_ = bids[_bidId].lender;

        if (lender_ == address(lenderManager)) {
            return lenderManager.ownerOf(_bidId);
        }
    }
...
        address lender = getLoanLender(_bidId);

        // Send payment to the lender
        bid.loanDetails.lendingToken.safeTransferFrom(
            _msgSenderForMarket(bid.marketplaceId),
            lender,
            paymentAmount
        );

```
If setLenderManager is called to change the lenderManager, in getLoanLender, since the bid.lender is not the current lenderManager, the old lenderManager address will be returned as the lender, and the repaid assets will be sent to the old lenderManager, resulting in the loss of the lender's assets
## Impact
It may cause some Lenders to lose their assets
## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L212-L229
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L560-L574
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L1037-L1047
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L744-L752

## Tool used

Manual Review

## Recommendation
Consider using MAGIC_NUMBER as bid.lender in claimLoanNFT and using that MAGIC_NUMBER in getLoanLender to do the comparison.
```diff
+  address MAGIC_NUMBER = 0x...;
    function claimLoanNFT(uint256 _bidId)
        external
        acceptedLoan(_bidId, "claimLoanNFT")
        whenNotPaused
    {
        // Retrieve bid
        Bid storage bid = bids[_bidId];

        address sender = _msgSenderForMarket(bid.marketplaceId);
        require(sender == bid.lender, "only lender can claim NFT");
        // mint an NFT with the lender manager
        lenderManager.registerLoan(_bidId, sender);
        // set lender address to the lender manager so we know to check the owner of the NFT for the true lender
-       bid.lender = address(lenderManager);
+       bid.lender = MAGIC_NUMBER;
    }
...
    function getLoanLender(uint256 _bidId)
        public
        view
        returns (address lender_)
    {
        lender_ = bids[_bidId].lender;

-       if (lender_ == address(lenderManager)) {
+       if (lender_ == MAGIC_NUMBER) {
            return lenderManager.ownerOf(_bidId);
        }
    }
```
