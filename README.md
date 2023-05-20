# Issue H-1: A borrower/lender or liquidator will fail to withdraw the collateral assets due to reaching a gas limit 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/357 

## Found by 
0xmuxyz, HonorLt, cccz, yixxas

## Summary
Within the TellerV2#`submitBid()`, there is no limitation that how many collateral assets a borrower can assign into the `_collateralInfo` array parameter.

This lead to some bad scenarios like this due to reaching gas limit:
- A borrower or a lender fail to withdraw the collateral assets when the loan would not be liquidated.
- A liquidator will fail to withdraw the collateral assets when the loan would be liquidated.

## Vulnerability Detail

Within the ICollateralEscrowV1, the `Collateral` struct would be defined line this:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/interfaces/escrow/ICollateralEscrowV1.sol#L10-L15
```solidity
struct Collateral {
    CollateralType _collateralType;
    uint256 _amount;
    uint256 _tokenId;
    address _collateralAddress;
}
```

Within the CollateralManager, the CollateralInfo struct would be defined like this:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L34-L37
```solidity
    /**
     * Since collateralInfo is mapped (address assetAddress => Collateral) that means
     * that only a single tokenId per nft per loan can be collateralized.
     * Ex. Two bored apes cannot be used as collateral for a single loan.
     */
    struct CollateralInfo {
        EnumerableSetUpgradeable.AddressSet collateralAddresses;
        mapping(address => Collateral) collateralInfo;
    }
```

Within the CollateralManager, the `_bidCollaterals` storage would be defined like this:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L27
```solidity
    // bidIds -> validated collateral info
    mapping(uint256 => CollateralInfo) internal _bidCollaterals;
```

When a borrower submits a bid, the TellerV2#`submitBid()` would be called.
Within the TellerV2#`submitBid()`, multiple collaterals, which are ERC20/ERC721/ERC1155, can be assigned into the `_collateralInfo` array parameter by a borrower.
And then, these collateral assets stored into the `_collateralInfo` array would be associated with `bidId_` through internally calling the CollateralManager#`commitCollateral()` like this:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L311
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L325
```solidity
    function submitBid(
        address _lendingToken,
        uint256 _marketplaceId,
        uint256 _principal,
        uint32 _duration,
        uint16 _APR,
        string calldata _metadataURI,
        address _receiver,
        Collateral[] calldata _collateralInfo /// @audit
    ) public override whenNotPaused returns (uint256 bidId_) {
        ...
        bool validation = collateralManager.commitCollateral(
            bidId_,
            _collateralInfo /// @audit 
        );
        ...
```

Within the CollateralManager#`commitCollateral()`, each collateral asset (`info`) would be associated with a `_bidId` respectively by calling the CollateralManager#`_commitCollateral()` in the for-loop like this:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L127
```solidity
    /**
     * @notice Checks the validity of a borrower's multiple collateral balances and commits it to a bid.
     * @param _bidId The id of the associated bid.
     * @param _collateralInfo Additional information about the collateral assets.
     * @return validation_ Boolean indicating if the collateral balances were validated.
     */
    function commitCollateral(
        uint256 _bidId,
        Collateral[] calldata _collateralInfo  /// @audit
    ) public returns (bool validation_) {
        address borrower = tellerV2.getLoanBorrower(_bidId);
        (validation_, ) = checkBalances(borrower, _collateralInfo);

        if (validation_) {
            for (uint256 i; i < _collateralInfo.length; i++) {    
                Collateral memory info = _collateralInfo[i];
                _commitCollateral(_bidId, info);  /// @audit
            }
        }
    }
```

Within the CollateralManager#`_commitCollateral()`, the `_collateralInfo` would be stored into the `_bidCollaterals` storage like this:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L428
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L430-L434
```solidity
    /**
     * @notice Checks the validity of a borrower's collateral balance and commits it to a bid.
     * @param _bidId The id of the associated bid.
     * @param _collateralInfo Additional information about the collateral asset.
     */
    function _commitCollateral(
        uint256 _bidId,
        Collateral memory _collateralInfo
    ) internal virtual {
        CollateralInfo storage collateral = _bidCollaterals[_bidId];
        collateral.collateralAddresses.add(_collateralInfo._collateralAddress);
        collateral.collateralInfo[
            _collateralInfo._collateralAddress
        ] = _collateralInfo;  /// @audit
        ...
```

When the deposited-collateral would be withdrawn by a borrower or a lender, the CollateralManager#`withdraw()` would be called.
Within the CollateralManager#`withdraw()`, the CollateralManager#`_withdraw()` would be called like this:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L253
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L255
```solidity
    /**
     * @notice Withdraws deposited collateral from the created escrow of a bid that has been successfully repaid.
     * @param _bidId The id of the bid to withdraw collateral for.
     */
    function withdraw(uint256 _bidId) external {
        BidState bidState = tellerV2.getBidState(_bidId);
        if (bidState == BidState.PAID) {
            _withdraw(_bidId, tellerV2.getLoanBorrower(_bidId)); /// @audit 
        } else if (tellerV2.isLoanDefaulted(_bidId)) {
            _withdraw(_bidId, tellerV2.getLoanLender(_bidId));  /// @audit 
           ...
```

When the deposited-collateral would be liquidated by a liquidator, the CollateralManager#`liquidateCollateral()` would be called.
Within the CollateralManager#`liquidateCollateral()`, the CollateralManager#`_withdraw()` would be called like this:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L278
```solidity
    /**
     * @notice Sends the deposited collateral to a liquidator of a bid.
     * @notice Can only be called by the protocol.
     * @param _bidId The id of the liquidated bid.
     * @param _liquidatorAddress The address of the liquidator to send the collateral to.
     */
    function liquidateCollateral(uint256 _bidId, address _liquidatorAddress)
        external
        onlyTellerV2
    {
        if (isBidCollateralBacked(_bidId)) {
            BidState bidState = tellerV2.getBidState(_bidId);
            require(
                bidState == BidState.LIQUIDATED,
                "Loan has not been liquidated"
            );
            _withdraw(_bidId, _liquidatorAddress);  /// @audit
        }
    }
```

Within the CollateralManager#`_withdraw()`, each collateral asset (`collateralInfo._collateralAddress`) would be withdrawn by internally calling the ICollateralEscrowV1#`withdraw()` in a for-loop like this:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L394-L409
```solidity
    /**
     * @notice Withdraws collateral to a given receiver's address.
     * @param _bidId The id of the bid to withdraw collateral for.
     * @param _receiver The address to withdraw the collateral to.
     */
    function _withdraw(uint256 _bidId, address _receiver) internal virtual {
        for (
            uint256 i;
            i < _bidCollaterals[_bidId].collateralAddresses.length(); /// @audit
            i++
        ) {
            // Get collateral info
            Collateral storage collateralInfo = _bidCollaterals[_bidId]
                .collateralInfo[
                    _bidCollaterals[_bidId].collateralAddresses.at(i)
                ];
            // Withdraw collateral from escrow and send it to bid lender
            ICollateralEscrowV1(_escrows[_bidId]).withdraw(   /// @audit
                collateralInfo._collateralAddress,
                collateralInfo._amount,
                _receiver
            );
```

However, within the TellerV2#`submitBid()`, there is no limitation that how many collateral assets a borrower can assign into the `_collateralInfo` array parameter.

This lead to a bad scenario like below:
- ① A borrower assign too many number of the collateral assets (ERC20/ERC721/ERC1155) into the `_collateralInfo` array parameter when the borrower call the TellerV2#`submitBid()` to submit a bid.
- ② Then, a lender accepts the bid via calling the TellerV2#`lenderAcceptBid()`
- ③ Then, a borrower or a lender try to withdraw the collateral, which is not liquidated, by calling the CollateralManager#`withdraw()`. Or, a liquidator try to withdraw the collateral, which is liquidated, by calling the CollateralManager#`liquidateCollateral()`
- ④ But, the transaction of the CollateralManager#`withdraw()` or the CollateralManager#`liquidateCollateral()` will be reverted in the for-loop of the CollateralManager#`_withdraw()` because that transaction will reach a gas limit.


## Impact
Due to reaching gas limit, some bad scenarios would occur like this:
- A borrower or a lender fail to withdraw the collateral assets when the loan would not be liquidated.
- A liquidator will fail to withdraw the collateral assets when the loan would be liquidated.

## Code Snippet
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/interfaces/escrow/ICollateralEscrowV1.sol#L10-L15
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L34-L37
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L27
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L311
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L325
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L127
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L428
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L430-L434
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L253
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L255
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L278
- https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L394-L409

## Tool used
Manual Review

## Recommendation
Within the TellerV2#`submitBid()`, consider adding a limitation about how many collateral assets a borrower can assign into the `_collateralInfo` array parameter.



## Discussion

**ethereumdegen**

Thank you for your feedback.  This is very similar / essentially the same as the 'collateral poisoning' issue that had been identified in the README of this contest as a known-issue:  it had been explained and known that collateral could be made impossible to withdraw which could impact the ability to do the last repayment of a loan.   This is a slight variation in that it describes that the collateral could be so vast that withdrawing it would exceed the gas limit of a block.  Thank you for this perspective.  In any case we do plan to separate the repayment logic from the collateral withdraw logic to mitigate such an issue.  

# Issue H-2: Malicious user can abuse UpdateCommitment to create commitments for other users 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/260 

## Found by 
0x52, 0xbepresent, Bauer, J4de, dingo, immeas

## Summary

UpdateCommitment checks that the original lender is msg.sender but never validates that the original lender == new lender. This allows malicious users to effectively create a commitment for another user, allowing them to drain funds from them.

## Vulnerability Detail

[LenderCommitmentForwarder.sol#L208-L224](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L208-L224)

    function updateCommitment(
        uint256 _commitmentId,
        Commitment calldata _commitment
    ) public commitmentLender(_commitmentId) { <- @audit-info checks that lender is msg.sender
        require(
            _commitment.principalTokenAddress ==
                commitments[_commitmentId].principalTokenAddress,
            "Principal token address cannot be updated."
        );
        require(
            _commitment.marketId == commitments[_commitmentId].marketId,
            "Market Id cannot be updated."
        );

        commitments[_commitmentId] = _commitment; <- @audit-issue never checks _commitment.lender

        validateCommitment(commitments[_commitmentId]);

UpdateCommitment is intended to allow users to update their commitment but due to lack of verification of _commitment.lender, a malicious user create a commitment then update it to a new lender. By using bad loan parameters they can steal funds from the attacker user.

## Impact

UpdateCommitment can be used to create a malicious commitment for another user and steal their funds

## Code Snippet

[LenderCommitmentForwarder.sol#L208-L233](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L208-L233)

## Tool used

Manual Review

## Recommendation

Check that the update lender is the same the original lender



## Discussion

**ethereumdegen**

Thank you for this feedback.  This is a high severity issue as it could be used to unexpectedly steal tokens that another use had previously approved to the contract.  Will fix. 

**passabilities**

https://github.com/teller-protocol/teller-protocol-v2/pull/67

# Issue H-3: Lender force Loan become default 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/202 

## Found by 
T1MOH, carrotsmuggler, cccz, cducrest-brainbot

## Summary
in `_repayLoan()` directly transfer the debt token to Lender, but did not consider that Lender can not accept the token (in contract blacklist), resulting in `_repayLoan()` always revert, and finally the Loan will be default.

## Vulnerability Detail
The only way for the borrower to get the collateral token back is to repay the amount owed via _repayLoan(). Currently in the _repayLoan() method transfers the principal token directly to the Lender.
This has a problem:
if the Lender is blacklisted by the principal token now, the debtToken.transferFrom() method will fail and the _repayLoan() method will always fail and finally the Loan will default.

See also https://github.com/sherlock-audit/2023-01-cooler-judging/issues/23
## Impact
Lender forced Loan become default for get collateral, borrower lost collateral

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L747

## Tool used

Manual Review

## Recommendation
Instead of transferring the debt token directly, put the debt token into the protocol and set like: withdrawBalance[token][lender] += amount, and provide the method withdraw(address token, address receiver) for lender to get principal token back



## Discussion

**ethereumdegen**

The proposed solution is poor for UX and for gas fees.  

The way that we decided that this will be handled overall is to warn borrowers about accepting loans with principal tokens that can have blacklists.  However, this is untenable because USDC has blacklist capabilities. Therefore perhaps we should discuss a better solution such as separating the logic for repayment and sending funds to the lender.  

# Issue H-4: Malicious user can poison bids before they exist 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/184 

## Found by 
0x52, HonorLt

## Summary

Bids can be committed to before they even exist allowing bids to be poisoned with malicious ERC20 tokens making bids created and fulfilled by the LenderCommitmentForwarder extremely dangerous.

## Vulnerability Detail

In the readme it states:
`If a rebasing/weird token breaks just the loan that it is in, we want to know about it but that is bad but largely OK (not hyper critical) since the borrower and lender both agreed to that asset manually beforehand and, really, shouldnt have.`

The second part of that statement isn't true because the bids can be poisoned beforehand. 

[CollateralManager.sol#L117-L130](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L117-L130)

    function commitCollateral(
        uint256 _bidId,
        Collateral[] calldata _collateralInfo
    ) public returns (bool validation_) {
        address borrower = tellerV2.getLoanBorrower(_bidId);
        (validation_, ) = checkBalances(borrower, _collateralInfo); <- @audit-issue no access control

        if (validation_) {
            for (uint256 i; i < _collateralInfo.length; i++) {
                Collateral memory info = _collateralInfo[i];
                _commitCollateral(_bidId, info);
            }
        }
    }

This happens because commitCollateral never checks that the borrower != address(0) (i.e. that the bid doesn't exist). BidId's are assigned sequentially, which makes this very problematic for bids created and fulfilled by the LenderCommitmentForwarder. It makes the assumption that the agreed upon collateral is the only collateral in the contract. Since they can be easily poisoned (bids are assigned sequentially) this creates a serious issue for those loans.

A malicious user can easily poison a large number of bidIds with a malicious token and trap any users who use LenderCommitmentForwarder to open a loan

## Impact

Bids created and fulfilled by LenderCommitmentForwarder are highly dangerous since they can easily be poisoned

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L138-L147

## Tool used

Manual Review

## Recommendation

Cause CollateralManager#commitCollateral to revert if borrower == address(0)



## Discussion

**ethereumdegen**

Thank you for the feedback.  This is very similar to the issue that states that 'commitCollateral' can be called by anyone. This issue is the same as that issue however just points out an additional attack vector for that same issue.  I would consider this a high severity vulnerability just like the 'commitCollateral is public callable' issue.'  One in the same. 

# Issue H-5: CollateralManager#setCollateralEscrowBeacon lacks access control allowing anyone to set the beacon implementation and steal all escrowed funds 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/182 

## Found by 
0x52, 8olidity, Dug, Inspex, cducrest-brainbot, chaduke, dingo, evilakela, nicobevi, shaka, warRoom

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



## Discussion

**ethereumdegen**

A unit tests exists that proves that once this function is called once, it can never be called again :


    function test_setCollateralEscrowBeacon() public {
        // Deploy implementation
        CollateralEscrowV1 escrowImplementation = new CollateralEscrowV1_Mock();
        // Deploy beacon contract with implementation
        UpgradeableBeacon escrowBeacon = new UpgradeableBeacon(
            address(escrowImplementation)
        );

        collateralManager.setCollateralEscrowBeacon(address(escrowBeacon));

        //how to test ?
    }

    function test_setCollateralEscrowBeacon_invalid_twice() public {
        CollateralEscrowV1 escrowImplementation = new CollateralEscrowV1_Mock();
        // Deploy beacon contract with implementation
        UpgradeableBeacon escrowBeacon = new UpgradeableBeacon(
            address(escrowImplementation)
        );
        collateralManager.setCollateralEscrowBeacon(address(escrowBeacon));

        vm.expectRevert("Initializable: contract is already initialized");
        collateralManager.setCollateralEscrowBeacon(address(escrowBeacon));
        //
    }


However it does seem wise to add an extra precaution and to add an onlyOwner modifier here 

# Issue H-6: CollateralManager#commitCollateral can be called by anyone 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/169 

## Found by 
0x52, 0xbepresent, 8olidity, BAHOZ, HonorLt, Inspex, J4de, MiloTruck, PawelK, Ruhum, \_\_141345\_\_, cccz, cducrest-brainbot, chaduke, ctf\_sec, duc, evmboi32, giovannidisiena, immeas, jpserrat, juancito, mahdikarimi, nobody2018, shaka, sinarette, ubl4nk, whoismatthewmc1, xAlismx, yshhjain

## Summary

CollateralManager#commitCollateral has no access control allowing users to freely add malicious tokens to any bid

## Vulnerability Detail

[CollateralManager.sol#L117-L130](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L117-L130)

    function commitCollateral(
        uint256 _bidId,
        Collateral[] calldata _collateralInfo
    ) public returns (bool validation_) {
        address borrower = tellerV2.getLoanBorrower(_bidId);
        (validation_, ) = checkBalances(borrower, _collateralInfo); <- @audit-issue no access control

        if (validation_) {
            for (uint256 i; i < _collateralInfo.length; i++) {
                Collateral memory info = _collateralInfo[i];
                _commitCollateral(_bidId, info);
            }
        }
    }

CollateralManager#commitCollateral has no access control and can be called by anyone on any bidID. This allows an attacker to front-run lenders and add malicious tokens to a loan right before it is filled. 

1) A malicious user creates a malicious token that can be transferred once before being paused and returns uint256.max for balanceOf
2) User A creates a loan for 10e18 ETH against 50,000e6 USDC at 10% APR
3) User B decides to fill this loan and calls TellerV2#lenderAcceptBid
4) The malicious user sees this and front-runs with a CollateralManager#commitCollateral call adding the malicious token
5) Malicious token is now paused breaking both liquidations and fully paying off the loan
6) Malicious user leverages this to ransom the locked tokens, unpausing when it is paid

## Impact

User can add malicious collateral calls to any bid they wish

## Code Snippet

[CollateralManager.sol#L117-L130](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L117-L130)

[CollateralManager.sol#L138-L147](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L138-L147)

## Tool used

Manual Review

## Recommendation

Cause CollateralManager#commitCollateral to revert if called by anyone other than the borrower, their approved forwarder or TellerV2



## Discussion

**ethereumdegen**

Thank you to the many many auditors who discovered this vulnerability.  Will fix.  

# Issue H-7: CollateralManager#commitCollateral can be called on an active loan 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/168 

## Found by 
0x52, dipp, innertia, jpserrat, spyrosonic10

## Summary

CollateralManager#commitCollateral never checks if the loan has been accepted allowing users to add collaterals after which can DOS the loan.

## Vulnerability Detail

[CollateralManager.sol#L117-L130](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L117-L130)

    function commitCollateral(
        uint256 _bidId,
        Collateral[] calldata _collateralInfo
    ) public returns (bool validation_) {
        address borrower = tellerV2.getLoanBorrower(_bidId);
        (validation_, ) = checkBalances(borrower, _collateralInfo); <- @audit-issue never checks that loan isn't active

        if (validation_) {
            for (uint256 i; i < _collateralInfo.length; i++) {
                Collateral memory info = _collateralInfo[i];
                _commitCollateral(_bidId, info);
            }
        }
    }

CollateralManager#commitCollateral does not contain any check that the bidId is pending or at least that it isn't accepted. This means that collateral can be committed to an already accepted bid, modifying bidCollaterals.

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L393-L409

    function _withdraw(uint256 _bidId, address _receiver) internal virtual {
        for (
            uint256 i;
            i < _bidCollaterals[_bidId].collateralAddresses.length();
            i++
        ) {
            // Get collateral info
            Collateral storage collateralInfo = _bidCollaterals[_bidId]
                .collateralInfo[
                    _bidCollaterals[_bidId].collateralAddresses.at(i)
                ];
            // Withdraw collateral from escrow and send it to bid lender
            ICollateralEscrowV1(_escrows[_bidId]).withdraw(
                collateralInfo._collateralAddress,
                collateralInfo._amount,
                _receiver
            );

bidCollaterals is used to trigger the withdrawal from the escrow to the receiver, which closing the loan and liquidations. This can be used to DOS a loan AFTER it has already been filled.

1) User A creates a bid for 10 ETH against 50,000 USDC at 10% APR
2) User B sees this bid and decides to fill it
3) After the loan is accepted, User A calls CollateralManager#commitCollateral with a malicious token they create
4) User A doesn't pay their loan and it becomes liquidatable
5) User B calls liquidate but it reverts when the escrow attempts to transfer out the malicious token
6) User A demands a ransom to return the funds
7) User A enables the malicious token transfer once the ransom is paid

## Impact

Loans can be permanently DOS'd even after being accepted 

## Code Snippet

[CollateralManager.sol#L117-L130](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L117-L130)

[CollateralManager.sol#L138-L147](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L138-L147)

## Tool used

Manual Review

## Recommendation

CollateralManager#commitCollateral should revert if loan is active.



## Discussion

**ethereumdegen**

This seems to be a duplicate of the issue that states that the commitCollateral is publicly callable.   A fix is being implemented which will make that function only callable by TellerV2.sol contract which should remedy this vulnerability. Thank you . 

# Issue M-1: A malicious market owner/protocol owner can front-run calls to lenderAcceptBid and change the marketplace fee to steal lender funds 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/497 

## Found by 
0xGoodess, BAHOZ, Bauer, HonorLt, MiloTruck, Nyx, Saeedalipoor01988, cducrest-brainbot, ck, ctf\_sec, dingo, duc, hake, immeas, innertia, jpserrat, monrel, spyrosonic10, tallo, whoismatthewmc1

## Lines of Code
https://github.com/teller-protocol/teller-protocol-v2/blob/develop/packages/contracts/contracts/TellerV2.sol#L470
https://github.com/teller-protocol/teller-protocol-v2/blob/develop/packages/contracts/contracts/ProtocolFee.sol#L44
https://github.com/teller-protocol/teller-protocol-v2/blob/develop/packages/contracts/contracts/MarketRegistry.sol#L621

## Summary
Malicious market owners and protocol owners can arbitrary set fees to extraordinary rates to steal all of the lenders funds.

## Vulnerability Detail
A malicious market owner can front run lenders who wish to accept a bid through ```lenderAcceptBid``` by calling ```MarketRegistry.setMarketFeePercent```  to set the marketplace fee to 100%. This allows the malicious market owner to steal 100% of the funds from the lender. The same thing can be done by a malicious protocol owner by calling ```ProtocolFee.setProtocolFee``` 

## Impact
Lender loses all their funds on a bid they accept due to malicious or compromised market owner/protocol owner.

## Code Snippet
```solidity
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
        //..

        //@audit here the fee amounts are calculated
        amountToProtocol = bid.loanDetails.principal.percent(protocolFee());

        //@audit this value is what is front-ran by the marketplace owner/protocol owner through MarketRegistry.setMarketFeePercent
        amountToMarketplace = bid.loanDetails.principal.percent(
            marketRegistry.getMarketplaceFee(bid.marketplaceId)
        );

        //@audit here the total amount to send to the borrower is calculated by subtracting the fees
        //from the principal value.
        amountToBorrower =
            bid.loanDetails.principal -
            amountToProtocol -
            amountToMarketplace;

        //@audit transfer fee to protocol
        bid.loanDetails.lendingToken.safeTransferFrom(
            sender,
            owner(),
            amountToProtocol
        );

        //@audit transfer fee to marketplace
        bid.loanDetails.lendingToken.safeTransferFrom(
            sender,
            marketRegistry.getMarketFeeRecipient(bid.marketplaceId),
            amountToMarketplace
        );
        //..
}
```


```solidity
    function setMarketFeePercent(uint256 _marketId, uint16 _newPercent)
        public
        ownsMarket(_marketId)
    {
        require(_newPercent >= 0 && _newPercent <= 10000, "invalid percent");
        if (_newPercent != markets[_marketId].marketplaceFeePercent) {
            //@audit here the market fee is set
            markets[_marketId].marketplaceFeePercent = _newPercent;
            emit SetMarketFee(_marketId, _newPercent);
        }
    }
```

## Tool used

Manual Review

## Recommendation
1. Add a timelock delay for setMarketFeePercent/setProtocolFee 
2. allow lenders to specify the exact fees they were expecting as a parameter to ```lenderAcceptBid```
Note: The developers seem to be aware of this attack vector but their doesn't appear to be a fix in this case

"Market owners should NOT be able to race-condition attack borrowers or lenders by changing market settings while bids are being submitted or accepted (while tx are in mempool). Care has been taken to ensure that this is not possible (similar in theory to sandwich attacking but worse as if possible it could cause unexpected and non-consentual interest rate on a loan) and further-auditing of this is welcome. The best way to defend against this is to allow borrowers and lenders to specify such loan parameters in their TX such that they are explicitly consenting to them in the tx and then reverting if the market settings conflict with those tx arguments."


# Issue M-2: Premature Liquidation When a Borrower Pays early 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/494 

## Found by 
branch\_indigo

## Summary
On TellerV2 markets, whenever a borrower pays early in one payment cycle, they could be at risk to be liquidated in the next payment cycle. And this is due to a vulnerability in the liquidation logic implemented in `_canLiquidateLoan`. Note: This issue is submitted separately from issue #2 because the exploit is based on user behaviors regardless of a specific market setting. And the vulnerability might warrant a change in the liquidation logic. 
## Vulnerability Detail
In TellerV2.sol, the sole liquidation logic is dependent on the time gap between now and the previous payment timestamp. But a user might decide to pay at any time within a given payment cycle, which makes the time gap unreliable and effectively renders this logic vulnerable to exploitation. 

```solidity
        return (uint32(block.timestamp) -
            _liquidationDelay -
            lastRepaidTimestamp(_bidId) >
            bidDefaultDuration[_bidId]);
```
Suppose a scenario where a user takes on a loan on a market with 3 days payment cycle and 3 days paymentDefaultDuration. And the loan is 14 days in duration. The user decided to make the first minimal payment an hour after receiving the loan, and the next payment due date is after the sixth day. Now 5 days passed since the user made the first payment, and a liquidator comes in and liquidates the loan and claims the collateral before the second payment is due.

[Here is a test to show proof of concept for this scenario. ](https://gist.github.com/bzpassersby/cd1faaefb9b8c846588a81c56cd3d685)

## Impact
Given the fact that this vulnerability is not market specific and that users can pay freely during a payment cycle, it's quite easy for a liquidator to liquidate loans prematurely. And the effect might be across multiple markets. 

When there are proportional collaterals, the exploit can be low cost. An attacker could take on flash loans to pay off the principal and interest, and the interest could be low when early in the loan duration. The attacker would then sell the collateral received in the same transaction to pay off flash loans and walk away with profits.

## Code Snippet
[https://github.com/teller-protocol/teller-protocol-v2/blob/cb66c9e348cdf1fd6d9b0416a49d663f5b6a693c/packages/contracts/contracts/TellerV2.sol#L965-L969](https://github.com/teller-protocol/teller-protocol-v2/blob/cb66c9e348cdf1fd6d9b0416a49d663f5b6a693c/packages/contracts/contracts/TellerV2.sol#L965-L969)
## Tool used

Manual Review

## Recommendation
Consider using the current timestamp - previous payment due date instead of just `lastRepaidTimestamp` in the liquidation check logic. Also, add the check to see whether a user is late on a payment in `_canLiquidateLoan`.



## Discussion

**ethereumdegen**

In this logic, we should be calculating the default date(s) based relative to a 'due date' and not a 'repaid date' . We will look into this more closely. 

# Issue M-3: Lenders can front run tx and take more collateral from borrowers. 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/441 

## Found by 
Nyx

## Summary
The lender can front-run tx and update _maxPrincipalPerCollateralAmount to a lower amount so he can take more collateral from the borrower.
## Vulnerability Detail
```solidity
uint256 requiredCollateral = getRequiredCollateral(
            _principalAmount,
            commitment.maxPrincipalPerCollateralAmount,
            commitment.collateralTokenType,
            commitment.collateralTokenAddress,
            commitment.principalTokenAddress
        );

```
When a borrower uses the acceptCommitment() function, needed collateral is calculated by getRequiredCollateral() function. 
```solidity
return
            MathUpgradeable.mulDiv(
                _principalAmount,
                (10**(collateralDecimals + principalDecimals)),
                _maxPrincipalPerCollateralAmount, 
                MathUpgradeable.Rounding.Up
            );
```
_maxPrincipalPerCollateralAmount is controllable by the lender. 
```solidity
function updateCommitment(
        uint256 _commitmentId,
        Commitment calldata _commitment
    ) public commitmentLender(_commitmentId) {
        require(
            _commitment.principalTokenAddress ==
                commitments[_commitmentId].principalTokenAddress,
            "Principal token address cannot be updated."
        );
        require(
            _commitment.marketId == commitments[_commitmentId].marketId,
            "Market Id cannot be updated."
        );

        commitments[_commitmentId] = _commitment;

        validateCommitment(commitments[_commitmentId]);

        emit UpdatedCommitment(
            _commitmentId,
            _commitment.lender,
            _commitment.marketId,
            _commitment.principalTokenAddress,
            _commitment.maxPrincipal
        );
    }
```

The lender can front runs borrower's tx and update _maxPrincipalPerCollateralAmount lower amount so he can take more collateral from the borrower.

## Impact
borrower providing more collateral than initially agreed upon, potentially allowing the lender to exploit the borrower.
## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L288-L400

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L436-L443

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L208-L233
## Tool used

Manual Review

## Recommendation
Lenders shouldn't be able to take more collateral from borrowers than agreed upon.




## Discussion

**ethereumdegen**

Yes this is an issue that we intend to fix.   

# Issue M-4: Users cannot renounce approval to the market forwarder 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/433 

## Found by 
0xbepresent, GimelSec, HonorLt, Inspex, J4de, chaduke, immeas, monrel

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

# Issue M-5: setLenderManager may cause some Lenders to lose their assets 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/339 

## Found by 
MiloTruck, T1MOH, cccz, dingo, duc, saidam017, shaka, yixxas

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

# Issue M-6: last repayments are calculated incorrectly for "irregular" loan durations 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/328 

## Found by 
immeas

## Summary
When taking a loan, a borrower expects that at the end of each payment cycle they should pay `paymentCycleAmount`. This is not true for loans that are not a multiple of `paymentCycle`.

## Vulnerability Detail
Imagine a loan of `1000` that is taken for 2.5 payment cycles (skip interest to keep calculations simple).

A borrower would expect to pay `400` + `400` + `200`

This holds true for the first installment.

But lets look at what happens at the second installment, here's the calculation of what is to pay in `V2Calculations.sol`:

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol#L93-L101
```solidity
File: libraries/V2Calculations.sol

 93:        // Cast to int265 to avoid underflow errors (negative means loan duration has passed)
 94:        int256 durationLeftOnLoan = int256(
 95:            uint256(_bid.loanDetails.loanDuration)
 96:        ) -
 97:            (int256(_timestamp) -
 98:                int256(uint256(_bid.loanDetails.acceptedTimestamp)));
 99:        bool isLastPaymentCycle = durationLeftOnLoan <
100:            int256(uint256(_bid.terms.paymentCycle)) || // Check if current payment cycle is within or beyond the last one
101:            owedPrincipal_ + interest_ <= _bid.terms.paymentCycleAmount; // Check if what is left to pay is less than the payment cycle amount
```

Simplified the first calculation says `timeleft = loanDuration - (now - acceptedTimestamp)` and then if `timeleft < paymentCycle` we are within the last payment cycle.

This isn't true for loan durations that aren't multiples of the payment cycles. This code says the last payment cycle is when you are one payment cycle from the end of the loan. Which is not the same as last payment cycle as my example above shows.

PoC:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

import { AddressUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";

import { TellerV2 } from "../contracts/TellerV2.sol";
import { Payment } from "../contracts/TellerV2Storage.sol";
import { CollateralManager } from "../contracts/CollateralManager.sol";
import { LenderCommitmentForwarder } from "../contracts/LenderCommitmentForwarder.sol";
import { CollateralEscrowV1 } from "../contracts/escrow/CollateralEscrowV1.sol";
import { Collateral, CollateralType } from "../contracts/interfaces/escrow/ICollateralEscrowV1.sol";

import { ReputationManagerMock } from "../contracts/mock/ReputationManagerMock.sol";
import { LenderManagerMock } from "../contracts/mock/LenderManagerMock.sol";
import { MarketRegistryMock } from "../contracts/mock/MarketRegistryMock.sol";

import {TestERC20Token} from "./tokens/TestERC20Token.sol";

import "lib/forge-std/src/Test.sol";

contract LoansTest is Test {
    using AddressUpgradeable for address;

    MarketRegistryMock marketRegistry;

    TellerV2 tellerV2;
    LenderCommitmentForwarder lenderCommitmentForwarder;
    CollateralManager collateralManager;
    
    TestERC20Token principalToken;

    address alice = address(0x1111);

    uint256 marketId = 0;

    function setUp() public {
        tellerV2 = new TellerV2(address(0));

        marketRegistry = new MarketRegistryMock();

        lenderCommitmentForwarder = new LenderCommitmentForwarder(address(tellerV2),address(marketRegistry));
        
        collateralManager = new CollateralManager();
        collateralManager.initialize(address(new UpgradeableBeacon(address(new CollateralEscrowV1()))), address(tellerV2));

        address rm = address(new ReputationManagerMock());
        address lm = address(new LenderManagerMock());
        tellerV2.initialize(0, address(marketRegistry), rm, address(lenderCommitmentForwarder), address(collateralManager), lm);

        marketRegistry.setMarketOwner(address(this));
        marketRegistry.setMarketFeeRecipient(address(this));

        tellerV2.setTrustedMarketForwarder(marketId,address(lenderCommitmentForwarder));

        principalToken = new TestERC20Token("Principal Token", "PRIN", 12e18, 18);
    }


    function testLoanInstallmentsCalculatedIncorrectly() public {
        // payment cycle is 1000 in market registry
        
        uint256 amount = 1000;
        principalToken.transfer(alice,amount);
     
        vm.startPrank(alice);
        principalToken.approve(address(tellerV2),2*amount);
        uint256 bidId = tellerV2.submitBid(
            address(principalToken),
            marketId,
            amount,
            2500, // 2.5 payment cycles
            0, // 0 interest to make calculations easier
            "",
            alice
        );
        tellerV2.lenderAcceptBid(bidId);
        vm.stopPrank();

        // jump to first payment cycle end
        vm.warp(block.timestamp + 1000);
        Payment memory p = tellerV2.calculateAmountDue(bidId);
        assertEq(400,p.principal);

        // borrower pays on time
        vm.prank(alice);
        tellerV2.repayLoanMinimum(bidId);

        // jump to second payment cycle
        vm.warp(block.timestamp + 1000);
        p = tellerV2.calculateAmountDue(bidId);

        // should be 400 but is full loan
        assertEq(600,p.principal);
    }
}
```

The details of this finding are out of scope but since it makes `TellerV2`, in scope, behave unexpectedly I believe this finding to be in scope.

## Impact
A borrower taking a loan might not be able to pay the last payment cycle and be liquidated. At the worst possible time since they've paid the whole loan on schedule up to the last installment. The liquidator just need to pay the last installment to take the whole collateral.

This requires the loan to not be a multiple of the payment cycle which might sound odd. But since a year is 365 days and a common payment cycle is 30 days I imagine there can be quite a lot of loans that after 360 days will end up in this issue.

There is also nothing stopping an unknowing borrower from placing a bid or accepting a commitment with an odd duration.

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol#L94-L101

## Tool used
Manual Review

## Recommendation
First I thought that you could remove the `lastPaymentCycle` calculation all together. I tried that and then also tested what happened with "irregular" loans with interest.

Then I found this in the EMI calculation:

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/libraries/NumbersLib.sol#L123
```solidity
File: libraries/NumbersLib.sol

132:        uint256 n = Math.ceilDiv(loanDuration, cycleDuration);
```

EMI, which is designed for mortgages, assumes the payments is a discrete number of the same amortization essentially. I.e they don't allow "partial" periods at the end, because that doesn't make sense for a mortgage.

In Teller this is allowed which causes some issues with the EMI calculation since the above row will always round up to a full number of payment periods. If you also count interest, which triggers the EMI calculation: The lender, in an "irregular" loan duration, would get less per installment up to the last one which would be bigger. The funds would all be paid with the correct interest in the end just not in the expected amounts.

### My recommendation now is:
either

- **don't allow loan durations that aren't a multiple of the period**, at least warn about it UI-wise, no one will lose any money but the installments might be split in unexpected amounts.
- **Do away with EMI all together** as DeFi loans aren't the same as mortgages. The defaulting/liquidation logic only cares about time since last payment.
- **Do more math** to make EMI work with irregular loan durations. This nerd sniped me:

### More math:
From the link in the comment, https://en.wikipedia.org/wiki/Equated_monthly_installment you can follow one of the links in that wiki page to a derivation of the formula: http://rmathew.com/2006/calculating-emis.html

In the middle we have an equation which describes the owed amount at a time $P_n$:

$$P_n=Pt^n-E\frac{(t^n-1)}{t-n}$$
where $t=1+r$ and $r$ is the monthly interest rate ($apy*C/year$).

Now, from here, we want to calculate the loan at a time $P_{n + \Delta}$:

$$P_{n + \Delta}=Pt^nt_\Delta-E\frac{t^n-1}{t-1}t_\Delta-kE$$

Where $k$ is $c/C$ i.e. the ratio of partial cycle compared to a full cycle.

Same with $t_\Delta$ which is $1+r_\Delta$, ($r_\Delta$ is also equal to $kr$, ratio of partial cycle rate to full cycle rate, which we'll use later).

Reorganize to get $E$ from above:

$$
E = P r \frac{t^nt_\Delta}{t_\Delta \frac{t^n-1}{t-1} + k}
$$

Now substitute in $1+r$ in place of $t$ and $1+r_\Delta$ instead of $t_\Delta$ and multiply both numerator and denominator with $r$:

$$
E = P \frac{r (1+r)^n(1+r_\Delta)}{(1+r_\Delta)((1+r)^n - 1) + kr}
$$

and $kr = r_\Delta$ gives us:

$$
E = P r (1+r)^n \frac{(1+r_\Delta)}{(1+r_\Delta)((1+r)^n - 1) + r_\Delta}
$$

To check that this is correct, $r_\Delta = 0$ (no extra cycle added) should give us the regular EMI equation. Which we can see is true for the above. And $r_\Delta = r$ (a full extra cycle added) should give us the EMI equation but with $n+1$ which we can also see it does.

Here are the code changes to use this, together with changes to `V2Calculations.sol` to calculate the last period correctly:
```diff
diff --git a/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol b/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol
index 1cce8da..1ad5bcf 100644
--- a/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol
+++ b/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol
@@ -90,30 +90,15 @@ library V2Calculations {
         uint256 owedTime = _timestamp - uint256(_lastRepaidTimestamp);
         interest_ = (interestOwedInAYear * owedTime) / daysInYear;
 
-        // Cast to int265 to avoid underflow errors (negative means loan duration has passed)
-        int256 durationLeftOnLoan = int256(
-            uint256(_bid.loanDetails.loanDuration)
-        ) -
-            (int256(_timestamp) -
-                int256(uint256(_bid.loanDetails.acceptedTimestamp)));
-        bool isLastPaymentCycle = durationLeftOnLoan <
-            int256(uint256(_bid.terms.paymentCycle)) || // Check if current payment cycle is within or beyond the last one
-            owedPrincipal_ + interest_ <= _bid.terms.paymentCycleAmount; // Check if what is left to pay is less than the payment cycle amount
-
         if (_bid.paymentType == PaymentType.Bullet) {
-            if (isLastPaymentCycle) {
-                duePrincipal_ = owedPrincipal_;
-            }
+            duePrincipal_ = owedPrincipal_;
         } else {
             // Default to PaymentType.EMI
             // Max payable amount in a cycle
             // NOTE: the last cycle could have less than the calculated payment amount
-            uint256 maxCycleOwed = isLastPaymentCycle
-                ? owedPrincipal_ + interest_
-                : _bid.terms.paymentCycleAmount;
 
             // Calculate accrued amount due since last repayment
-            uint256 owedAmount = (maxCycleOwed * owedTime) /
+            uint256 owedAmount = (_bid.terms.paymentCycleAmount * owedTime) /
                 _bid.terms.paymentCycle;
             duePrincipal_ = Math.min(owedAmount - interest_, owedPrincipal_);
         }

```

And then `NumbersLib.sol`:
```diff
diff --git a/teller-protocol-v2/packages/contracts/contracts/libraries/NumbersLib.sol b/teller-protocol-v2/packages/contracts/contracts/libraries/NumbersLib.sol
index f34dd9c..8ca48bc 100644
--- a/teller-protocol-v2/packages/contracts/contracts/libraries/NumbersLib.sol
+++ b/teller-protocol-v2/packages/contracts/contracts/libraries/NumbersLib.sol
@@ -120,7 +120,8 @@ library NumbersLib {
                 );
 
         // Number of payment cycles for the duration of the loan
-        uint256 n = Math.ceilDiv(loanDuration, cycleDuration);
+        uint256 n = loanDuration/ cycleDuration;
+        uint256 rest = loanDuration%cycleDuration;
 
         uint256 one = WadRayMath.wad();
         uint256 r = WadRayMath.pctToWad(apr).wadMul(cycleDuration).wadDiv(
@@ -128,8 +129,16 @@ library NumbersLib {
         );
         uint256 exp = (one + r).wadPow(n);
         uint256 numerator = principal.wadMul(r).wadMul(exp);
-        uint256 denominator = exp - one;
 
-        return numerator.wadDiv(denominator);
+        if(rest==0) {
+            // duration is multiple of cycle
+            uint256 denominator = exp - one;
+            return numerator.wadDiv(denominator);
+        }
+        // duration is an uneven cycle
+        uint256 rDelta = WadRayMath.pctToWad(apr).wadMul(rest).wadDiv(daysInYear);
+        uint256 n1 = numerator.wadMul(one + rDelta);
+        uint256 denom = ((one + rDelta).wadMul(exp - one)) + rDelta;
+        return n1.wadDiv(denom);
     }
 }
```



## Discussion

**ethereumdegen**

It seems that in that example of a loan with 3 cycles, 400 then 400 and then 200,  if the borrower is more than halfway through the second installment (second 400) , they would be considered to be in the 'lastPaymentCycle' incorrectly and would 'owe' 600  instead of 400.   We will investigate this more for a fix. 

# Issue M-7: bids can be created against markets that doesn't exist 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/323 

## Found by 
immeas, saidam017

## Summary
Bids can be created against markets that does not yet exist. When this market is created, the bid can be accepted but neither defaulted/liquidated nor repaid.

## Vulnerability Detail
There's no verification that the market actually exists when submitting a bid. Hence a user could submit a bid for a non existing market.

For it to not revert it must have 0% APY and the bid cannot be accepted until a market exists.

However, when this market is created the bid can be accepted. Then the loan would be impossible to default/liquidate:

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L963
```solidity
File: TellerV2.sol

963:        if (bidDefaultDuration[_bidId] == 0) return false;
```
Since `bidDefaultDuration[_bidId]` will be `0`

Any attempt to repay will revert due to division by 0:

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol#L116-L117
```solidity
File: libraries/V2Calculations.sol

116:            uint256 owedAmount = (maxCycleOwed * owedTime) /
117:                _bid.terms.paymentCycle; 
``` 
Since `_bid.terms.paymentCycle` will also be `0` (and it will always end up in this branch since `PaymentType` will be `EMI (0)`).

Hence the loan can never be closed.

PoC:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

import { TellerV2 } from "../contracts/TellerV2.sol";
import { CollateralManager } from "../contracts/CollateralManager.sol";
import { LenderCommitmentForwarder } from "../contracts/LenderCommitmentForwarder.sol";
import { CollateralEscrowV1 } from "../contracts/escrow/CollateralEscrowV1.sol";
import { MarketRegistry } from "../contracts/MarketRegistry.sol";

import { ReputationManagerMock } from "../contracts/mock/ReputationManagerMock.sol";
import { LenderManagerMock } from "../contracts/mock/LenderManagerMock.sol";
import { TellerASMock } from "../contracts/mock/TellerASMock.sol";

import {TestERC20Token} from "./tokens/TestERC20Token.sol";

import "lib/forge-std/src/Test.sol";
import "lib/forge-std/src/StdAssertions.sol";

contract LoansTest is Test {
    MarketRegistry marketRegistry;
    TellerV2 tellerV2;
    
    TestERC20Token principalToken;

    address alice = address(0x1111);
    address bob = address(0x2222);
    address owner = address(0x3333);

    function setUp() public {
        tellerV2 = new TellerV2(address(0));

        marketRegistry = new MarketRegistry();
        TellerASMock tellerAs = new TellerASMock();
        marketRegistry.initialize(tellerAs);

        LenderCommitmentForwarder lenderCommitmentForwarder = 
            new LenderCommitmentForwarder(address(tellerV2),address(marketRegistry));
        CollateralManager collateralManager = new CollateralManager();
        collateralManager.initialize(address(new UpgradeableBeacon(address(new CollateralEscrowV1()))),
            address(tellerV2));
        address rm = address(new ReputationManagerMock());
        address lm = address(new LenderManagerMock());
        tellerV2.initialize(0, address(marketRegistry), rm, address(lenderCommitmentForwarder),
            address(collateralManager), lm);

        principalToken = new TestERC20Token("Principal Token", "PRIN", 12e18, 18);
    }

    function testSubmitBidForNonExistingMarket() public {
        uint256 amount = 12e18;
        principalToken.transfer(bob,amount);

        vm.prank(bob);
        principalToken.approve(address(tellerV2),amount);

        // alice places bid on non-existing market
        vm.prank(alice);
        uint256 bidId = tellerV2.submitBid(
            address(principalToken),
            1, // non-existing right now
            amount,
            360 days,
            0, // any APY != 0 will cause revert on div by 0
            "",
            alice
        );

        // bid cannot be accepted before market
        vm.expectRevert(); // div by 0
        vm.prank(bob);
        tellerV2.lenderAcceptBid(bidId);

        vm.startPrank(owner);
        uint256 marketId = marketRegistry.createMarket(
            owner,
            30 days,
            30 days,
            1 days,
            0,
            false,
            false,
            ""
        );
        marketRegistry.setMarketFeeRecipient(marketId, owner);
        vm.stopPrank();

        // lender takes bid
        vm.prank(bob);
        tellerV2.lenderAcceptBid(bidId);

        // should be liquidatable now
        vm.warp(32 days);

        // loan cannot be defaulted/liquidated
        assertFalse(tellerV2.isLoanDefaulted(bidId));
        assertFalse(tellerV2.isLoanLiquidateable(bidId));

        vm.startPrank(alice);
        principalToken.approve(address(tellerV2),12e18);

        // and loan cannot be repaid
        vm.expectRevert(); // division by 0
        tellerV2.repayLoanFull(bidId);
        vm.stopPrank();
    }
}
```

## Impact
This will lock any collateral forever since there's no way to retrieve it. For this to happen accidentally a borrower would have to create a bid for a non existing market with 0% APY though.

This could also be used to lure lenders since the loan cannot be liquidated/defaulted. This might be difficult since the APY must be 0% for the bid to be created. Also, this will lock any collateral provided by the borrower forever.

Due to these circumstances I'm categorizing this as medium.

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L334-L411

## Tool used
Manual Review

## Recommendation
When submitting a bid, verify that the market exists.



## Discussion

**ethereumdegen**

A user creating a bid for a market that does not yet exist yet COULD exist in the future is potentially a concern.  For example an attacker could see that there are bids open for market 88, create markets until market 88 exists , and then fulfill those loans with whatever rules they want.   Our user interface on the front end will prevent bids from being created with an invalid market ID so in reality this should not be an issue but in solidity strictly yes this is a valid issue.   Thank you. 

**ethereumdegen**

We should make a function name isMarketOpen that verifies that 1) the marketId is less than the number of markets and 2) the market is not closed and we should use that in submitBid instead of !isMarketClosed 

# Issue M-8: EMI last payment not handled perfectly could lead to borrower losing collaterals 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/315 

## Found by 
RaymondFam

## Summary
The ternary logic of `calculateAmountOwed()` could have the last EMI payment under calculated, leading to borrower not paying the owed principal and possibly losing the collaterals if care has not been given to.

## Vulnerability Detail
Supposing Bob has a loan duration of 100 days such that the payment cycle is evenly spread out, i.e payment due every 10 days, here is a typical scenario:

1. Bob has been making his payment due on time to avoid getting marked delinquent. For the last payment due, Bob decides to make it 5 minutes earlier just to make sure he will not miss it.
2. However, `duePrincipal_` ends up assigned the minimum of `owedAmount - interest_` and `owedPrincipal_`, where the former is chosen since `oweTime` is less than `_bid.terms.paymentCycle`:

```solidity
        } else {
            // Default to PaymentType.EMI
            // Max payable amount in a cycle
            // NOTE: the last cycle could have less than the calculated payment amount
            uint256 maxCycleOwed = isLastPaymentCycle
                ? owedPrincipal_ + interest_
                : _bid.terms.paymentCycleAmount;

            // Calculate accrued amount due since last repayment
            uint256 owedAmount = (maxCycleOwed * owedTime) /
                _bid.terms.paymentCycle;
            duePrincipal_ = Math.min(owedAmount - interest_, owedPrincipal_);
        }
```
3. Hence, in `_repayLoan()`, `paymentAmount >= _owedAmount` equals false failing to  close the loan to have the collaterals returned to Bob:

```solidity
        if (paymentAmount >= _owedAmount) {
            paymentAmount = _owedAmount;
            bid.state = BidState.PAID;

            // Remove borrower's active bid
            _borrowerBidsActive[bid.borrower].remove(_bidId);

            // If loan is is being liquidated and backed by collateral, withdraw and send to borrower
            if (_shouldWithdrawCollateral) {
                collateralManager.withdraw(_bidId);
            }

            emit LoanRepaid(_bidId);
```
4. While lingering and not paying too much attention to the collateral still in escrow, Bob presumes his loan is now settled.
5. Next, Alex the lender has been waiting for this golden opportunity and proceeds to calling [`CollateralManager.withdraw()`](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L250-L260) to claim all collaterals as soon as the loan turns defaulted.

## Impact
Bob ended up losing all collaterals for the sake of the minute amount of loan unpaid whereas Alex receives almost all principal plus interests on top of the collaterals. 

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol#L107-L119

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L727-L739

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L250-L260

## Tool used

Manual Review

## Recommendation
Consider refactoring the affected ternary logic as follows:

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/libraries/V2Calculations.sol#L107-L119

```diff
        } else {
+            duePrincipal = isLastPaymentCycle
+                ? owedPrincipal
+               : (_bid.terms.paymentCycleAmount * owedTime) / _bid.terms.paymentCycle;

            // Default to PaymentType.EMI
            // Max payable amount in a cycle
            // NOTE: the last cycle could have less than the calculated payment amount
-            uint256 maxCycleOwed = isLastPaymentCycle
-                ? owedPrincipal_ + interest_
-                : _bid.terms.paymentCycleAmount;

            // Calculate accrued amount due since last repayment
-            uint256 owedAmount = (maxCycleOwed * owedTime) /
-                _bid.terms.paymentCycle;
-            duePrincipal_ = Math.min(owedAmount - interest_, owedPrincipal_);
        }
```


# Issue M-9: Borrower/lender will not be able to withdraw any collateral when partially blacklisted 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/227 

## Found by 
HexHackers, Saeedalipoor01988, cducrest-brainbot, saidam017

## Summary

The function to withdraw collateral directly sends each collateral token either to the loan borrower (when loan is repaid) or to the lender (when loan is defaulted).

If the borrower committed multiple tokens and one of them uses a blacklist, it could be that they are blacklisted for part of the collateral and will not be able to withdraw any of the collateral.

## Vulnerability Detail

When a loan is repaid, `CollateralManager.withdraw()` allows borrower to withdraw all of their collateral:
```solidity
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

The `_withdraw()` function loops over all the committed collateral and withdraws each one:

```solidity
    function _withdraw(uint256 _bidId, address _receiver) internal virtual {
        for (
            uint256 i;
            i < _bidCollaterals[_bidId].collateralAddresses.length();
            i++
        ) {
            // Get collateral info
            Collateral storage collateralInfo = _bidCollaterals[_bidId]
                .collateralInfo[
                    _bidCollaterals[_bidId].collateralAddresses.at(i)
                ];
            // Withdraw collateral from escrow and send it to bid lender
            ICollateralEscrowV1(_escrows[_bidId]).withdraw(
                collateralInfo._collateralAddress,
                collateralInfo._amount,
                _receiver
            );
            emit CollateralWithdrawn(
                _bidId,
                collateralInfo._collateralType,
                collateralInfo._collateralAddress,
                collateralInfo._amount,
                collateralInfo._tokenId,
                _receiver
            );
        }
    }
```

The `CollateralEscrowV1.withdraw()` function directly sends the token to withdrawer:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L84-L103
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L158-L194

## Impact

If borrower is blacklisted for one of its collateral, they will not be able to withdraw the other tokens they are not blacklisted with. This results in a loss of collateral for the borrower.

The same is true when loan is defaulted and lender wants to withdraw the collateral. However, the lender can transfer the loan to another address they own via the `LenderManager` so this is less of a problem.

I cannot tell if protocol wants to allow withdrawal of tokens held by the escrow that belonged to a blacklisted borrower, but that is also obviously impossible.

## Code Snippet

## Tool used

Manual Review

## Recommendation

If protocol wants to allow withdrawal of blacklisted tokens, allow withdrawer to specify new withdrawal address if they are the borrower and the loan has been repaid.
Otherwise, allow withdrawal of individual tokens to be able to withdraw the non-blacklisting tokens.



## Discussion

**ethereumdegen**

Thank you for your response. This is very similar to a known issue that was explained in the README for the contest, it was known that collateral could be made non-transferrable and thus a loan would be unable to be repaid.  It has been planned to separate the repay and collateralWithdraw functionality so that repayment can still occur.  

# Issue M-10: Use `safeTransfer()` instead of `transfer()` 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/220 

## Found by 
0x2e, 0xeix, 0xepley, ArbitraryExecution, Bauer, Delvir0, HexHackers, Inspex, Kodyvim, MiloTruck, Saeedalipoor01988, \_\_141345\_\_, ak1, cducrest-brainbot, dacian, georgits, ginlee, giovannidisiena, innertia, jasonxiale, nicobevi, spyrosonic10, techOptimizor, tsvetanovv, w42d3n


## Summary
The `transfer()` function of the `IERC20Upgradeable` interface return a boolean value that indicates a success status. However, some tokens do not implement the EIP20 standard correctly, and the `transfer()` function return void instead.


## Vulnerability Detail
After the lender accepts the borrower's bid, the borrower's collateral is deposited into the `CollateralEscrowV1` contract using the `SafeERC20Upgradeable.safeTransferFrom()` function.

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L119-L124


However, when users withdraw funds from the `CollateralEscrowV1` contract, such as when liquidating or fully repaying a loan, the token is transferred using the `IERC20Upgradeable.transfer()` function. This can cause issues with tokens that are not implemented according to the EIP20 standard, such as `USDT` token on the mainnet network, as they may be reverted.

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L166-L169

Therefore, if users use tokens that are not implemented according to the EIP20 standard, such as the `USDT` token, it can prevent the loan from being repaid or liquidated, potentially resulting in the loss of the user's collateral.

## Impact
Users of the Teller platform may be at risk of losing their collateral if they use non-EIP20 standard tokens such as the `USDT` token, which results in the token being reverted. This can cause the loan to become unrecoverable and result in the loss of the user's collateral.

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L166-L169

## Tool used

Manual Review

## Recommendation
We recommend adding the implementation of the OpenZeppelin's `SafeERC20` library, which replaces the usage of the `transfer()` function with the `safeTransfer()` function.

# Issue M-11: Bid submission vulnerable to market parameters changes 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/205 

## Found by 
BAHOZ, Fanz, T1MOH, cducrest-brainbot, ck, immeas, jpserrat, juancito, whoismatthewmc1

## Summary

The details for the audit state: 

> Market owners should NOT be able to race-condition attack borrowers or lenders by changing market settings while bids are being submitted or accepted (while tx are in mempool). Care has been taken to ensure that this is not possible (similar in theory to sandwich attacking but worse as if possible it could cause unexpected and non-consentual interest rate on a loan) and further-auditing of this is welcome.

However, there is little protection in place to protect the submitter of a bid from changes in market parameters.

## Vulnerability Detail

In _submitBid(), certain bid parameters are taken from the `marketRegistry`:

```solidity
    function _submitBid(...)
        ...
        (bid.terms.paymentCycle, bidPaymentCycleType[bidId]) = marketRegistry
            .getPaymentCycle(_marketplaceId);

        bid.terms.APR = _APR;

        bidDefaultDuration[bidId] = marketRegistry.getPaymentDefaultDuration(
            _marketplaceId
        );

        bidExpirationTime[bidId] = marketRegistry.getBidExpirationTime(
            _marketplaceId
        );

        bid.paymentType = marketRegistry.getPaymentType(_marketplaceId);
        
        bid.terms.paymentCycleAmount = V2Calculations
            .calculatePaymentCycleAmount(
                bid.paymentType,
                bidPaymentCycleType[bidId],
                _principal,
                _duration,
                bid.terms.paymentCycle,
                _APR
            );
        ...
```

All the parameters taken from marketRegistry are controlled by the market owner:
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/MarketRegistry.sol#L487-L511

## Impact

If market parameters are changed in between the borrower submitting a bid transaction and the transaction being applied, borrower may be subject to changes in `bidDefaultDuration`, `bidExpirationTime`, `paymentType`, `paymentCycle`, `bidPaymentCycleType` and `paymentCycleAmount`.

That is, the user may be committed to the bid for longer / shorter than expected. They may have a longer / shorter default duration (time for the loan being considered defaulted / eligible for liquidation). They have un-provisioned for payment type and cycle parameters.

I believe most of this will have a medium impact on borrower (mild inconveniences / resolvable by directly repaying the loan) if the market owner is not evil and adapting the parameters reasonably.

An evil market owner can set the value of `bidDefaultDuration` and `paymentCycle` very low (0) so that the loan will default immediately. It can then accept the bid, make user default immediately, and liquidate the loan to steal the user's collateral. This results in a loss of collateral for the borrower.

## Code Snippet

## Tool used

Manual Review

## Recommendation

Take every single parameters as input of `_submitBid()` (including fee percents) and compare them to the values in `marketRegistry` to make sure borrower agrees with them, revert if they differ.



## Discussion

**ethereumdegen**

The way the protocol was designed, market owners are 'trusted' however we will add a new submitBid method that adds these checks in case we want to support trustless market owners in the future 

# Issue M-12: The submitBid transaction lack of expiration timestamp check 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/187 

## Found by 
PawelK, T1MOH

## Summary
Submitting bid misses the transaction expiration check, which may lead to receiving principal at a lower price and to collateral being sold at a higher price than the market price at the moment of a `submitBid()`. Borrowers can receive less than expected for provided collateral.

## Vulnerability Detail
The transaction can be pending in mempool for a long time and can be executed in a long time after the user submit the transaction.
Problem is `submitBid()`, which trusts bid as valid even if market prices of principal and collateral have changed a lot.
```solidity
        bid.loanDetails.timestamp = uint32(block.timestamp);
        bid.loanDetails.loanDuration = _duration;
```


## Impact
It makes borrower to lose money by submitting disadvantageous bid in worse case. And prevents the borrower from making bids that will be valid for a short period of time in best case.

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L334-L368

## Tool used

Manual Review

## Recommendation
Use deadline mechanism as in Uniswap V2 contract addLiquidity function implementation
https://github.com/Uniswap/v2-periphery/blob/0335e8f7e1bd1e8d8329fd300aea2ef2f36dd19f/contracts/UniswapV2Router02.sol#L61
```solidity
function addLiquidity(
	address tokenA,
	address tokenB,
	uint amountADesired,
	uint amountBDesired,
	uint amountAMin,
	uint amountBMin,
	address to,
	uint deadline
) external virtual override ensure(deadline) returns (uint amountA, uint amountB, uint liquidity) {
	(amountA, amountB) = _addLiquidity(tokenA, tokenB, amountADesired, amountBDesired, amountAMin, amountBMin);
	address pair = UniswapV2Library.pairFor(factory, tokenA, tokenB);
	TransferHelper.safeTransferFrom(tokenA, msg.sender, pair, amountA);
	TransferHelper.safeTransferFrom(tokenB, msg.sender, pair, amountB);
	liquidity = IUniswapV2Pair(pair).mint(to);
}
```
```solidity
modifier ensure(uint deadline) {
	require(deadline >= block.timestamp, 'UniswapV2Router: EXPIRED');
	_;
}
```

# Issue M-13: Borrower's Loan can unexpectedly default as there's no check for alignment between `_duration` and `_paymentDefaultDuration` 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/185 

## Found by 
HexHackers

## Summary
Borrower's Loan can unexpectedly default as there's no check if  `_duration` <= `_paymentDefaultDuration`

## Vulnerability Detail
For example `_paymentDefaultDuration` can be set by market Owner to 10 days
but a borrower makes the recurring payment to be 14 days by setting `_duration` to 14 days and he'll think he's okay to make the payment in 14 days but instead the loan will automatically default.
## Impact
Borrower's Loan can default unexpectedly because there's no check to make sure the `_duration` set by the borrowers  is <= the `_paymentDefaultDuration` set by the market owners.

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L334-L411

## Tool used

Manual Review

## Recommendation
This can be prevented with a require statement in `_submitBid` like this:
```solidity
require(_duration <= _paymentDefaultDuration, "duration is above default payment date");
```



## Discussion

**ethereumdegen**

We should update _canLiquidateLoan to be based off of a 'due date' instead of last repaid date. 

# Issue M-14: Expiration is completely broken for markets that set bidExpirationTime = 0 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/178 

## Found by 
0x52, cccz

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

# Issue M-15: lenderAcceptBid won't function if fee = 0 and token doesn't support zero transfers 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/177 

## Found by 
0x52, GimelSec, Saeedalipoor01988, duc

## Summary

Whenever a bid is accepted the contract attempt to sends fee recipients their fees but if there is a low value loan or no fee it will attempt to transfer zero. This will break compatibility with tokens that don't support zero transfers.

## Vulnerability Detail

[TellerV2.sol#L512-L540](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L512-L540)

        // Transfer funds to borrower from the lender
        amountToProtocol = bid.loanDetails.principal.percent(protocolFee());
        amountToMarketplace = bid.loanDetails.principal.percent(
            marketRegistry.getMarketplaceFee(bid.marketplaceId)
        );
        amountToBorrower =
            bid.loanDetails.principal -
            amountToProtocol -
            amountToMarketplace;
        //transfer fee to protocol
        bid.loanDetails.lendingToken.safeTransferFrom(
            sender,
            owner(),
            amountToProtocol
        );

        //transfer fee to marketplace
        bid.loanDetails.lendingToken.safeTransferFrom(
            sender,
            marketRegistry.getMarketFeeRecipient(bid.marketplaceId),
            amountToMarketplace
        );

        //transfer funds to borrower
        bid.loanDetails.lendingToken.safeTransferFrom( <- @audit-issue this can fail if sending 0
            sender,
            bid.receiver,
            amountToBorrower
        );

With each accepted bid it attempts to send the fees to the fee recipients. If there is no fee then this transfer could break for tokens that don't support zero transfers 

## Impact

Loans for markets with no fees will be incompatible with zero transfer tokens

## Code Snippet

[TellerV2.sol#L470-L558](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/TellerV2.sol#L470-L558)

## Tool used

Manual Review

## Recommendation

Only transfer is amount > 0

# Issue M-16: LenderCommitmentForwarder#updateCommitment can be front-run by malicious borrower to cause lender to over-commit funds 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/176 

## Found by 
0x52, chaduke

## Summary

This is the same idea as approve vs increaseAlllowance. updateCommitment is a bit worse though because there are more reason why a user may wish to update their commitment (expiration, collateral ratio, interest rate, etc).

## Vulnerability Detail

[LenderCommitmentForwarder.sol#L212-L222](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L212-L222)

        require(
            _commitment.principalTokenAddress ==
                commitments[_commitmentId].principalTokenAddress,
            "Principal token address cannot be updated."
        );
        require(
            _commitment.marketId == commitments[_commitmentId].marketId,
            "Market Id cannot be updated."
        );

        commitments[_commitmentId] = _commitment;

LenderCommitmentForwarder#updateCommitment overwrites ALL of the commitment data. This means that even if a user is calling it to update even one value the maxPrincipal will reset, opening up the following attack vector:

1) User A creates a commitment for 100e6 USDC lending against ETH
2) User A's commitment is close to expiry so they call to update their commitment with a new expiration
3) User B sees this update and front-runs it with a loan against the commitment for 100e6 USDC
4) User A's commitment is updated and the amount is set back to 100e6 USDC
5) User B takes out another loan for 100e6 USDC
6) User A has now loaned out 200e6 USDC when they only meant to loan 100e6 USDC

## Impact

Commitment is abused to over-commit lender

## Code Snippet

[LenderCommitmentForwarder.sol#L208-L233](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L208-L233)

## Tool used

Manual Review

## Recommendation

Create a function that allows users to extend expiry while keeping amount unchanged. Additionally create a function similar to increaseApproval which increase amount instead of overwriting amount.



## Discussion

**ethereumdegen**

I think the only correct way to solve this is to never decrement or change the 'max principal' amount on a commitment because no matter how that is done it can be frontrun attacked in this way.

The only viable solution is to add a mapping that keeps track of how much capital has been allocated from a commitment and always make sure that that is LEQ than the maxPrincipal for that commitment. 

# Issue M-17: LenderCommitmentForwarder#acceptCommitment can be front-run by malicious lender to permanently lock user collateral 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/175 

## Found by 
0x52

## Summary

## Vulnerability Detail

[LenderCommitmentForwarder.sol#L208-L224](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L208-L224)

    function updateCommitment(
        uint256 _commitmentId,
        Commitment calldata _commitment
    ) public commitmentLender(_commitmentId) {
        require(
            _commitment.principalTokenAddress ==
                commitments[_commitmentId].principalTokenAddress,
            "Principal token address cannot be updated."
        );
        require(
            _commitment.marketId == commitments[_commitmentId].marketId,
            "Market Id cannot be updated."
        );

        commitments[_commitmentId] = _commitment;

        validateCommitment(commitments[_commitmentId]);

LenderCommitmentForwarder#updateCommitment allows a lender with an outstanding commitment to update their commitment. Key variables like the token address and the marketId can't be changed to prevent malicious behavior. It misses a key variable, the collateral type. Due to the overlap in functions between ERC20 and ERC721 this change can be exploited to permanently lock user collateral.

[LenderCommitmentForwarder.sol#L300-L308](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L300-L308)

    function acceptCommitment(
        uint256 _commitmentId,
        uint256 _principalAmount,
        uint256 _collateralAmount,
        uint256 _collateralTokenId,
        address _collateralTokenAddress,
        uint16 _interestRate,
        uint32 _loanDuration
    ) external returns (uint256 bidId) {

When accepting a commitment the borrower is unable to specify the collateral type. This can be exploited by updating the collateral type from ERC721 to ERC20 as follows:

1) A malicious user creates a commitment for an ERC721 token as collateral for a loan of 100e6 USDC
2) User B sees this commitment and calls LenderCommitmentForwarder#acceptCommitment with tokenId = 1
3) The malicious user sees this and calls updateCommitment changing the type from ERC721 to ERC20
4) ERC721 tokens have a balanceOf function allowing it to pass the balance checks for commitCollateral
5) ERC721 token is transfered to escrow using transferFrom
6) The user is making payments and on the final payment the escrow tries to call transfer on the ERC721 contract
7) ERC721 contract don't have a transfer function meaning it's impossible to liquidate or payoff the loan
8) ERC721 token is permanently trapped

## Impact

Borrower collateral is permanently locked

## Code Snippet

[LenderCommitmentForwarder.sol#L208-L233](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L208-L233)

## Tool used

Manual Review

## Recommendation

Don't allow collateral type to be updated




## Discussion

**ethereumdegen**

This is something that we intend to fix, thank you. 

# Issue M-18: _withdrawCollateral() withdraws the wrong amount of ERC 20 tokens. 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/140 

## Found by 
0xPkhatri, Aymen0909, HonorLt, MiloTruck, PawelK, cccz, chaduke, immeas, shaka, sinarette, yixxas

## Summary
_withdrawCollateral() withdraws the wrong amount of ERC 20 tokens.  The main problem is that while the input argument for _withdrawCollateral() is ``_amount``, the function uses the `` _collateral._amount`` to withdraw all the balance of ERC20 tokens from the contract of ``CollateralEscrowV1``.


## Vulnerability Detail
To see why _withdrawCollateral() withdraws the wrong amount of ERC 20 tokens, let's see the flow of ``CollateralEscrowV1#withdraw()->withdrawCollateral()``:

1. Let's assume the collateral type to be withdrawn is ERC20, that is ``_collateralType == CollateralType.ERC20``.

2. ``CollateralEscrowV1#withdraw()``will decease the balance by the input ``_amount``:
[https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L101](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L101)

3. However, when it calls ``withdrawCollateral()``, the amount that will be transferred is  ``collateral._amount``, which is not necesarily equal to ``_amount``.
[https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L165-L170](https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L165-L170)

4. Note that when the collateral is ERC1155, the ``_amount`` is used instead:
```javascript
 else if (_collateral._collateralType == CollateralType.ERC1155) {
            bytes memory data;

            IERC1155Upgradeable(_collateralAddress).safeTransferFrom(
                address(this),
                _recipient,
                _collateral._tokenId,
                _amount,
                data
            );
        } else {
```

This confirms that for ERC20 collateral, ``_amount`` should be used as well, not ``_collateral._amount``!

## Impact
When the input ``_amount <  _collateral._amount``, for ERC collateral, more tokens will be withdrawn by ``withdrawCollateral()`` than it is supposed to be. 


## Code Snippet
See above

## Tool used
VSCode

Manual Review

## Recommendation
Use  ``_amount`` instead of ``_collateral._amount`` for withdrawing ERC20 collateral
```diff
function _withdrawCollateral(
        Collateral memory _collateral,
        address _collateralAddress,
        uint256 _amount,
        address _recipient
    ) internal {
        // Withdraw ERC20
        if (_collateral._collateralType == CollateralType.ERC20) {
            IERC20Upgradeable(_collateralAddress).transfer(
                _recipient,
-                _collateral._amount
+             _amount
            );
        }
        // Withdraw ERC721
        else if (_collateral._collateralType == CollateralType.ERC721) {
            require(_amount == 1, "Incorrect withdrawal amount");
            IERC721Upgradeable(_collateralAddress).transferFrom(
                address(this),
                _recipient,
                _collateral._tokenId
            );
        }
        // Withdraw ERC1155
        else if (_collateral._collateralType == CollateralType.ERC1155) {
            bytes memory data;

            IERC1155Upgradeable(_collateralAddress).safeTransferFrom(
                address(this),
                _recipient,
                _collateral._tokenId,
                _amount,
                data
            );
        } else {
            revert("Invalid collateral type");
        }
    }
```

# Issue M-19: ERC721 tokens can be permanently lost if recipient is a contract that doesn't implement `onERC721Received` 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/139 

## Found by 
8olidity, ArbitraryExecution, Bnke0x0, Breeje, IceBear, Kodyvim, Ruhum, T1MOH, carrotsmuggler, ck, giovannidisiena, innertia, tsvetanovv, w42d3n

## Summary

ERC721 tokens can be permanently lost if recipient is a contract that doesn't implement `onERC721Received`

## Vulnerability Detail

In the function `CollateralEscrowV1::_withdrawCollateral`, if the recipient of the ERC721 token is a contract that doesn't implement `onERC721Received`, the token would be permanently lost.

This is because `transferFrom` does not check whether a target contract is able to receive an ERC721 token. 

```solidity
        // Withdraw ERC721
        else if (_collateral._collateralType == CollateralType.ERC721) {
            require(_amount == 1, "Incorrect withdrawal amount");
            IERC721Upgradeable(_collateralAddress).transferFrom(
                address(this),
                _recipient,
                _collateral._tokenId
            );
        }
```

There are also no additional checks in the contract to ensure that the recipient is an EOA instead of a contract.
 
## Impact

Loss of ERC721 tokens.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L171-L179

## Tool used

Manual Review

## Recommendation

Either enforce restrictions that the recipient address of ERC721 tokens is an EOA. Alternativerly use the safeTransferFrom function.



## Discussion

**ethereumdegen**

Ideally should use safeTransferFrom to make this safer, and/or allow for specifying the withdraw recipient 

# Issue M-20: Function _canLiquidateLoan() will revert when it is called near ``lastRepaidTimestamp(_bidId)`` 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/119 

## Found by 
T1MOH, cducrest-brainbot, chaduke

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




## Discussion

**Trumpero**

`_canLiquidateLoan` function can only be triggered by `isLoanDefaulted` and `isLoanLiquidateable`. Both of these are view functions, so I believe this is a low/informational issue.

# Issue M-21: Lender can take borrower's collateral before first payment due 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/92 

## Found by 
dacian

## Summary
For PaymentCycleType.Seconds if PaymentDefault < PaymentCycle, Lender can take Borrower's collateral before first payment is due. If PaymentDefault > 0 but very small, Lender can do this almost immediately after accepting borrower's bid. This is especially bad as the Market Operator who controls these parameters can also be the Lender.

## Vulnerability Detail
Lender calls CollateralManager.withdraw() [L254](https://github.com/teller-protocol/teller-protocol-v2/blob/cb66c9e348cdf1fd6d9b0416a49d663f5b6a693c/packages/contracts/contracts/CollateralManager.sol#L254), which calls TellerV2.isLoanDefaulted() [L930](https://github.com/teller-protocol/teller-protocol-v2/blob/cb66c9e348cdf1fd6d9b0416a49d663f5b6a693c/packages/contracts/contracts/TellerV2.sol#L930), which bypasses the 1 day grace period & doesn't take into account when first payment is due.

## Impact
Borrower loses their collateral before they can even make their first repayment, almost instantly if PaymentDefault > 0 but very small.

## Code Snippet
Put this test in TellerV2_Test.sol:
```solidity
function test_LenderQuicklyTakesCollateral() public {
	MarketRegistry mReg = (MarketRegistry)(payable(address(tellerV2.marketRegistry())));

	// payment cycle 3600 seconds, payment default 1 second
	// payment will be in default almost immediately upon being
	// accepted, even though the first payment is not due for much longer
	// than the default time
	uint32 PAYMENT_CYCLE_SEC   = 3600;
	uint32 PAYMENT_DEFAULT_SEC = 1;

	vm.startPrank(address(marketOwner));
	mReg.setPaymentCycle(marketId1, PaymentCycleType.Seconds, PAYMENT_CYCLE_SEC);
	mReg.setPaymentDefaultDuration(marketId1, PAYMENT_DEFAULT_SEC);
	vm.stopPrank();

	//Submit bid as borrower
	uint256 bidId = submitCollateralBid();
	// Accept bid as lender
	acceptBid(bidId);

	// almost immediately take the collateral as the lender, even though
	// the first payment wasn't due for much later
	ICollateralManager cMgr = tellerV2.collateralManager();
	skip(PAYMENT_DEFAULT_SEC+1);
	cMgr.withdraw(bidId);
	// try again to verify the collateral has been taken
	vm.expectRevert("No collateral balance for asset");
	cMgr.withdraw(bidId);
}
``` 

## Tool used
Manual Review

## Recommendation
Change the calculations done as a consequence of calling TellerV2.isLoanDefaulted() to take into account when first payment is due; see similar code which does this TellerV2.calculateNextDueDate() [L886-L899](https://github.com/teller-protocol/teller-protocol-v2/blob/cb66c9e348cdf1fd6d9b0416a49d663f5b6a693c/packages/contracts/contracts/TellerV2.sol#L886-L899). Lender should only be able to take Borrower's collateral after the Borrower has missed their first payment deadline by PaymentDefault seconds.

Consider enforcing sensible minimums for PaymentDefault. If PaymentDefault = 0 no liquidations will ever be possible as TellerV2._canLiquidateLoan() [L963](https://github.com/teller-protocol/teller-protocol-v2/blob/cb66c9e348cdf1fd6d9b0416a49d663f5b6a693c/packages/contracts/contracts/TellerV2.sol#L963) will always return false, so perhaps it shouldn't be possible to set PaymentDefault = 0.


# Issue M-22: updateCommitmentBorrowers does not delete all existing users 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/88 

## Found by 
cducrest-brainbot, monrel, nobody2018

## Summary

`delete` a complex structure that includes mapping will cause problem. See [[ethereum/solidity#11843](https://github.com/ethereum/solidity/pull/11843)](https://github.com/ethereum/solidity/pull/11843) for more info.

## Vulnerability Detail

The lender can update the list of borrowers by calling `LenderCommitmentForwarder.updateCommitmentBorrowers`. The list of borrowers is EnumerableSetUpgradeable.AddressSet that is a complex structure containing mapping. Using the `delete` keyword to delete this structure will not erase the mapping inside it. Let's look at the code of this function.

```solidity
mapping(uint256 => EnumerableSetUpgradeable.AddressSet)
        internal commitmentBorrowersList;
        
function updateCommitmentBorrowers(
        uint256 _commitmentId,
        address[] calldata _borrowerAddressList
    ) public commitmentLender(_commitmentId) {
        delete commitmentBorrowersList[_commitmentId];
        _addBorrowersToCommitmentAllowlist(_commitmentId, _borrowerAddressList);
    }
```

I wrote a similar function to prove the problem.

```solidity
using EnumerableSet for EnumerableSet.AddressSet;
    mapping(uint256 => EnumerableSet.AddressSet) internal users;
    
    function test_deleteEnumerableSet() public {
        uint256 id = 1;
        address[] memory newUsers = new address[](2);
        newUsers[0] = address(0x1);
        newUsers[1] = address(0x2);

        for (uint256 i = 0; i < newUsers.length; i++) {
            users[id].add(newUsers[i]);
        }
        delete users[id];
        newUsers[0] = address(0x3);
        newUsers[1] = address(0x4);
        for (uint256 i = 0; i < newUsers.length; i++) {
            users[id].add(newUsers[i]);
        }
        bool exist = users[id].contains(address(0x1));
        if(exist) {
            emit log_string("address(0x1) exist");
        }
        exist = users[id].contains(address(0x2));
        if(exist) {
            emit log_string("address(0x2) exist");
        }
    }
/*
[PASS] test_deleteEnumerableSet() (gas: 174783)
Logs:
  address(0x1) exist
  address(0x2) exist
*/
```

## Impact

The deleted Users can still successfully call `LenderCommitmentForwarder.acceptCommitment` to get a loan.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L240-L246

## Tool used

Manual Review

## Recommendation

In order to clean an `EnumerableSet`, you can either remove all elements one by one or create a fresh instance using an array of `EnumerableSet`.

# Issue M-23: The calculation time methods of `calculateNextDueDate` and `_canLiquidateLoan` are inconsistent 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/78 

## Found by 
J4de

## Summary

The calculation time methods of `calculateNextDueDate` and `_canLiquidateLoan` are inconsistent

## Vulnerability Detail

```solidity
File: TellerV2.sol
 854     function calculateNextDueDate(uint256 _bidId)
 855         public
 856         view
 857         returns (uint32 dueDate_)
 858     {
 859         Bid storage bid = bids[_bidId];
 860         if (bids[_bidId].state != BidState.ACCEPTED) return dueDate_;
 861
 862         uint32 lastRepaidTimestamp = lastRepaidTimestamp(_bidId);
 863
 864         // Calculate due date if payment cycle is set to monthly
 865         if (bidPaymentCycleType[_bidId] == PaymentCycleType.Monthly) {
 866             // Calculate the cycle number the last repayment was made
 867             uint256 lastPaymentCycle = BPBDTL.diffMonths(
 868                 bid.loanDetails.acceptedTimestamp,
 869               
```

The `calculateNextDueDate` function is used by the borrower to query the date of the next repayment. Generally speaking, the borrower will think that as long as the repayment is completed at this point in time, the collateral will not be liquidated.

```solidity
File: TellerV2.sol
 953     function _canLiquidateLoan(uint256 _bidId, uint32 _liquidationDelay)
 954         internal
 955         view
 956         returns (bool)
 957     {
 958         Bid storage bid = bids[_bidId];
 959
 960         // Make sure loan cannot be liquidated if it is not active
 961         if (bid.state != BidState.ACCEPTED) return false;
 962
 963         if (bidDefaultDuration[_bidId] == 0) return false;
 964
 965         return (uint32(block.timestamp) -
 966             _liquidationDelay -
 967             lastRepaidTimestamp(_bidId) >
 968             bidDefaultDuration[_bidId]);
 969     }
```

However, when the `_canLiquidateLoan` function actually judges whether it can be liquidated, the time calculation mechanism is completely different from that of `calculateNextDueDate` function, which may cause that if the time point calculated by `_canLiquidateLoan` is earlier than the time point of `calculateNextDueDate` function, the borrower may also be liquidated in the case of legal repayment.

Borrowers cannot query the specific liquidation time point, but can only query whether they can be liquidated through the `isLoanDefaulted` function or `isLoanLiquidateable` function. When they query that they can be liquidated, they may have already been liquidated.

## Impact

Borrowers may be liquidated if repayments are made on time.

## Code Snippet

https://github.com/teller-protocol/teller-protocol-v2/blob/cb66c9e348cdf1fd6d9b0416a49d663f5b6a693c/packages/contracts/contracts/TellerV2.sol#L953-L969

## Tool used

Manual Review

## Recommendation

It is recommended to verify that the liquidation time point cannot be shorter than the repayment period and allow users to query the exact liquidation time point.


# Issue M-24: LenderCommitmentForwarder.updateCommitmentBorrowers() 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/26 

## Found by 
ravikiran.web3

## Summary
The implementation of updateCommitmentBorrowers function could lead to corrupt storage. In the commitment, the structure is maintaining a list of borrowersList, which is essentially an **EnumerableSetUpgradeable.AddressSet** mapped to the commitment id.

The problem is in the delete call on commitmentBorrowersList. The delete call can cause the storage to be corrupted and become unusable.

**Refer to the below documentation from OpenZeppelin**, [refer line 31 to 31 in the link]

https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/utils/structs/EnumerableSetUpgradeable.sol

## Vulnerability Detail
The way the list of borrowers for the commitment is done can corrupt the data.

## Impact
The list may become unreadable and conflict with the flow of the contract logic. The attempt to add element after deletion may fail.

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L240-L246

function updateCommitmentBorrowers(
        uint256 _commitmentId,
        address[] calldata _borrowerAddressList
    ) public commitmentLender(_commitmentId) {
        **delete commitmentBorrowersList[_commitmentId];**
        _addBorrowersToCommitmentAllowlist(_commitmentId, _borrowerAddressList);
    }

## Tool used

Manual Review
Code review done manually.

## Recommendation
Remove each element one by one using the remove function provided by the library. Or create a fresh instance of the array of EnumerableSet.



## Discussion

**ethereumdegen**

duplicate with issue 88 

# Issue M-25: Use safeMint instead of mint for ERC721 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/8 

## Found by 
Bauer, Dug, MohammedRizwan, Phantasmagoria, sayan\_, yy

## Summary
Use safeMint instead of mint for ERC721
## Vulnerability Detail
The msg.sender will be minted as a proof of staking NFT when  the `claimLoanNFT()` function is called.
However, if lender is a contract address that does not support ERC721, the NFT can be frozen in the contract.

As per the documentation of EIP-721:
A wallet/broker/auction application MUST implement the wallet interface if it will accept safe transfers.

Ref: https://eips.ethereum.org/EIPS/eip-721
As per the documentation of ERC721.sol by Openzeppelin
Ref: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L274-L285
```solidity
LenderManager.sol
   function registerLoan(uint256 _bidId, address _newLender)
        public
        override
        onlyOwner
    {
        _mint(_newLender, _bidId);
    }

```
## Impact
Users possibly lose their NFTs

## Code Snippet
https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderManager.sol#L45

## Tool used

Manual Review

## Recommendation
Use safeMint instead of mint to check received address support for ERC721 implementation.

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L262

# Issue M-26: lender could be forced to withdraw collateral even if he/she would rather wait for liquidation during default 

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/2 

## Found by 
0xGoodess, 0xbepresent, MiloTruck, Nyx, cducrest-brainbot, chaduke, ctf\_sec, duc, innertia

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



## Discussion

**ethereumdegen**

Thank you for the feedback i will review this with the team. 

