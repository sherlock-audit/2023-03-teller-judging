carrotsmuggler

high

# Un-liquidatable loans due to ERC721 tokens registered as ERC20 tokens

## Summary

Loans can be made un-liquidatable, if a borrower registers an NFT as an ERC20.

## Vulnerability Detail

Collaterals registered can be of three types, ERC20, ERC721 and ERC1155. The contract does not check if the collateral is of the correct type. This can be used to register an ERC721 token as an ERC20 token, by setting the tokenid in the amount parameter. This will confuse lenders, since they will see a valid nft and nftid is listed for collateral, and lenders will even be able to execute the loan transactions and have the escrow contract own the correct NFT. But this NFT is actually forever locked in the escrow and cannot be recovered, and thus cannot be liquidated.

Consider a malicious user deposits a collateral argument with the following setup.

```solidity
_collateralType: ERC20, // should actually be ERC721
_amount: tokenId,
_tokenId: tokenId,
_collateralAddress: NFTAddress;
```

If the tokenId is a low number and the user owns multiple NFTs of the same collection, the user will pass the `balanceOf` check in collateral Manager. The contract address will also show a legitimate NFT in the front end, providing confidence to the lender. When the lender accepts this bid, the call does not revert and actually transfers the NFT to the escrow correctly. This transfer is done in the `deployAndDeposit` function of collateralManager.

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L179-L199

The `deposit` function takes care of the transfer.

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/CollateralManager.sol#L320-L341

Here we can see that if an ERC721 is registered as an ERC20, the transfer still goes through since ERC721 implements the `transferFrom` function, as well as the `approve` function. As long as the variable `collateralInfo._amount` holds the tokenId, all these checks will pass. In the actual `depositAsset` function, NFT is transferred to the escrow.

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L118-L125

The `safeTransferFrom` function passes even without a return value and the NFT transfer takes place without a reverts. So the lender can even see that the escrow contract is the actual owner of the expected NFT, and does not see any issue with the position.

The issue arises during withdrawal. The `_withdrawCollateral` on the escrow function is called during either the repayment od the liquidation.

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L165-L170

Here we see that the contract tries to call the `transfer` function, but ERC721 tokens don't have a `transfer` function implemented. Thus this call will revert, reverting any liquidation calls, losing the lender the lent funds as well as the collateral.

## Impact

Stuck NFT in escrow contract, non-liquidatable loans, loss of funds for lender.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L165-L170

## Tool used

Foundry

## Recommendation

During withdrawal, also use the `safeTransferFrom` function from safeERC20 library. This would ensure that even if a malicious setup is used, the NFT will still be transferred out correctly.
