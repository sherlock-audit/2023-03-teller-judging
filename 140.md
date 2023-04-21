ck

medium

# ERC721 tokens can be permanently lost if recipient is a contract that doesn't implement `onERC721Received`

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