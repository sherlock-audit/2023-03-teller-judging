helpMePlease

high

# No condition for erc721 and erc1155 in validateCommitment

## Summary
There isn't any condition for erc721 and erc1155 to valide the commitment in the `validateCommitment` function.

## Vulnerability Detail
in the function https://github.com/teller-protocol/teller-protocol-v2/blob/8f090356c413968600baafc0a51d99900fad9f93/packages/contracts/contracts/LenderCommitmentForwarder.sol#L137 there isn't any kind of condition for `erc721` and `erc1155`, so there won't be validation of `erc721` and `erc1155`

## Impact
The code won't be able to validate if the commitment is ERC721 and ERC1155 so it won't be validated

## Code Snippet
```solidity
 function validateCommitment(Commitment storage _commitment) internal {
        require(
            _commitment.expiration > uint32(block.timestamp), 
            "expired commitment"
        );
        require(
            _commitment.maxPrincipal > 0,
            "commitment principal allocation 0"
        );

        if (_commitment.collateralTokenType != CommitmentCollateralType.NONE) {
            require(
                _commitment.maxPrincipalPerCollateralAmount > 
                "commitment collateral ratio 0"
            );

            if (
                _commitment.collateralTokenType ==
                CommitmentCollateralType.ERC20
            ) {
                require(
                    _commitment.collateralTokenId == 0,
                    "commitment collateral token id must be 0 for ERC20"
                ); //@audit - where are the conditions for erc721 and erc1155
            }
        }
    }
```

## Tool used

Manual Review

## Recommendation
Add the require conditon for ERC721 and ERC1155