chaduke

medium

# _withdrawCollateral() withdraws the wrong amount of ERC 20 tokens.

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
