HonorLt

medium

# Escrow does not support native asset

## Summary

The escrow deposit function can receive native assets but there is no support for it.

## Vulnerability Detail

`depositAsset` is `payable` even though the native asset collateral type is not supported:

```solidity
    function depositAsset(
        CollateralType _collateralType,
        address _collateralAddress,
        uint256 _amount,
        uint256 _tokenId
    ) external payable virtual onlyOwner
```

## Impact

Native assets sent to this function will be lost because the Escrow does not have a function to withdraw it.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/escrow/CollateralEscrowV1.sol#L56

## Tool used

Manual Review

## Recommendation

Remove `payable` or add rescue functions, or wrap native asset into ERC20 token (e.g. ETH <-> WETH).
