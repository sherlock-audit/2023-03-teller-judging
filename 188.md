T1MOH

medium

# The submitBid transaction lack of expiration timestamp check

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
