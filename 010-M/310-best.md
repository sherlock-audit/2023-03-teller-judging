ctf_sec

high

# LenderCommitmentForwarder#acceptCommitment can be frontrunned with updateCommitment

## Summary

LenderCommitmentForwarder#acceptCommitment can be frontrunned with updateCommitment

## Vulnerability Detail

the function updateCommitment can be runed at no cost

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

Suppose user A want to call LenderCommitmentForwarder#acceptCommitment

User B can just frontrun the transaction and call updateCommitment, maybe the use B can raise high interest rate, or shorten the duration and expiration and user A is forced to take the commitment in a suboptimal term.

## Impact

LenderCommitmentForwarder#acceptCommitment can be frontrunned with updateCommitment to force the user take suboptimal commitment term.

## Code Snippet

https://github.com/sherlock-audit/2023-03-teller/blob/main/teller-protocol-v2/packages/contracts/contracts/LenderCommitmentForwarder.sol#L208

## Tool used

Manual Review

## Recommendation

We recommend the protocol let the acceptCommitment
