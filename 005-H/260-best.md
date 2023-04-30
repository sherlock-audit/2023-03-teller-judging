0x52

high

# Malicious user can abuse UpdateCommitment to create commitments for other users

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