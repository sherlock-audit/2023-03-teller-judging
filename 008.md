Bauer

medium

# Use safeMint instead of mint for ERC721

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
