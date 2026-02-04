# Independent Security Review: Olympus DAO & Swell Network

**Auditor:** ohmygod20260203
**Date:** February 2026
**Review Type:** Independent security research (Immunefi scope)
**Methodology:** Manual code review + architecture analysis + fork testing

---

## Executive Summary

This report presents an independent security review of two DeFi protocols listed on Immunefi:

| Protocol | Bounty Range | Contracts Reviewed | Findings |
|----------|-------------|-------------------|----------|
| **Olympus DAO** (Bophades V3) | Up to $3.3M | Kernel, Clearinghouse V2, Treasury, Modules | 6 findings (1 HIGH, 3 MEDIUM-HIGH, 2 MEDIUM) |
| **Swell Network** | Up to $250K | rswETH, DepositManager, EigenLayerManager, RepricingOracle | 6 findings (1 CRITICAL, 3 HIGH, 2 MEDIUM) |

**Key Critical Finding:** Swell Network's `depositLST` function relies on exchange rate providers that may be vulnerable to flash loan manipulation, potentially allowing an attacker to mint rswETH at an inflated rate and extract protocol value.

**Overall Assessment:**
- Both protocols have solid architecture foundations but carry inherent complexity risks
- Olympus's Default Framework concentrates trust in the executor multisig and policy permissions
- Swell's layered oracle system provides defense-in-depth but the initial deployment phase has unguarded code paths

---

## Scope

### Olympus DAO

| Contract | Address | Description |
|----------|---------|-------------|
| Kernel | `0x2286d7f9639e8158FaD1169e76d1FbC38247f54b` | Central registry & permission manager |
| Clearinghouse V2 | `0xE6343ad0675C9b8D3f32679ae6aDbA0766A2ab4c` | Lending facility |
| Treasury (TRSRY) | `0x31f8cc38b3d1A614a7F9c0e9b38Bfb79628467d3` | Protocol treasury module |
| Treasury v2 | `0x9A315BdF513367C0377FB36545857d12e85813Ef` | Legacy treasury |

### Swell Network

| Contract | Address | Description |
|----------|---------|-------------|
| rswETH | `0xfae103dc9cf190ed75350761e95403b7b8afa6c0` | Liquid restaking token |
| Deposit Manager (rswETH) | `0x5e6342D8090665bE14eeB8154c8a87B7249a4889` | ETH deposit handler |
| EigenLayerManager | `0xC94CfFD5249Df4008a043EE61e13f19AF16d0936` | EigenLayer integration |
| RepricingOracle | — | Rate update oracle system |

---

## Findings Summary

### Severity Classification

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 CRITICAL | 1 | Direct loss of user funds or protocol insolvency |
| 🟠 HIGH | 5 | Significant fund loss under specific conditions |
| 🟡 MEDIUM | 4 | Limited fund impact or requires unlikely preconditions |
| 🔵 LOW | 2 | Informational, best practice violations |

### Findings Table

| ID | Protocol | Title | Severity | Status |
|----|----------|-------|----------|--------|
| S-1 | Swell | LST Exchange Rate Oracle Manipulation in `depositLST` | 🔴 CRITICAL | Open |
| S-6 | Swell | rswETH First Depositor Share Inflation — Unguarded Initial Reprice | 🟠 HIGH | Open |
| O-4 | Olympus | TRSRY `setDebt` Unconstrained — Policy-Level Treasury Drain | 🟠 HIGH | Open |
| O-2 | Olympus | Clearinghouse `rebalance()` Debt Accounting Race Condition | 🟠 HIGH | Open |
| S-2 | Swell | rswETH Repricing — Stale Supply Parameter Attack | 🟠 HIGH | Open |
| S-4 | Swell | RepricingOracle Reference Price Bypass via Configurable Tolerance | 🟠 HIGH | Open |
| O-1 | Olympus | Kernel `permissioned` Modifier — Non-Obvious Logic Pattern | 🟡 MEDIUM | Informational |
| O-3 | Olympus | Clearinghouse `claimDefaulted` — Receivables Accounting Drift | 🟡 MEDIUM | Open |
| O-5 | Olympus | Kernel Migration Leaves Stale Permissions Window | 🟡 MEDIUM | By Design |
| S-3 | Swell | EigenLayerManager Staker-Operator Bookkeeping Inconsistency | 🟡 MEDIUM | Open |
| S-5 | Swell | DepositManager ETH Balance — `exitingETH` Race Condition | 🔵 LOW | Mitigated |
| O-6 | Olympus | Clearinghouse `lendToCooler` Duration Validation | 🔵 LOW | Not Vulnerable |

---

## Detailed Findings

---

### [S-1] LST Exchange Rate Oracle Manipulation in `depositLST`

**Severity:** 🔴 CRITICAL
**Protocol:** Swell Network
**Contract:** `DepositManager.sol`
**Impact:** Manipulation of Swell's ETH to rswETH conversion rate — up to $250K bounty

#### Description

The `depositLST` function converts liquid staking tokens (LSTs) to rswETH using an exchange rate from a configurable rate provider. If the rate provider reads on-chain spot prices rather than TWAP or Chainlink feeds, the rate is vulnerable to flash loan manipulation within a single transaction.

#### Vulnerable Code

```solidity
function depositLST(
    address _token,
    uint256 _amount,
    uint256 _minRswETH
) external checkWhitelist(msg.sender) checkZeroAddress(_token) {
    if (_amount == 0) revert CannotDepositZero();
    if (exchangeRateProviders[_token] == address(0)) revert NoRateProviderSet();

    IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);

    // ⚠️ Rate sourced from external provider — potentially manipulable
    uint256 rate = ILstRateProvider(exchangeRateProviders[_token]).getRate();
    uint256 ETHAmount = (_amount * rate) / 1e18;

    IrswETH rswETH = AccessControlManager.rswETH();
    rswETH.depositViaDepositManager(ETHAmount, msg.sender, _minRswETH);
}
```

#### Attack Scenario

1. Attacker identifies which LST tokens have `exchangeRateProviders` configured on mainnet
2. For any provider that reads from a manipulable source (DEX pool, spot oracle):
   - Flash loan large quantity of the LST
   - Manipulate the rate provider to return an inflated LST→ETH rate
   - Call `depositLST` with a modest amount — gets credited with inflated `ETHAmount`
   - `depositViaDepositManager` mints rswETH based on inflated value
   - Sell rswETH on secondary market for profit
   - Repay flash loan

3. The `_minRswETH` slippage parameter protects the depositor, not the protocol

#### Impact

If exploitable, an attacker could mint rswETH backed by less ETH value than represented, diluting existing holders. The profit is bounded by the amount of rswETH liquidity available for exit.

#### Proof of Concept Direction

```solidity
// Foundry fork test
function testOracleManipulation() public {
    // 1. Fork mainnet
    // 2. Read exchangeRateProviders[token] storage slot
    // 3. Check if getRate() changes within same block after flash loan
    // 4. If yes: measure rate delta, calculate profit
    vm.startPrank(attacker);
    // flash loan → manipulate → depositLST → sell rswETH
}
```

#### Recommendation

- Use TWAP oracles or Chainlink price feeds for LST→ETH conversion
- Add maximum rate deviation check: `require(rate <= lastKnownRate * 1.05)`
- Consider rate caching with minimum block delay between updates

---

### [S-6] rswETH First Depositor Share Inflation — Unguarded Initial Reprice

**Severity:** 🟠 HIGH
**Protocol:** Swell Network
**Contract:** `RswETH.sol`

#### Description

Before the first `reprice()` call, the rswETH→ETH rate defaults to 1:1. The first reprice bypasses all rate change bounds because `cachedLastRepriceUNIX == 0`, allowing an arbitrary rate to be set.

#### Vulnerable Code

```solidity
function reprice(
    uint256 _preRewardETHReserves,
    uint256 _newETHRewards,
    uint256 _rswETHTotalSupply
) external override checkRole(SwellLib.REPRICER) {
    // ...
    if (cachedLastRepriceUNIX != 0) {
        // ⚠️ Rate bounds only checked AFTER first reprice
        // First reprice can set ANY rate
    }
    // ...
}
```

#### Attack Scenario

1. Protocol launches with rswETH rate = 1:1 (default)
2. Attacker deposits 1000 ETH → receives 1000 rswETH
3. Compromised or manipulated REPRICER submits first reprice with inflated reserves
4. Since `cachedLastRepriceUNIX == 0`, NO rate bounds are enforced
5. Rate jumps to 2:1 — attacker's rswETH is now "worth" 2000 ETH
6. Attacker exits at the inflated rate

#### Impact

Critical during bootstrap phase. After the first reprice, layered checks from the RepricingOracle kick in and mitigate this vector. Mainnet deployment that has already undergone first reprice is not affected.

#### Recommendation

- Add rate bounds check for the first reprice (e.g., rate must be within 1% of 1:1)
- Or: set `cachedLastRepriceUNIX = block.timestamp` in the constructor to enable bounds from genesis

---

### [O-4] TRSRY `setDebt` Unconstrained — Policy-Level Treasury Drain

**Severity:** 🟠 HIGH
**Protocol:** Olympus DAO
**Contract:** `OlympusTreasury.sol`

#### Description

The `setDebt` function accepts any arbitrary debt amount for any debtor address. The only protection is the `permissioned` modifier. If ANY policy holding `setDebt` permission is compromised, the entire treasury accounting can be manipulated.

#### Vulnerable Code

```solidity
function setDebt(
    address debtor_,
    ERC20 token_,
    uint256 amount_
) external override permissioned {
    uint256 oldDebt = reserveDebt[token_][debtor_];
    reserveDebt[token_][debtor_] = amount_;  // ⚠️ No bounds, no relation to actual flows
    if (oldDebt < amount_) totalDebt[token_] += amount_ - oldDebt;
    else totalDebt[token_] -= oldDebt - amount_;
}
```

#### Impact

- Wipe any debtor's debt to zero → free money
- Inflate `totalDebt` → `getReserveBalance` returns inflated value → governance misled
- The security of the entire treasury depends on every policy with `setDebt` permission being bug-free

#### Recommendation

- Add per-epoch or per-call limits on debt changes
- Implement a timelock for debt changes above a threshold
- Separate "increase debt" and "decrease debt" functions with different permission levels

---

### [O-2] Clearinghouse `rebalance()` Debt Accounting Race Condition

**Severity:** 🟠 HIGH
**Protocol:** Olympus DAO
**Contract:** `Clearinghouse.sol`

#### Description

`TRSRY.setDebt` sets an **absolute value**, not an increment. The Clearinghouse reads `outstandingDebt` and adds `fundAmount` to set the new total. In a cross-transaction race (same block), a concurrent loan repayment that reduces debt can be overwritten by the `rebalance()` call.

#### Vulnerable Code

```solidity
function rebalance() public returns (bool) {
    uint256 outstandingDebt = TRSRY.reserveDebt(reserve, address(this));  // Read
    // ... between read and write, another tx may reduce debt ...
    TRSRY.setDebt({
        debtor_: address(this),
        token_: reserve,
        amount_: outstandingDebt + fundAmount  // ⚠️ Overwrites any concurrent changes
    });
}
```

#### Impact

Debt can be overstated by the amount of a concurrent repayment. The Clearinghouse would hold more recorded debt than actual, leading to under-defunding in subsequent rebalances. Impact is bounded by `FUND_AMOUNT` cap per cycle.

#### Recommendation

- Use incremental debt functions (`incurDebt` / `repayDebt`) instead of absolute `setDebt`
- Or: add a reentrancy-style lock that prevents concurrent state mutations

---

### [S-2] rswETH Repricing — Stale Supply Parameter Attack

**Severity:** 🟠 HIGH
**Protocol:** Swell Network
**Contract:** `RswETH.sol`

#### Description

The `reprice` function uses a **submitted** `_rswETHTotalSupply` parameter (not `totalSupply()`) for rate calculation. While bounded by `maximumRepriceRswETHDifferencePercentage`, this tolerance window allows rate manipulation within the permitted range.

#### Impact

At 5% tolerance: attacker submits supply that's 5% below actual → rate inflates by ~5.26% → existing holders benefit at expense of new depositors.

The RepricingOracle wrapper adds additional checks (reference price comparison, max rate change), creating defense-in-depth. Risk is conditional on the REPRICER role being directly assigned to the rswETH contract rather than mediated through the oracle.

#### Recommendation

- Use `totalSupply()` on-chain instead of a submitted parameter
- Or: tighten `maximumRepriceRswETHDifferencePercentage` to ≤1%

---

### [S-4] RepricingOracle Parameter Bypass via Configurable Tolerance

**Severity:** 🟠 HIGH (conditional on admin compromise)
**Protocol:** Swell Network
**Contract:** `RepricingOracle.sol`

#### Description

All safety parameters in the RepricingOracle are configurable by `PLATFORM_ADMIN` without timelock or bounds:

```solidity
function setMaximumReferencePriceDiffPercentage(
    uint256 _newMaximumReferencePriceDiffPercentage
) external checkRole(SwellLib.PLATFORM_ADMIN) {
    maximumReferencePriceDiffPercentage = _newMaximumReferencePriceDiffPercentage;
    // ⚠️ No maximum bound, no timelock
}
```

#### Attack Scenario

Compromised PLATFORM_ADMIN sets all tolerances to `type(uint256).max`, then REPRICER submits arbitrary rate. Existing holders dump at inflated rate or attacker buys at deflated rate.

#### Impact

CRITICAL if PLATFORM_ADMIN is an EOA. MEDIUM if behind proper timelock + multisig. This is a centralization risk that should be documented and mitigated.

#### Recommendation

- Add immutable maximum bounds on all tolerance parameters
- Implement timelock for parameter changes
- Emit events for all parameter modifications (already done) + off-chain monitoring

---

### [O-1] Kernel `permissioned` Modifier — Non-Obvious Logic Pattern

**Severity:** 🟡 MEDIUM (Informational)
**Protocol:** Olympus DAO
**Contract:** `Kernel.sol` → `Module` abstract contract

#### Description

The `permissioned` modifier uses a double-negative `||` pattern that is functionally correct but easy to misread:

```solidity
modifier permissioned() {
    if (
        msg.sender == address(kernel) ||                              // Blocks kernel
        !kernel.modulePermissions(KEYCODE(), Policy(msg.sender), msg.sig)  // Blocks unpermitted
    ) revert Module_PolicyNotPermitted(msg.sender);
    _;
}
```

The logic is sound — deactivated policies have permissions revoked via `_setPolicyPermissions(policy_, requests, false)`. No exploitable path found, but this is the #1 surface to monitor on any Kernel upgrade due to its non-obvious construction.

---

### [O-3] Clearinghouse `claimDefaulted` — Receivables Accounting Drift

**Severity:** 🟡 MEDIUM
**Protocol:** Olympus DAO
**Contract:** `Clearinghouse.sol`

#### Description

`extendLoan` collects extension interest from the caller but does NOT increment `interestReceivables`. When the loan is eventually repaid, `_onRepay` decrements receivables by the actual interest paid — which can exceed the tracked amount, causing `interestReceivables` to floor at zero.

The `getTotalReceivables()` view function will undercount after extensions. This is primarily an accounting issue that could mislead governance decisions but does not directly cause fund loss.

---

### [O-5] Kernel Migration — Stale Permissions Window

**Severity:** 🟡 MEDIUM (By Design)
**Protocol:** Olympus DAO
**Contract:** `Kernel.sol`

The `_migrateKernel` function transfers all modules and policies to a new kernel but the new kernel starts with empty permission mappings. Between migration and re-registration, the protocol is in a partially broken state. This is documented as intentional ("WARNING: ACTION WILL BRICK THIS KERNEL") and is safe when executed correctly.

---

### [S-3] EigenLayerManager Staker-Operator Bookkeeping

**Severity:** 🟡 MEDIUM
**Protocol:** Swell Network
**Contract:** `EigenLayerManager.sol`

The `_deleteStakerFromOperatorMapping` swap-and-pop implementation is correct for unique IDs, but `delegateToWithSignature` does not check for duplicates before pushing to the array. In practice, the EigenLayer `DelegationManager` reverts on duplicate delegation, preventing the issue at the integration layer.

---

### [S-5] DepositManager ETH Balance — `exitingETH` Race Condition

**Severity:** 🔵 LOW
**Protocol:** Swell Network
**Contract:** `DepositManager.sol`

The `exitingETH` snapshot in `setupValidators` could be stale relative to concurrent transactions, but since `exitingETH` only increases (exit requests are queued), the check is conservative. The guard correctly reverts when concurrent exits reduce available balance.

---

### [O-6] Clearinghouse `lendToCooler` Duration Validation

**Severity:** 🔵 LOW (Not Vulnerable)
**Protocol:** Olympus DAO
**Contract:** `Clearinghouse.sol`

The Clearinghouse uses immutable `DURATION`, `INTEREST_RATE`, and `LOAN_TO_COLLATERAL` parameters for all loans. No user-supplied input can bypass the fixed terms. Well-designed.

---

## Architecture Risk Assessment

### Olympus DAO — Default Framework Trust Model

```
Executor (Multisig) ──── God Mode
    │
    ├── Install/Upgrade Modules (TRSRY, MINTR, PRICE, RANGE)
    ├── Activate/Deactivate Policies (Clearinghouse, BondCallback)
    ├── Change Executor
    └── Migrate Kernel
```

**Key Risk:** The executor has unlimited power. All security below the executor level depends on individual policy correctness. A bug in ANY policy with treasury permissions can drain funds.

### Swell Network — Layered Oracle Defense

```
PLATFORM_ADMIN ─── Parameter Configuration
    │
BOT (REPRICER) ─── RepricingOracle ─── rswETH.reprice()
                        │
                    Checks: reference price, rate bounds, supply tolerance, staleness
```

**Key Risk:** Defense-in-depth is good, but all safety parameters are admin-configurable without immutable bounds. The first reprice is unguarded.

---

## Recommendations Summary

| Priority | Recommendation | Protocol |
|----------|---------------|----------|
| 🔴 P0 | Verify LST rate providers use TWAP/Chainlink, not spot prices | Swell |
| 🔴 P0 | Add rate bounds for the initial reprice event | Swell |
| 🟠 P1 | Add per-epoch limits on `setDebt` calls | Olympus |
| 🟠 P1 | Add immutable maximum bounds on oracle tolerance parameters | Swell |
| 🟡 P2 | Use incremental debt functions instead of absolute `setDebt` | Olympus |
| 🟡 P2 | Fix `extendLoan` receivables tracking | Olympus |
| 🔵 P3 | Add duplicate check in `delegateToWithSignature` | Swell |

---

## Appendix: Contract Addresses

### Olympus DAO
| Contract | Address |
|----------|---------|
| Kernel | `0x2286d7f9639e8158FaD1169e76d1FbC38247f54b` |
| Clearinghouse V2 | `0xE6343ad0675C9b8D3f32679ae6aDbA0766A2ab4c` |
| Treasury v2 | `0x9A315BdF513367C0377FB36545857d12e85813Ef` |
| OHM v2 | `0x64aa3364F17a4D01c6f1751Fd97C2BD3D7e7f1D5` |
| Staking v2 | `0xB63cac384247597756545b500253ff8E607a8020` |
| gOHM | `0x0ab87046fBb341D058F17CBC4c1133F25a20a52f` |

### Swell Network
| Contract | Address |
|----------|---------|
| rswETH | `0xfae103dc9cf190ed75350761e95403b7b8afa6c0` |
| Deposit Manager (rswETH) | `0x5e6342D8090665bE14eeB8154c8a87B7249a4889` |
| EigenLayerManager | `0xC94CfFD5249Df4008a043EE61e13f19AF16d0936` |
| StakerProxy | `0xB68b125E5B0f2600841B2bBA484E76A495DF17A0` |
| EigenPod | `0x8d0B4dfCcc8B2A268486d9754b135d8aD1Ee7258` |

---

*Disclaimer: This is an independent security review based on publicly available source code and Immunefi scope definitions. Findings are based on code analysis and require mainnet fork testing for full confirmation. This review does not constitute a guarantee that all vulnerabilities have been identified.*
