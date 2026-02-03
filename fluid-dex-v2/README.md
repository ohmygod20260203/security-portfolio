# Fluid DEX V2 - Sherlock Audit Contest Submissions

**Contest:** Fluid DEX V2 (Instadapp) - Sherlock $150K Bounty Pool  
**Deadline:** February 19, 2026  
**Commit:** `904c2989aa404ecb9cf75eb1efa1a5fa526007b0`

## Findings

### HIGH-1: Fee Growth Global Overflow Bricks Pool via BigMath Revert
- **File:** `HIGH-1-FeeGrowthBigMathOverflow.md`
- **Severity:** HIGH
- **Impact:** Permanent DoS - all swaps revert, LP tokens locked
- **Root Cause:** `BigMathMinified.toBigNumber()` reverts when fee growth exceeds max representable value; `fromBigNumber()` silently truncates values needing >256 bits
- **PoC:** `poc/FeeGrowthBigMathOverflow.t.sol` (5 tests, all pass)

### HIGH-2: Unchecked Fee Growth uint256 Overflow Corrupts LP Fee Accounting  
- **File:** `HIGH-2-UncheckedFeeGrowthOverflow.md`
- **Severity:** HIGH  
- **Impact:** Silent fee corruption, LP fee theft/loss, potential protocol insolvency
- **Root Cause:** Fee growth accumulated in `unchecked` block wraps around uint256, corrupting all fee tracking
- **PoC:** `poc/UncheckedFeeGrowthOverflow.t.sol` (7 tests, all pass)

## Running the PoCs

```bash
cd poc/
forge test -vvv
```

**Results:**
```
Ran 12 tests for 2 test suites
[PASS] All 12 tests pass
- FeeGrowthBigMathOverflowTest: 5 passed
- UncheckedFeeGrowthOverflowTest: 7 passed
```

## Key Finding Relationship

HIGH-1 and HIGH-2 are related but distinct:
- **HIGH-1**: The BigMath encoding has a max representable value. When fee growth exceeds this (via `fromBigNumber` silent overflow at exponent >= 183), data is silently corrupted.
- **HIGH-2**: The `unchecked` accumulation can wrap uint256, causing fee growth to drop to near-zero. This corrupts all fee accounting and causes tick crossing to revert (checked subtraction).
- **Combined effect**: The uint256 overflow (HIGH-2) can prevent the BigMath revert (HIGH-1) by wrapping to a small value, but causes silent corruption - which is worse than a detectable revert.

## Affected Code

Both findings target the same code path in `swapModuleInternals.sol`:
- `_swapIn()` and `_swapOut()` fee growth accumulation (unchecked block)
- `toBigNumber()` / `fromBigNumber()` in `bigMathMinified.sol`
- Fee growth storage/reload cycle in dex variables packing
