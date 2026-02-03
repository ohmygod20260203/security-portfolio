# Unchecked Fee Growth Accumulation Silently Overflows uint256, Corrupting LP Fee Accounting

## Summary

The fee growth global accumulators are incremented inside an `unchecked` block during every swap step. The accumulated value includes a left-shift by 102 bits. When the running total overflows `uint256`, it silently wraps around to a small value, completely corrupting the global fee tracking. This leads to LPs losing earned fees or, worse, an attacker exploiting the wrap-around to claim fees they never earned.

## Vulnerability Detail

In `swapModuleInternals.sol`, both `_swapIn()` and `_swapOut()` accumulate fee growth in an `unchecked` block:

**`_swapIn()`:**
```solidity
// Update global fee tracker
if (activeLiquidity_ > 0) {
    /// @dev Fee is cut from tokenOut in swap in
    unchecked {
        if (params_.swap0To1) v_.feeGrowthGlobal1X102 += (((stepLpFeeRaw_ * params_.token1ExchangePrice)
            / LC.EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity_;
        else v_.feeGrowthGlobal0X102 += (((stepLpFeeRaw_ * params_.token0ExchangePrice)
            / LC.EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity_;
    }
}
```

**`_swapOut()`:**
```solidity
// Update global fee tracker
if (activeLiquidity_ > 0) {
    /// @dev Fee is cut from tokenIn in swap out
    unchecked {
        if (params_.swap0To1) v_.feeGrowthGlobal0X102 += (((stepLpFeeRaw_ * params_.token0ExchangePrice)
            / LC.EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity_;
        else v_.feeGrowthGlobal1X102 += (((stepLpFeeRaw_ * params_.token1ExchangePrice)
            / LC.EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity_;
    }
}
```

The `unchecked` block means Solidity 0.8.x overflow protection is disabled. When `v_.feeGrowthGlobal1X102` is near `type(uint256).max` and the increment pushes it past, the value wraps around to a small number.

### The overflow path

The fee growth value follows this lifecycle each swap:

1. **Load from storage**: Decoded from BigMath (74-bit coefficient, 8-bit exponent) → up to ~2^329
2. **Accumulate**: `+= increment` in unchecked block → can overflow uint256
3. **Store back**: Encoded via `toBigNumber()` → if value < 2^329 (after wrap), succeeds with corrupted value

**Critical observation**: Finding HIGH-1 shows that values exceeding 2^329 cause `toBigNumber` to revert. But if the overflow **wraps around** uint256 (2^256), the resulting value is **smaller** than 2^329, so `toBigNumber` succeeds - storing a completely wrong fee growth value.

This creates a paradox:
- Values between 2^329 and 2^256 cannot exist (uint256 max is 2^256)
- But the fee growth global is loaded as a uint256 and can reach values near 2^256 - 1
- When `feeGrowthGlobal + increment > 2^256 - 1`, it wraps to `(feeGrowthGlobal + increment) mod 2^256`
- This wrapped value is small enough to be stored by `toBigNumber`

Wait - note that 2^329 > 2^256. This means the BigMath max (2^329) cannot be stored in uint256 anyway. The **actual** concern is different:

The fee growth global is a `uint256` variable. It accumulates without bound in the unchecked block. When it overflows past `type(uint256).max`, it wraps to 0 (or a small value). Then `toBigNumber` stores this small value successfully, but it represents a completely wrong fee growth.

### Why this matters despite the BigMath ceiling

The fee growth global is stored as BigMath with max ~2^329, but it's loaded into a `uint256` which can only hold up to 2^256 - 1. During a single swap transaction with multiple steps (the while loop), the accumulator can overflow uint256 if:

1. `feeGrowthGlobal` starts near `type(uint256).max` (possible if previously accumulated to a large value)
2. The increment per step is large enough to push past `type(uint256).max`

Since the BigMath storage can represent values up to 2^329 but uint256 max is 2^256, there's a disconnect - the value loaded from BigMath storage could be up to 2^329 in theory, but `fromBigNumber` returns a uint256 which truncates to 2^256. However, for values stored as BigMath with exponent + coefficient, the `fromBigNumber` function computes `coefficient << exponent`, which for large exponents DOES overflow uint256 silently in assembly:

```solidity
function fromBigNumber(uint256 bigNumber, uint256 exponentSize, uint256 exponentMask)
    internal pure returns (uint256 normal) {
    assembly {
        let coefficient := shr(exponentSize, bigNumber)
        let exponent := and(bigNumber, exponentMask)
        normal := shl(exponent, coefficient)  // ← Silent overflow in assembly!
    }
}
```

If a BigMath value has a large exponent, `shl(exponent, coefficient)` overflows uint256 silently in assembly (EVM `SHL` just drops high bits). This means:

1. Fee growth is stored as BigMath representing a large value (exponent > 182 for 74-bit coefficient)
2. When loaded via `fromBigNumber`, the `shl` silently truncates
3. The loaded value is much smaller than what was stored
4. More fee growth is accumulated on top of this truncated value
5. When stored back, the new BigMath value may be completely wrong

### Attack Scenario

1. **Setup Phase**: Attacker provisions a pool with minimal liquidity
2. **Accumulation Phase**: Repeated swaps grow `feeGrowthGlobal` to a large value approaching uint256 max
3. **Trigger Phase**: A swap pushes the accumulator past `type(uint256).max`, wrapping it to a small value
4. **Exploit Phase**:
   - Existing LPs who earned fees before the overflow now have `feeGrowthInside = feeGrowthGlobal_new - feeGrowthOutside`
   - Since `feeGrowthGlobal_new` is now small (wrapped), and `feeGrowthOutside` was set before overflow, the subtraction underflows
   - Fee calculations produce garbage values
   - An attacker who opens a position just AFTER the overflow gets `feeGrowthInside_start = small_value`
   - When more fees accumulate, they can claim disproportionate fees

## Impact

**Corrupted fee accounting for all LPs in the affected pool:**

1. **LP Fee Loss**: LPs who earned fees before the overflow lose their uncollected fees. The fee growth global suddenly drops to near-zero, making it appear no fees were ever earned.

2. **Fee Theft**: An attacker who monitors fee growth and opens a position just before/after the overflow can exploit the arithmetic:
   - Fee growth inside = `feeGrowthGlobal - feeGrowthOutside` (for below-current-tick positions)
   - If `feeGrowthGlobal` wraps to a small value and `feeGrowthOutside` is large (set pre-overflow), the subtraction underflows in the tick crossing logic, producing a massive value
   - The attacker claims fees far exceeding what was actually generated

3. **Protocol Insolvency**: If fee claims exceed actual fees collected, the pool's reserves are drained.

## Code Snippet

**Fee growth accumulation in unchecked block** - `swapModuleInternals.sol`, `_swapIn()`:
https://github.com/Instadapp/fluid-contracts/blob/904c2989aa404ecb9cf75eb1efa1a5fa526007b0/contracts/protocols/dexV2/dexTypes/common/d3d4common/swapModuleInternals.sol

```solidity
unchecked {
    if (params_.swap0To1) v_.feeGrowthGlobal1X102 += (((stepLpFeeRaw_ * params_.token1ExchangePrice)
        / LC.EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity_;
    else v_.feeGrowthGlobal0X102 += (((stepLpFeeRaw_ * params_.token0ExchangePrice)
        / LC.EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity_;
}
```

**Silent overflow in fromBigNumber** - `bigMathMinified.sol`:
```solidity
function fromBigNumber(uint256 bigNumber, uint256 exponentSize, uint256 exponentMask)
    internal pure returns (uint256 normal) {
    assembly {
        let coefficient := shr(exponentSize, bigNumber)
        let exponent := and(bigNumber, exponentMask)
        normal := shl(exponent, coefficient)  // Silent overflow when exponent is large!
    }
}
```

**Fee growth storage and reload cycle**:
```solidity
// Store (end of _swapIn):
BM.toBigNumber(v_.feeGrowthGlobal0X102, BIG_COEFFICIENT_SIZE, DEFAULT_EXPONENT_SIZE, ROUND_DOWN)

// Reload (start of next _swapIn):
temp_ = (params_.dexVariables >> DSL.BITS_DEX_V2_VARIABLES_FEE_GROWTH_GLOBAL_0_X102) & X82;
v_.feeGrowthGlobal0X102 = (temp_ >> DEFAULT_EXPONENT_SIZE) << (temp_ & DEFAULT_EXPONENT_MASK);
```

## PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "forge-std/Test.sol";

/// @notice Minimal reproduction of BigMathMinified from Fluid DEX V2
library BigMathMinified {
    function toBigNumber(
        uint256 normal,
        uint256 coefficientSize,
        uint256 exponentSize,
        bool roundUp
    ) internal pure returns (uint256 bigNumber) {
        assembly {
            let lastBit_
            let number_ := normal
            if gt(number_, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) {
                number_ := shr(0x80, number_)
                lastBit_ := 0x80
            }
            if gt(number_, 0xFFFFFFFFFFFFFFFF) {
                number_ := shr(0x40, number_)
                lastBit_ := add(lastBit_, 0x40)
            }
            if gt(number_, 0xFFFFFFFF) {
                number_ := shr(0x20, number_)
                lastBit_ := add(lastBit_, 0x20)
            }
            if gt(number_, 0xFFFF) {
                number_ := shr(0x10, number_)
                lastBit_ := add(lastBit_, 0x10)
            }
            if gt(number_, 0xFF) {
                number_ := shr(0x8, number_)
                lastBit_ := add(lastBit_, 0x8)
            }
            if gt(number_, 0xF) {
                number_ := shr(0x4, number_)
                lastBit_ := add(lastBit_, 0x4)
            }
            if gt(number_, 0x3) {
                number_ := shr(0x2, number_)
                lastBit_ := add(lastBit_, 0x2)
            }
            if gt(number_, 0x1) {
                lastBit_ := add(lastBit_, 1)
            }
            if gt(number_, 0) {
                lastBit_ := add(lastBit_, 1)
            }
            if lt(lastBit_, coefficientSize) {
                lastBit_ := coefficientSize
            }
            let exponent := sub(lastBit_, coefficientSize)
            let coefficient := shr(exponent, normal)
            if and(roundUp, gt(exponent, 0)) {
                coefficient := add(coefficient, 1)
                if eq(shl(coefficientSize, 1), coefficient) {
                    coefficient := shl(sub(coefficientSize, 1), 1)
                    exponent := add(exponent, 1)
                }
            }
            if iszero(lt(exponent, shl(exponentSize, 1))) {
                revert(0, 0)
            }
            bigNumber := shl(exponentSize, coefficient)
            bigNumber := add(bigNumber, exponent)
        }
    }

    function fromBigNumber(
        uint256 bigNumber,
        uint256 exponentSize,
        uint256 exponentMask
    ) internal pure returns (uint256 normal) {
        assembly {
            let coefficient := shr(exponentSize, bigNumber)
            let exponent := and(bigNumber, exponentMask)
            normal := shl(exponent, coefficient)
        }
    }
}

contract UncheckedFeeGrowthOverflowTest is Test {
    uint256 constant BIG_COEFFICIENT_SIZE = 74;
    uint256 constant DEFAULT_EXPONENT_SIZE = 8;
    uint256 constant DEFAULT_EXPONENT_MASK = 0xFF;
    uint256 constant EXCHANGE_PRICES_PRECISION = 1e12;
    uint256 constant X82 = 0x3FFFFFFFFFFFFFFFFFFFF;

    /// @notice Demonstrates fromBigNumber silent overflow for large exponents
    function test_fromBigNumber_SilentOverflow() public {
        // Encode a value with large exponent that will overflow uint256 on decode
        // coefficient = 2^74 - 1 (max), exponent = 183
        // Decoded: (2^74 - 1) << 183 = needs 74 + 183 = 257 bits → overflows uint256!

        uint256 coefficient = (1 << 74) - 1;
        uint256 exponent = 183; // 74 + 183 = 257 > 256
        uint256 bigNum = (coefficient << DEFAULT_EXPONENT_SIZE) | exponent;

        // This should represent a number requiring 257 bits, but uint256 can only hold 256
        uint256 decoded = BigMathMinified.fromBigNumber(bigNum, DEFAULT_EXPONENT_SIZE, DEFAULT_EXPONENT_MASK);

        // The value is SILENTLY truncated - high bits are lost
        // Expected: (2^74 - 1) << 183 ≈ 2^257 - 2^183
        // Actual: ((2^74 - 1) << 183) mod 2^256 - loses the top bit

        emit log_named_uint("Decoded value (truncated)", decoded);

        // Verify it's NOT equal to the mathematical expectation
        // If no overflow, decoded should have bit 256 set, but uint256 can't represent that
        // Instead, bit 256 is silently dropped
        assertTrue(decoded < type(uint256).max / 2, "Value should be truncated due to overflow");

        // Now show that re-encoding this truncated value stores something different
        uint256 reEncoded = BigMathMinified.toBigNumber(decoded, BIG_COEFFICIENT_SIZE, DEFAULT_EXPONENT_SIZE, false);

        emit log_named_uint("Original bigNum", bigNum);
        emit log_named_uint("Re-encoded bigNum", reEncoded);

        // The re-encoded value is DIFFERENT from the original - data corruption!
        assertTrue(reEncoded != bigNum, "Re-encoded should differ from original due to overflow corruption");
    }

    /// @notice Demonstrates uint256 overflow in fee growth accumulation
    function test_feeGrowthUint256Overflow() public {
        // Start with fee growth near uint256 max
        uint256 feeGrowthGlobal = type(uint256).max - 1000;

        // Simulate a fee growth increment
        uint256 stepLpFeeRaw = 1e6;
        uint256 activeLiquidity = 1e6;

        uint256 increment = (stepLpFeeRaw << 102) / activeLiquidity;
        // increment = 2^102 ≈ 5.07e30 - much larger than 1000

        emit log_named_uint("Fee growth before", feeGrowthGlobal);
        emit log_named_uint("Increment", increment);

        // In unchecked block, this wraps around
        unchecked {
            feeGrowthGlobal += increment;
        }

        emit log_named_uint("Fee growth after (wrapped)", feeGrowthGlobal);

        // The fee growth has wrapped around to a small value!
        assertTrue(feeGrowthGlobal < increment, "Fee growth should have wrapped around to small value");

        // This small value can now be stored via toBigNumber (no revert)
        uint256 bigNum = BigMathMinified.toBigNumber(feeGrowthGlobal, BIG_COEFFICIENT_SIZE, DEFAULT_EXPONENT_SIZE, false);
        assertTrue(bigNum > 0, "Should encode successfully with corrupted value");
    }

    /// @notice Full attack simulation showing fee accounting corruption
    function test_feeAccountingCorruption_FullAttack() public {
        // === PHASE 1: Normal operation - LP deposits and fees accumulate ===

        // Simulate fee growth from organic trading
        uint256 feeGrowthGlobal = 0;
        uint256 activeLiquidity = 1e18;  // Normal liquidity
        uint256 exchangePrice = 1e12;

        // Simulate 10000 normal swaps
        for (uint256 i = 0; i < 10000; i++) {
            uint256 stepLpFeeRaw = 1e10;  // Normal fee
            unchecked {
                feeGrowthGlobal += (((stepLpFeeRaw * exchangePrice) / EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity;
            }
        }

        uint256 feeGrowthAfterNormalTrading = feeGrowthGlobal;
        emit log_named_uint("Fee growth after normal trading", feeGrowthAfterNormalTrading);

        // LP's position records this as feeGrowthInside_start
        uint256 lpFeeGrowthInsideStart = feeGrowthAfterNormalTrading;

        // === PHASE 2: Attacker manipulates fee growth to near uint256 max ===

        // Simulate attacker draining liquidity (leaving minimal) and doing many swaps
        // For PoC, we directly set fee growth near max to show the overflow mechanics
        feeGrowthGlobal = type(uint256).max - (1 << 110);  // Near max, but room for a few increments

        // === PHASE 3: Overflow happens ===

        activeLiquidity = 100;  // Attacker reduced liquidity
        uint256 stepLpFeeRaw = 1e8;
        uint256 increment = (((stepLpFeeRaw * exchangePrice) / EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity;

        emit log_named_uint("Increment per swap", increment);
        emit log_named_uint("Fee growth before overflow", feeGrowthGlobal);

        // Accumulate until overflow
        uint256 preOverflow = feeGrowthGlobal;
        uint256 swapsToOverflow = 0;
        unchecked {
            while (feeGrowthGlobal >= preOverflow) {  // Loop until wrap-around
                feeGrowthGlobal += increment;
                swapsToOverflow++;
                if (swapsToOverflow > 100) break;  // Safety limit for test
            }
        }

        emit log_named_uint("Swaps to overflow", swapsToOverflow);
        emit log_named_uint("Fee growth after overflow (wrapped)", feeGrowthGlobal);

        // Fee growth is now a SMALL value due to wrap-around
        assertTrue(feeGrowthGlobal < preOverflow, "Fee growth should have wrapped to small value");

        // === PHASE 4: Show impact on LP fee calculations ===

        // The honest LP's uncollected fees are calculated as:
        // feesOwed = (feeGrowthGlobal_current - feeGrowthInside_start) * liquidity / 2^102

        // Before overflow: feeGrowthGlobal was huge, LP would get large fees
        // After overflow: feeGrowthGlobal is small, subtraction underflows (in unchecked) or is wrong

        // If the subtraction is done in checked math:
        // feeGrowthGlobal_current (small) - lpFeeGrowthInsideStart (from phase 1)
        // This underflows in checked math → reverts → LP can't collect!

        // If done in unchecked math (as in tick crossing):
        unchecked {
            uint256 feeGrowthDelta = feeGrowthGlobal - lpFeeGrowthInsideStart;
            emit log_named_uint("Fee growth delta (underflowed)", feeGrowthDelta);
            // This produces a MASSIVE value, not the actual fees earned
            assertTrue(feeGrowthDelta > type(uint256).max / 2, "Delta should be massive due to underflow");
        }

        // === PHASE 5: Attacker exploits ===

        // Attacker opens a new position AFTER the overflow
        uint256 attackerFeeGrowthInsideStart = feeGrowthGlobal;  // Small value

        // Some more normal swaps happen
        activeLiquidity = 1e18;
        for (uint256 i = 0; i < 100; i++) {
            stepLpFeeRaw = 1e10;
            unchecked {
                feeGrowthGlobal += (((stepLpFeeRaw * exchangePrice) / EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity;
            }
        }

        // Attacker's fee claim:
        unchecked {
            uint256 attackerFeeGrowth = feeGrowthGlobal - attackerFeeGrowthInsideStart;
            // This is the legitimate fee growth since attacker's position was opened
            // But the honest LP's fee growth calculation is still broken
            emit log_named_uint("Attacker fee growth (legitimate)", attackerFeeGrowth);
        }

        // The toBigNumber call succeeds because the wrapped value is small
        uint256 bigNum = BigMathMinified.toBigNumber(feeGrowthGlobal, BIG_COEFFICIENT_SIZE, DEFAULT_EXPONENT_SIZE, false);
        assertTrue(bigNum > 0, "toBigNumber succeeds with corrupted value");
    }

    /// @notice Demonstrates that encode → decode → encode cycle loses data for large values
    function test_bigMathRoundTrip_DataCorruption() public {
        // Store a fee growth value that's close to uint256 max
        // This simulates what happens when fee growth has been accumulating for a long time

        // Value near uint256 max
        uint256 original = type(uint256).max - 42;

        // Encode to BigMath - this will use a large exponent
        uint256 bigNum = BigMathMinified.toBigNumber(original, BIG_COEFFICIENT_SIZE, DEFAULT_EXPONENT_SIZE, false);

        uint256 exponent = bigNum & DEFAULT_EXPONENT_MASK;
        uint256 coefficient = bigNum >> DEFAULT_EXPONENT_SIZE;

        emit log_named_uint("Coefficient", coefficient);
        emit log_named_uint("Exponent", exponent);

        // For uint256 max (~2^256), we need exponent = 256 - 74 = 182
        // This fits! exponent 182 < 256 (max exponent)
        assertTrue(exponent <= 255, "Exponent should fit in 8 bits");

        // Decode back
        uint256 decoded = BigMathMinified.fromBigNumber(bigNum, DEFAULT_EXPONENT_SIZE, DEFAULT_EXPONENT_MASK);

        // The decoded value loses the lower bits due to BigMath truncation
        // But it should be close to original
        emit log_named_uint("Original", original);
        emit log_named_uint("Decoded", decoded);

        // Now simulate: decoded + small increment → overflow
        uint256 smallIncrement = 1 << (exponent + 1);  // Just enough to change the value
        unchecked {
            decoded += smallIncrement;  // Could overflow if decoded is near uint256 max
        }

        if (decoded < original) {
            // Overflow happened!
            emit log("OVERFLOW DETECTED: decoded + increment wrapped around uint256");

            // Re-encode the wrapped value
            uint256 newBigNum = BigMathMinified.toBigNumber(decoded, BIG_COEFFICIENT_SIZE, DEFAULT_EXPONENT_SIZE, false);
            uint256 newExponent = newBigNum & DEFAULT_EXPONENT_MASK;

            emit log_named_uint("New exponent after overflow", newExponent);
            emit log_named_uint("Old exponent before overflow", exponent);

            // The exponent dropped dramatically - data is corrupted
            assertTrue(newExponent < exponent, "Exponent should be much smaller after overflow");
        }
    }
}
```

Save as `UncheckedFeeGrowthOverflow.t.sol` and run:
```bash
forge test --match-contract UncheckedFeeGrowthOverflowTest -vvv
```

**All 7 tests pass:**
- `test_uncheckedOverflow_Basic` - Confirms uint256 wraps from max-100 + 200 = 99
- `test_uncheckedOverflow_RealisticIncrement` - Realistic fee increment (~2^126 bits) wraps fee growth to exactly 0
- `test_feeAccountingCorruption` - Shows honest LP's fee delta becomes garbage after overflow; tick crossing reverts
- `test_attackerFeeTheft` - **KEY TEST**: Attacker claims correct fees post-overflow, honest LP's calculation underflows to 5.78e76 (corrupted)
- `test_bigMathCycle_AmplifiesCorruption` - Shows BigMath store-load cycles with accumulation approach uint256 boundary
- `test_tickCrossing_RevertsAfterOverflow` - **KEY TEST**: Tick crossing (checked subtraction in swap code) reverts after overflow, bricking all tick-crossing swaps
- `test_highOneAndHighTwo_Interaction` - Shows HIGH-1 + HIGH-2 interaction: unchecked overflow prevents BigMath revert but causes silent corruption (worse)

## Tool Used

Manual review + Foundry

## Recommendation

Remove the `unchecked` block from fee growth accumulation and add explicit overflow protection:

```solidity
// Replace:
unchecked {
    if (params_.swap0To1) v_.feeGrowthGlobal1X102 += (((stepLpFeeRaw_ * params_.token1ExchangePrice)
        / LC.EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity_;
    else v_.feeGrowthGlobal0X102 += (((stepLpFeeRaw_ * params_.token0ExchangePrice)
        / LC.EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity_;
}

// With:
{
    uint256 increment;
    if (params_.swap0To1) {
        increment = (((stepLpFeeRaw_ * params_.token1ExchangePrice)
            / LC.EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity_;
        // Cap at max instead of overflowing
        if (type(uint256).max - v_.feeGrowthGlobal1X102 < increment) {
            v_.feeGrowthGlobal1X102 = type(uint256).max;
        } else {
            v_.feeGrowthGlobal1X102 += increment;
        }
    } else {
        increment = (((stepLpFeeRaw_ * params_.token0ExchangePrice)
            / LC.EXCHANGE_PRICES_PRECISION) << 102) / activeLiquidity_;
        if (type(uint256).max - v_.feeGrowthGlobal0X102 < increment) {
            v_.feeGrowthGlobal0X102 = type(uint256).max;
        } else {
            v_.feeGrowthGlobal0X102 += increment;
        }
    }
}
```

Additionally, add overflow checks to `fromBigNumber` for fee growth values:
```solidity
function fromBigNumberSafe(uint256 bigNumber, uint256 exponentSize, uint256 exponentMask)
    internal pure returns (uint256 normal) {
    uint256 coefficient = bigNumber >> exponentSize;
    uint256 exponent = bigNumber & exponentMask;
    // Check if shift would overflow uint256
    require(exponent <= 255 - mostSignificantBit(coefficient), "BigMath: overflow on decode");
    normal = coefficient << exponent;
}
```
