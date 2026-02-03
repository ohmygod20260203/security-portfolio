# Security Audit Portfolio

Smart contract security researcher specializing in DeFi protocol auditing.

## Audits

### Fluid DEX V2 (Instadapp) - Sherlock Contest
- **Platform:** [Sherlock](https://sherlock.xyz) ($150K bounty pool)
- **Protocol:** Fluid DEX V2 by Instadapp
- **Findings:** 2 HIGH severity
- **Full Report:** [fluid-dex-v2-findings](https://github.com/ohmygod20260203/fluid-dex-v2-findings)

#### HIGH-1: Fee Growth Global Overflow Bricks Pool via BigMath Revert
- **Impact:** Permanent DoS - all swaps revert, LP tokens locked
- **Root Cause:** `BigMathMinified.toBigNumber()` reverts when fee growth exceeds max representable value
- [Full writeup](https://github.com/ohmygod20260203/fluid-dex-v2-findings/blob/main/HIGH-1-FeeGrowthBigMathOverflow.md)

#### HIGH-2: Unchecked Fee Growth uint256 Overflow Corrupts LP Fee Accounting
- **Impact:** Silent fee corruption, LP fee theft/loss, potential protocol insolvency
- **Root Cause:** Fee growth accumulated in `unchecked` block wraps around uint256
- [Full writeup](https://github.com/ohmygod20260203/fluid-dex-v2-findings/blob/main/HIGH-2-UncheckedFeeGrowthOverflow.md)

## Skills
- Solidity / EVM internals
- DeFi protocol security (DEX, lending, yield)
- Foundry PoC development
- Mathematical overflow / precision analysis

## Contact
GitHub: [@ohmygod20260203](https://github.com/ohmygod20260203)
