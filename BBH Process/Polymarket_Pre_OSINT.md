# Polymarket_OSINT_Report.md

## Program Summary

Polymarket is a prediction market platform on Polygon, allowing bets on future events across categories like sports, politics, and pop culture, integrating UMA oracles and Conditional Tokens. The bug bounty program, hosted on Immunefi, went live on April 22, 2024, and offers rewards in USDC on Ethereum, denominated in USD. It follows the Immunefi Vulnerability Severity Classification System V2.3, with Primacy of Impact for critical and high severities in smart contracts and web/apps. Payouts are handled by Polymarket, no KYC is required, and a Proof of Concept (PoC) is mandatory for all submissions. Known issues from audits are ineligible, and responsible disclosure requires approval (Category 3).

### Rewards
Rewards are based on impact, with critical smart contract bugs offering high bounties tied to 10% of affected funds (calculated at submission time). For repeatable attacks on upgradable/pausable contracts, only the initial attack is considered; for non-upgradable ones, cumulative impact applies up to the cap.

| Severity | Min/Max Reward | Conditions |
|----------|---------------|------------|
| Smart Contract - Critical | $25,000 / $1,000,000 | 10% of directly affected funds; min to discourage withholding; e.g., fund theft, permanent freezing, protocol insolvency. Temporary freezing escalates (doubles per 24 hours frozen, up to cap). |
| Smart Contract - High | $2,000 / $25,000 | Theft/freezing of unclaimed yield/royalties; temporary freezing. |
| Smart Contract - Medium | $2,000 | Flat rate. |
| Smart Contract - Low | $1,000 | Flat rate. |
| Websites/Apps - Critical | $5,000 / $20,000 | E.g., fund theft without user action ($20,000); other impacts like taking down the site ($5,000). |
| Websites/Apps - High | $5,000 | Flat rate. |
| Websites/Apps - Medium | $2,000 | Flat rate. |
| Websites/Apps - Low | $1,000 | Flat rate. |

### Rules/Eligibility
Submissions must demonstrate in-scope impacts with a valid PoC adhering to Immunefi guidelines. Eligibility requires novel bugs not from prior audits. Testing is restricted to local forks of mainnet or testnet; no direct interaction with live systems. Primacy of Impact allows reports on out-of-scope assets if they affect program assets. Ineligible: Known issues, unfixed audit findings.

### Prohibitions
- Mainnet or public testnet testing.
- Interactions with pricing oracles/third-party contracts.
- Phishing/social engineering.
- DoS attacks.
- Automated high-traffic testing.
- Public disclosure without embargo approval.

### Feasibility Limitations
Reports may be valid but face real-world execution barriers; Immunefi standards prevent downgrading based on unconventional mitigations.

## Scope Details

### In-Scope Assets

| Asset | URL/Address | Type |
|-------|-------------|------|
| NegRiskUmaCtfAdapter | https://polygonscan.com/address/0x2F5e3684cb1F318ec51b00Edba38d79Ac2c0aA9d | Smart Contract |
| NegRiskWrappedCollateral | https://polygonscan.com/address/0x3A3BD7bb9528E159577F7C2e685CC81A765002E2 | Smart Contract |
| CTFExchange | https://polygonscan.com/address/0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e | Smart Contract |
| ConditionalTokens | https://polygonscan.com/address/0x4d97dcd97ec945f40cf65f87097ace5ea0476045 | Smart Contract |
| FeeModule | https://polygonscan.com/address/0x56C79347e95530c01A2FC76E732f9566dA16E113 | Smart Contract |
| UmaCtfAdapter | https://polygonscan.com/address/0x6A9D222616C90FcA5754cd1333cFD9b7fb6a4F74 | Smart Contract |
| NegRiskOperator | https://polygonscan.com/address/0x71523d0f655B41E805Cec45b17163f528B59B820 | Smart Contract |
| NegRiskFeeModule | https://polygonscan.com/address/0x78769D50Be1763ed1CA0D5E878D93f05aabff29e | Smart Contract |
| NegRiskCtfExchange | https://polygonscan.com/address/0xC5d563A36AE78145C45a50134d48A1215220f80a | Smart Contract |
| ProxyFactory | https://polygonscan.com/address/0xaB45c5A4B0c941a2F231C04C3f49182e1A254052 | Smart Contract |
| Websites and Applications | N/A | Websites and Applications |

All assets added on April 22, 2024.

### Out-of-Scope
- Smart Contract: Incorrect oracle data (unless manipulated via code), basic economic/governance attacks (e.g., 51% attack), lack of liquidity, Sybil attacks, centralization risks.
- General: Self-exploited attacks, leaked keys/credentials, privileged address access without mods, stablecoin depegging not caused by code bug, GitHub secrets without production proof, best practices/recommendations, feature requests, test/config files, phishing/social engineering.

### Prioritized Impacts/Severities
Focus on high-reward areas like oracle manipulation in UmaCtfAdapter, logic flaws in CTFExchange, access control in NegRiskOperator.
- **Critical**: Governance manipulation, fund theft, permanent freezing, insolvency, arbitrary commands, sensitive data retrieval, site takedown, subdomain takeover, wallet interactions (e.g., modifying txs), XSS via metadata. (High bounty potential, e.g., $1M for SC fund loss.)
- **High**: Temporary freezing (rewards scale with duration, doubling per 24 hours).
- Lower severities follow standard rules.

Scope gaps: Avoid reports on oracle data errors unless code-manipulated; no rewards for known audit issues or out-of-scope attacks.

## Resources Analysis

### Repos
- **contract-security**: Contains audits and deployments for Polymarket contracts on Polygon mainnet. No detailed structure or commits provided.
- **uma-ctf-adapter**: Adapter for resolving markets via UMA Optimistic Oracle, integrating CTF. Structure: Solidity contracts for oracle, initialization, preparation, resolution. Audited by OpenZeppelin (report available). No mixins folder noted; uses Foundry for dev. Recent commits/issues: Not detailed. Security: Auto-reset on disputes, fallback to DVM.
- **conditional-tokens-contracts**: Core for conditional tokens. Structure: Solidity (53.5%), JS/TS. No detailed folders/commits/issues. Security: No warranty disclaimer.
- **ctf-exchange**: Docs and audit by Chainsecurity (report link in repo).

### Docs
- Official docs: https://docs.polymarket.com/ (introduction to platform; no security specifics).

### Audits
Audits available at https://github.com/Polymarket/contract-security. Specifics:
- uma-ctf-adapter: OpenZeppelin audit (no extracted vulns from fetch).
- ctf-exchange: Chainsecurity audit.
Known issues ineligible for bounties; focus on unfixed or new vulns.

| Vuln | Status | Relevance |
|------|--------|-----------|
| (Data insufficient for detailed table; audits mention no major unfixed issues from available summaries.) | N/A | Avoid reporting known audit findings to prevent invalid submissions. |

## Additional Research

### Past Incidents
- March 2025: Governance attack on Polymarket via UMA oracle manipulation; attacker used 5M tokens (25% votes) to settle false results and profit. Polymarket committed to prevention.
- July 2025: User funds stolen in a market resolution issue (described as "stole from users," but details suggest oracle tampering).
- Cheating incidents: E.g., scammer buying against own market; detectable on-chain.
- No major contract hacks found; confusion with Poly Network (unrelated, $611M exploit in 2021). 

### Dependency Risks
- **UMA Oracle**: Vulnerabilities include manipulation attacks (e.g., distorting inputs for financial gain in DeFi). General risks: Oracle exploits in smart contracts, griefing via disputes. 
- **Conditional Tokens**: Exploits in related frameworks (e.g., reentrancy in resolve paths); general DeFi risks like flash loans, bugs in token handling. No specific unfixed issues found.

### Community Insights
- X/Reddit Tips: No Polymarket-specific experiences; general bug bounty advice: Focus on one contract class (e.g., oracles), hunt with friends, persist until P1/P2 found, avoid wide chases.  
- Immunefi Experiences: No specific Polymarket reports; platform has paid $100M+ overall, but some complaints on rejections. 

### Hunting Strategies
- Prioritize economic attacks like oracle griefing in UmaCtfAdapter, reentrancy in resolve() paths.
- Test long-duration freezes for escalating rewards.
- Use local forks for PoCs; focus on critical impacts like fund theft via logic flaws in CTFExchange.
- Monitor dependencies for inherited risks (e.g., UMA disputes).

## Implications for Hunting
- Avoid known audit issues and out-of-scope (e.g., pure oracle data errors); prioritize novel criticals for $1M max.
- High opportunities in SC on Polygon forks; test access controls in NegRiskOperator.
- Risks: Invalid reports from prohibitions (e.g., no mainnet DoS); assume good intent in testing.
- Key takeaway: Focus on manipulation edges, like temporary freezing scaling with time, for max rewards.

## References
- Immunefi Program Pages: [Information](https://immunefi.com/bug-bounty/polymarket/information/#top), [Scope](https://immunefi.com/bug-bounty/polymarket/scope/#top), [Resources](https://immunefi.com/bug-bounty/polymarket/resources/#top)
- GitHub Repos: [contract-security](https://github.com/Polymarket/contract-security), [uma-ctf-adapter](https://github.com/Polymarket/uma-ctf-adapter), [conditional-tokens-contracts](https://github.com/Polymarket/conditional-tokens-contracts), [ctf-exchange](https://github.com/Polymarket/ctf-exchange)
- Docs: [Polymarket Docs](https://docs.polymarket.com/)
- Web Searches: Various sources on exploits (e.g., [arxiv.org on oracle problems](https://www.arxiv.org/pdf/2507.02125)), past incidents from X posts.
- Community: General tips from X semantic search; no Polymarket-specific on Reddit/HackerOne.
