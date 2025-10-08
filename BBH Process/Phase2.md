# Polymarket Smart Contract Comprehensive Audit Analysis

## Executive Summary
This analysis covers the **idukei/ctf-exchange-BBHmain** repository containing Polymarket's conditional token trading infrastructure. The codebase consists of three main modules: **CTF Exchange** (order matching), **Conditional Tokens** (ERC1155 outcome tokens), and **UMA Adapters** (oracle resolution). Total identified: **10 core contracts**, **9 mixin contracts**, **15+ interfaces**, with **~50 critical functions** requiring audit focus.

---

## 1. REPOSITORY STRUCTURE & CONTRACT INVENTORY

### Core Modules

#### **Module A: CTF Exchange** (`src/exchange/`)
The primary trading engine for binary outcome tokens using EIP-712 signed orders.

**Main Contract:**
- `CTFExchange.sol` - Entry point contract inheriting from multiple mixins

**Mixins** (`src/exchange/mixins/`):
- `Auth.sol` - Role-based access control (admin/operator)
- `Assets.sol` - Collateral (USDC) and CTF token addresses
- `AssetOperations.sol` - Split/merge operations on CTF
- `Fees.sol` - Fee collection logic
- `Hashing.sol` - EIP-712 order hashing
- `NonceManager.sol` - Order cancellation via nonce
- `Pausable.sol` - Trading kill switch
- `Registry.sol` - Token/complement/conditionId registration
- `Signatures.sol` - ECDSA signature validation
- `Trading.sol` - Core order matching logic

**Interfaces** (`src/exchange/interfaces/`):
- `IAssets.sol`, `IConditionalTokens.sol`, `IHashing.sol`, `IRegistry.sol`, `ITrading.sol`, etc.

**Libraries** (`src/exchange/libraries/`):
- `OrderStructs.sol` - Order, Side, MatchType enums
- `CalculatorHelper.sol` - Fee/amount calculations
- `TransferHelper.sol` - Safe ERC20/ERC1155 transfers

#### **Module B: Conditional Tokens** (External dependency)
Gnosis fork for ERC1155 outcome tokenization.

**Key Functions** (from `IConditionalTokens.sol`):
- `prepareCondition(oracle, questionId, outcomeSlotCount)` - Initialize condition
- `splitPosition(collateral, parentCollectionId, conditionId, partition, amount)` - Mint outcomes
- `mergePositions(...)` - Burn outcomes for collateral
- `redeemPositions(...)` - Redeem post-resolution
- `reportPayouts(questionId, payouts)` - Oracle reports results

**Invariants:**
- Payout vectors sum to 1 (or parent denominator)
- Position IDs via elliptic curve addition
- No reentrancy guards (relies on functional correctness)

#### **Module C: UMA Adapters** (Oracle Integration)
**Not fully present in knowledge base**, but referenced extensively.

**Key Contracts:**
- `UmaCtfAdapter.sol` - Standard resolution (binary YES/NO)
- `NegRiskUmaCtfAdapter.sol` - Negative risk markets (wrapped collateral)

**Functions** (from docs):
- `initializeMarket(...)` - Store params, request UMA data
- `prepareResolve(...)` - Set CTF condition
- `resolve(...)` - Fetch UMA result, call `reportPayouts`
- `reset(...)` - Auto-reset on first dispute

**External Dependencies:**
- UMA Optimistic Oracle (OOv2) - `requestPrice`, `proposePrice`, `disputePrice`, `settle`

---

## 2. FUNCTION EXTRACTION & CLASSIFICATION

### High-Priority Functions (Fund Handling & Oracle)

#### **CTFExchange.sol**
| Function | Visibility | Parameters | Risk | Reason |
|----------|-----------|------------|------|---------|
| `fillOrder` | external | `Order order, uint256 fillAmount` | **HIGH** | Transfers funds between maker/taker; reentrancy via `nonReentrant` |
| `fillOrders` | external | `Order[] orders, uint256[] fillAmounts` | **HIGH** | Batch fills; loop complexity |
| `matchOrders` | external | `Order takerOrder, Order[] makerOrders, uint256 takerFillAmount, uint256[] makerFillAmounts` | **HIGH** | Complex matching logic (MINT/MERGE/COMPLEMENTARY); operator trust |
| `pauseTrading` | external | None | **MEDIUM** | Admin only; centralization risk |
| `registerToken` | external | `uint256 token, uint256 complement, bytes32 conditionId` | **MEDIUM** | Admin only; incorrect registration breaks trading |

#### **Trading.sol (Mixin)**
| Function | Visibility | Parameters | Risk | Reason |
|----------|-----------|------------|------|---------|
| `_fillOrder` | internal | `Order order, uint256 fillAmount, address to` | **HIGH** | Core fill logic; fee calculation vulnerable to manipulation |
| `_matchOrders` | internal | `Order takerOrder, Order[] makerOrders, ...` | **HIGH** | Transfers to exchange, then to maker; balance checks critical |
| `_validateOrder` | internal | `bytes32 orderHash, Order order` | **HIGH** | Signature, nonce, expiration, fee validation; bypass = fund theft |
| `_executeMatchCall` | internal | `uint256 makingAmount, uint256 takingAmount, ...` | **HIGH** | Calls CTF `splitPosition`/`mergePositions`; reentrancy possible |

#### **AssetOperations.sol (Mixin)**
| Function | Visibility | Parameters | Risk | Reason |
|----------|-----------|------------|------|---------|
| `_mint` | internal | `bytes32 conditionId, uint256 amount` | **HIGH** | Calls CTF `splitPosition`; infinite minting if condition invalid |
| `_merge` | internal | `bytes32 conditionId, uint256 amount` | **HIGH** | Calls CTF `mergePositions`; stuck funds if incorrect |
| `_transfer` | internal | `address from, address to, uint256 id, uint256 value` | **HIGH** | Handles both ERC20 (collateral) and ERC1155 (CTF); improper checks = loss |

#### **Signatures.sol (Mixin)**
| Function | Visibility | Parameters | Risk | Reason |
|----------|-----------|------------|------|---------|
| `validateOrderSignature` | internal | `bytes32 orderHash, Order order` | **HIGH** | ECDSA recovery; malleability if `v` not checked; past audit found "Signatures Valid for Any Address" critical bug |

#### **UmaCtfAdapter (Referenced, not in KB)**
| Function | Visibility | Parameters | Risk | Reason |
|----------|-----------|------------|------|---------|
| `initializeMarket` | external | `...` | **HIGH** | Stores oracle params; incorrect ancillary data = wrong resolution |
| `resolve` | external | `...` | **CRITICAL** | Fetches UMA result, calls CTF `reportPayouts`; oracle manipulation = fund theft |
| `reset` | external | `...` | **HIGH** | Auto-reset on dispute; griefing via repeated disputes (>24h freeze = escalating bounty) |

#### **ConditionalTokens (External)**
| Function | Visibility | Parameters | Risk | Reason |
|----------|-----------|------------|------|---------|
| `reportPayouts` | external | `bytes32 questionId, uint256[] payouts` | **CRITICAL** | Only oracle can call; if compromised, all funds at risk |
| `redeemPositions` | external | `...` | **HIGH** | Burns positions for collateral; payout vector manipulation = fund loss |

### Medium-Priority Functions (Logic-Heavy)

#### **Registry.sol**
| Function | Visibility | Parameters | Risk | Reason |
|----------|-----------|------------|------|---------|
| `_registerToken` | internal | `uint256 token0, uint256 token1, bytes32 conditionId` | **MEDIUM** | Validates tokenIds; `AlreadyRegistered` or `InvalidTokenId` checks |
| `validateComplement` | public | `uint256 token, uint256 complement` | **MEDIUM** | Used in matching; incorrect complement = order rejection |

#### **Fees.sol**
| Function | Visibility | Parameters | Risk | Reason |
|----------|-----------|------------|------|---------|
| `_chargeFee` | internal | `address payer, address receiver, uint256 tokenId, uint256 fee` | **MEDIUM** | Fee deduction; past audit: "Fee Rate Not Hashed" (fixed) |

#### **NonceManager.sol**
| Function | Visibility | Parameters | Risk | Reason |
|----------|-----------|------------|------|---------|
| `incrementNonce` | external | None | **LOW** | User can cancel orders; no direct fund risk |
| `isValidNonce` | public | `address usr, uint256 nonce` | **MEDIUM** | Used in validation; bypass = replay attack |

### Low-Priority Functions (Getters/Utils)

- `getCollateral()`, `getCtf()`, `getOrderStatus()`, `getConditionId()`, `getComplement()` - All `view` functions, no state changes.

---

## 3. DEPENDENCY ANALYSIS

### Dependency Graph (Text Format)
```
CTFExchange
├── Auth (onlyAdmin, onlyOperator)
├── Assets (collateral, ctf)
│   └── AssetOperations
│       └── IConditionalTokens (external)
│           ├── splitPosition
│           ├── mergePositions
│           └── reportPayouts (called by UmaCtfAdapter)
├── Fees (feeReceiver, feeRateBps)
├── Hashing (EIP-712 domain separator)
├── Signatures (ECDSA, proxy/safe factories)
├── NonceManager (nonces mapping)
├── Pausable (paused bool)
├── Registry (tokenId -> complement/conditionId)
└── Trading
    ├── _fillOrder
    ├── _matchOrders
    │   └── _executeMatchCall
    │       ├── _mint (CTF.splitPosition)
    │       └── _merge (CTF.mergePositions)
    └── _validateOrder
        ├── validateOrderSignature (Signatures)
        ├── validateTokenId (Registry)
        └── isValidNonce (NonceManager)

UmaCtfAdapter (External)
├── UMA Optimistic Oracle (OOv2)
│   ├── requestPrice
│   ├── proposePrice
│   ├── disputePrice (griefing vector)
│   └── settle
└── ConditionalTokens
    ├── prepareCondition
    └── reportPayouts (HIGH RISK)

NegRiskUmaCtfAdapter
├── Inherits UmaCtfAdapter logic
└── Uses wrapped collateral for negative risk markets
```

### External Calls Map
| Contract | Calls To | Function | Risk |
|----------|----------|----------|------|
| CTFExchange | ConditionalTokens | `splitPosition`, `mergePositions` | Reentrancy if CTF malicious |
| UmaCtfAdapter | UMA OO | `requestPrice`, `settle` | Oracle manipulation (March 2025 attack: 5M UMA tokens) |
| UmaCtfAdapter | ConditionalTokens | `prepareCondition`, `reportPayouts` | If oracle compromised, reports false payouts |
| Trading | AssetOperations | `_mint`, `_merge` | CTF calls; stuck funds if condition invalid |

### Folder Structure
```
src/
├── exchange/
│   ├── CTFExchange.sol
│   ├── BaseExchange.sol
│   ├── mixins/
│   │   ├── Auth.sol
│   │   ├── Assets.sol
│   │   ├── AssetOperations.sol
│   │   ├── Fees.sol
│   │   ├── Hashing.sol
│   │   ├── NonceManager.sol
│   │   ├── Pausable.sol
│   │   ├── Registry.sol
│   │   ├── Signatures.sol
│   │   └── Trading.sol
│   ├── interfaces/
│   │   ├── IAssets.sol
│   │   ├── IConditionalTokens.sol
│   │   ├── IHashing.sol
│   │   ├── IRegistry.sol
│   │   ├── ITrading.sol
│   │   └── ...
│   ├── libraries/
│   │   ├── OrderStructs.sol
│   │   ├── CalculatorHelper.sol
│   │   └── TransferHelper.sol
│   ├── scripts/
│   │   └── ExchangeDeployment.s.sol
│   └── test/
│       ├── CTFExchange.t.sol
│       ├── MatchOrders.t.sol
│       └── BaseExchangeTest.sol
├── common/
│   ├── auth/Owned.sol
│   └── ERC20.sol
└── dev/
    ├── mocks/USDC.sol
    └── util/
        ├── Deployer.sol
        └── Json.sol

(External repos not in KB)
uma-ctf-adapter/
├── UmaCtfAdapter.sol
├── NegRiskUmaCtfAdapter.sol
└── ...

conditional-tokens-contracts/
└── ConditionalTokens.sol (Gnosis fork)
```

---

## 4. EXECUTION PATH MAPPING

### Path 1: `fillOrder()` - Simple Fill
```
User → CTFExchange.fillOrder(order, fillAmount)
  ├── Modifiers: nonReentrant, onlyOperator, notPaused
  └── Trading._fillOrder(order, fillAmount, msg.sender)
      ├── _performOrderChecks(order, fillAmount)
      │   ├── _validateOrder(orderHash, order)
      │   │   ├── Check expiration (block.timestamp)
      │   │   ├── Signatures.validateOrderSignature(orderHash, order)
      │   │   │   └── ECDSA.recover (malleability check critical)
      │   │   ├── Check feeRateBps <= maxFeeRate
      │   │   ├── Registry.validateTokenId(order.tokenId)
      │   │   ├── Check orderStatus[orderHash].isFilledOrCancelled
      │   │   └── NonceManager.isValidNonce(order.maker, order.nonce)
      │   ├── _updateOrderStatus(orderHash, order, fillAmount)
      │   └── Calculate takingAmount (CalculatorHelper)
      ├── Calculate fee (CalculatorHelper.calculateFee)
      ├── _transfer(msg.sender, order.maker, takerAssetId, taking - fee)
      │   └── If tokenId == 0: TransferHelper._transferFromERC20(USDC)
      │       Else: TransferHelper._transferFromERC1155(CTF)
      ├── _transfer(order.maker, to, makerAssetId, making)
      └── Emit OrderFilled
```
**Risk Points:**
- Signature validation bypass → fund theft
- Fee manipulation if `feeRateBps` not hashed (fixed in audit)
- Reentrancy in `_transfer` if CTF/USDC malicious

### Path 2: `matchOrders()` - MINT Type (Two BUY orders)
```
Operator → CTFExchange.matchOrders(takerBuy, [makerBuy], takerFillAmount, [makerFillAmounts])
  ├── Modifiers: nonReentrant, onlyOperator, notPaused
  └── Trading._matchOrders(...)
      ├── _performOrderChecks(takerOrder, takerFillAmount)
      │   └── (same as Path 1)
      ├── _transfer(takerOrder.maker, address(this), makerAssetId, making)
      │   └── Transfer collateral (USDC) from taker to exchange
      ├── _fillMakerOrders(takerOrder, makerOrders, makerFillAmounts)
      │   └── For each makerOrder:
      │       ├── _performOrderChecks(makerOrder, fillAmount)
      │       ├── _validateTakerAndMaker(takerOrder, makerOrder, matchType)
      │       │   ├── Check orders crossing (price validation)
      │       │   ├── MINT type: Validate complementary tokenIds
      │       │   └── Revert if invalid
      │       ├── _executeMatchCall(makingAmount, takingAmount, makerOrder, matchType)
      │       │   └── If MINT:
      │       │       ├── _transfer(makerOrder.maker, address(this), makerAssetId, making)
      │       │       │   └── Transfer USDC from maker to exchange
      │       │       └── _mint(conditionId, takingAmount)
      │       │           └── ConditionalTokens.splitPosition(USDC, parentCollectionId, conditionId, [1,2], amount)
      │       │               └── Mints YES and NO tokens to exchange
      │       ├── _updateTakingWithSurplus(taking, takerAssetId)
      │       │   └── Check actual balance vs expected
      │       ├── Calculate fee
      │       ├── _transfer(address(this), makerOrder.maker, takerAssetId, taking - fee)
      │       │   └── Send YES/NO tokens to maker
      │       └── _chargeFee(address(this), msg.sender, takerAssetId, fee)
      ├── _updateTakingWithSurplus(taking, takerAssetId)
      ├── Calculate taker fee
      ├── _transfer(address(this), takerOrder.maker, takerAssetId, taking - takerFee)
      ├── _chargeFee(address(this), msg.sender, takerAssetId, takerFee)
      └── Emit OrdersMatched
```
**Risk Points:**
- MINT logic calls CTF.splitPosition → infinite minting if `conditionId` not prepared
- Balance checks (`_updateTakingWithSurplus`) → insufficient tokens = revert (but check griefing)
- Operator trust → front-running/order manipulation
- Fee calculation errors → under/overcharge

### Path 3: `matchOrders()` - MERGE Type (Two SELL orders)
```
(Similar to Path 2, but:)
      ├── _executeMatchCall(..., MatchType.MERGE)
      │   └── _merge(conditionId, makingAmount)
      │       └── ConditionalTokens.mergePositions(USDC, parentCollectionId, conditionId, [1,2], amount)
      │           └── Burns YES and NO tokens, returns USDC to exchange
```
**Risk Points:**
- MERGE requires both YES and NO tokens; missing one = revert (stuck funds?)
- Incorrect `conditionId` = burn wrong tokens

### Path 4: `UmaCtfAdapter.resolve()` - Oracle Resolution
```
Anyone → UmaCtfAdapter.resolve(market, ...)
  ├── Checks:
  │   ├── Market initialized (initializeMarket called)
  │   ├── OO has settled data (liveness period passed OR dispute resolved)
  │   └── Not already resolved
  ├── Fetch result from UMA Optimistic Oracle
  │   └── OptimisticOracle.settle(questionId, timestamp, ancillaryData)
  │       └── Returns result (e.g., 1 for YES, 0 for NO)
  ├── Convert to payout vector (e.g., [1, 0] for YES wins)
  └── ConditionalTokens.reportPayouts(questionId, payouts)
      └── Sets payout numerators for condition
          └── Enables redeemPositions for users
```
**Success Path:**
- Liveness passes (default 2 hours) → result finalized → users redeem

**Dispute Path:**
```
Disputer → UMA OO.disputePrice(questionId, timestamp, ancillaryData)
  ├── Auto-reset (first dispute):
  │   └── UmaCtfAdapter.reset() → Re-requests data with new timestamp
  ├── Repeated disputes:
  │   └── Escalate to UMA DVM (48-72 hours delay)
  │       └── If disputed again, no auto-reset → DVM decides
```
**Griefing Path:**
- Repeated invalid disputes → 24+ hour freeze → bounty doubles per 24h (HIGH priority)

**Oracle Manipulation Path (March 2025 attack):**
```
Attacker with 25% UMA tokens:
  ├── Propose false result
  ├── Vote in DVM with whale stake
  └── False resolution → UmaCtfAdapter.resolve(fake result)
      └── Users redeem with wrong payouts → $7M loss
```
**Risk Points:**
- No bond/stake checks in adapter (relies on UMA)
- Reentrancy in `resolve()` → call ConditionalTokens before state update
- Incorrect ancillary data → wrong question resolved

---

## 5. RISK PRIORITIZATION

### Scoring Methodology
**Impact:** Fund Loss (5), Temporary Freeze (4), Logic Error (3), Access Control (2), Gas (1)  
**Complexity:** External Calls + Loops (5), Multiple Contracts (4), Single Contract (3), Mixin (2), View (1)  
**Score = Impact × Complexity**

### High-Risk Areas (Score ≥ 15)

| Contract/Function | Impact | Complexity | Score | Threat |
|-------------------|---------|-----------|-------|--------|
| `UmaCtfAdapter.resolve()` | 5 (Fund Loss) | 5 (UMA + CTF calls) | **25** | Oracle manipulation; false payouts; reentrancy |
| `Trading._matchOrders()` (MINT/MERGE) | 5 (Fund Loss) | 5 (Loops + CTF calls) | **25** | Infinite minting; balance manipulation; operator front-running |
| `ConditionalTokens.reportPayouts()` | 5 (Fund Loss) | 4 (Oracle-only access) | **20** | If oracle compromised, all markets at risk |
| `Signatures.validateOrderSignature()` | 5 (Fund Loss) | 3 (ECDSA) | **15** | Signature malleability; past critical bug |
| `AssetOperations._mint()` | 5 (Fund Loss) | 4 (CTF call) | **20** | Invalid `conditionId` → infinite minting |

### Medium-Risk Areas (Score 10-14)

| Contract/Function | Impact | Complexity | Score | Threat |
|-------------------|---------|-----------|-------|--------|
| `Trading._fillOrder()` | 4 (Freeze/Logic) | 3 (Single contract) | **12** | Fee calculation errors; nonce bypass |
| `Registry._registerToken()` | 3 (Logic) | 2 (Admin-only) | **6** | Incorrect complement → trade failures |
| `UmaCtfAdapter.reset()` | 4 (Freeze) | 3 (Auto-reset logic) | **12** | Griefing via repeated disputes (>24h = bounty escalation) |

### Low-Risk Areas (Score < 10)
- `NonceManager.incrementNonce()` - User cancellation only
- `Auth.onlyAdmin/onlyOperator` - Centralization, not exploit
- All `view` functions - No state changes

---

## 6. BATCHING STRATEGY

### Batch 1: **Core Trading Engine** (FIRST PRIORITY)
**Focus:** Fund handling, order matching, signature validation  
**Contracts:**
- `CTFExchange.sol` (entry points)
- `Trading.sol` (core logic)
- `Signatures.sol` (ECDSA)

**Functions (8 total):**
1. `fillOrder()` - external
2. `matchOrders()` - external
3. `_fillOrder()` - internal
4. `_matchOrders()` - internal
5. `_validateOrder()` - internal
6. `validateOrderSignature()` - internal
7. `_performOrderChecks()` - internal
8. `_deriveMatchType()` - internal

**Dependencies:** Assets, Registry, NonceManager, Fees  
**Threat Model:** Signature bypass → fund theft; operator manipulation; fee exploits  
**Estimated Time:** 3-5 days (high complexity)

---

### Batch 2: **Asset Operations & CTF Integration**
**Focus:** Mint/merge logic, CTF external calls, balance checks  
**Contracts:**
- `AssetOperations.sol`
- `Assets.sol`
- `Registry.sol`

**Functions (7 total):**
1. `_mint()` - internal (calls CTF.splitPosition)
2. `_merge()` - internal (calls CTF.mergePositions)
3. `_transfer()` - internal (ERC20 + ERC1155)
4. `_getBalance()` - internal
5. `_registerToken()` - internal
6. `validateTokenId()` - public
7. `validateComplement()` - public

**Dependencies:** ConditionalTokens (external), TransferHelper  
**Threat Model:** Infinite minting; stuck funds; balance manipulation; reentrancy in CTF calls  
**Estimated Time:** 2-3 days

---

### Batch 3: **Oracle Resolution (UMA Integration)**
**Focus:** Market initialization, resolution, dispute handling  
**Contracts:**
- `UmaCtfAdapter.sol` (not in KB, use docs)
- `NegRiskUmaCtfAdapter.sol`

**Functions (5 total):**
1. `initializeMarket()` - external
2. `prepareResolve()` - external
3. `resolve()` - external
4. `reset()` - external
5. Interaction with `ConditionalTokens.reportPayouts()`

**Dependencies:** UMA Optimistic Oracle, ConditionalTokens  
**Threat Model:** Oracle manipulation (March 2025 attack); griefing via disputes (>24h freeze); reentrancy in resolve(); incorrect ancillary data  
**Estimated Time:** 4-6 days (critical path, external dependencies)

---

### Batch 4: **Access Control & Support**
**Focus:** Admin functions, pausable, nonces, fees  
**Contracts:**
- `Auth.sol`
- `Pausable.sol`
- `NonceManager.sol`
- `Fees.sol`

**Functions (8 total):**
1. `pauseTrading()` / `unpauseTrading()` - external
2. `setProxyFactory()` / `setSafeFactory()` - external
3. `registerToken()` - external
4. `incrementNonce()` - external
5. `_chargeFee()` - internal
6. `setFeeReceiver()` - external

**Dependencies:** None (standalone)  
**Threat Model:** Centralization risks; fee manipulation (past audit: "Fee Rate Not Hashed")  
**Estimated Time:** 1-2 days (lower complexity)

---

### Batch 5: **Conditional Tokens (External Audit)**
**Focus:** Gnosis fork, payout vectors, redemption  
**Contracts:**
- `ConditionalTokens.sol` (external repo)

**Functions (5 total):**
1. `prepareCondition()`
2. `splitPosition()`
3. `mergePositions()`
4. `redeemPositions()`
5. `reportPayouts()`

**Dependencies:** None (standalone)  
**Threat Model:** Infinite minting (ID negation); irregular ERC20 stuck funds; reportPayouts manipulation  
**Estimated Time:** 3-4 days (external codebase, coordination needed)

---

## 7. CONSOLIDATED SUMMARY TABLE

| Contract | File | Key Functions | Dependencies | Critical Paths | Priority | Batch |
|----------|------|---------------|--------------|----------------|----------|-------|
| CTFExchange | `src/exchange/CTFExchange.sol` | `fillOrder`, `matchOrders`, `pauseTrading`, `registerToken` | All mixins | Order validation → MINT/MERGE → CTF calls | **HIGH** | 1 |
| Trading | `src/exchange/mixins/Trading.sol` | `_fillOrder`, `_matchOrders`, `_validateOrder`, `_executeMatchCall` | Signatures, Registry, NonceManager, AssetOperations | Signature check → balance transfers → fee deduction | **HIGH** | 1 |
| Signatures | `src/exchange/mixins/Signatures.sol` | `validateOrderSignature`, ECDSA recovery | None | Signature validation (past critical bug: "Valid for Any Address") | **HIGH** | 1 |
| AssetOperations | `src/exchange/mixins/AssetOperations.sol` | `_mint`, `_merge`, `_transfer` | ConditionalTokens (external) | CTF.splitPosition/mergePositions; reentrancy risk | **HIGH** | 2 |
| Assets | `src/exchange/mixins/Assets.sol` | Constructor, `getCollateral`, `getCtf` | None | Immutable addresses; max approval to CTF | **MEDIUM** | 2 |
| Registry | `src/exchange/mixins/Registry.sol` | `_registerToken`, `validateTokenId`, `validateComplement` | None | Token/complement mapping; trade validation | **MEDIUM** | 2 |
| UmaCtfAdapter | `uma-ctf-adapter/UmaCtfAdapter.sol` | `initializeMarket`, `resolve`, `reset` | UMA OO, ConditionalTokens | Oracle result → reportPayouts; griefing via disputes | **CRITICAL** | 3 |
| NegRiskUmaCtfAdapter | `uma-ctf-adapter/NegRiskUmaCtfAdapter.sol` | Same as UmaCtfAdapter + wrapped collateral | UmaCtfAdapter, NegRiskWrappedCollateral | Negative risk resolution; operator access control | **HIGH** | 3 |
| ConditionalTokens | `conditional-tokens-contracts/ConditionalTokens.sol` | `prepareCondition`, `splitPosition`, `mergePositions`, `reportPayouts`, `redeemPositions` | None | Oracle reports → payout vectors; redemption | **CRITICAL** | 5 |
| Auth | `src/exchange/mixins/Auth.sol` | `onlyAdmin`, `onlyOperator`, `addAdmin`, `addOperator` | None | Role management; centralization | **MEDIUM** | 4 |
| Pausable | `src/exchange/mixins/Pausable.sol` | `_pauseTrading`, `_unpauseTrading` | None | Kill switch; admin trust | **MEDIUM** | 4 |
| NonceManager | `src/exchange/mixins/NonceManager.sol` | `incrementNonce`, `isValidNonce` | None | Order cancellation; nonce bypass = replay | **MEDIUM** | 4 |
| Fees | `src/exchange/mixins/Fees.sol` | `_chargeFee`, `setFeeReceiver` | None | Fee collection; past bug: "Fee Rate Not Hashed" | **MEDIUM** | 4 |

---

## 8. HIGH-RISK SUMMARY

### Top 5 Critical Areas

1. **Oracle Manipulation in `UmaCtfAdapter.resolve()`**  
   **Why:** March 2025 attack ($7M) via UMA governance (25% token whale). False `reportPayouts()` = all users redeem wrong amounts.  
   **Hunt:** Symbolic execution (Halmos) on resolve path; fuzz ancillary data; test reentrancy before `reportPayouts()`.

2. **Signature Malleability in `Signatures.validateOrderSignature()`**  
   **Why:** Past critical audit finding: "Signatures Valid for Any Address". ECDSA `v` parameter bypass → fund theft.  
   **Hunt:** Test EOA vs contract signer; check `ecrecover` return == order.maker; replay attacks.

3. **Infinite Minting via `AssetOperations._mint()`**  
   **Why:** If `conditionId` not prepared via `prepareCondition()`, `splitPosition()` may mint arbitrary tokens.  
   **Hunt:** Test _mint with unprepared conditions; check CTF invariant (payout sum = 1); negative token IDs (elliptic curve edge).

4. **Operator Front-Running in `Trading._matchOrders()`**  
   **Why:** Trusted operator can reorder/manipulate matches for profit; no onchain price checks.  
   **Hunt:** Test order crossing validation; simulate operator sandwich attacks; check fee manipulation (past bug: "Fee Rate Not Hashed").

5. **Griefing via UMA Disputes (`UmaCtfAdapter.reset()`)**  
   **Why:** Repeated invalid disputes freeze resolution >24h → bounty doubles per day (temp freezing = HIGH reward).  
   **Hunt:** Test auto-reset on first dispute; simulate 48h+ freeze via DVM escalation; measure bond requirements.
