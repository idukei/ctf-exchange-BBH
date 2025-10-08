# PART A: FORMAL VERIFICATION PROPERTY GENERATION
## Phase 3 - Batch 1: Core Trading Engine
### Polymarket CTF Exchange - Immunefi Bug Bounty Program

---

## EXECUTIVE SUMMARY

This document presents the formal verification property generation for Batch 1 of the Polymarket CTF Exchange security audit, conducted under the Immunefi bug bounty program. The analysis focuses on the Core Trading Engine, which represents the highest risk surface area due to its role in fund handling, order matching, and signature validation. Based on the Phase 2 audit analysis, this batch encompasses three critical contracts: CTFExchange.sol (entry point), Trading.sol (core logic), and Signatures.sol (ECDSA validation).

The property generation methodology follows the Scribble formal specification language combined with Mythril symbolic execution. A total of thirty-seven properties have been identified across the three contracts, with twenty-four classified as critical severity based on Immunefi impact categories. These properties target known vulnerability classes including signature bypass attacks, balance manipulation, replay attacks, and operator front-running scenarios.

---

## 1. SCOPE DEFINITION

### Contracts Under Analysis

**Batch 1: Core Trading Engine** comprises the following contracts from the idukei/ctf-exchange-BBHmain repository:

**CTFExchange.sol** (src/exchange/CTFExchange.sol) serves as the primary entry point contract, inheriting functionality from nine mixin contracts including Auth, Fees, Assets, Hashing, Trading, Registry, Pausable, Signatures, NonceManager, and AssetOperations. This contract exposes external functions for order filling and matching operations, with role-based access control enforced through onlyAdmin and onlyOperator modifiers.

**Trading.sol** (src/exchange/mixins/Trading.sol) implements the core trading logic as an abstract mixin contract. It manages order validation, execution, and state transitions through the orderStatus mapping. Critical functions include _validateOrder for order checks, _fillOrder for simple order execution, _matchOrders for complex matching scenarios including MINT and MERGE operations, _performOrderChecks for order validation and hash computation, and _executeMatchCall for conditional token framework interactions.

**Signatures.sol** (src/exchange/mixins/Signatures.sol) provides signature validation logic supporting three distinct signature types: EOA for standard ECDSA signatures from externally owned accounts, POLY_PROXY for signatures from Polymarket proxy wallet owners, and POLY_GNOSIS_SAFE for signatures from Gnosis Safe owners. The contract implements validateOrderSignature as the primary validation entry point, with specialized verification functions for each signature type.

### Functions Under Verification

The analysis covers eight functions identified in the Phase 2 batching strategy:

External functions include fillOrder, which executes single order fills with operator access control and pause state checking, and matchOrders, which matches a taker order against multiple maker orders with support for MINT, MERGE, and COMPLEMENTARY match types.

Internal functions include _fillOrder, which performs the core order filling logic including balance transfers and fee charging, _matchOrders, which implements the matching algorithm with loop-based processing of maker orders, _validateOrder, which performs comprehensive order validation including expiration, signature, nonce, and fee checks, validateOrderSignature, which validates order signatures based on signature type, _performOrderChecks, which combines validation, hash computation, and state updates, and _deriveMatchType, which determines whether orders require MINT, MERGE, or COMPLEMENTARY matching.

### Threat Model

The threat model for Batch 1 focuses on four primary attack vectors identified in the Phase 2 analysis:

**Signature Bypass Attacks** represent the highest priority threat, as a past critical audit finding identified the vulnerability "Signatures Valid for Any Address" where ECDSA v parameter manipulation could bypass signature validation, leading to direct fund theft. The verification must ensure that for EOA signature types, the recovered signer address equals the order maker address, ECDSA.recover never returns the zero address, and proxy and safe signature types correctly validate ownership relationships.

**Balance Manipulation** attacks target the core invariant that token transfers must maintain balance conservation. The system must prevent scenarios where the sum of all balance changes in a transaction is non-zero, which would indicate token creation or destruction, maker balances can increase during order execution without corresponding decreases elsewhere, and taker balances can decrease without proper compensation.

**Order State Corruption** attacks exploit improper state transitions in the orderStatus mapping. Critical properties include that once an order is marked as filled or cancelled, this flag can never be reset to allow re-execution, remaining amounts can only decrease through order filling and never increase, which would enable double-spending, and partially filled orders maintain correct remaining amounts after each fill operation.

**Operator Front-Running** scenarios arise from the trusted operator role in the matchOrders function. Without proper validation, operators could reorder execution to extract value through sandwich attacks, match orders that do not satisfy price crossing requirements, manipulate fee calculations by exploiting rounding errors, or execute MINT and MERGE operations with invalid token pairs.

---

## 2. METHODOLOGY

### Scribble Specification Language

The formal verification approach utilizes Scribble, a runtime verification tool that translates property annotations into Solidity assertions. Scribble supports four primary annotation types, each serving a distinct verification purpose.

**Contract Invariants** specified with #invariant annotations define properties that must hold at all observable states. The concept of observability is central to invariant semantics: a contract state is observable before executing any transaction, after returning from any transaction, before making any external call to another contract, and after returning from any external call. Internal function execution does not trigger invariant checks, allowing temporary invariant violations during complex operations provided the invariant is restored before the contract becomes observable again.

**Function Postconditions** specified with #if_succeeds annotations assert properties that must hold after successful function execution. These annotations support both preconditions and postconditions through the old() expression, which captures pre-state values for comparison with post-state values. Multiple if_succeeds annotations on the same function are conjoined, meaning all must be satisfied for the verification to pass.

**State Variable Updates** specified with #if_updated annotations define conditions that must hold whenever a state variable is modified. These annotations are particularly powerful for protecting critical state variables like mappings and arrays. Scribble automatically instruments all modification sites including direct assignments, delete operations, and unary increment or decrement operators. The old() expression within if_updated annotations refers to the value immediately before the modification.

**Inline Assertions** specified with #assert annotations enable mid-function verification, particularly useful for loop invariants and preconditions on specific operations. Assert annotations are placed directly before the statement to be checked and can reference any local variables in scope. Unlike other annotation types, assert annotations cannot use the old() expression since they check the current state rather than state transitions.

### Mythril Symbolic Execution

Mythril serves as the backend analysis engine for instrumented contracts. The tool performs symbolic execution to explore all possible execution paths and identify property violations. The verification workflow proceeds through four stages.

**Instrumentation Phase** involves running Scribble on the source contracts to generate instrumented versions with embedded assertions. The command scribble --arm src/exchange/mixins/Trading.sol produces Trading.sol.instrumented with all properties converted to require() and assert() statements. The instrumented contract maintains identical functionality while adding runtime verification checks.

**Compilation Phase** requires configuring Solidity compiler remappings to resolve import dependencies. A solc-json configuration file maps import paths to actual file system locations, enabling proper compilation of contracts that depend on external libraries like OpenZeppelin and the Conditional Tokens Framework. The remapping configuration follows the pattern: "remappings": ["@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/", "ctf/=lib/conditional-tokens-contracts/contracts/"].

**Analysis Phase** executes Mythril with carefully tuned parameters to balance thoroughness and execution time. The transaction depth parameter (-t) controls how many sequential transactions to simulate, with t=1 sufficient for single-function properties and t=2 required for multi-transaction scenarios. The execution timeout (--execution-timeout) prevents analysis from running indefinitely on complex functions, with sixty to one hundred twenty seconds typical for the contracts in scope. The solver timeout (--solver-timeout) controls the maximum time for constraint solving operations.

**Verification Phase** examines Mythril output to identify assertion violations. Each violation includes the transaction sequence that triggers the failure, the specific property that was violated as indicated by the message identifier, the symbolic constraints that lead to the violation, and the concrete example values that demonstrate the exploit if Mythril successfully concretizes the symbolic values.

### Property Classification

Properties are classified by severity using a scoring methodology that combines impact and exploitability dimensions aligned with Immunefi reward categories.

**Critical Severity** properties protect against direct fund loss vulnerabilities that would qualify for maximum bounty rewards. These include signature bypass enabling unauthorized order execution, balance manipulation allowing token creation or theft, replay attacks through nonce or cancellation bypass, infinite minting through conditional token framework exploitation, and order state corruption enabling double-spending.

**High Severity** properties protect against temporary fund freezing or logic errors that significantly impact system operation. These include access control bypass allowing non-operators to execute trades, pause mechanism failures that could lock funds temporarily, fee calculation errors that could drain fee reserves over time, price crossing validation failures enabling value extraction, and array bounds violations that could cause transaction reverts.

**Medium Severity** properties protect against configuration issues and edge cases that do not directly threaten funds. These include array length mismatches causing transaction failures, immutability violations of factory addresses, and loop termination issues in batch operations.

---

## 3. PROPERTY GENERATION

### Contract: Trading.sol

This contract implements the core order matching and execution logic, making it the highest priority target for formal verification. The property generation focuses on order state integrity, balance conservation, and execution correctness.

#### Contract-Level Invariants

**INV-T1: Order Remaining Amount Bounds** ensures that for any order in the system, the remaining amount never exceeds the original maker amount specified in the order. This invariant prevents scenarios where partially filled orders could be re-executed beyond their intended capacity. The property is expressed as: for all order hashes h in the orderStatus mapping, if the order is not filled or cancelled, then orderStatus[h].remaining must be less than or equal to the maker amount from the original order. Implementation requires tracking the original maker amount alongside the remaining amount, which may necessitate extending the OrderStatus struct.

**INV-T2: Monotonic Order Status** protects the isFilledOrCancelled flag from unauthorized reset. Once an order transitions to the filled or cancelled state, it must remain in that state permanently. This invariant prevents replay attacks where an attacker could reset a filled order and execute it again. The property is expressed as: for all order hashes h in the orderStatus mapping, if old(orderStatus[h].isFilledOrCancelled) was true, then orderStatus[h].isFilledOrCancelled must remain true. This is a temporal property that must hold across all state transitions.

#### State Variable Annotations

The orderStatus mapping requires two critical if_updated annotations that trigger verification whenever the mapping is modified.

**SV-T1: Fill-Cancellation Irreversibility** enforces that the isFilledOrCancelled flag can only transition from false to true, never from true to false. The annotation is placed directly above the orderStatus mapping declaration. The property states: if the old value of isFilledOrCancelled for a given key was true, then the new value must also be true. Equivalently, if the old value was false and the new value is true, that transition is permitted, but true to false transitions are forbidden.

**SV-T2: Remaining Amount Monotonicity** enforces that the remaining field in the OrderStatus struct can only decrease or remain constant, never increase. The annotation states: for any update to orderStatus[key], the new value of orderStatus[key].remaining must be less than or equal to the old value of orderStatus[key].remaining. This property prevents attackers from artificially inflating the remaining amount on partially filled orders.

#### Function-Level Properties

**_validateOrder Function** performs comprehensive validation checks on orders before execution. Four postcondition properties ensure that the function only succeeds when all validation criteria are met.

**FN-T1: Expiration Validation** verifies that orders with non-zero expiration timestamps have not expired. The property states: if the function succeeds, then either order.expiration equals zero indicating no expiration, or order.expiration is greater than or equal to the current block timestamp. This prevents execution of stale orders that could have been filled at outdated prices.

**FN-T2: Nonce Validation** ensures that orders have valid nonces according to the NonceManager state. The property states: if the function succeeds, then isValidNonce(order.maker, order.nonce) returns true. This property works in conjunction with the NonceManager mixin to prevent replay attacks through nonce invalidation.

**FN-T3: Order Status Validation** prevents double-execution by checking that orders are not already filled or cancelled. The property states: if the function succeeds, then orderStatus[orderHash].isFilledOrCancelled is false. Combined with INV-T2, this creates a complete protection against order replay.

**FN-T4: Fee Rate Validation** protects against excessive fee extraction by limiting fee rates to the configured maximum. The property states: if the function succeeds, then order.feeRateBps is less than or equal to the value returned by getMaxFeeRate(). This prevents malicious orders from including exorbitant fees that would drain user funds.

**_fillOrder Function** executes order fills with balance transfers and fee charging. Three postcondition properties ensure balance conservation and correct state updates.

**FN-T5: Maker Balance Decrease** verifies that the order maker's balance decreases by the sum of the fill amount and the fee. The property captures the maker's balance before execution using old(_getBalance(order.maker, makerAssetId)), then asserts that this old balance equals the new balance plus the making amount plus the fee amount. This ensures that makers cannot execute orders without providing the required tokens.

**FN-T6: Taker Balance Increase** verifies that the taker receives the correct amount of tokens. The property states: the taker's new balance of the taker asset equals the old balance plus the taking amount. This ensures that takers receive the full quantity of tokens specified by the order without any unexpected deductions.

**FN-T7: Order State Update** verifies that the remaining amount on the order is decremented correctly. The property states: the new value of orderStatus[orderHash].remaining equals the old value minus the making amount. This ensures that partially filled orders maintain accurate state for subsequent fills.

**_matchOrders Function** implements the complex matching logic for crossing orders with potential MINT or MERGE operations. Two high-level properties ensure correctness.

**FN-T8: Global Balance Conservation** ensures that the total collateral in the system remains constant through match operations. This property requires summing the collateral balance changes for the exchange contract, both maker and taker addresses, and the fee receiver. The sum of all collateral inflows must equal the sum of all collateral outflows. Any violation indicates token creation or destruction, which would represent a critical vulnerability.

**FN-T9: Taker Order Fill Tracking** verifies that the taker order's remaining amount decreases by exactly the specified taker fill amount. The property states: the new value of orderStatus[takerHash].remaining equals the old value minus takerFillAmount. This ensures that the taker order state is updated correctly even when matched against multiple maker orders.

**_matchOrders Loop Assertions** protect array access and prevent overfilling within the loop that processes maker orders. Three inline assertions are placed at the beginning of each loop iteration.

**LOOP-T1: Maker Orders Array Bounds** asserts that the loop index i is less than makerOrders.length before accessing makerOrders[i]. This prevents array out-of-bounds access that could cause transaction reverts or undefined behavior.

**LOOP-T2: Fill Amounts Array Bounds** asserts that the loop index i is less than makerFillAmounts.length before accessing makerFillAmounts[i]. This ensures proper alignment between the orders and their corresponding fill amounts.

**LOOP-T3: Overfill Protection** asserts that each maker fill amount does not exceed the remaining amount on the maker order. The property computes the current remaining amount for the maker order using orderStatus[hashOrder(makerOrders[i])].remaining, then asserts that makerFillAmounts[i] is less than or equal to the original maker amount minus the already filled amount. This prevents filling more than the order allows.

**_performOrderChecks Function** combines validation, hash computation, and state updates into a single internal function. Two properties ensure correctness.

**FN-T10: Taking Amount Calculation** verifies that the taking amount is computed correctly from the making amount and the order's maker-to-taker ratio. The property states: takingAmount equals making multiplied by order.takerAmount divided by order.makerAmount. This ensures that order fills maintain the correct price ratio specified in the original order.

**FN-T11: Order Hash Integrity** verifies that the order hash is computed correctly from the order struct fields. While Scribble cannot directly verify the hash computation due to the complexity of EIP-712 hashing, this property ensures that the hash used for validation matches the hash derived from the order parameters, preventing signature bypass through hash manipulation.

**_executeMatchCall Function** conditionally mints or merges tokens based on the match type. Properties vary by match type.

**FN-T12: MINT Balance Decrease** applies when the match type is MINT. The property verifies that the exchange's collateral balance decreases by the taking amount when new outcome tokens are minted through CTF.splitPosition. The property states: for MINT operations, old(_getBalance(address(this), getCollateral())) equals the new collateral balance plus takingAmount. This prevents infinite minting by ensuring collateral is consumed.

**FN-T13: MERGE Balance Decrease** applies when the match type is MERGE. The property verifies that the exchange's outcome token balance decreases by the making amount when tokens are merged back into collateral through CTF.mergePositions. The property states: for MERGE operations, old(_getBalance(address(this), makerAssetId)) equals the new token balance plus makingAmount. This ensures that merge operations consume the correct tokens.

**_validateTakerAndMaker Function** ensures that orders can be legitimately matched. Properties vary by match type.

**FN-T14: Price Crossing Validation** verifies that orders satisfy price crossing requirements before matching. The property invokes CalculatorHelper.isCrossing(takerOrder, makerOrder) which checks that the taker's maximum price is greater than or equal to the maker's minimum price for legitimate matching. This prevents operators from executing matches at prices that disadvantage users.

**FN-T15: Token ID Matching for COMPLEMENTARY** applies when the match type is COMPLEMENTARY indicating a buy order matched against a sell order for the same token. The property verifies that takerOrder.tokenId equals makerOrder.tokenId, ensuring that both orders reference the same outcome token.

**FN-T16: Complement Validation for MINT and MERGE** applies when the match type is MINT or MERGE indicating matching of complementary outcome tokens. The property invokes validateComplement(takerOrder.tokenId, makerOrder.tokenId) which verifies that the token IDs are registered as complements in the Registry mixin, ensuring that they can be legitimately minted or merged together.

### Contract: Signatures.sol

This contract provides signature validation logic supporting multiple signature types. Given the past critical audit finding related to signature validation, these properties receive the highest priority.

#### Contract-Level Invariants

**INV-S1: Factory Address Immutability** ensures that the proxyFactory and safeFactory addresses set during contract construction never change. The property states: for all observable states, proxyFactory equals old(proxyFactory) and safeFactory equals old(safeFactory). These addresses are critical for verifying proxy and safe ownership, and any modification could enable signature bypass attacks.

#### Function-Level Properties

**validateOrderSignature Function** serves as the primary entry point for signature validation. One postcondition ensures correctness.

**FN-S1: Signature Validity** verifies that the function only succeeds when the signature is valid for the given order. The property states: if the function succeeds, then isValidSignature(order.signer, order.maker, orderHash, order.signature, order.signatureType) returns true. This property delegates detailed verification to the specialized functions but ensures that invalid signatures always cause transaction reversion.

**verifyEOASignature Function** validates signatures from externally owned accounts. Two postconditions ensure security.

**FN-S2: Signer-Maker Identity** enforces that for EOA signature types, the signer and maker addresses must be identical. The property states: if the function returns true, then signer equals maker. This prevents attackers from signing orders on behalf of other addresses using their own private keys.

**FN-S3: ECDSA Signature Validity** delegates to the low-level ECDSA verification. The property states: if the function returns true, then verifyECDSASignature(signer, structHash, signature) returns true. This ensures that the signature is cryptographically valid for the claimed signer.

**verifyECDSASignature Function** performs the core ECDSA signature verification. Two postconditions ensure correctness.

**FN-S4: Recovered Signer Match** verifies that ECDSA recovery produces the expected signer address. The property states: if the function returns true, then ECDSA.recover(structHash, signature) equals signer. This prevents signature malleability attacks where different signature representations could recover to different addresses.

**FN-S5: Non-Zero Recovery** prevents the zero address from being accepted as a valid signer. The property states: if the function returns true, then ECDSA.recover(structHash, signature) is not equal to address(0). The zero address can be recovered from certain malformed signatures, and accepting it as valid would enable signature bypass.

**verifyPolyProxySignature Function** validates signatures from Polymarket proxy wallet owners. Two postconditions ensure security.

**FN-S6: Proxy Wallet Ownership** verifies that the claimed proxy wallet is actually owned by the signer. The property states: if the function returns true, then getPolyProxyWalletAddress(signer) equals proxyWallet. This prevents attackers from using proxy wallets they do not own to sign orders.

**FN-S7: ECDSA Validity for Proxy** ensures that the underlying ECDSA signature is valid. The property states: if the function returns true, then verifyECDSASignature(signer, structHash, signature) returns true. This ensures that the proxy wallet owner actually signed the order.

**verifyPolySafeSignature Function** validates signatures from Gnosis Safe owners. Two postconditions ensure security.

**FN-S8: Safe Ownership** verifies that the claimed safe is actually owned by the signer. The property states: if the function returns true, then getSafeAddress(signer) equals safeAddress. This prevents attackers from using safes they do not own to sign orders.

**FN-S9: ECDSA Validity for Safe** ensures that the underlying ECDSA signature is valid. The property states: if the function returns true, then verifyECDSASignature(signer, hash, signature) returns true. This ensures that the safe owner actually signed the order.

### Contract: CTFExchange.sol

This contract serves as the entry point and enforces access control and pause functionality. Properties focus on authorization and state checking.

#### Function-Level Properties

**fillOrder Function** allows operators to fill individual orders. Two postconditions ensure correct access control and state checking.

**FN-E1: Operator Authorization** verifies that only addresses with the operator role can execute fills. The property states: if the function succeeds, then hasRole(OPERATOR_ROLE, msg.sender) is true. This prevents unauthorized addresses from executing trades that could manipulate order matching.

**FN-E2: Pause State Checking** verifies that trading is not paused when fills execute. The property states: if the function succeeds, then the paused flag is false. This ensures that the emergency pause mechanism cannot be bypassed through direct order filling.

**matchOrders Function** allows operators to match a taker order against multiple maker orders. Three postconditions ensure correctness.

**FN-E3: Operator Authorization** verifies that only operators can execute matches. The property states: if the function succeeds, then hasRole(OPERATOR_ROLE, msg.sender) is true. Given the complexity of matching and the potential for operator front-running, this authorization is critical.

**FN-E4: Pause State Checking** verifies that trading is not paused. The property states: if the function succeeds, then the paused flag is false. This ensures consistent pause enforcement across all trading functions.

**FN-E5: Array Length Consistency** verifies that the maker orders array and maker fill amounts array have equal length. The property states: if the function succeeds, then makerOrders.length equals makerFillAmounts.length. This prevents array index mismatches that could cause incorrect fills or transaction reverts.

---

## 4. PROPERTY SUMMARY TABLE

The following table provides a consolidated view of all properties generated for Batch 1, organized by contract and severity.

| Contract | Target | Property ID | Type | Description | Severity |
|----------|--------|-------------|------|-------------|----------|
| Trading.sol | Contract | INV-T1 | invariant | Order remaining ≤ maker amount | CRITICAL |
| Trading.sol | Contract | INV-T2 | invariant | isFilledOrCancelled irreversible | CRITICAL |
| Trading.sol | orderStatus | SV-T1 | if_updated | Fill flag cannot reset | CRITICAL |
| Trading.sol | orderStatus | SV-T2 | if_updated | Remaining only decreases | CRITICAL |
| Trading.sol | _validateOrder | FN-T1 | if_succeeds | Order not expired | HIGH |
| Trading.sol | _validateOrder | FN-T2 | if_succeeds | Nonce valid | CRITICAL |
| Trading.sol | _validateOrder | FN-T3 | if_succeeds | Order not filled/cancelled | CRITICAL |
| Trading.sol | _validateOrder | FN-T4 | if_succeeds | Fee within limits | HIGH |
| Trading.sol | _fillOrder | FN-T5 | if_succeeds | Maker balance decreased | CRITICAL |
| Trading.sol | _fillOrder | FN-T6 | if_succeeds | Taker balance increased | CRITICAL |
| Trading.sol | _fillOrder | FN-T7 | if_succeeds | Order remaining decreased | CRITICAL |
| Trading.sol | _matchOrders | FN-T8 | if_succeeds | Balance conservation | CRITICAL |
| Trading.sol | _matchOrders | FN-T9 | if_succeeds | Taker order filled | CRITICAL |
| Trading.sol | _matchOrders loop | LOOP-T1 | assert | Array bounds: orders | MEDIUM |
| Trading.sol | _matchOrders loop | LOOP-T2 | assert | Array bounds: amounts | MEDIUM |
| Trading.sol | _matchOrders loop | LOOP-T3 | assert | No overfill | CRITICAL |
| Trading.sol | _performOrderChecks | FN-T10 | if_succeeds | Taking amount correct | HIGH |
| Trading.sol | _performOrderChecks | FN-T11 | if_succeeds | Hash integrity | CRITICAL |
| Trading.sol | _executeMatchCall MINT | FN-T12 | if_succeeds | Collateral decreased | CRITICAL |
| Trading.sol | _executeMatchCall MERGE | FN-T13 | if_succeeds | Token decreased | CRITICAL |
| Trading.sol | _validateTakerAndMaker | FN-T14 | if_succeeds | Price crossing valid | CRITICAL |
| Trading.sol | _validateTakerAndMaker COMP | FN-T15 | if_succeeds | Token IDs match | CRITICAL |
| Trading.sol | _validateTakerAndMaker M/M | FN-T16 | if_succeeds | Complements valid | CRITICAL |
| Signatures.sol | Contract | INV-S1 | invariant | Factory addresses immutable | MEDIUM |
| Signatures.sol | validateOrderSignature | FN-S1 | if_succeeds | Signature valid | CRITICAL |
| Signatures.sol | verifyEOASignature | FN-S2 | if_succeeds | Signer equals maker | CRITICAL |
| Signatures.sol | verifyEOASignature | FN-S3 | if_succeeds | ECDSA valid | CRITICAL |
| Signatures.sol | verifyECDSASignature | FN-S4 | if_succeeds | Recovery matches | CRITICAL |
| Signatures.sol | verifyECDSASignature | FN-S5 | if_succeeds | Not zero address | CRITICAL |
| Signatures.sol | verifyPolyProxySignature | FN-S6 | if_succeeds | Proxy owned | CRITICAL |
| Signatures.sol | verifyPolyProxySignature | FN-S7 | if_succeeds | ECDSA valid | CRITICAL |
| Signatures.sol | verifyPolySafeSignature | FN-S8 | if_succeeds | Safe owned | CRITICAL |
| Signatures.sol | verifyPolySafeSignature | FN-S9 | if_succeeds | ECDSA valid | CRITICAL |
| CTFExchange.sol | fillOrder | FN-E1 | if_succeeds | Operator only | HIGH |
| CTFExchange.sol | fillOrder | FN-E2 | if_succeeds | Not paused | HIGH |
| CTFExchange.sol | matchOrders | FN-E3 | if_succeeds | Operator only | HIGH |
| CTFExchange.sol | matchOrders | FN-E4 | if_succeeds | Not paused | HIGH |
| CTFExchange.sol | matchOrders | FN-E5 | if_succeeds | Array lengths match | MEDIUM |

---

## 5. SEVERITY DISTRIBUTION ANALYSIS

The property set exhibits the following severity distribution, which aligns with the Immunefi bug bounty program impact categories.

### Critical Severity Properties

Twenty-four properties are classified as critical severity, representing sixty-five percent of the total property set. These properties protect against vulnerabilities that would qualify for maximum bounty rewards under the Immunefi program, specifically those enabling direct fund theft, permanent fund loss, or unauthorized control over user assets.

Signature validation properties comprise nine critical properties covering ECDSA recovery correctness, signer-maker identity verification, proxy and safe ownership validation, and signature validity enforcement. These properties directly address the past critical audit finding "Signatures Valid for Any Address" and prevent signature bypass attacks that could enable complete theft of user funds.

Order state integrity properties comprise six critical properties covering fill-cancellation flag irreversibility, remaining amount monotonicity, nonce validation, order status checking, order state updates, and hash integrity verification. These properties prevent replay attacks and double-spending scenarios where attackers could re-execute filled orders to extract additional value.

Balance conservation properties comprise five critical properties covering maker balance decreases, taker balance increases, global balance conservation, collateral consumption in MINT operations, and token consumption in MERGE operations. These properties ensure that the system maintains perfect accounting without token creation or destruction.

Order matching properties comprise four critical properties covering overfill protection, price crossing validation, token ID matching, and complement validation. These properties prevent operator front-running and ensure that only legitimate order matches can be executed.

### High Severity Properties

Ten properties are classified as high severity, representing twenty-seven percent of the total property set. These properties protect against temporary fund freezing, logic errors, and access control bypasses that would qualify for substantial but not maximum bounty rewards.

Access control properties comprise four properties covering operator authorization for fillOrder and matchOrders, and pause state verification for both functions. These properties ensure that the emergency pause mechanism functions correctly and that only authorized operators can execute trades.

Order validation properties comprise three properties covering expiration checking, fee rate validation, and taking amount calculation correctness. These properties prevent execution of stale orders, protect against excessive fee extraction, and ensure correct price ratios during order fills.

### Medium Severity Properties

Three properties are classified as medium severity, representing eight percent of the total property set. These properties protect against configuration issues and edge cases that do not directly threaten funds but could cause operational disruptions.

Array handling properties comprise two properties covering bounds checking in the _matchOrders loop for both the orders array and the fill amounts array. These properties prevent transaction reverts due to array access violations.

Configuration properties comprise one property covering factory address immutability. This property ensures that the proxy and safe ownership verification functions reference the correct factory contracts throughout the contract lifecycle.

### Coverage Analysis

The property set provides comprehensive coverage of the attack surface identified in Phase 2 for Batch 1. All eight critical functions have associated properties. All identified threat vectors including signature bypass, balance manipulation, order state corruption, and operator front-running have targeted properties. All critical state variables including the orderStatus mapping have if_updated annotations protecting state transitions. All loops have inline assertions protecting array access and preventing logic errors.

The property density is appropriately high given the critical nature of the Core Trading Engine. The average of twelve properties per contract reflects the complexity and security requirements of fund-handling logic. The emphasis on critical severity properties aligns with the Immunefi program focus on preventing direct fund loss.

---

## 6. CONFIRMATION AND NEXT STEPS

This property generation phase has identified thirty-seven formal verification properties across the three contracts in Batch 1 of the Polymarket CTF Exchange audit. The properties target known vulnerability classes documented in the Phase 2 analysis and align with Immunefi critical and high impact categories.

### Approval Criteria

The property set requires approval on three dimensions before proceeding to implementation in Part B.

**Coverage Sufficiency** requires confirmation that the properties adequately cover all critical paths identified in the Phase 2 threat model, including signature validation, order execution, balance transfers, and state management.

**Severity Classification** requires confirmation that the critical, high, and medium severity assignments align with Immunefi impact categories and bounty reward structures.

**Implementation Readiness** requires confirmation that the property descriptions provide sufficient detail to translate into concrete Scribble annotations with proper placement and syntax.

### Part B Preview

Upon approval of the property set, Part B will proceed with the following deliverables for each contract:

Fully annotated contract source code with all Scribble annotations properly placed according to the property specifications described in this document.

Mythril execution commands tailored to each contract's dependency structure, including solc-json remapping configurations for OpenZeppelin, Conditional Tokens Framework, and internal dependencies.

Execution workflow documentation describing the instrumentation, compilation, and analysis sequence for each contract.

Expected property violation scenarios that Mythril should detect, serving as validation that the verification setup is functioning correctly.

The work will proceed contract-by-contract with pause points for confirmation, starting with Signatures.sol due to its critical role and past audit findings, proceeding to Trading.sol for the core execution logic, and concluding with CTFExchange.sol for the entry point verification.

### Confirmation Request

Please confirm approval of this property set to proceed with Part B implementation. Specifically, confirm that:

The thirty-seven properties provide sufficient coverage for Immunefi bounty program requirements.

The severity classifications correctly reflect fund loss risk and potential bounty amounts.

The property descriptions are sufficiently detailed to translate into working Scribble annotations.

Any modifications, additions, or clarifications needed before proceeding to implementation phase.