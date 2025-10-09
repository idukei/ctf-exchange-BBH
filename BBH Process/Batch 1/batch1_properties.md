# Batch 1: Core Trading Engine - Formal Verification Properties

## Property Classification Legend
- **CRITICAL**: Violation leads to fund theft or permanent freezing (Immunefi Critical)
- **HIGH**: Violation leads to temporary freezing or logic errors (Immunefi High)
- **MEDIUM**: Violation leads to incorrect state or access control issues

---

## 1. Signatures.sol - Signature Validation Properties

### Contract-Level Invariants

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| SIG-INV-01 | #invariant | ProxyFactory and SafeFactory addresses are never zero after construction | HIGH | Contract-level |

### Function: validateOrderSignature(bytes32 orderHash, Order order)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| SIG-FS-01 | #if_succeeds | For EOA signatures, recovered signer MUST equal order.maker | **CRITICAL** | Function-level |
| SIG-FS-02 | #if_succeeds | Function only succeeds if signature is valid (never returns on invalid signature) | **CRITICAL** | Function-level |
| SIG-FS-03 | #if_succeeds | Signature verification must use the correct EIP-712 domain separator | **CRITICAL** | Function-level |

### Function: isValidSignature(address signer, address associated, bytes32 structHash, bytes signature, uint256 signatureType)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| SIG-FS-04 | #if_succeeds | Returns false if signature length is invalid (not 65 bytes for ECDSA) | HIGH | Function-level |
| SIG-FS-05 | #if_succeeds | For POLY_PROXY type, associated address must be a valid proxy owned by signer | **CRITICAL** | Function-level |
| SIG-FS-06 | #if_succeeds | For POLY_GNOSIS_SAFE type, associated address must be a valid safe with signer as owner | **CRITICAL** | Function-level |
| SIG-FS-07 | #if_succeeds | SignatureType enum must be valid (0=EOA, 1=POLY_PROXY, 2=POLY_GNOSIS_SAFE) | HIGH | Function-level |

### Function: verifyECDSASignature(address signer, bytes32 structHash, bytes signature)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| SIG-FS-08 | #if_succeeds | ecrecover result equals signer when signature is valid | **CRITICAL** | Function-level |
| SIG-FS-09 | #if_succeeds | Returns false if ecrecover returns zero address | **CRITICAL** | Function-level |
| SIG-FS-10 | #if_succeeds | Signature 'v' parameter must be 27 or 28 (prevents malleability) | **CRITICAL** | Function-level |

### Inline Assertions

| ID | Property Type | Description | Severity | Location |
|----|--------------|-------------|----------|----------|
| SIG-AS-01 | #assert | Signature length equals 65 before ECDSA verification | HIGH | Before ecrecover call |
| SIG-AS-02 | #assert | Signer address is not zero address | **CRITICAL** | At function entry |

---

## 2. Trading.sol - Order Matching & Execution Properties

### Contract-Level Invariants

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| TRD-INV-01 | #invariant | Total collateral balance in contract equals sum of all order escrows | **CRITICAL** | Contract-level |
| TRD-INV-02 | #invariant | OrderStatus.remaining is always <= original order amount | **CRITICAL** | Contract-level |
| TRD-INV-03 | #invariant | Paused state can only be modified by admin | HIGH | Contract-level |

### State Variable: orderStatus mapping

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| TRD-UP-01 | #if_updated | OrderStatus.remaining only decreases or stays same, never increases | **CRITICAL** | State variable |
| TRD-UP-02 | #if_updated | OrderStatus.isFilledOrCancelled can only transition from false to true | **CRITICAL** | State variable |
| TRD-UP-03 | #if_updated | OrderStatus can only be updated during fillOrder or matchOrders calls | **CRITICAL** | State variable |

### Function: fillOrder(Order order, uint256 fillAmount)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| TRD-FS-01 | #if_succeeds | fillAmount must be > 0 and <= order remaining amount | **CRITICAL** | Function-level |
| TRD-FS-02 | #if_succeeds | Order signature is valid before execution | **CRITICAL** | Function-level |
| TRD-FS-03 | #if_succeeds | Order is not expired (block.timestamp <= order.expiration) | **CRITICAL** | Function-level |
| TRD-FS-04 | #if_succeeds | Order nonce matches maker's current nonce | **CRITICAL** | Function-level |
| TRD-FS-05 | #if_succeeds | Maker balance decreases by exactly makerAmount | **CRITICAL** | Function-level |
| TRD-FS-06 | #if_succeeds | Taker balance decreases by exactly takerAmount | **CRITICAL** | Function-level |
| TRD-FS-07 | #if_succeeds | Fees are charged correctly per fee rate | HIGH | Function-level |
| TRD-FS-08 | #if_succeeds | OrderStatus.remaining decreases by exactly fillAmount | **CRITICAL** | Function-level |
| TRD-FS-09 | #if_succeeds | If fillAmount equals remaining, isFilledOrCancelled becomes true | **CRITICAL** | Function-level |
| TRD-FS-10 | #if_succeeds | Exchange contract is not paused | **CRITICAL** | Function-level |

### Function: matchOrders(Order takerOrder, Order[] makerOrders, uint256 takerFillAmount, uint256[] makerFillAmounts)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| TRD-FS-11 | #if_succeeds | Only operator can call this function | **CRITICAL** | Function-level |
| TRD-FS-12 | #if_succeeds | makerOrders.length equals makerFillAmounts.length | **CRITICAL** | Function-level |
| TRD-FS-13 | #if_succeeds | Sum of makerFillAmounts equals takerFillAmount (accounting for match type) | **CRITICAL** | Function-level |
| TRD-FS-14 | #if_succeeds | All orders (taker + makers) have valid signatures | **CRITICAL** | Function-level |
| TRD-FS-15 | #if_succeeds | No order is expired | **CRITICAL** | Function-level |
| TRD-FS-16 | #if_succeeds | No order has insufficient remaining amount | **CRITICAL** | Function-level |
| TRD-FS-17 | #if_succeeds | Exchange contract is not paused | **CRITICAL** | Function-level |

### Function: _matchOrders(Order takerOrder, Order[] makerOrders, uint256 takerFillAmount, uint256[] makerFillAmounts)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| TRD-FS-18 | #if_succeeds | For MINT type: collateral transferred equals minted token amount | **CRITICAL** | Function-level |
| TRD-FS-19 | #if_succeeds | For MERGE type: merged tokens equal collateral received | **CRITICAL** | Function-level |
| TRD-FS-20 | #if_succeeds | For NORMAL type: direct token transfers are 1:1 | **CRITICAL** | Function-level |
| TRD-FS-21 | #if_succeeds | Price improvement always goes to taker | HIGH | Function-level |
| TRD-FS-22 | #if_succeeds | Total value in equals total value out (conservation of value) | **CRITICAL** | Function-level |

### Function: _fillOrder(Order takerOrder, Order makerOrder, uint256 fillAmount)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| TRD-FS-23 | #if_succeeds | Calculated makerAmount = (fillAmount * makerOrder.makerAmount) / makerOrder.takerAmount | **CRITICAL** | Function-level |
| TRD-FS-24 | #if_succeeds | No rounding errors favor the exchange | **CRITICAL** | Function-level |
| TRD-FS-25 | #if_succeeds | Fees are symmetric for maker and taker | HIGH | Function-level |
| TRD-FS-26 | #if_succeeds | After fees, maker receives exactly their expected amount | **CRITICAL** | Function-level |

### Function: _validateOrder(Order order)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| TRD-FS-27 | #if_succeeds | Order.maker is not zero address | **CRITICAL** | Function-level |
| TRD-FS-28 | #if_succeeds | Order amounts (makerAmount, takerAmount) are non-zero | **CRITICAL** | Function-level |
| TRD-FS-29 | #if_succeeds | Order.nonce equals nonces[order.maker] | **CRITICAL** | Function-level |
| TRD-FS-30 | #if_succeeds | block.timestamp <= order.expiration | **CRITICAL** | Function-level |
| TRD-FS-31 | #if_succeeds | Order.feeRateBps <= MAX_FEE_RATE | HIGH | Function-level |

### Function: _deriveMatchType(Order takerOrder, Order makerOrder)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| TRD-FS-32 | #if_succeeds | Returns NORMAL when both sides trade same token type | HIGH | Function-level |
| TRD-FS-33 | #if_succeeds | Returns MINT when sides trade complementary outcome tokens | **CRITICAL** | Function-level |
| TRD-FS-34 | #if_succeeds | Returns MERGE when positions can be merged | **CRITICAL** | Function-level |
| TRD-FS-35 | #if_succeeds | Tokens must be registered in Registry before matching | **CRITICAL** | Function-level |

### Inline Assertions for _matchOrders

| ID | Property Type | Description | Severity | Location |
|----|--------------|-------------|----------|----------|
| TRD-AS-01 | #assert | Each iteration: makerFillAmounts[i] > 0 | **CRITICAL** | Inside maker order loop |
| TRD-AS-02 | #assert | Each iteration: makerOrders[i].remaining >= makerFillAmounts[i] | **CRITICAL** | Inside maker order loop |
| TRD-AS-03 | #assert | Before MINT: sum of collateral from both sides equals tokens to mint | **CRITICAL** | Before CTF.splitPosition |
| TRD-AS-04 | #assert | Before MERGE: both complementary tokens exist in sufficient quantity | **CRITICAL** | Before CTF.mergePositions |
| TRD-AS-05 | #assert | After transfers: no tokens left in exchange contract (except fees) | **CRITICAL** | After all transfers |

---

## 3. CTFExchange.sol - Entry Point Properties

### Function: fillOrder(Order order, uint256 fillAmount)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| CTF-FS-01 | #if_succeeds | NonReentrant modifier prevents reentrancy | **CRITICAL** | Function-level |
| CTF-FS-02 | #if_succeeds | Delegates to _fillOrder with same parameters | HIGH | Function-level |

### Function: matchOrders(Order takerOrder, Order[] makerOrders, uint256 takerFillAmount, uint256[] makerFillAmounts)

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| CTF-FS-03 | #if_succeeds | Only operator can call (onlyOperator modifier) | **CRITICAL** | Function-level |
| CTF-FS-04 | #if_succeeds | NonReentrant modifier prevents reentrancy | **CRITICAL** | Function-level |
| CTF-FS-05 | #if_succeeds | Contract must not be paused (notPaused modifier) | **CRITICAL** | Function-level |

---

## 4. Cross-Contract Properties (AssetOperations & Registry Integration)

### Asset Transfer Properties

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| AST-FS-01 | #if_succeeds | ERC20 transfers: balanceAfter = balanceBefore ± amount | **CRITICAL** | AssetOperations._transfer |
| AST-FS-02 | #if_succeeds | ERC1155 transfers: balanceAfter = balanceBefore ± amount | **CRITICAL** | AssetOperations._transfer |
| AST-FS-03 | #if_succeeds | No tokens stuck in contract after successful operation | **CRITICAL** | Multiple functions |

### Mint/Merge Properties

| ID | Property Type | Description | Severity | Annotation |
|----|--------------|-------------|----------|------------|
| AST-FS-04 | #if_succeeds | MINT: collateral spent equals token amount minted | **CRITICAL** | AssetOperations._mint |
| AST-FS-05 | #if_succeeds | MERGE: complementary tokens burned equals collateral received | **CRITICAL** | AssetOperations._merge |
| AST-FS-06 | #if_succeeds | ConditionId must be registered before MINT/MERGE | **CRITICAL** | Registry integration |
| AST-FS-07 | #if_succeeds | Complement token validation: token + complement must sum to valid set | **CRITICAL** | Registry validation |

---

## 5. Additional Helper Properties

### User-Defined Scribble Functions

These helper functions should be defined at contract level to simplify property expressions:

```solidity
/// #define isValidNonce(address maker, uint256 nonce) bool = nonces[maker] == nonce;
/// #define isNotExpired(uint256 expiration) bool = block.timestamp <= expiration;
/// #define isFeeValid(uint256 feeRateBps) bool = feeRateBps <= MAX_FEE_RATE;
/// #define areComplementary(uint256 token1, uint256 token2) bool = registry.validateComplement(token1, token2);
/// #define calculateMakerAmount(uint256 fillAmount, uint256 makerAmount, uint256 takerAmount) uint256 = (fillAmount * makerAmount) / takerAmount;
```

---

## Summary Statistics

### Properties by Severity
- **CRITICAL**: 59 properties (Fund theft, Infinite minting, Signature bypass)
- **HIGH**: 13 properties (Temporary freeze, Logic errors)
- **MEDIUM**: 0 properties

### Properties by Type
- **#invariant**: 4 contract-level invariants
- **#if_succeeds**: 62 function postconditions
- **#if_updated**: 3 state variable conditions
- **#assert**: 5 inline assertions
- **Total**: 74 properties

### Coverage by Contract
- **Signatures.sol**: 12 properties
- **Trading.sol**: 48 properties
- **CTFExchange.sol**: 5 properties
- **Cross-contract**: 9 properties

---

## Next Steps

1. **Review & Confirm**: Please review these properties and confirm alignment with Immunefi bounty priorities
2. **Property Refinement**: Any properties to add, modify, or remove?
3. **Proceed to Part B**: Once confirmed, we'll annotate each contract with Scribble syntax
4. **Mythril Execution**: Generate solc-json remapping files for each contract's dependencies

**Estimated Annotation Time**: 4-6 hours per contract (8-12 hours total for Batch 1)
