# Spark USDC Vault

An ERC4626-compliant tokenized vault contract for USDC, which handles USDC deposits by converting USDC to USDS using [dss-lite-psm](https://github.com/makerdao/dss-lite-psm) (through the [UsdsPsmWrapper](https://github.com/makerdao/usds-wrappers/blob/dev/src)) and depositing USDS into [sUSDS](https://github.com/makerdao/sdai/tree/susds). To handle USDC withdrawals, the vault withdraws USDS from sUSDS and converts USDS back to USDC using dss-lite-psm.

## Deposits

When a user deposits USDC into the vault, the vault converts the user's USDC into USDS which it deposits into sUSDS, thereby receiving minted sUSDS shares (held by the vault on behalf of the user), before minting an equal amount of Spark USDC Vault shares to the user.

In case the PSM's `tin` parameter is non zero, users must pay more than 1 USDC per converted USDS, implying that withdrawing from the vault soon after depositing into it may result in a loss for the user. If the USDC-to-USDS PSM conversion is turned off (`tin == type(uint256).max`), attempts to deposit USDC into the Spark USDC Vault will revert.

## Withdrawals

When a user redeems its Spark USDC Vault shares, the vault burns the user's Spark USDC Vault shares, redeems the sUSDS shares it holds on behalf of the user and converts the obtained USDS into USDC, which it sends to the user.

In case the PSM's `tout` parameter is non zero, users receive less than 1 USDC per converted USDS, implying that withdrawing from the vault soon after depositing into it may result in a loss for the user. If the USDS-to-USDC PSM conversion is turned off (`tout == type(uint256).max`), attempts to withdraw USDC from the Spark USDC Vault will revert.

### Escape hatch

The vault offers the possibility to redeem sUSDS instead of USDC, which may be advantageous to users when the PSM has large `tout` fees or has USDS-to-USDC conversions turned off.

## Upgradability

The contract uses the ERC-1822 UUPS pattern for upgradeability and the ERC-1967 proxy storage slots standard.
It is important that the `UsdcVaultDeploy` library sequence be used for deploying.

#### OZ upgradeability validations

The OZ validations can be run alongside the existing tests:  
`VALIDATE=true forge test --ffi --build-info --extra-output storageLayout`

## Referral Code

The `deposit` and `mint` functions accept an optional `uint16 referral` parameter that frontends can use to mark deposits as originating from them. Such deposits emit a `Referral(uint16 indexed referral, address indexed owner, uint256 assets, uint256 shares)` event. This could be used to implement a revshare campaign, in which case the off-chain calculation scheme will likely need to keep track of any `Transfer` and `Withdraw` events following a `Referral` for a given token owner.

## Sanity checks

Manual review should be done on the deployed UsdcVault contract to replace the sanity checks that are usually done in an init lib.

For example, the following manual validations will be required:

- Verify that calling `version()` on the proxy returns `"1"`
- Verify that calling `getImplementation()` on the proxy returns the address of the implementation contract.
- Verify that calling `psm()` on the proxy returns the expected `UsdsPsmWrapper` address.
- Verify that calling `susds()` on the proxy returns the expected `sUsds` address.

## L2 Version

This repository also contains a version of the vault for L2 deployments. It interacts with the Spark [PSM3 contract](https://github.com/marsfoundation/spark-psm/blob/master/src/PSM3.sol).
The sUSDS and PSM getters that exist on the mainnet version are omitted here on purpose. The conversion rate can be fetched from the rate provider.

## General Notes

- In case the PSM has outflow fees, the escape hatch should not be viewed as a means to avoid them, as it does not use the PSM and does not swap to USDC.
- The available liquidity for the different operations (except `exit`) is limited by the PSM funds. It is taken into account in the `max*` functions. This is especially important for `withdraw` and `redeem`, which rely on USDC availability.
- As when working directly with the PSM, front-runners can cause operations to revert by swapping or withdrawing liquidity. This can be partly mitigated by using private transactions, when available. Also fees could be added, if supported by the PSM (initially relevant to mainnet). In case this becomes a severe problem, the escape hatch mechanism can be used by the user to extract their funds in sUSDS form.
- As in the ERC4626 spec, the functions that adhere to its format assume that slippage protection, if needed, is added in a separate layer.
- It is assumed that if the PSM funds are migrated and/or the PSM to be used changes, upgrading the vault will be considered as part of that process (and in the same spell if needed). That process is assumed to be examined carefully.
- The view functions assume that the system is set up correctly and works as intended. They do not check things like allowances or unexpected token implementation changes.
- L1 sUSDS and L2 PSM referral codes are passed as 0. It is assumed that only deposit referral codes will be tracked when using the vault.
