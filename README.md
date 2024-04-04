## Multisig Plugin

Multisig Plugin is an ERC6900-compatible k-of-n ownership plugin that supports both EOA and smart contract owners.

## Overview

This repository contains:
1. An ERC6900-compatible k-of-n Multisig Plugin
2. A factory contract that deploys [Modular Account](https://github.com/alchemyplatform/modular-account)s with Multisig Plugin installed

The plugin conforms to these ERC versions:
- ERC-4337: [0.6.0](https://github.com/eth-infinitism/account-abstraction/blob/releases/v0.6/eip/EIPS/eip-4337.md)
- ERC-6900: [0.7.0](https://github.com/erc6900/reference-implementation/blob/v0.7.x/standard/ERCs/erc-6900.md)

## Core Functionalities

Multisig Plugin is an plugin that provides validation functions for a k-of-n ownership scheme. **Multisig validation only works in the user operation context.**

Its core features include:
1. Multisig user operation validation on native account functions (`installPlugin`, `uninstallPlugin`, `execute`, `executeBatch`, `upgradeToAndCall`).
2. An execution function that modifies account ownership by adding or removing owners, and/or modifies the threshold. This is guarded by the above validation function.
3. Support for ERC-1271 smart contract signatures based on the same multisig scheme.
4. Variable gas feature that allows for more flexibility and control over gas spent.

### Technical Decisions

**Multisig validation scheme is applied only for the User Operation context**  
We expect multisig signers to implement key management best practices such as key rotation. By using the user operation path, keys can be used just for signing without needing to procure native tokens for gas. Like other ERC-4337 operations, the transaction would be paid for by the account or by a paymaster service.

**Variable gas feature**  
User operations contain several gas/fee related fields - `preVerificationGas`, `maxFeePerGas` and `maxPriorityFeePerGas` - that specify the maximum fees that can be used for the user op. These fields are used to form `userOpHash` which has to be signed over by the k signers. If collecting the k signatures takes too long, it's likely that network prices would have shifted. If the userop is overpriced, the account would end up overpaying for transaction inclusion. However, if the userop is underpriced, the bundler would reject the user op and the k signers have to re-sign this user operation.

This Multisig plugin includes a variable gas feature to address this problem. The fee values selected and signed over by the first k-1 signers is treated as a "maximum fee" and the k-th signer is able to choose final fee values to use based on the current network conditions. With this feature, there is no longer a risk of overpaying, or having to re-collect the k signatures.

**Multisig signature spec**  
The multisig signature scheme has the following format:

`k signatures` || `contract signatures (if any)`

Each signature in the `k signatures` is sorted in ascending order by owner address, is 65 bytes long, uses packed encoding and has the following format:
1. If it's an EOA signature, `signature = abi.encodePacked(r, s, v)`
2. If it's a contract signature, it is also `abi.encodePacked(r, s, v)` with `v` set to 0, `r` set to the address of the contract owner packed to 32 bytes, and `s` being the bytes offset of where the actual signature is located. This is relative to the starting location of `k signatures`. The actual contract signature has regular abi encoding, appended after the k signatures.

The above is the format for a ERC1271 signature. However, for user operation signatures, we prepend the above signature with 3 gas values from the variable gas feature to form this full signature:  
`uint256 upperLimitPreVerificationGas` || `uint256 upperLimitMaxFeePerGas` || `uint256 upperLimitMaxPriorityFeePerGas` || `k signatures` || `contract signatures (if any)`

Lastly, if the variable gas feature is used, we increment the `v` value of the k-th signature to denote that the signature is over the actual gas values. The other signatures would be verified against the `userOpHash` containing the above upper limit gas values.

## Development

### Building and testing

```bash
# Build
forge build

# Lint
pnpm lint

# Test
forge test -vvv
```

### Deployment

A deployment script can be found in the `scripts/` folder

```bash
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

## Security and audits

TBD

## Acknowledgements

The signature verification logic takes inspiration from the work done by [Gnosis Safe](https://github.com/safe-global/safe-smart-account).

## License

The Multisig Plugin code is licensed under the GNU General Public License v3.0, also included in our repository in [LICENSE-GPL](LICENSE-GPL).

Alchemy Insights, Inc., 548 Market St., PMB 49099, San Francisco, CA 94104; legal@alchemy.com