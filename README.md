## Multisig Plugin

Multisig Plugin is an ERC6900-compatible k-of-n ownership plugin that supports both EOA and smart contract owners.

## Overview

This repository contains:
1. An ERC6900-compatible k-of-n Multisig Plugin
2. A factory contract that deploys [Modular Account](https://github.com/alchemyplatform/modular-account)s with Multisig Plugin installed

The plugin conforms to these ERC versions:
- ERC-4337: [0.6.0](https://github.com/eth-infinitism/account-abstraction/blob/releases/v0.6/eip/EIPS/eip-4337.md)
- ERC-6900: [0.7.0](https://github.com/erc6900/reference-implementation/blob/v0.7.x/standard/ERCs/erc-6900.md)

The core features are:
1. Variable gas limits on User Operations
2. The k-th signer only needs to sign once

## Development

### Building and testing

```bash
# Build options
forge build
FOUNDRY_PROFILE=lite forge build
FOUNDRY_PROFILE=optimized-build forge build --sizes

# Lint
pnpm lint

# Test Options
forge test -vvv
FOUNDRY_PROFILE=lite forge test -vvv
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