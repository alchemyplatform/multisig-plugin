## Multisig Plugin

This repository contains an ERC6900 compatible k-of-n Multisig Plugin and a factory contract that deploys [Modular Accounts](https://github.com/alchemyplatform/modular-account) with Multisig Plugin installed. 

The signature verification design took inspiration from [Safe](https://github.com/safe-global/safe-smart-account). 

ERC4337 User Operations require gas fields to be specified and signed over which presents a problem - if the time taken between the first and the k-th signer is long, and the network's gas prices spike, there is a risk that the user operation would not be included.

We implemented a variable gas price feature to address this. The first k-1 signers can specify an upper limit gas bound that the transaction should cost, and the kth signer can choose how much the transaction will cost before submitting it as long as it's below the upper limit set by the first k-1 signers. This reduces the risk of having to collect k signatures again without having to overpay.

## Testing and Deploying

```forge test``` to test

```forge scripts script/Deploy.s.sol``` to deploy