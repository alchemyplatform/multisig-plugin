// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UpgradeableModularAccount} from "@alchemy/modular-account/src/account/UpgradeableModularAccount.sol";
import {IEntryPoint} from "@alchemy/modular-account/src/interfaces/erc4337/IEntryPoint.sol";
import {UserOperation} from "@alchemy/modular-account/src/interfaces/erc4337/UserOperation.sol";
import {MultiOwnerModularAccountFactory} from "@alchemy/modular-account/src/factory/MultiOwnerModularAccountFactory.sol";
import {MultiOwnerPlugin} from "@alchemy/modular-account/src/plugins/owner/MultiOwnerPlugin.sol";
import {IMultiOwnerPlugin} from "@alchemy/modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";
import {FunctionReference} from "@alchemy/modular-account/src/interfaces/IPluginManager.sol";
import {FunctionReferenceLib} from "@alchemy/modular-account/src/helpers/FunctionReferenceLib.sol";

import {CounterPlugin} from "../src/CounterPlugin.sol";

contract CounterTest is Test {
    using ECDSA for bytes32;

    IEntryPoint entryPoint;
    UpgradeableModularAccount account1;
    CounterPlugin counterPlugin;
    address owner1;
    uint256 owner1Key;
    address[] public owners;
    address payable beneficiary;

    uint256 constant CALL_GAS_LIMIT = 70000;
    uint256 constant VERIFICATION_GAS_LIMIT = 1000000;

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));

        // setup plugins and factory
        MultiOwnerPlugin multiOwnerPlugin = new MultiOwnerPlugin();
        MultiOwnerModularAccountFactory factory = new MultiOwnerModularAccountFactory(
            address(this),
            address(multiOwnerPlugin),
            address(new UpgradeableModularAccount(entryPoint)),
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );

        beneficiary = payable(makeAddr("beneficiary"));

        (owner1, owner1Key) = makeAddrAndKey("owner1");
        owners = new address[](1);
        owners[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));
        vm.deal(address(account1), 100 ether);

        counterPlugin = new CounterPlugin();
        bytes32 manifestHash = keccak256(abi.encode(counterPlugin.pluginManifest()));

        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );

        vm.prank(owner1);
        account1.installPlugin({
            plugin: address(counterPlugin),
            manifestHash: manifestHash,
            pluginInstallData: "0x",
            dependencies: dependencies
        });
    }

    function test_Increment() public {
        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(CounterPlugin.increment, ()),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(counterPlugin.count(address(account1)), 1);
    }
}
