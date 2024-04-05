// This file is part of Multisig Plugin.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/Test.sol";

import {IEntryPoint as I4337EntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {UpgradeableModularAccount} from "@alchemy/modular-account/src/account/UpgradeableModularAccount.sol";
import {IEntryPoint} from "@alchemy/modular-account/src/interfaces/erc4337/IEntryPoint.sol";

import {MultisigModularAccountFactory} from "../src/MultisigModularAccountFactory.sol";
import {MultisigPlugin} from "../src/MultisigPlugin.sol";

contract GetInitcodeHash is Script {
    // Load entrypoint from env
    address public entryPointAddr = vm.envAddress("ENTRYPOINT");
    IEntryPoint public entryPoint = IEntryPoint(payable(entryPointAddr));

    // Load factory owner from env
    address public owner = vm.envAddress("OWNER");

    // Load core contract from env
    address public maImpl = vm.envAddress("MA_IMPL");

    address public multisigPluginAddress = vm.envAddress("MULTISIG_PLUGIN");

    function run() public {
        console.log("******** Calculating Initcode Hashes *********");
        console.log("Chain: ", block.chainid);
        console.log("EP: ", entryPointAddr);
        console.log("Factory owner: ", owner);
        console.log("Modular Account implementation: ", maImpl);
        console.log("Multisig plugin address (for factory calculation): ", multisigPluginAddress);

        bytes memory multisigInitcode = abi.encodePacked(type(MultisigPlugin).creationCode, abi.encode(entryPointAddr));

        bytes32 multisigInitcodeHash = keccak256(multisigInitcode);

        console.log("Multisig plugin initcode hash:");
        console.logBytes32(multisigInitcodeHash);

        // Deploy the multisig plugin in the script environment to read the manifest
        MultisigPlugin tempMultisigPlugin = new MultisigPlugin(address(entryPoint));

        bytes32 multisigPluginManifestHash = keccak256(abi.encode(tempMultisigPlugin.pluginManifest()));

        console.log("Calculated multisig plugin manifest hash:");
        console.logBytes32(multisigPluginManifestHash);

        bytes memory factoryInitcode = abi.encodePacked(
            type(MultisigModularAccountFactory).creationCode,
            abi.encode(owner, multisigPluginAddress, maImpl, multisigPluginManifestHash, entryPoint)
        );

        bytes32 factoryInitcodeHash = keccak256(factoryInitcode);

        console.log("Factory initcode hash:");
        console.logBytes32(factoryInitcodeHash);
    }
}
