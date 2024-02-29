// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {BasePlugin} from "@alchemy/modular-account/src/plugins/BasePlugin.sol";
import {IPluginExecutor} from "@alchemy/modular-account/src/interfaces/IPluginExecutor.sol";
import {SIG_VALIDATION_PASSED} from "@alchemy/modular-account/src/libraries/Constants.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata,
    IPlugin
} from "@alchemy/modular-account/src/interfaces/IPlugin.sol";

/// @title Counter Plugin
/// @author Alchemy
/// @notice This plugin lets increment a count!
contract CounterPlugin is BasePlugin {
    string public constant NAME = "Counter Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "Alchemy";

    mapping(address => uint256) public count;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function increment() external {
        count[msg.sender]++;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    // solhint-disable-next-line no-empty-blocks
    function onInstall(bytes calldata) external pure override {}

    /// @inheritdoc BasePlugin
    // solhint-disable-next-line no-empty-blocks
    function onUninstall(bytes calldata) external pure override {}

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.dependencyInterfaceIds = new bytes4[](1);
        manifest.dependencyInterfaceIds[0] = type(IPlugin).interfaceId;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.increment.selector;

        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // unused since it's a dependency
            dependencyIndex: 0 // <-- the index of the multi owner function
        });

        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.increment.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;
        return metadata;
    }
}
