// This file is part of Modular Account.
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

import {Test, console} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {PluginManifest} from "@alchemy/modular-account/src/interfaces/IPlugin.sol";
import {BasePlugin} from "@alchemy/modular-account/src/plugins/BasePlugin.sol";
import {UserOperation} from "@alchemy/modular-account/src/interfaces/erc4337/UserOperation.sol";
import {IEntryPoint} from "@alchemy/modular-account/src/interfaces/erc4337/IEntryPoint.sol";

import {MultisigPlugin} from "../src/MultisigPlugin.sol";
import {IMultisigPlugin} from "../src/IMultisigPlugin.sol";
import {MockContractOwner} from "./mocks/MockContractOwner.sol";

contract MultisigPluginTest is Test {
    using ECDSA for bytes32;

    MultisigPlugin plugin;
    address accountA; // using a contract since plugins require callers to be contracts
    address ownerToAdd = address(2);
    address[] ownersToAdd;
    bytes4 internal _1271_MAGIC_VALUE = 0x1626ba7e;
    IEntryPoint entryPoint;

    // Re-declare events for vm.expectEmit
    event OwnerUpdated(address indexed account, address[] addedOwners, address[] removedOwners, uint256 newThreshold);

    struct Owner {
        address signer;
        address owner; // different from signer for contract owner
        uint256 privateKey;
    }

    function _createAccountOwner(uint256 seed) internal returns (Owner memory) {
        (address signer, uint256 privateKey) = makeAddrAndKey(string(abi.encodePacked(seed)));
        MockContractOwner m = new MockContractOwner(signer);
        return Owner({signer: signer, owner: address(m), privateKey: privateKey});
    }

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        plugin = new MultisigPlugin(address(entryPoint));
        accountA = address(new MockContractOwner(address(0)));
        ownersToAdd.push(ownerToAdd);
        vm.prank(accountA);
        plugin.onInstall(abi.encode(ownersToAdd, 1)); // not contract caller
    }

    function test_pluginManifest() public {
        PluginManifest memory manifest = plugin.pluginManifest();
        // 3 execution functions
        assertEq(3, manifest.executionFunctions.length);
        // 5 native + 1 plugin exec func
        assertEq(6, manifest.userOpValidationFunctions.length);
        // 5 native + 1 plugin exec func + 2 plugin view func
        assertEq(8, manifest.runtimeValidationFunctions.length);
    }

    function test_onInstall_success() public {
        uint256 threshold = 1;

        vm.expectEmit(true, true, true, true);
        emit OwnerUpdated(address(this), ownersToAdd, new address[](0), 1);

        plugin.onInstall(abi.encode(ownersToAdd, threshold));
        (address[] memory returnedOwners, uint256 actualThreshold) = plugin.ownershipInfoOf(address(this));
        assertEq(returnedOwners.length, 1);
        assertEq(returnedOwners[0], ownerToAdd);
        assertEq(actualThreshold, threshold);
    }

    function test_onUninstall_success() public {
        vm.expectEmit(true, true, true, true);
        emit OwnerUpdated(accountA, new address[](0), ownersToAdd, 0);

        vm.prank(accountA);
        plugin.onUninstall(abi.encode(""));
        (address[] memory returnedOwners, uint256 actualThreshold) = plugin.ownershipInfoOf(accountA);
        assertEq(returnedOwners.length, 0);
        assertEq(actualThreshold, 0);
    }

    function test_eip712Domain() public {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = plugin.eip712Domain();
        assertEq(fields, hex"1f");
        assertEq(name, "Multisig Plugin");
        assertEq(version, "1.0.0");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(this));
        assertEq(salt, bytes32(bytes20(address(plugin))));
        assertEq(extensions.length, 0);
    }

    function test_updateOwners_failWithEmptyOwners() public {
        vm.expectRevert(IMultisigPlugin.EmptyOwnersNotAllowed.selector);
        vm.prank(accountA);
        plugin.updateOwnership(new address[](0), ownersToAdd, 0);
    }

    function test_updateOwners_failWithZeroAddressOwner() public {
        address[] memory badOwnersToAdd = new address[](1);

        vm.startPrank(accountA);
        vm.expectRevert(abi.encodeWithSelector(IMultisigPlugin.InvalidOwner.selector, address(0)));
        plugin.updateOwnership(badOwnersToAdd, new address[](0), 0);
    }

    function test_updateOwners_failWithDuplicatedAddresses() public {
        address[] memory badOwnersToAdd = new address[](2);
        badOwnersToAdd[0] = ownerToAdd;
        badOwnersToAdd[1] = ownerToAdd;

        vm.expectRevert(abi.encodeWithSelector(IMultisigPlugin.InvalidOwner.selector, ownerToAdd));
        vm.prank(accountA);
        plugin.updateOwnership(badOwnersToAdd, new address[](0), 0);
    }

    function test_updateOwners_failExceedThreshold() public {
        vm.expectRevert(abi.encodeWithSelector(IMultisigPlugin.InvalidThreshold.selector));
        vm.prank(accountA);
        plugin.updateOwnership(new address[](0), new address[](0), 2);
    }

    function test_updateOwners_failWithNotExist() public {
        address[] memory ownersToRemove = new address[](1);
        ownersToRemove[0] = address(3);

        vm.expectRevert(abi.encodeWithSelector(IMultisigPlugin.OwnerDoesNotExist.selector, ownersToRemove[0]));
        vm.prank(accountA);
        plugin.updateOwnership(new address[](0), ownersToRemove, 0);
    }

    function test_updateOwners_success() public {
        vm.startPrank(accountA);

        // remove should also work
        address[] memory ownersToRemove = new address[](1);
        ownersToRemove[0] = ownerToAdd; // was added in setup

        address newOwner = address(3);
        address newOwner2 = address(4);
        address[] memory ownersToAdd1 = new address[](2);
        ownersToAdd1[0] = newOwner;
        ownersToAdd1[1] = newOwner2;

        uint128 newThreshold = 2;

        vm.expectEmit(true, true, true, true);
        emit OwnerUpdated(accountA, ownersToAdd1, ownersToRemove, newThreshold);

        plugin.updateOwnership(ownersToAdd1, ownersToRemove, newThreshold);

        (address[] memory newOwnerList, uint256 actualThreshold) = plugin.ownershipInfoOf(accountA);
        assertEq(newOwnerList.length, 2);
        assertEq(newOwnerList[0], newOwner2);
        assertEq(newOwnerList[1], newOwner);
        assertEq(actualThreshold, newThreshold);
    }

    function testFuzz_isValidSignature_EOAOwner(string memory salt, bytes32 digest) public {
        vm.startPrank(accountA);

        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);
        bytes32 messageDigest = plugin.getMessageHash(address(accountA), abi.encode(digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageDigest);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = signer;

        if (!plugin.isOwnerOf(accountA, signer)) {
            // sig check should fail
            assertEq(bytes4(0xFFFFFFFF), plugin.isValidSignature(digest, abi.encodePacked(r, s, v)));

            plugin.updateOwnership(ownersToAdd1, new address[](0), 0);
        }

        // sig check should pass
        assertEq(_1271_MAGIC_VALUE, plugin.isValidSignature(digest, abi.encodePacked(r, s, v)));
    }

    function testFuzz_isValidSignature_ContractOwner(uint256 seed, bytes32 digest) public {
        vm.startPrank(accountA);

        Owner memory newOwner = _createAccountOwner(seed);
        bytes32 messageDigest = plugin.getMessageHash(address(accountA), abi.encode(digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwner.privateKey, messageDigest);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = newOwner.owner;

        bytes memory sig = abi.encodePacked(abi.encode(newOwner.owner), uint256(65), uint8(0), uint256(65), r, s, v);

        if (!plugin.isOwnerOf(accountA, newOwner.owner)) {
            // sig check should fail
            assertEq(bytes4(0xFFFFFFFF), plugin.isValidSignature(digest, abi.encodePacked(r, s, v)));

            plugin.updateOwnership(ownersToAdd1, new address[](0), 0);
        }

        assertEq(_1271_MAGIC_VALUE, plugin.isValidSignature(digest, sig));
    }

    function test_runtimeValidationFunction_OwnerOrSelf(uint8 functionId) public {
        vm.expectRevert(
            abi.encodeWithSelector(
                BasePlugin.NotImplemented.selector, BasePlugin.runtimeValidationFunction.selector, functionId
            )
        );
        plugin.runtimeValidationFunction(functionId, accountA, 0, "");
    }

    function test_multiOwnerPlugin_sentinelIsNotOwner() public {
        assertFalse(plugin.isOwnerOf(accountA, address(1)));
    }

    function test_failUserOpValidationFunction_EOAOwner() public {
        vm.startPrank(accountA);

        uint256 gasPrice = 50 gwei;

        UserOperation memory userOp;
        userOp.preVerificationGas = gasPrice; // note: technically this should be a gas price * gas value number
        userOp.maxFeePerGas = gasPrice;
        userOp.maxPriorityFeePerGas = gasPrice;

        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey("test_failUserOpValidationFunction_EOAOwner");
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        userOp.signature = abi.encodePacked(gasPrice, gasPrice, gasPrice, r, s, v);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = signer;

        // Only check that the signature should fail if the signer is not already an owner
        if (!plugin.isOwnerOf(accountA, signer)) {
            // should fail without owner access
            assertEq(
                plugin.userOpValidationFunction(
                    uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
                ),
                1
            );

            // add signer to owner
            plugin.updateOwnership(ownersToAdd1, new address[](0), 0);
        }

        // sig check should pass
        assertEq(
            plugin.userOpValidationFunction(
                uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
            ),
            0
        );
    }

    function test_failUserOpValidation_SigLenTooShort() public {
        vm.startPrank(accountA);

        UserOperation memory userOp;
        userOp.signature = new bytes(95);
        vm.expectRevert(abi.encodeWithSelector(IMultisigPlugin.InvalidSigLength.selector));
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, bytes32(0));
    }

    function test_failUserOpValidation_SigLenTooLong(uint256 seed, UserOperation memory userOp) public {
        vm.startPrank(accountA);

        userOp.signature = new bytes(95);
        vm.expectRevert(abi.encodeWithSelector(IMultisigPlugin.InvalidSigLength.selector));
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, bytes32(0));

        vm.startPrank(accountA);

        Owner memory newOwner = _createAccountOwner(seed);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwner.privateKey, userOpHash.toEthSignedMessageHash());

        userOp.signature = abi.encodePacked(
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            abi.encode(newOwner.owner),
            uint256(65),
            uint8(0),
            uint256(65),
            r,
            s,
            v
        );

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = newOwner.owner;

        // Only check that the signature should fail if the signer is not already an owner
        if (!plugin.isOwnerOf(accountA, newOwner.owner)) {
            // should fail without owner access
            assertEq(
                plugin.userOpValidationFunction(
                    uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
                ),
                1
            );

            // add signer to owner
            plugin.updateOwnership(ownersToAdd1, new address[](0), 0);
        }

        // sig check should pass
        assertEq(
            plugin.userOpValidationFunction(
                uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
            ),
            0
        );

        // append bytes to sig - should fail
        userOp.signature = abi.encodePacked(userOp.signature, bytes1(0));
        vm.expectRevert(abi.encodeWithSelector(IMultisigPlugin.InvalidSigLength.selector));
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);

        // extension in the middle also fails
        userOp.signature = abi.encodePacked(
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            abi.encode(newOwner.owner),
            uint256(66),
            uint8(0),
            uint256(65),
            bytes1(0), // bad byte
            r,
            s,
            v
        );
        vm.expectRevert(abi.encodeWithSelector(IMultisigPlugin.InvalidSigOffset.selector));
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    }

    function test_failUserOpValidation_SigOffset() public {
        vm.startPrank(accountA);

        UserOperation memory userOp;

        Owner memory newOwner = _createAccountOwner(uint256(keccak256("test_failUserOpValidation_SigOffset")));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwner.privateKey, userOpHash.toEthSignedMessageHash());

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = newOwner.owner;

        userOp.signature = abi.encodePacked(
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            abi.encode(newOwner.owner),
            uint256(65),
            uint8(0),
            uint256(65),
            r,
            s,
            v
        );

        // Only check that the signature should fail if the signer is not already an owner
        if (!plugin.isOwnerOf(accountA, newOwner.owner)) {
            // should fail without owner access BUT not revert like below
            assertEq(
                plugin.userOpValidationFunction(
                    uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
                ),
                1
            );

            // add signer to owner
            plugin.updateOwnership(ownersToAdd1, new address[](0), 0);
        }

        // sig check should fail
        userOp.signature = abi.encodePacked(
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            abi.encode(newOwner.owner),
            uint256(64),
            uint8(0),
            uint256(65),
            r,
            s,
            v
        );
        vm.expectRevert(abi.encodeWithSelector(IMultisigPlugin.InvalidSigOffset.selector));
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);

        userOp.signature = abi.encode(
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            abi.encode(newOwner.owner),
            uint256(131),
            uint8(0),
            uint256(65),
            r,
            s,
            v
        );
        vm.expectRevert(abi.encodeWithSelector(IMultisigPlugin.InvalidSigOffset.selector));
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    }

    function test_fuzzFailUserOpValidationFunction_BadGas(string memory salt, UserOperation memory userOp) public {
        vm.startPrank(accountA);

        vm.assume(userOp.preVerificationGas != 0);
        vm.assume(userOp.maxFeePerGas != 0);
        vm.assume(userOp.maxPriorityFeePerGas != 0);

        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        userOp.signature =
            abi.encodePacked(userOp.preVerificationGas, userOp.maxFeePerGas, userOp.maxPriorityFeePerGas, r, s, v);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = signer;

        // Only check that the signature should fail if the signer is not already an owner
        if (!plugin.isOwnerOf(accountA, signer)) {
            // should fail without owner access BUT not revert like below
            assertEq(
                plugin.userOpValidationFunction(
                    uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
                ),
                1
            );

            // add signer to owner
            plugin.updateOwnership(ownersToAdd1, new address[](0), 0);
        }

        // sig check should fail
        userOp.signature =
            abi.encodePacked(userOp.preVerificationGas - 1, userOp.maxFeePerGas, userOp.maxPriorityFeePerGas, r, s, v);
        vm.expectRevert(IMultisigPlugin.InvalidGasValues.selector);
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);

        userOp.signature =
            abi.encodePacked(userOp.preVerificationGas, userOp.maxFeePerGas - 1, userOp.maxPriorityFeePerGas, r, s, v);
        vm.expectRevert(IMultisigPlugin.InvalidGasValues.selector);
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);

        userOp.signature =
            abi.encodePacked(userOp.preVerificationGas, userOp.maxFeePerGas, userOp.maxPriorityFeePerGas - 1, r, s, v);
        vm.expectRevert(IMultisigPlugin.InvalidGasValues.selector);
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    }

    // This test checks the "upper bound invariant"
    // In the worst case scenario (2/2 multisig), if signer A signs with some gas values, signer B should
    // not be able to pass validation with a userop with gas values higher than what A signed over
    function test_fuzzFailUserOpValidationFunction_BadGas2(UserOperation memory userOp) public {
        vm.startPrank(accountA);

        uint256 maxUint256 = type(uint256).max;

        vm.assume(userOp.preVerificationGas != maxUint256);
        vm.assume(userOp.maxFeePerGas != maxUint256);
        vm.assume(userOp.maxPriorityFeePerGas != maxUint256);

        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey("1");
        (address signer2, uint256 privateKey2) = makeAddrAndKey("2");

        address[] memory ownersToAdd1 = new address[](2);
        ownersToAdd1[0] = signer;
        ownersToAdd1[1] = signer2;

        // Only check that the signature should fail if the signer is not already an owner
        if (!plugin.isOwnerOf(accountA, signer)) {
            // add signer to owner
            plugin.updateOwnership(ownersToAdd1, new address[](0), 2);
        }

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        // sig check should fail
        uint256 originalPreVerificationGas = userOp.preVerificationGas;
        userOp.preVerificationGas = maxUint256;
        (uint8 v2, bytes32 r2, bytes32 s2) =
            vm.sign(privateKey2, entryPoint.getUserOpHash(userOp).toEthSignedMessageHash());
        v += 32; // signer2 trying to use signer1's sig as upper bound
        bytes memory sig =
            signer > signer2 ? abi.encodePacked(r, s, v, r2, s2, v2) : abi.encodePacked(r2, s2, v2, r, s, v);
        userOp.signature =
            abi.encodePacked(originalPreVerificationGas, userOp.maxFeePerGas, userOp.maxPriorityFeePerGas, sig);
        vm.expectRevert(IMultisigPlugin.InvalidPreVerificationGas.selector);
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);

        uint256 originalMaxFeePerGas = userOp.maxFeePerGas;
        userOp.maxFeePerGas = maxUint256;
        (v2, r2, s2) = vm.sign(privateKey2, entryPoint.getUserOpHash(userOp).toEthSignedMessageHash());
        v += 32; // signer2 trying to use signer1's sig as upper bound
        sig = signer > signer2 ? abi.encodePacked(r, s, v, r2, s2, v2) : abi.encodePacked(r2, s2, v2, r, s, v);
        userOp.signature =
            abi.encodePacked(userOp.preVerificationGas, originalMaxFeePerGas, userOp.maxPriorityFeePerGas, sig);
        vm.expectRevert(IMultisigPlugin.InvalidMaxFeePerGas.selector);
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);

        uint256 originalMaxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        userOp.maxPriorityFeePerGas = maxUint256;
        (v2, r2, s2) = vm.sign(privateKey2, entryPoint.getUserOpHash(userOp).toEthSignedMessageHash());
        v += 32; // signer2 trying to use signer1's sig as upper bound
        sig = signer > signer2 ? abi.encodePacked(r, s, v, r2, s2, v2) : abi.encodePacked(r2, s2, v2, r, s, v);
        userOp.signature =
            abi.encodePacked(userOp.preVerificationGas, userOp.maxFeePerGas, originalMaxPriorityFeePerGas, sig);
        vm.expectRevert(IMultisigPlugin.InvalidMaxPriorityFeePerGas.selector);
        plugin.userOpValidationFunction(uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash);
    }

    function testFuzz_userOpValidationFunction_EOAOwner(string memory salt, UserOperation memory userOp) public {
        vm.startPrank(accountA);

        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        userOp.signature =
            abi.encodePacked(userOp.preVerificationGas, userOp.maxFeePerGas, userOp.maxPriorityFeePerGas, r, s, v);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = signer;

        // Only check that the signature should fail if the signer is not already an owner
        if (!plugin.isOwnerOf(accountA, signer)) {
            // should fail without owner access
            assertEq(
                plugin.userOpValidationFunction(
                    uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
                ),
                1
            );

            // add signer to owner
            plugin.updateOwnership(ownersToAdd1, new address[](0), 0);
        }

        // sig check should pass
        assertEq(
            plugin.userOpValidationFunction(
                uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
            ),
            0
        );
    }

    function testFuzz_userOpValidationFunction_ContractOwner(uint256 seed, UserOperation memory userOp) public {
        vm.startPrank(accountA);

        Owner memory newOwner = _createAccountOwner(seed);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwner.privateKey, userOpHash.toEthSignedMessageHash());

        userOp.signature = abi.encodePacked(
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            abi.encode(newOwner.owner),
            uint256(65),
            uint8(0),
            uint256(65),
            r,
            s,
            v
        );

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = newOwner.owner;

        // Only check that the signature should fail if the signer is not already an owner
        if (!plugin.isOwnerOf(accountA, newOwner.owner)) {
            // should fail without owner access
            assertEq(
                plugin.userOpValidationFunction(
                    uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
                ),
                1
            );

            // add signer to owner
            plugin.updateOwnership(ownersToAdd1, new address[](0), 0);
        }

        // sig check should pass
        assertEq(
            plugin.userOpValidationFunction(
                uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
            ),
            0
        );
    }

    function testFuzz_userOpValidationFunction_Multisig(uint256 k, uint256 n, UserOperation memory userOp) public {
        // making sure numbers are sensible
        n %= 11;
        vm.assume(n > 0);

        k %= 11;
        k %= n;
        vm.assume(k > 0);

        // get all owners
        Owner[] memory owners = new Owner[](n);
        address[] memory ownersToAdd1 = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 seed = k + n + i;
            if (seed % 2 == 0) {
                owners[i] = _createAccountOwner(seed);
                ownersToAdd1[i] = owners[i].owner;
            } else {
                (address signer, uint256 privateKey) = makeAddrAndKey(string(abi.encodePacked(seed)));
                owners[i] = Owner({signer: signer, owner: signer, privateKey: privateKey});
                ownersToAdd1[i] = signer;
            }
        }

        // sort owners
        uint256 minIdx;
        for (uint256 i = 0; i < n; i++) {
            minIdx = i;
            for (uint256 j = i; j < n; j++) {
                if (owners[j].owner < owners[minIdx].owner) {
                    minIdx = j;
                }
            }
            (owners[i], owners[minIdx]) = (owners[minIdx], owners[i]);
        }

        plugin.onInstall(abi.encode(ownersToAdd1, k));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        userOp.signature = bytes("");
        bytes memory contractSigs = bytes("");
        uint256 offset = k * 65;
        for (uint256 i = 0; i < k; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owners[i].privateKey, userOpHash.toEthSignedMessageHash());
            // EOA case
            if (owners[i].signer == owners[i].owner) {
                userOp.signature = abi.encodePacked(userOp.signature, abi.encodePacked(r, s, v));
            } else {
                userOp.signature =
                    abi.encodePacked(userOp.signature, abi.encode(owners[i].owner), uint256(offset), uint8(0));
                offset += 97; // 65 + 32 for length
                contractSigs = abi.encodePacked(contractSigs, uint256(65), r, s, v);
            }
        }
        userOp.signature = abi.encodePacked(
            userOp.preVerificationGas, userOp.maxFeePerGas, userOp.maxPriorityFeePerGas, userOp.signature, contractSigs
        );

        // sig check should pass
        assertEq(
            plugin.userOpValidationFunction(
                uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
            ),
            0
        );
    }

    function testFuzz_userOpValidationFunction_Multisig_VariableGas(uint256 k, uint256 n, UserOperation memory userOp)
        public
    {
        // making sure numbers are sensible
        n %= 11;
        vm.assume(n > 0);

        k %= 11;
        k %= n;
        vm.assume(k > 0);

        vm.assume(userOp.preVerificationGas != 0);
        vm.assume(userOp.maxFeePerGas != 0);
        vm.assume(userOp.maxPriorityFeePerGas != 0);

        // get all owners
        Owner[] memory owners = new Owner[](n);
        address[] memory ownersToAdd1 = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 seed = k + n + i;
            if (seed % 2 == 0) {
                owners[i] = _createAccountOwner(seed);
                ownersToAdd1[i] = owners[i].owner;
            } else {
                (address signer, uint256 privateKey) = makeAddrAndKey(string(abi.encodePacked(seed)));
                owners[i] = Owner({signer: signer, owner: signer, privateKey: privateKey});
                ownersToAdd1[i] = signer;
            }
        }

        // sort owners
        uint256 minIdx;
        for (uint256 i = 0; i < n; i++) {
            minIdx = i;
            for (uint256 j = i; j < n; j++) {
                if (owners[j].owner < owners[minIdx].owner) {
                    minIdx = j;
                }
            }
            (owners[i], owners[minIdx]) = (owners[minIdx], owners[i]);
        }

        // grab a ~random owner in the first k sigs to be the last signer
        // last signer must sign over actual gas vals used
        address finalOwnerAddr = owners[n % k].owner;

        plugin.onInstall(abi.encode(ownersToAdd1, k));
        bytes32 maxGasUserOpHash = entryPoint.getUserOpHash(userOp);
        uint256 upperLimitPreVerificationGas = userOp.preVerificationGas;
        uint256 upperLimitMaxFeePerGas = userOp.maxFeePerGas;
        uint256 upperLimitMaxPriorityFeePerGas = userOp.maxPriorityFeePerGas;

        // use 0 as the actual gas vals
        userOp.preVerificationGas = 0;
        userOp.maxFeePerGas = 0;
        userOp.maxPriorityFeePerGas = 0;
        bytes32 actualGasUserOpHash = entryPoint.getUserOpHash(userOp);

        userOp.signature = bytes("");
        bytes memory contractSigs = bytes("");
        uint256 offset = k * 65;
        for (uint256 i = 0; i < k; i++) {
            uint8 v;
            bytes32 r;
            bytes32 s;

            // if final owner, sign the digest with lower gas
            if (owners[i].owner == finalOwnerAddr) {
                (v, r, s) = vm.sign(owners[i].privateKey, actualGasUserOpHash.toEthSignedMessageHash());
            } else {
                (v, r, s) = vm.sign(owners[i].privateKey, maxGasUserOpHash.toEthSignedMessageHash());
            }

            // EOA case
            if (owners[i].signer == owners[i].owner) {
                if (owners[i].owner == finalOwnerAddr) {
                    v += 32;
                }
                userOp.signature = abi.encodePacked(userOp.signature, abi.encodePacked(r, s, v));
            } else {
                userOp.signature = abi.encodePacked(
                    userOp.signature,
                    abi.encode(owners[i].owner),
                    uint256(offset),
                    owners[i].owner == finalOwnerAddr ? uint8(32) : uint8(0)
                );
                offset += 97; // 65 + 32 for length
                contractSigs = abi.encodePacked(contractSigs, uint256(65), r, s, v);
            }
        }
        userOp.signature = abi.encodePacked(
            upperLimitPreVerificationGas,
            upperLimitMaxFeePerGas,
            upperLimitMaxPriorityFeePerGas,
            userOp.signature,
            contractSigs
        );

        // sig check should pass
        assertEq(
            plugin.userOpValidationFunction(
                uint8(IMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, actualGasUserOpHash
            ),
            0
        );
    }

    function test_pluginInitializeGuards() public {
        vm.startPrank(accountA);
        plugin.onUninstall(bytes(""));

        address[] memory addrArr = new address[](1);
        addrArr[0] = address(this);

        // can't transfer owner if not initialized yet
        vm.expectRevert(abi.encodeWithSelector(BasePlugin.NotInitialized.selector));
        plugin.updateOwnership(addrArr, new address[](0), 0);

        // can't oninstall twice
        plugin.onInstall(abi.encode(addrArr, 1));
        vm.expectRevert(abi.encodeWithSelector(BasePlugin.AlreadyInitialized.selector));
        plugin.onInstall(abi.encode(addrArr, 1));
    }
}
