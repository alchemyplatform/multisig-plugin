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

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {UpgradeableModularAccount} from "@alchemy/modular-account/src/account/UpgradeableModularAccount.sol";
import {IEntryPoint} from "@alchemy/modular-account/src/interfaces/erc4337/IEntryPoint.sol";

import {MultisigModularAccountFactory} from "../src/MultisigModularAccountFactory.sol";
import {IMultisigPlugin} from "../src/IMultisigPlugin.sol";
import {MultisigPlugin} from "../src/MultisigPlugin.sol";

contract MultisigModularAccountFactoryTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    MultisigModularAccountFactory public factory;
    MultisigPlugin public multisigPlugin;
    address public impl;

    address public notOwner = address(1);
    address public owner1 = address(2);
    address public owner2 = address(3);
    address public badImpl = address(4);

    address[] public owners;
    address[] public largeOwners;

    uint256 internal constant _MAX_OWNERS_ON_CREATION = 100;

    function setUp() public {
        owners.push(owner1);
        owners.push(owner2);
        entryPoint = new EntryPoint();
        impl = address(new UpgradeableModularAccount(IEntryPoint(address(entryPoint))));
        multisigPlugin = new MultisigPlugin();
        bytes32 manifestHash = keccak256(abi.encode(multisigPlugin.pluginManifest()));
        factory = new MultisigModularAccountFactory(
            address(this), address(multisigPlugin), impl, manifestHash, IEntryPoint(address(entryPoint))
        );
        for (uint160 i = 0; i < _MAX_OWNERS_ON_CREATION; i++) {
            largeOwners.push(address(i + 1));
        }
        vm.deal(address(this), 100 ether);
    }

    function test_addressMatch() public {
        address predicted = factory.getAddress(0, owners, 1, 0);
        address deployed = factory.createAccount(0, owners, 1, 0);
        assertEq(predicted, deployed);
    }

    function test_deploy() public {
        address deployed = factory.createAccount(0, owners, 1, 0);

        // test that the deployed account is initialized
        assertEq(address(UpgradeableModularAccount(payable(deployed)).entryPoint()), address(entryPoint));

        // test that the deployed account installed owner plugin correctly
        (address[] memory actualOwners,,) = multisigPlugin.ownershipInfoOf(deployed);
        assertEq(actualOwners.length, 2);
        assertEq(actualOwners[0], owner2);
        assertEq(actualOwners[1], owner1);
    }

    function test_deployCollision() public {
        address deployed = factory.createAccount(0, owners, 1, 0);

        uint256 gasStart = gasleft();

        // deploy 2nd time which should short circuit
        // test for short circuit -> call should cost less than a CREATE2, or 32000 gas
        address secondDeploy = factory.createAccount(0, owners, 1, 0);

        assertApproxEqAbs(gasleft(), gasStart, 31999);
        assertEq(deployed, secondDeploy);
    }

    function test_deployedAccountHasCorrectPlugins() public {
        address deployed = factory.createAccount(0, owners, 1, 0);

        // check installed plugins on account
        address[] memory plugins = UpgradeableModularAccount(payable(deployed)).getInstalledPlugins();
        assertEq(plugins.length, 1);
        assertEq(plugins[0], address(multisigPlugin));
    }

    function test_badOwnersArray() public {
        vm.expectRevert(MultisigModularAccountFactory.OwnersArrayEmpty.selector);
        factory.getAddress(0, new address[](0), 1, 0);

        address[] memory badOwners = new address[](2);

        vm.expectRevert(MultisigModularAccountFactory.InvalidOwner.selector);
        factory.getAddress(0, badOwners, 1, 0);

        badOwners[0] = address(1);
        badOwners[1] = address(1);

        vm.expectRevert(MultisigModularAccountFactory.InvalidOwner.selector);
        factory.getAddress(0, badOwners, 1, 0);
    }

    function test_badThreshold() public {
        vm.expectRevert(MultisigModularAccountFactory.InvalidThreshold.selector);
        factory.createAccount(0, owners, 3, 0);

        vm.expectRevert(MultisigModularAccountFactory.InvalidThreshold.selector);
        factory.getAddress(0, owners, 3, 0);

        vm.expectRevert(MultisigModularAccountFactory.InvalidThreshold.selector);
        factory.createAccount(0, owners, 0, 0);

        vm.expectRevert(MultisigModularAccountFactory.InvalidThreshold.selector);
        factory.getAddress(0, owners, 0, 0);
    }

    function test_addStake() public {
        assertEq(entryPoint.balanceOf(address(factory)), 0);
        vm.deal(address(this), 100 ether);
        factory.addStake{value: 10 ether}(10 hours, 10 ether);
        assertEq(entryPoint.getDepositInfo(address(factory)).stake, 10 ether);
    }

    function test_unlockStake() public {
        test_addStake();
        factory.unlockStake();
        assertEq(entryPoint.getDepositInfo(address(factory)).withdrawTime, block.timestamp + 10 hours);
    }

    function test_withdrawStake() public {
        test_unlockStake();
        vm.warp(10 hours);
        vm.expectRevert("Stake withdrawal is not due");
        factory.withdrawStake(payable(address(this)));
        assertEq(address(this).balance, 90 ether);
        vm.warp(10 hours + 1);
        factory.withdrawStake(payable(address(this)));
        assertEq(address(this).balance, 100 ether);
    }

    function test_withdraw() public {
        factory.addStake{value: 10 ether}(10 hours, 1 ether);
        assertEq(address(factory).balance, 9 ether);
        factory.withdraw(payable(address(this)), address(0), 0); // amount = balance if native currency
        assertEq(address(factory).balance, 0);
    }

    function test_2StepOwnershipTransfer() public {
        assertEq(factory.owner(), address(this));
        factory.transferOwnership(owner1);
        assertEq(factory.owner(), address(this));
        vm.prank(owner1);
        factory.acceptOwnership();
        assertEq(factory.owner(), owner1);
    }

    function test_getAddressWithMaxOwnersAndDeploy() public {
        address addr = factory.getAddress(0, largeOwners, 1, 0);
        assertEq(addr, factory.createAccount(0, largeOwners, 1, 0));
    }

    function test_getAddressWithTooManyOwners() public {
        largeOwners.push(address(101));
        vm.expectRevert(MultisigModularAccountFactory.OwnersLimitExceeded.selector);
        factory.getAddress(0, largeOwners, 1, 0);
    }

    function test_getAddressWithUnsortedOwners() public {
        address[] memory tempOwners = new address[](2);
        tempOwners[0] = address(2);
        tempOwners[1] = address(1);
        vm.expectRevert(MultisigModularAccountFactory.InvalidOwner.selector);
        factory.getAddress(0, tempOwners, 1, 0);
    }

    function test_deployWithDuplicateOwners() public {
        address[] memory tempOwners = new address[](2);
        tempOwners[0] = address(1);
        tempOwners[1] = address(1);
        vm.expectRevert(MultisigModularAccountFactory.InvalidOwner.selector);
        factory.createAccount(0, tempOwners, 1, 0);
    }

    function test_deployWithUnsortedOwners() public {
        address[] memory tempOwners = new address[](2);
        tempOwners[0] = address(2);
        tempOwners[1] = address(1);
        vm.expectRevert(MultisigModularAccountFactory.InvalidOwner.selector);
        factory.createAccount(0, tempOwners, 1, 0);
    }

    // to receive funds from withdraw
    receive() external payable {}
}
