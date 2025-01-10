// SPDX-License-Identifier: AGPL-3.0-or-later

// Copyright (C) 2024 Dai Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.21;

import "dss-test/DssTest.sol";
import "dss-interfaces/Interfaces.sol";
import "erc4626-tests/ERC4626.test.sol";

import { UsdcVault } from "src/UsdcVault.sol";
import { UsdcVaultInstance } from "deploy/UsdcVaultInstance.sol";
import { UsdcVaultDeploy } from "deploy/UsdcVaultDeploy.sol";

contract UsdcVaultERC4626Test is DssTest, ERC4626Test {

    DssInstance dss;
    UsdcVault usdcVault;
    address sUsds;
    address pauseProxy;
    address pocket;
    address vat;
    address vow;
    address usdsJoin;

    function setUp() public override {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));

        ChainlogAbstract LOG = ChainlogAbstract(0xdA0Ab1e0017DEbCd72Be8599041a2aa3bA7e740F);
        dss = MCD.loadFromChainlog(LOG);
         
        pauseProxy   = LOG.getAddress("MCD_PAUSE_PROXY");
        pocket       = LOG.getAddress("MCD_LITE_PSM_USDC_A_POCKET");
        address usdc = LOG.getAddress("USDC");
        sUsds        = LOG.getAddress("SUSDS");
        vat          = LOG.getAddress("MCD_VAT");
        vow          = LOG.getAddress("MCD_VOW");
        usdsJoin     = LOG.getAddress("USDS_JOIN");
        
        UsdcVaultInstance memory inst = UsdcVaultDeploy.deploy(address(this), pauseProxy);
        usdcVault = UsdcVault(inst.usdcVault);

        _underlying_ = address(usdc);
        _vault_ = address(usdcVault);
        _delta_ = 0;
        _vaultMayBeEmpty = true;
        _unlimitedAmount = false;

        VatAbstract(vat).hope(address(usdsJoin));
    }

    // setup initial vault state
    function setUpVault(Init memory init) public override {
        uint256 maxShare = usdcVault.maxMint(address(0)) / N;
        uint256 maxAsset = usdcVault.maxDeposit(address(0)) / N;
        for (uint256 i = 0; i < N; i++) {
            init.share[i] %= maxShare;
            init.asset[i] %= maxAsset;

            address user = init.user[i];
            uint256 shares = init.share[i];
            uint256 assets = init.asset[i];
            
            vm.assume(user != address(0) && _isEOA(user) && user != pocket);
            vm.assume(IERC4626(_vault_).balanceOf(user) == 0 && IMockERC20(_underlying_).balanceOf(user) == 0);

            uint256 assetsForShares = usdcVault.previewMint(shares);
            deal(_underlying_, user, assets + assetsForShares, true);
            _approve(_underlying_, user, _vault_, assetsForShares);
            vm.prank(user); uint256 depositedAssets = IERC4626(_vault_).mint(shares, user);
            assertEq(depositedAssets, assetsForShares);
            assertEq(IERC4626(_vault_).balanceOf(user), shares);
            assertEq(IMockERC20(_underlying_).balanceOf(user), assets);
        }

        setUpYield(init);
    }

    // setup initial yield
    function setUpYield(Init memory init) public override {
        vm.assume(init.yield >= 0);
        init.yield %= 1_000_000 * 10**6;
        uint256 gain = uint256(init.yield);

        uint256 supply = IERC4626(sUsds).totalSupply();
        if (supply > 0) {
            uint256 nChi = gain * RAY / supply + usdcVault.chi();
            uint256 chiRho = (block.timestamp << 192) + nChi;
            vm.store(
                sUsds,
                bytes32(uint256(5)),
                bytes32(chiRho)
            );
            assertEq(uint256(usdcVault.chi()), nChi);
            assertEq(uint256(usdcVault.rho()), block.timestamp);
            vm.prank(pauseProxy); VatAbstract(vat).suck(vow, address(this), gain * RAY);
            DaiJoinAbstract(usdsJoin).exit(sUsds, gain);
        }
    }

}
