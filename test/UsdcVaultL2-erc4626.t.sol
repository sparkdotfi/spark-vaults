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

import { UsdcVaultL2 } from "src/UsdcVaultL2.sol";
import { UsdcVaultInstance } from "deploy/UsdcVaultInstance.sol";
import { UsdcVaultL2Deploy } from "deploy/UsdcVaultL2Deploy.sol";

interface PsmLike {
    function usdc() external view returns (address);
    function susds() external view returns (address);
    function pocket() external view returns (address);
    function rateProvider() external view returns (address);
}

interface RateProviderLike {
    struct SUSDSData {
        uint96  ssr;
        uint120 chi;
        uint40  rho;
    }
    function getSSR() external view returns (uint256);
    function getChi() external view returns (uint256);
    function getRho() external view returns (uint256);
    function setSUSDSData(SUSDSData calldata nextData) external;
}

contract UsdcVaultL2ERC4626Test is DssTest, ERC4626Test {

    UsdcVaultL2 usdcVault;
    PsmLike psm;
    address sUsds;
    address owner = address(0x987);
    address pocket;
    RateProviderLike rateProvider;
    address baseReceiver;

    function setUp() public override {
        vm.createSelectFork(vm.envString("BASE_RPC_URL"));

        psm          = PsmLike(0x1601843c5E9bC251A3272907010AFa41Fa18347E); // https://github.com/marsfoundation/spark-address-registry/blob/0894d151cab9cc50dcf49c4c32e6469b16b391a1/src/Base.sol#L28
        pocket       = psm.pocket();
        address usdc = psm.usdc();
        sUsds        = psm.susds();
        rateProvider = RateProviderLike(psm.rateProvider());
        baseReceiver = 0x212871A1C235892F86cAB30E937e18c94AEd8474; // https://github.com/marsfoundation/spark-address-registry/blob/0894d151cab9cc50dcf49c4c32e6469b16b391a1/src/Base.sol#L53


        UsdcVaultInstance memory inst = UsdcVaultL2Deploy.deploy(address(this), owner, address(psm));
        usdcVault = UsdcVaultL2(inst.usdcVault);

        _underlying_ = address(usdc);
        _vault_ = address(usdcVault);
        _delta_ = 0;
        _vaultMayBeEmpty = true;
        _unlimitedAmount = false;
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

            // Avoid invalid amount reverts
            vm.assume(usdcVault.convertToAssets(shares) > 0);
            vm.assume(usdcVault.convertToShares(assets) > 0);

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

        // We take the L2 supply, so gain is distributed only on the L2. Good enough for our purpose.
        uint256 supply = IERC4626(sUsds).totalSupply();
        if (supply > 0) {
            vm.startPrank(baseReceiver);
            rateProvider.setSUSDSData(RateProviderLike.SUSDSData({
                ssr: uint96(rateProvider.getSSR()),
                chi: uint120(gain * RAY / supply + rateProvider.getChi()),
                rho: uint40(block.timestamp)
            }));
            vm.stopPrank();
        }
    }
}
