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
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { VatAbstract, PotAbstract, ChainlogAbstract } from "dss-interfaces/Interfaces.sol";
import { UsdcVaultL2 } from "src/UsdcVaultL2.sol";

interface TokenLike {
    function approve(address, uint256) external;
    function balanceOf(address) external view returns (uint256);
}

interface PsmLike {
    function usdc() external view returns (address);
    function susds() external view returns (address);
    function usds() external view returns (address);
}

contract Handler is StdUtils, StdCheats {
    Vm         public vm;
    TokenLike  public usdc;
    TokenLike  public susds;
    TokenLike  public usds;
    UsdcVaultL2  public vault;
    mapping(bytes32 => uint256) public numCalls;

    constructor(
        Vm      vm_,
        address usdc_,
        address susds_,
        address usds_,
        address vault_
    ) {
        vm         = vm_;
        usdc       = TokenLike(usdc_);
        susds      = TokenLike(susds_);
        usds       = TokenLike(usds_);
        vault      = UsdcVaultL2(vault_);
    }

    function warp(uint256 secs) external {
        numCalls["warp"]++;
        secs = bound(secs, 0, 365 days);
        vm.warp(block.timestamp + secs);
    }

    function vdeposit(uint256 assets) external {
        numCalls["vdeposit"]++;
        deal(address(usdc), address(this), assets);
        usdc.approve(address(vault), assets);
        vault.deposit(assets, address(this));
    }

    function vmint(uint256 shares) external {
        numCalls["vmint"]++;
        uint256 assets = vault.previewMint(shares);
        deal(address(usdc), address(this), assets);
        usdc.approve(address(vault), assets);
        vault.mint(shares, address(this));
    }

    function vwithdraw(uint256 assets) external {
        numCalls["vwithdraw"]++;
        assets = bound(assets, 0, vault.maxWithdraw(address(this)));
        vault.withdraw(assets, address(this), address(this));
    }

    function vwithdrawAll() external {
        numCalls["vwithdrawAll"]++;
        vault.withdraw(vault.maxWithdraw(address(this)), address(this), address(this));
    }

    function vredeem(uint256 shares) external {
        numCalls["vredeem"]++;
        shares = bound(shares, 0, vault.maxRedeem(address(this)));
        vault.redeem(shares, address(this), address(this));
    }

    function vredeemAll() external {
        numCalls["vredeemAll"]++;
        vault.redeem(vault.maxRedeem(address(this)), address(this), address(this));
    }

    function vexit(uint256 shares) external {
        numCalls["vexit"]++;
        shares = bound(shares, 0, vault.balanceOf(address(this)));
        vault.exit(shares, address(this), address(this));
    }
}

contract SUsdsInvariantsTest is DssTest {
    TokenLike   usdc;
    TokenLike   usds;
    TokenLike   susds;
    PsmLike     psm;
    UsdcVaultL2 vault;
    Handler     handler;

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_RPC_URL"));

        psm   = PsmLike(0x1601843c5E9bC251A3272907010AFa41Fa18347E); // https://github.com/marsfoundation/spark-address-registry/blob/0894d151cab9cc50dcf49c4c32e6469b16b391a1/src/Base.sol#L28
        usdc  = TokenLike(psm.usdc());
        usds  = TokenLike(psm.usds());
        susds = TokenLike(psm.susds());

        vault = UsdcVaultL2(address(new ERC1967Proxy(address(new UsdcVaultL2(address(psm))), abi.encodeCall(UsdcVaultL2.initialize, ()))));

        handler = new Handler(
            vm,
            address(usdc),
            address(susds),
            address(usds),
            address(vault)
        );

         // uncomment and fill to only call specific functions
        bytes4[] memory selectors = new bytes4[](8);
        selectors[0] = Handler.warp.selector;
        selectors[1] = Handler.vdeposit.selector;
        selectors[2] = Handler.vmint.selector;
        selectors[3] = Handler.vwithdraw.selector;
        selectors[4] = Handler.vwithdrawAll.selector;
        selectors[5] = Handler.vredeem.selector;
        selectors[6] = Handler.vredeemAll.selector;
        selectors[7] = Handler.vexit.selector;

        targetSelector(FuzzSelector({
            addr: address(handler),
            selectors: selectors
        }));

        targetContract(address(handler)); // invariant tests should fuzz only handler functions
    }

    function invariant_vault_total_supply_equals_susds_balance() external view {
        assertEq(vault.totalSupply(), susds.balanceOf(address(vault)));
    }

    function invariant_vault_usdc_and_usds_balance_is_0() external view {
        assertEq(usdc.balanceOf(address(vault)), 0);
        assertEq(usds.balanceOf(address(vault)), 0);
    }

    function invariant_call_summary() public view { // make external to enable
        console.log("------------------");

        console.log("\nCall Summary\n");
        console.log("warp",         handler.numCalls("warp"));
        console.log("vdeposit",     handler.numCalls("vdeposit"));
        console.log("vmint",        handler.numCalls("vmint"));
        console.log("vwithdraw",    handler.numCalls("vwithdraw"));
        console.log("vwithdrawAll", handler.numCalls("vwithdrawAll"));
        console.log("vredeem",      handler.numCalls("vredeem"));
        console.log("vredeemAll",   handler.numCalls("vredeemAll"));
        console.log("vexit",        handler.numCalls("vexit"));
    }
}
