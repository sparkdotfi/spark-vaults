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

import "token-tests/TokenFuzzChecks.sol";
import "dss-interfaces/Interfaces.sol";
import { Upgrades, Options } from "openzeppelin-foundry-upgrades/Upgrades.sol";

import { UsdcVault, UUPSUpgradeable, Initializable, ERC1967Utils } from "src/UsdcVault.sol";
import { UsdcVaultInstance } from "deploy/UsdcVaultInstance.sol";
import { UsdcVaultDeploy } from "deploy/UsdcVaultDeploy.sol";

interface PsmWrapperLike {
    function psm() external view returns (address);
}
interface PsmLike {
    function pocket() external view returns (address);
    function tin() external view returns (uint256);
    function tout() external view returns (uint256);
    function file(bytes32, uint256) external;
}

interface SUsdsLike is GemAbstract {
    function chi() external view returns (uint192);
    function rho() external view returns (uint64);
    function ssr() external view returns (uint256);
    function file(bytes32, uint256) external;
    function drip() external returns (uint256);
    function convertToShares(uint256) external view returns (uint256);
    function convertToAssets(uint256) external view returns (uint256);
    function previewDeposit(uint256) external view returns (uint256);
    function previewWithdraw(uint256) external view returns (uint256);
}

contract UsdcVault2 is UUPSUpgradeable {
    // Admin
    mapping (address => uint256) public wards;
    // ERC20
    uint256                                           public totalSupply;
    mapping (address => uint256)                      public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => uint256)                      public nonces;

    string public constant version = "2";

    event UpgradedTo(string version);

    modifier auth {
        require(wards[msg.sender] == 1, "UsdcVault/not-authorized");
        _;
    }

    constructor() {
        _disableInitializers(); // Avoid initializing in the context of the implementation
    }

    function reinitialize() reinitializer(2) external {
        emit UpgradedTo(version);
    }

    function _authorizeUpgrade(address newImplementation) internal override auth {}

    function getImplementation() external view returns (address) {
        return ERC1967Utils.getImplementation();
    }
}

contract UsdcVaultTest is TokenFuzzChecks {

    DssInstance dss;
    address pauseProxy;
    GemAbstract usdc;
    GemAbstract usds;
    SUsdsLike susds;
    address psmWrapper;
    address psm;
    address pocket;
    UsdcVault token;
    bool validate;

    event UpgradedTo(string version);
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
    event Exit(address indexed sender, address indexed receiver, address indexed owner, uint256 shares);
    event Referral(uint16 indexed referral, address indexed owner, uint256 assets, uint256 shares);

    function deployVault(address deployer, address owner) external returns (UsdcVaultInstance memory inst) {
        inst = UsdcVaultDeploy.deploy(deployer, owner);
    }

    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));
        validate = vm.envOr("VALIDATE", false);

        ChainlogAbstract LOG = ChainlogAbstract(0xdA0Ab1e0017DEbCd72Be8599041a2aa3bA7e740F);
        dss = MCD.loadFromChainlog(LOG);
        
        pauseProxy        = LOG.getAddress("MCD_PAUSE_PROXY");
        psmWrapper        = LOG.getAddress("WRAPPER_USDS_LITE_PSM_USDC_A");
        susds   = SUsdsLike(LOG.getAddress("SUSDS"));
        usdc  = GemAbstract(LOG.getAddress("USDC"));
        usds  = GemAbstract(LOG.getAddress("USDS"));
        psm = PsmWrapperLike(psmWrapper).psm();
        pocket = PsmLike(psm).pocket();

        vm.expectEmit(true, true, true, true);
        emit Rely(address(this));
        vm.expectEmit(true, true, true, true);
        emit Rely(pauseProxy);
        vm.expectEmit(true, true, true, true);
        emit Deny(address(this));

        UsdcVaultInstance memory inst = this.deployVault(address(this), pauseProxy);
        token = UsdcVault(inst.usdcVault);

        assertEq(address(token.psm()), psmWrapper);
        assertEq(address(token.usdc()), address(usdc));
        assertEq(address(token.susds()), address(susds));
        assertEq(usdc.allowance(address(token), psmWrapper), type(uint256).max);
        assertEq(usds.allowance(address(token), psmWrapper), type(uint256).max);
        assertEq(usds.allowance(address(token), address(susds)), type(uint256).max);
        assertEq(token.wards(address(this)), 0);
        assertEq(token.wards(pauseProxy), 1);
        assertEq(token.getImplementation(), inst.usdcVaultImp);
        assertEq(token.name(), "Spark USDC Vault");
        assertEq(token.symbol(), "sUSDC");
        assertEq(token.version(), "1");
        assertEq(token.decimals(), 18);

        susds.drip();
        vm.prank(pauseProxy); susds.file("ssr", 1000000001547125957863212448);

        deal(address(usdc), address(this), 200 * 10**6);
        usdc.approve(address(token), type(uint256).max);
    }

    function testGetters() public {
        assertEq(token.asset(), address(usdc));

        uint256 shares1 = token.deposit(12 * 10*6, address(222));
        assertEq(token.totalAssets(), susds.convertToAssets(shares1) / 10**12);
        vm.warp(block.timestamp + 365 days);
        uint256 shares2 = token.deposit(34 * 10*6, address(222));
        assertEq(token.totalAssets(), susds.convertToAssets(shares1 + shares2) / 10**12);

        assertEq(token.ssr(), susds.ssr());
        assertEq(token.rho(), susds.rho());
        assertEq(token.chi(), susds.chi());
        vm.warp(block.timestamp + 365 days);
        susds.drip();
        assertEq(token.rho(), susds.rho());
        assertEq(token.chi(), susds.chi());

        vm.prank(pauseProxy); PsmLike(psm).file("tin", 0.1234 ether);
        vm.prank(pauseProxy); PsmLike(psm).file("tout", 0.5678 ether);
        assertEq(token.tin(), 0.1234 ether);
        assertEq(token.tout(), 0.5678 ether);
    }

    function testDeployWithUpgradesLib() public {
        Options memory opts;
        if (!validate) {
            opts.unsafeSkipAllChecks = true;
        } else {
            opts.unsafeAllow = 'state-variable-immutable,constructor';
        }
        opts.constructorData = abi.encode(psmWrapper, address(susds));

        vm.expectEmit(true, true, true, true);
        emit Rely(address(this));
        address proxy = Upgrades.deployUUPSProxy(
            "out/UsdcVault.sol/UsdcVault.json",
            abi.encodeCall(UsdcVault.initialize, ()),
            opts
        );
        assertEq(UsdcVault(proxy).version(), "1");
        assertEq(UsdcVault(proxy).wards(address(this)), 1);
    }

    function testUpgrade() public {
        address implementation1 = token.getImplementation();

        address newImpl = address(new UsdcVault2());
        vm.startPrank(pauseProxy);
        vm.expectEmit(true, true, true, true);
        emit UpgradedTo("2");
        token.upgradeToAndCall(newImpl, abi.encodeCall(UsdcVault2.reinitialize, ()));
        vm.stopPrank();

        address implementation2 = token.getImplementation();
        assertEq(implementation2, newImpl);
        assertTrue(implementation2 != implementation1);
        assertEq(token.version(), "2");
        assertEq(token.wards(address(pauseProxy)), 1); // still a ward
    }

    function testUpgradeWithUpgradesLib() public {
        address implementation1 = token.getImplementation();

        Options memory opts;
        if (!validate) {
            opts.unsafeSkipAllChecks = true;
        } else {
            opts.referenceContract = "out/UsdcVault.sol/UsdcVault.json";
            opts.unsafeAllow = 'constructor';
        }

        vm.startPrank(pauseProxy);
        vm.expectEmit(true, true, true, true);
        emit UpgradedTo("2");
        Upgrades.upgradeProxy(
            address(token),
            "out/UsdcVault-integration.t.sol/UsdcVault2.json",
            abi.encodeCall(UsdcVault2.reinitialize, ()),
            opts
        );
        vm.stopPrank();

        address implementation2 = token.getImplementation();
        assertTrue(implementation1 != implementation2);
        assertEq(token.version(), "2");
        assertEq(token.wards(address(pauseProxy)), 1); // still a ward
    }

    function testUpgradeUnauthed() public {
        address newImpl = address(new UsdcVault2());
        vm.expectRevert("UsdcVault/not-authorized");
        vm.prank(address(0x123)); token.upgradeToAndCall(newImpl, abi.encodeCall(UsdcVault2.reinitialize, ()));
    }

    function testInitializeAgain() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        token.initialize();
    }

    function testInitializeDirectly() public {
        address implementation = token.getImplementation();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        UsdcVault(implementation).initialize();
    }

    function testAuth() public {
        checkAuth(address(token), "UsdcVault");
    }

    function testERC20() public {
        checkBulkERC20(address(token), "UsdcVault", "Spark USDC Vault", "sUSDC", "1", 18);
    }

    function testPermit() public {
        checkBulkPermit(address(token), "UsdcVault");
    }

    function testERC20Fuzz(
        address from,
        address to,
        uint256 amount1,
        uint256 amount2
    ) public {
        checkBulkERC20Fuzz(address(token), "UsdcVault", from, to, amount1, amount2);
    }

    function testPermitFuzz(
        uint128 privKey,
        address to,
        uint256 amount,
        uint256 deadline,
        uint256 nonce
    ) public {
        checkBulkPermitFuzz(address(token), "UsdcVault", privKey, to, amount, deadline, nonce);
    }

    function testConversion() public {
        assertGt(token.ssr(), 0);

        uint256 pshares = token.convertToShares(1e18);
        assertEq(pshares, SUsdsLike(susds).convertToShares(1e18 * 1e12));

        uint256 passets = token.convertToAssets(pshares);
        assertEq(passets, SUsdsLike(susds).convertToAssets(pshares) / 1e12);

        // Converting back and forth should always round against
        assertLe(passets, 1e18);

        // Accrue some interest
        vm.warp(block.timestamp + 1 days);

        uint256 shares = token.convertToShares(1e18);

        // Shares should be less because more interest has accrued
        assertLt(shares, pshares);
    }

    function testDepositMintBadAddress() public {
        vm.expectRevert("UsdcVault/invalid-address");
        token.deposit(1e6, address(0));
        vm.expectRevert("UsdcVault/invalid-address");
        token.deposit(1e6, address(token));
        vm.expectRevert("UsdcVault/invalid-address");
        token.mint(1e18, address(0));
        vm.expectRevert("UsdcVault/invalid-address");
        token.mint(1e18, address(token));
    }

    function _checkDepositWithdraw(uint256 depositedAssets, uint256 withdrawnAssets) internal {
        uint256 initialTokenSUsds = susds.balanceOf(address(token));
        uint256 initialPsmUsdc = usdc.balanceOf(pocket);
        uint256 initialSenderUsdc = usdc.balanceOf(address(this));
        uint256 initialReceiverShares = token.balanceOf(address(0x222));
        uint256 initialTotalShares = token.totalSupply();

        uint256 mintedShares = token.previewDeposit(depositedAssets);
        vm.expectRevert("UsdcVault/shares-too-low");
        token.deposit(depositedAssets, address(0x222), mintedShares + 1, 888);
        vm.expectEmit(true, true, true, true);
        emit Deposit(address(this), address(0x222), depositedAssets, mintedShares);
        vm.expectEmit(true, true, true, true);
        emit Referral(888, address(0x222), depositedAssets, mintedShares);
        uint256 shares = token.deposit(depositedAssets, address(0x222), mintedShares, 888);

        assertEq(shares, mintedShares);
        assertEq(token.totalSupply(), initialTotalShares + mintedShares);
        assertEq(token.balanceOf(address(0x222)), initialReceiverShares + mintedShares);
        assertEq(susds.balanceOf(address(token)), initialTokenSUsds + mintedShares);
        assertEq(usds.balanceOf(address(token)), 0);
        assertEq(usdc.balanceOf(address(token)), 0);
        assertEq(usdc.balanceOf(pocket), initialPsmUsdc + depositedAssets);
        assertEq(usdc.balanceOf(address(this)), initialSenderUsdc - depositedAssets);

        vm.warp(block.timestamp + 30 * 365 days); // long enough to be profitable even if tout and/or tin are as large as 0.5*WAD

        if (withdrawnAssets > 0) vm.expectRevert("UsdcVault/insufficient-balance");
        token.withdraw(withdrawnAssets, address(this), address(0xbad));
        if (withdrawnAssets > 0) vm.expectRevert("UsdcVault/insufficient-allowance");
        token.withdraw(withdrawnAssets, address(this), address(0x222));

        uint256 withdrawnByApproval = withdrawnAssets / 2;
        uint256 burnedByApproval = token.previewWithdraw(withdrawnByApproval);
        vm.expectEmit(true, true, true, true);
        emit Approval(address(0x222), address(this), burnedByApproval);
        vm.prank(address(0x222)); token.approve(address(this), burnedByApproval);
        if (burnedByApproval > 0) {
            vm.expectRevert("UsdcVault/shares-too-high");
            token.withdraw(withdrawnByApproval, address(this), address(0x222), burnedByApproval - 1);
        }
        if (mintedShares > 0) vm.expectRevert("UsdcVault/insufficient-allowance");
        else                  vm.expectRevert("SUsds/insufficient-balance");
        token.withdraw(withdrawnByApproval + 1, address(this), address(0x222));
        vm.expectEmit(true, true, true, true);
        emit Withdraw(address(this), address(this), address(0x222), withdrawnByApproval, burnedByApproval);
        shares = token.withdraw(withdrawnByApproval, address(this), address(0x222), burnedByApproval);
        assertEq(shares, burnedByApproval);

        uint256 withdrawnDirectly = withdrawnAssets - withdrawnByApproval;
        uint256 burnedDirectly = token.previewWithdraw(withdrawnDirectly);
        vm.expectEmit(true, true, true, true);
        emit Withdraw(address(0x222), address(this), address(0x222), withdrawnDirectly, burnedDirectly);
        vm.prank(address(0x222)); shares = token.withdraw(withdrawnDirectly, address(this), address(0x222));

        assertEq(shares, burnedDirectly);
        assertLe(burnedByApproval + burnedDirectly, mintedShares);
        assertEq(token.totalSupply(), initialTotalShares + mintedShares - burnedByApproval - burnedDirectly);
        assertEq(token.balanceOf(address(0x222)), initialReceiverShares + mintedShares - burnedByApproval - burnedDirectly);
        assertEq(susds.balanceOf(address(token)), initialTokenSUsds + mintedShares - burnedByApproval - burnedDirectly);
        assertLt(usds.balanceOf(address(token)), 1e12);
        assertEq(usdc.balanceOf(address(token)), 0);
        assertEq(usdc.balanceOf(pocket), initialPsmUsdc + depositedAssets - withdrawnAssets);
        assertEq(usdc.balanceOf(address(this)), initialSenderUsdc - depositedAssets + withdrawnAssets);
    }

    function testDepositWithdrawZeroPsmFee() public {
        vm.startPrank(pauseProxy);
        PsmLike(psm).file("tin", 0);
        PsmLike(psm).file("tout", 0);
        vm.stopPrank();

        _checkDepositWithdraw(100 * 10**6, 100 * 10**6);
    }

    function testDepositWithdrawNonZeroPsmFee() public {
        vm.startPrank(pauseProxy);
        PsmLike(psm).file("tin", 0.003 ether);
        PsmLike(psm).file("tout", 0.005 ether);
        vm.stopPrank();

        _checkDepositWithdraw(100 * 10**6, 100 * 10**6);
    }

    function testDepositWithdraw(uint256 tin, uint256 tout, uint256 deposited, uint256 withdrawn) public {
        tin %= 0.5 ether;
        tout %= 0.5 ether;
        vm.startPrank(pauseProxy);
        PsmLike(psm).file("tin", tin);
        PsmLike(psm).file("tout", tout);
        vm.stopPrank();

        deposited = bound(deposited, 0, token.maxDeposit(address(this)));
        deal(address(usdc), address(this), deposited);

        uint256 snap = vm.snapshot();
        token.deposit(deposited, address(0x222));
        vm.warp(block.timestamp + 30 * 365 days);
        withdrawn = bound(withdrawn, 0, token.maxWithdraw(address(0x222)));
        vm.revertTo(snap);

        _checkDepositWithdraw(deposited, withdrawn);
    }

    function _checkMintRedeem(uint256 mintedShares, uint256 redeemedShares) internal {
        uint256 initialTokenSUsds = susds.balanceOf(address(token));
        uint256 initialPsmUsdc = usdc.balanceOf(pocket);
        uint256 initialSenderUsdc = usdc.balanceOf(address(this));
        uint256 initialReceiverShares = token.balanceOf(address(0x222));
        uint256 initialTotalShares = token.totalSupply();

        uint256 depositedAssets = token.previewMint(mintedShares);
        if (depositedAssets > 0) {
            vm.expectRevert("UsdcVault/assets-too-high");
            token.mint(mintedShares, address(0x222), depositedAssets - 1, 888);
        }
        vm.expectEmit(true, true, true, true);
        emit Deposit(address(this), address(0x222), depositedAssets, mintedShares);
        vm.expectEmit(true, true, true, true);
        emit Referral(888, address(0x222), depositedAssets, mintedShares);
        uint256 assets = token.mint(mintedShares, address(0x222), depositedAssets, 888);

        assertEq(assets, depositedAssets);
        assertEq(token.totalSupply(), initialTotalShares + mintedShares);
        assertEq(token.balanceOf(address(0x222)), initialReceiverShares + mintedShares);
        assertEq(susds.balanceOf(address(token)), initialTokenSUsds + mintedShares);
        assertLt(usds.balanceOf(address(token)), 1e12);
        assertEq(usdc.balanceOf(address(token)), 0);
        assertEq(usdc.balanceOf(pocket), initialPsmUsdc + depositedAssets);
        assertEq(usdc.balanceOf(address(this)), initialSenderUsdc - depositedAssets);

        vm.warp(block.timestamp + 30 * 365 days); // long enough to be profitable even if tout and/or tin are as large as 0.5*WAD

        if (redeemedShares > 0) vm.expectRevert("UsdcVault/insufficient-balance");
        token.redeem(redeemedShares, address(this), address(0xbad));
        if (redeemedShares > 0) vm.expectRevert("UsdcVault/insufficient-allowance");
        token.redeem(redeemedShares, address(this), address(0x222));

        uint256 redeemedByApproval = redeemedShares / 2;
        uint256 withdrawnByApproval = token.previewRedeem(redeemedByApproval);
        vm.expectEmit(true, true, true, true);
        emit Approval(address(0x222), address(this), redeemedByApproval);
        vm.prank(address(0x222)); token.approve(address(this), redeemedByApproval);
        vm.expectRevert("UsdcVault/assets-too-low");
        token.redeem(redeemedByApproval, address(this), address(0x222), withdrawnByApproval + 1);
        if (mintedShares > 0) vm.expectRevert("UsdcVault/insufficient-allowance");
        else                  vm.expectRevert("SUsds/insufficient-balance");
        token.redeem(redeemedByApproval + 1, address(this), address(0x222));
        vm.expectEmit(true, true, true, true);
        emit Withdraw(address(this), address(this), address(0x222), withdrawnByApproval, redeemedByApproval);
        assets = token.redeem(redeemedByApproval, address(this), address(0x222), withdrawnByApproval);
        assertEq(assets, withdrawnByApproval);

        uint256 redeemedDirectly = redeemedShares - redeemedByApproval;
        uint256 withdrawnDirectly = token.previewRedeem(redeemedDirectly);
        vm.expectEmit(true, true, true, true);
        emit Withdraw(address(0x222), address(this), address(0x222), withdrawnDirectly, redeemedDirectly);
        vm.prank(address(0x222)); assets = token.redeem(redeemedDirectly, address(this), address(0x222));

        assertEq(assets, withdrawnDirectly);
        assertEq(token.totalSupply(), initialTotalShares + mintedShares - redeemedShares);
        assertEq(token.balanceOf(address(0x222)), initialReceiverShares + mintedShares - redeemedShares);
        assertEq(susds.balanceOf(address(token)), initialTokenSUsds + mintedShares - redeemedShares);
        assertLt(usds.balanceOf(address(token)), 4e12);
        assertEq(usdc.balanceOf(address(token)), 0);
        assertEq(usdc.balanceOf(pocket), initialPsmUsdc + depositedAssets - withdrawnByApproval - withdrawnDirectly);
        assertEq(usdc.balanceOf(address(this)), initialSenderUsdc - depositedAssets + withdrawnByApproval + withdrawnDirectly);
    }

    function testMintRedeemZeroPsmFee() public {
        uint256 shares = 100 * 10**18;
        vm.startPrank(pauseProxy);
        PsmLike(psm).file("tin", 0);
        PsmLike(psm).file("tout", 0);
        vm.stopPrank();

        _checkMintRedeem(shares, shares);
    }

    function testMintRedeemNonZeroPsmFee() public {
        uint256 shares = 100 * 10**18;
        vm.startPrank(pauseProxy);
        PsmLike(psm).file("tin", 0.003 ether);
        PsmLike(psm).file("tout", 0.005 ether);
        vm.stopPrank();

        _checkMintRedeem(shares, shares);
    }

    function testMintRedeem(uint256 tin, uint256 tout, uint256 minted, uint256 redeemed) public {
        tin %= 0.5 ether;
        tout %= 0.5 ether;
        vm.startPrank(pauseProxy);
        PsmLike(psm).file("tin", tin);
        PsmLike(psm).file("tout", tout);
        vm.stopPrank();

        minted = bound(minted, 0, token.maxMint(address(this))); 
        deal(address(usdc), address(this), token.previewMint(minted));

        uint256 snap = vm.snapshot();
        token.mint(minted, address(0x222));
        vm.warp(block.timestamp + 30 * 365 days);
        redeemed = bound(redeemed, 0, token.maxRedeem(address(0x222)));
        vm.revertTo(snap);

        _checkMintRedeem(minted, redeemed);
    }

    function testPsmDepositsDisabled() public {
        vm.prank(pauseProxy); PsmLike(psm).file("tin", WAD);

        uint256 maxDeposit = token.maxDeposit(address(this));
        assertEq(maxDeposit, 0);
        vm.expectRevert("UsdcVault/psm-sell-gem-halted");
        token.previewDeposit(0);
        vm.expectRevert("UsdcVault/psm-sell-gem-halted");
        token.deposit(0, address(this));

        uint256 maxMint = token.maxMint(address(this));
        assertEq(maxMint, 0);
        vm.expectRevert("UsdcVault/psm-sell-gem-halted");
        token.previewMint(0);
        vm.expectRevert("UsdcVault/psm-sell-gem-halted");
        token.mint(0, address(this));

        vm.prank(pauseProxy); PsmLike(psm).file("tin", type(uint256).max);

        maxDeposit = token.maxDeposit(address(this));
        assertEq(maxDeposit, 0);
        vm.expectRevert("UsdcVault/psm-sell-gem-halted");
        token.previewDeposit(0);
        vm.expectRevert("UsdcVault/psm-sell-gem-halted");
        token.deposit(0, address(this));

        maxMint = token.maxMint(address(this));
        assertEq(maxMint, 0);
        vm.expectRevert("UsdcVault/psm-sell-gem-halted");
        token.previewMint(0);
        vm.expectRevert("UsdcVault/psm-sell-gem-halted");
        token.mint(0, address(this));
    }

    function testPsmWithdrawalsDisabled() public {
        token.deposit(100 * 10**6, address(this));
        vm.prank(pauseProxy); PsmLike(psm).file("tout", type(uint256).max);

        uint256 maxWithdrawal = token.maxWithdraw(address(this));
        assertEq(maxWithdrawal, 0);
        vm.expectRevert("UsdcVault/psm-buy-gem-halted");
        token.previewWithdraw(0);
        vm.expectRevert("UsdcVault/psm-buy-gem-halted");
        token.withdraw(0, address(this), address(this));

        uint256 maxRedeem = token.maxRedeem(address(this));
        assertEq(maxRedeem, 0);
        vm.expectRevert("UsdcVault/psm-buy-gem-halted");
        token.previewRedeem(0);
        vm.expectRevert("UsdcVault/psm-buy-gem-halted");
        token.redeem(0, address(this), address(this));
    }

    function testMaxDeposit() public {
        vm.prank(pauseProxy); PsmLike(psm).file("tin", 0.003 ether);
        deal(address(dss.dai), psm, 10**9 * 10**18);
        uint256 maxDeposit = token.maxDeposit(address(this));
        
        assertEq(maxDeposit, 10**9 * 10**18 * 10**6 / (WAD - 0.003 ether));
        deal(address(usdc), address(this), 1.1 * 10**9 * 10**6);
        vm.expectRevert("Dai/insufficient-balance");
        token.deposit(maxDeposit + 1, address(this));
        token.deposit(maxDeposit, address(this));
        assertEq(token.maxDeposit(address(this)), 0);
    }

    function testMaxMint() public {
        vm.prank(pauseProxy); PsmLike(psm).file("tin", 0.003 ether);
        deal(address(dss.dai), psm, 10**9 * 10**18);
        uint256 maxMint = token.maxMint(address(this));
        assertEq(maxMint, susds.previewDeposit(10**9 * 10**18 * 10**6 / (WAD - 0.003 ether) * (WAD - 0.003 ether) / 10**6));
        deal(address(usdc), address(this), 1.1 * 10**9 * 10**6);
        vm.expectRevert("Dai/insufficient-balance");
        token.mint(maxMint + 10**12, address(this));
        token.mint(maxMint, address(this));
        assertEq(token.maxMint(address(this)), 0);
    }

    function testMaxWithdraw() public {
        vm.prank(pauseProxy); PsmLike(psm).file("tout", 0.005 ether);
        uint256 shares = token.deposit(200 * 10**6, address(this));
        uint256 maxWithdraw = token.maxWithdraw(address(this));
        assertEq(maxWithdraw, shares * susds.chi() / RAY * 10**6 / (WAD + 0.005 ether));
        vm.expectRevert("SUsds/insufficient-balance");
        token.withdraw(maxWithdraw + 1, address(this), address(this));
        token.withdraw(maxWithdraw, address(this), address(this));
        assertLt(token.maxWithdraw(address(this)), 2);
    }

    function testMaxWithdrawWithLowPocketBalance() public {
        vm.prank(pauseProxy); PsmLike(psm).file("tout", 0.005 ether);
        token.deposit(200 * 10**6, address(this));
        deal(address(usdc), pocket, 10**6);
        uint256 maxWithdraw = token.maxWithdraw(address(this));
        assertEq(maxWithdraw, 10**6);
        vm.expectRevert("ERC20: transfer amount exceeds balance");
        token.withdraw(maxWithdraw + 1, address(this), address(this));
        token.withdraw(maxWithdraw, address(this), address(this));
        assertLt(token.maxWithdraw(address(this)), 2);
    }

    function testMaxRedeem() public {
        uint256 shares = token.deposit(200 * 10**6, address(this));
        uint256 maxRedeem = token.maxRedeem(address(this));
        assertEq(maxRedeem, shares);
        vm.expectRevert("SUsds/insufficient-balance");
        token.redeem(maxRedeem + 1, address(this), address(this));
        token.redeem(maxRedeem, address(this), address(this));
        assertLt(token.maxRedeem(address(this)), 2 * 10**12);
    }

    function testMaxRedeemWithLowPocketBalance() public {
        vm.prank(pauseProxy); PsmLike(psm).file("tout", 0.005 ether);
        token.deposit(200 * 10**6, address(this));
        deal(address(usdc), pocket, 10**6);
        uint256 maxRedeem = token.maxRedeem(address(this));
        assertEq(maxRedeem, susds.previewWithdraw(10**6 * 10**12 * 1.005));
        assertLt(maxRedeem, token.balanceOf(address(this)));
        vm.expectRevert("ERC20: transfer amount exceeds balance");
        token.redeem(maxRedeem + 10**12, address(this), address(this));
        token.redeem(maxRedeem, address(this), address(this));
        assertLt(token.maxRedeem(address(this)), 2 * 10**12);
    }

    function testMaxDeposit(uint256 psmDaiBalance, uint256 tin) public {
        psmDaiBalance %= 1_000_000_000 ether;
        if (tin < type(uint256).max) tin %= 0.5 ether;

        vm.prank(pauseProxy); PsmLike(psm).file("tin", tin);
        deal(address(dss.dai), psm, psmDaiBalance);
        deal(address(usdc), address(this), 10_000_000_000 * 10**6);

        uint256 maxDeposit = token.maxDeposit(address(this));

        if (tin < WAD) {
            assertEq(maxDeposit, psmDaiBalance * 10**6 / (WAD - tin));
            vm.expectRevert("Dai/insufficient-balance");
            token.deposit(maxDeposit + 1, address(this));
            token.deposit(maxDeposit, address(this));
            assertEq(token.maxDeposit(address(this)), 0);
        } else {
            assertEq(maxDeposit, 0);
            vm.expectRevert("UsdcVault/psm-sell-gem-halted");
            token.deposit(0, address(this));
        }
    }

    function testMaxMint(uint256 psmDaiBalance, uint256 tin) public {
        psmDaiBalance %= 1_000_000_000 ether;
        if (tin < type(uint256).max) tin %= 0.5 ether;

        vm.prank(pauseProxy); PsmLike(psm).file("tin", tin);
        deal(address(dss.dai), psm, psmDaiBalance);
        deal(address(usdc), address(this), 10_000_000_000 * 10**6);

        uint256 maxMint = token.maxMint(address(this));

        if (tin < WAD) {
            vm.expectRevert("Dai/insufficient-balance");
            token.mint(maxMint + 10**12, address(this));
            token.mint(maxMint, address(this));
            assertEq(token.maxMint(address(this)), 0);
        } else {
            assertEq(maxMint, 0);
            vm.expectRevert("UsdcVault/psm-sell-gem-halted");
            token.mint(0, address(this));
        }
    }

    function testMaxWithdraw(uint256 depositAmount, uint256 tout, uint256 warp) public {
        if (tout < type(uint256).max) tout %= WAD;
        depositAmount = bound(depositAmount, 0, token.maxDeposit(address(this)));
        warp %= 365 days;

        vm.prank(pauseProxy); PsmLike(psm).file("tout", tout);
        deal(address(usdc), address(this), depositAmount);
        token.deposit(depositAmount, address(this));
        vm.warp(block.timestamp + warp);
    
        uint256 maxWithdraw = token.maxWithdraw(address(this));

        if (tout < type(uint256).max) {
            if (maxWithdraw < usdc.balanceOf(pocket)) {
                vm.expectRevert("SUsds/insufficient-balance");
            } else {
                vm.expectRevert("ERC20: transfer amount exceeds balance");
            }
            token.withdraw(maxWithdraw + 1, address(this), address(this));
            token.withdraw(maxWithdraw, address(this), address(this));
            assertLt(token.maxWithdraw(address(this)), 2);
        } else {
            assertEq(maxWithdraw, 0);
            vm.expectRevert("UsdcVault/psm-buy-gem-halted");
            token.withdraw(0, address(this), address(this));
        }
    }

    function testMaxRedeem(uint256 depositAmount, uint256 tout, uint256 warp) public {
        if (tout < type(uint256).max) tout %= WAD;
        depositAmount = bound(depositAmount, 0, token.maxDeposit(address(this)));
        warp %= 365 days;

        vm.prank(pauseProxy); PsmLike(psm).file("tout", tout);
        deal(address(usdc), address(this), depositAmount);
        uint256 shares = token.deposit(depositAmount, address(this));
        vm.warp(block.timestamp + warp);
    
        uint256 maxRedeem = token.maxRedeem(address(this));

        if (tout < type(uint256).max) {
            if (maxRedeem < shares) {
                vm.expectRevert("ERC20: transfer amount exceeds balance");
                token.redeem(maxRedeem + 10**12, address(this), address(this));
            } else {
                vm.expectRevert("SUsds/insufficient-balance");
                token.redeem(maxRedeem + 1, address(this), address(this));
            }
            token.redeem(maxRedeem, address(this), address(this));
            assertLt(token.maxRedeem(address(this)), 2 * 10**12);
        } else {
            assertEq(maxRedeem, 0);
            vm.expectRevert("UsdcVault/psm-buy-gem-halted");
            token.redeem(0, address(this), address(this));
        }
    }

    function testExit() public {
        uint256 initialTokenSUsds = susds.balanceOf(address(token));
        uint256 initialReceiverShares = token.balanceOf(address(0x222));
        uint256 initialTotalShares = token.totalSupply();

        uint256 mintedShares = token.deposit(100 * 10**6, address(0x222));

        assertEq(token.totalSupply(), initialTotalShares + mintedShares);
        assertEq(token.balanceOf(address(0x222)), initialReceiverShares + mintedShares);
        assertEq(susds.balanceOf(address(token)), initialTokenSUsds + mintedShares);

        vm.warp(block.timestamp + 365 days);
        uint256 exitedShares = mintedShares / 3;
        uint256 initialExitedReceiverSUsds = susds.balanceOf(address(0x333));

        vm.expectRevert("UsdcVault/insufficient-balance");
        token.exit(exitedShares, address(0x333), address(0xbad));
        vm.expectRevert("UsdcVault/insufficient-allowance");
        token.exit(exitedShares, address(0x333), address(0x222));

        vm.expectEmit(true, true, true, true);
        emit Exit(address(0x222), address(0x333), address(0x222), exitedShares);
        vm.prank(address(0x222)); token.exit(exitedShares, address(0x333), address(0x222));

        vm.expectEmit(true, true, true, true);
        emit Approval(address(0x222), address(this), exitedShares);
        vm.prank(address(0x222)); token.approve(address(this), exitedShares);
        vm.expectRevert("UsdcVault/insufficient-allowance");
        token.exit(exitedShares + 1, address(0x333), address(0x222));
        vm.expectEmit(true, true, true, true);
        emit Exit(address(this), address(0x333), address(0x222), exitedShares);
        token.exit(exitedShares, address(0x333), address(0x222));

        exitedShares *= 2;
        assertEq(token.totalSupply(), initialTotalShares + mintedShares - exitedShares);
        assertEq(susds.balanceOf(address(token)), initialTokenSUsds + mintedShares - exitedShares);
        assertEq(token.balanceOf(address(0x222)), initialReceiverShares + mintedShares - exitedShares);
        assertEq(susds.balanceOf(address(0x333)), initialExitedReceiverSUsds + exitedShares);
    }

}
