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

import { UsdcVaultL2, UUPSUpgradeable, Initializable, ERC1967Utils } from "src/UsdcVaultL2.sol";
import { UsdcVaultInstance } from "deploy/UsdcVaultInstance.sol";
import { UsdcVaultL2Deploy } from "deploy/UsdcVaultL2Deploy.sol";

interface PsmLike {
    function rateProvider() external view returns (address);
    function usdc() external view returns (address);
    function susds() external view returns (address);
    function pocket() external view returns (address);
    function previewSwapExactIn(address assetIn, address assetOut, uint256 amountIn) external view returns (uint256 amountOut);
    function previewSwapExactOut(address assetIn, address assetOut, uint256 amountOut) external view returns (uint256 amountIn);
}

contract UsdcVaultL22 is UUPSUpgradeable {
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
        require(wards[msg.sender] == 1, "UsdcVaultL2/not-authorized");
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

    address owner = address(0x987);
    GemAbstract usdc;
    GemAbstract susds;
    address psm;
    address rateProvider;
    address pocket;
    UsdcVaultL2 token;
    bool validate;

    event UpgradedTo(string version);
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
    event Exit(address indexed sender, address indexed receiver, address indexed owner, uint256 shares);
    event Referral(uint16 indexed referral, address indexed owner, uint256 assets, uint256 shares);

    function deployVault(address deployer, address owner_, address psm_) external returns (UsdcVaultInstance memory inst) {
        inst = UsdcVaultL2Deploy.deploy(deployer, owner_, psm_);
    }

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_RPC_URL"));
        validate = vm.envOr("VALIDATE", false);

        psm = 0x1601843c5E9bC251A3272907010AFa41Fa18347E; // https://github.com/marsfoundation/spark-address-registry/blob/0894d151cab9cc50dcf49c4c32e6469b16b391a1/src/Base.sol#L28
        rateProvider = PsmLike(psm).rateProvider();
        susds = GemAbstract(PsmLike(psm).susds());
        usdc  = GemAbstract(PsmLike(psm).usdc());
        pocket = PsmLike(psm).pocket();

        vm.expectEmit(true, true, true, true);
        emit Rely(address(this));
        vm.expectEmit(true, true, true, true);
        emit Rely(owner);
        vm.expectEmit(true, true, true, true);
        emit Deny(address(this));

        UsdcVaultInstance memory inst = this.deployVault(address(this), owner, psm);
        token = UsdcVaultL2(inst.usdcVault);

        assertEq(address(token.psm()), psm);
        assertEq(address(token.rateProvider()), rateProvider);
        assertEq(address(token.usdc()), address(usdc));
        assertEq(address(token.susds()), address(susds));
        assertEq(usdc.allowance(address(token), psm), type(uint256).max);
        assertEq(susds.allowance(address(token), psm), type(uint256).max);
        assertEq(token.wards(address(this)), 0);
        assertEq(token.wards(owner), 1);
        assertEq(token.getImplementation(), inst.usdcVaultImp);
        assertEq(token.name(), "Spark USDC Vault");
        assertEq(token.symbol(), "sUSDC");
        assertEq(token.version(), "1");
        assertEq(token.decimals(), 18);

        deal(address(usdc), address(this), 200 * 10**6);
        usdc.approve(address(token), type(uint256).max);

        vm.label(address(susds), "susds");
        vm.label(address(usdc),  "usdc");
        vm.label(psm, "psm");
        if (pocket != psm) vm.label(pocket, "pocket");
    }

    function testGetters() public {
        assertEq(token.asset(), address(usdc));

        uint256 shares1 = token.deposit(12 * 10*6, address(222));
        assertEq(token.totalAssets(), PsmLike(psm).previewSwapExactIn(address(susds), address(usdc), shares1));
        vm.warp(block.timestamp + 365 days);
        uint256 shares2 = token.deposit(34 * 10*6, address(222));
        assertEq(token.totalAssets(), PsmLike(psm).previewSwapExactIn(address(susds), address(usdc), shares1 + shares2));
    }

    function testDeployWithUpgradesLib() public {
        Options memory opts;
        if (!validate) {
            opts.unsafeSkipAllChecks = true;
        } else {
            opts.unsafeAllow = 'state-variable-immutable,constructor';
        }
        opts.constructorData = abi.encode(psm);

        vm.expectEmit(true, true, true, true);
        emit Rely(address(this));
        address proxy = Upgrades.deployUUPSProxy(
            "out/UsdcVaultL2.sol/UsdcVaultL2.json",
            abi.encodeCall(UsdcVaultL2.initialize, ()),
            opts
        );
        assertEq(UsdcVaultL2(proxy).version(), "1");
        assertEq(UsdcVaultL2(proxy).wards(address(this)), 1);
    }

    function testUpgrade() public {
        address implementation1 = token.getImplementation();

        address newImpl = address(new UsdcVaultL22());
        vm.startPrank(owner);
        vm.expectEmit(true, true, true, true);
        emit UpgradedTo("2");
        token.upgradeToAndCall(newImpl, abi.encodeCall(UsdcVaultL22.reinitialize, ()));
        vm.stopPrank();

        address implementation2 = token.getImplementation();
        assertEq(implementation2, newImpl);
        assertTrue(implementation2 != implementation1);
        assertEq(token.version(), "2");
        assertEq(token.wards(address(owner)), 1); // still a ward
    }

    function testUpgradeWithUpgradesLib() public {
        address implementation1 = token.getImplementation();

        Options memory opts;
        if (!validate) {
            opts.unsafeSkipAllChecks = true;
        } else {
            opts.referenceContract = "out/UsdcVaultL2.sol/UsdcVaultL2.json";
            opts.unsafeAllow = 'constructor';
        }

        vm.startPrank(owner);
        vm.expectEmit(true, true, true, true);
        emit UpgradedTo("2");
        Upgrades.upgradeProxy(
            address(token),
            "out/UsdcVaultL2-integration.t.sol/UsdcVaultL22.json",
            abi.encodeCall(UsdcVaultL22.reinitialize, ()),
            opts
        );
        vm.stopPrank();

        address implementation2 = token.getImplementation();
        assertTrue(implementation1 != implementation2);
        assertEq(token.version(), "2");
        assertEq(token.wards(address(owner)), 1); // still a ward
    }

    function testUpgradeUnauthed() public {
        address newImpl = address(new UsdcVaultL22());
        vm.expectRevert("UsdcVaultL2/not-authorized");
        vm.prank(address(0x123)); token.upgradeToAndCall(newImpl, abi.encodeCall(UsdcVaultL22.reinitialize, ()));
    }

    function testInitializeAgain() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        token.initialize();
    }

    function testInitializeDirectly() public {
        address implementation = token.getImplementation();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        UsdcVaultL2(implementation).initialize();
    }

    function testAuth() public {
        checkAuth(address(token), "UsdcVaultL2");
    }

    function testERC20() public {
        checkBulkERC20(address(token), "UsdcVaultL2", "Spark USDC Vault", "sUSDC", "1", 18);
    }

    function testPermit() public {
        checkBulkPermit(address(token), "UsdcVaultL2");
    }

    function testERC20Fuzz(
        address from,
        address to,
        uint256 amount1,
        uint256 amount2
    ) public {
        checkBulkERC20Fuzz(address(token), "UsdcVaultL2", from, to, amount1, amount2);
    }

    function testPermitFuzz(
        uint128 privKey,
        address to,
        uint256 amount,
        uint256 deadline,
        uint256 nonce
    ) public {
        checkBulkPermitFuzz(address(token), "UsdcVaultL2", privKey, to, amount, deadline, nonce);
    }

    function testConversion() public {
        uint256 pshares = token.convertToShares(1e18);
        assertEq(pshares, PsmLike(psm).previewSwapExactIn(address(usdc), address(susds), 1e18));

        uint256 passets = token.convertToAssets(pshares);
        assertEq(passets, PsmLike(psm).previewSwapExactIn(address(susds), address(usdc), pshares));

        // Converting back and forth should always round against
        assertLe(passets, 1e18);

        // Accrue some interest
        vm.warp(block.timestamp + 1 days);

        uint256 shares = token.convertToShares(1e18);

        // Shares should be less because more interest has accrued
        assertLt(shares, pshares);
    }

    function testDepositMintBadAddress() public {
        vm.expectRevert("UsdcVaultL2/invalid-address");
        token.deposit(1e6, address(0));
        vm.expectRevert("UsdcVaultL2/invalid-address");
        token.deposit(1e6, address(token));
        vm.expectRevert("UsdcVaultL2/invalid-address");
        token.mint(1e18, address(0));
        vm.expectRevert("UsdcVaultL2/invalid-address");
        token.mint(1e18, address(token));
    }

    // avoid stack too deep
    uint256 burnedAssets;
    uint256 burnedDirectly;
    function _checkDepositWithdraw(uint256 depositedAssets, uint256 withdrawnAssets) internal {
        uint256 initialTokenSUsds = susds.balanceOf(address(token));
        uint256 initialPsmUsdc = usdc.balanceOf(pocket);
        uint256 initialSenderUsdc = usdc.balanceOf(address(this));
        uint256 initialReceiverShares = token.balanceOf(address(0x222));
        uint256 initialTotalShares = token.totalSupply();

        uint256 mintedShares = token.previewDeposit(depositedAssets);
        vm.expectRevert("PSM3/amountOut-too-low");
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
        assertEq(usdc.balanceOf(address(token)), 0);
        assertEq(usdc.balanceOf(pocket), initialPsmUsdc + depositedAssets);
        assertEq(usdc.balanceOf(address(this)), initialSenderUsdc - depositedAssets);

        vm.warp(block.timestamp + 365 days);

        if (withdrawnAssets > 0) vm.expectRevert("UsdcVaultL2/insufficient-balance");
        token.withdraw(withdrawnAssets, address(this), address(0xbad));
        if (withdrawnAssets > 0) vm.expectRevert("UsdcVaultL2/insufficient-allowance");
        token.withdraw(withdrawnAssets, address(this), address(0x222));

        uint256 withdrawnByApproval = withdrawnAssets / 2;
        uint256 burnedByApproval = token.previewWithdraw(withdrawnByApproval);
        vm.expectEmit(true, true, true, true);
        emit Approval(address(0x222), address(this), burnedByApproval);
        vm.prank(address(0x222)); token.approve(address(this), burnedByApproval);

        vm.expectRevert("PSM3/amountIn-too-high");
        token.withdraw(withdrawnByApproval, address(this), address(0x222), burnedByApproval - 1);
        // Changed from l1 version since previewWithdraw(X) might be equal to previewWithdraw(X+1),
        // so need to take a safety margin to cause the failure and not just use withdrawnByApproval + 1.
        if (mintedShares >= token.previewWithdraw(withdrawnByApproval + 2)) vm.expectRevert("UsdcVaultL2/insufficient-allowance");
        else vm.expectRevert("SafeERC20/transfer-from-failed");
        token.withdraw(withdrawnByApproval + 2, address(this), address(0x222));
        vm.expectEmit(true, true, true, true);
        emit Withdraw(address(this), address(this), address(0x222), withdrawnByApproval, burnedByApproval);
        shares = token.withdraw(withdrawnByApproval, address(this), address(0x222), burnedByApproval);
        assertEq(shares, burnedByApproval);

        // Changed from l1 version since previewWithdraw(X) + previewWithdraw(Y) can be != previewWithdraw(X+Y),
        // so need to compute the remaining withdraw based on shares, and not simply as withdrawnAssets - withdrawnByApproval.
        burnedAssets = token.previewWithdraw(withdrawnAssets);
        uint256 withdrawnDirectly = token.previewRedeem(burnedAssets - burnedByApproval);
        burnedDirectly = token.previewWithdraw(withdrawnDirectly);
        vm.expectEmit(true, true, true, true);
        emit Withdraw(address(0x222), address(this), address(0x222), withdrawnDirectly, burnedDirectly);
        vm.prank(address(0x222)); shares = token.withdraw(withdrawnDirectly, address(this), address(0x222));

        assertEq(shares, burnedDirectly);
        assertLe(burnedByApproval + burnedDirectly, mintedShares);
        assertEq(token.totalSupply(), initialTotalShares + mintedShares - burnedByApproval - burnedDirectly);
        assertEq(token.balanceOf(address(0x222)), initialReceiverShares + mintedShares - burnedByApproval - burnedDirectly);
        assertEq(susds.balanceOf(address(token)), initialTokenSUsds + mintedShares - burnedByApproval - burnedDirectly);
        assertEq(usdc.balanceOf(address(token)), 0);

        // Changed from the l1 version since we no longer withdraw precisely withdrawnAssets,
        // but instead withdrawnByApproval + withdrawnDirectly.
        assertEq(usdc.balanceOf(pocket), initialPsmUsdc + depositedAssets - withdrawnByApproval - withdrawnDirectly);
        assertEq(usdc.balanceOf(address(this)), initialSenderUsdc - depositedAssets + withdrawnByApproval + withdrawnDirectly);
    }

    function testDepositWithdraw() public {
        _checkDepositWithdraw(100 * 10**6, 100 * 10**6);
    }

    function testDepositWithdraw(uint256 deposited, uint256 withdrawn) public {
        deposited = bound(deposited, 2, token.maxDeposit(address(this))); // minimum is 2 to allow dividing by 2
        deal(address(usdc), address(this), deposited);

        uint256 snap = vm.snapshot();
        token.deposit(deposited, address(0x222));
        vm.warp(block.timestamp + 365 days);
        uint256 maxWithdraw = token.maxWithdraw(address(0x222));
        vm.assume(maxWithdraw >= 2);
        withdrawn = bound(withdrawn, 2, maxWithdraw);
        vm.revertTo(snap);

        _checkDepositWithdraw(deposited, withdrawn);
    }

    function testDepositWithdrawZeroAmounts() public {
        assertEq(token.previewDeposit(0), 0);
        vm.expectRevert("PSM3/invalid-amountIn");
        token.deposit(0, address(0x222));
        assertEq(token.previewWithdraw(0), 0);
        vm.expectRevert("PSM3/invalid-amountOut");
        token.withdraw(0, address(this), address(0x222));
    }

    function _checkMintRedeem(uint256 mintedShares, uint256 redeemedShares) internal {
        uint256 initialTokenSUsds = susds.balanceOf(address(token));
        uint256 initialPsmUsdc = usdc.balanceOf(pocket);
        uint256 initialSenderUsdc = usdc.balanceOf(address(this));
        uint256 initialReceiverShares = token.balanceOf(address(0x222));
        uint256 initialTotalShares = token.totalSupply();

        uint256 depositedAssets = token.previewMint(mintedShares);
        vm.expectRevert("PSM3/amountIn-too-high");
        token.mint(mintedShares, address(0x222), depositedAssets - 1, 888);
        vm.expectEmit(true, true, true, true);
        emit Deposit(address(this), address(0x222), depositedAssets, mintedShares);
        vm.expectEmit(true, true, true, true);
        emit Referral(888, address(0x222), depositedAssets, mintedShares);
        uint256 assets = token.mint(mintedShares, address(0x222), depositedAssets, 888);

        assertEq(assets, depositedAssets);
        assertEq(token.totalSupply(), initialTotalShares + mintedShares);
        assertEq(token.balanceOf(address(0x222)), initialReceiverShares + mintedShares);
        assertEq(susds.balanceOf(address(token)), initialTokenSUsds + mintedShares);
        assertEq(usdc.balanceOf(address(token)), 0);
        assertEq(usdc.balanceOf(pocket), initialPsmUsdc + depositedAssets);
        assertEq(usdc.balanceOf(address(this)), initialSenderUsdc - depositedAssets);

        vm.warp(block.timestamp + 365 days);

        if (redeemedShares > 0) vm.expectRevert("UsdcVaultL2/insufficient-balance");
        token.redeem(redeemedShares, address(this), address(0xbad));
        if (redeemedShares > 0) vm.expectRevert("UsdcVaultL2/insufficient-allowance");
        token.redeem(redeemedShares, address(this), address(0x222));

        uint256 redeemedByApproval = redeemedShares / 2;
        uint256 withdrawnByApproval = token.previewRedeem(redeemedByApproval);
        vm.expectEmit(true, true, true, true);
        emit Approval(address(0x222), address(this), redeemedByApproval);
        vm.prank(address(0x222)); token.approve(address(this), redeemedByApproval);
        vm.expectRevert("PSM3/amountOut-too-low");
        token.redeem(redeemedByApproval, address(this), address(0x222), withdrawnByApproval + 1);
        if (mintedShares > 0) vm.expectRevert("UsdcVaultL2/insufficient-allowance");
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
        assertEq(usdc.balanceOf(address(token)), 0);
        assertEq(usdc.balanceOf(pocket), initialPsmUsdc + depositedAssets - withdrawnByApproval - withdrawnDirectly);
        assertEq(usdc.balanceOf(address(this)), initialSenderUsdc - depositedAssets + withdrawnByApproval + withdrawnDirectly);
    }

    function testMintRedeem() public {
        uint256 shares = 100 * 10**18;
        _checkMintRedeem(shares, shares);
    }

    function testMintRedeem(uint256 minted, uint256 redeemed) public {
        minted = bound(minted, 2, token.maxMint(address(this))); // minimum is 2 to allow dividing by 2
        deal(address(usdc), address(this), token.previewMint(minted));

        uint256 snap = vm.snapshot();
        token.mint(minted, address(0x222));
        vm.warp(block.timestamp + 365 days);
        redeemed = bound(redeemed, 2, token.maxRedeem(address(0x222)));
        vm.revertTo(snap);

        _checkMintRedeem(minted, redeemed);
    }

    function testMintRedeemZeroAmounts() public {
        assertEq(token.previewMint(0), 0);
        vm.expectRevert("PSM3/invalid-amountOut");
        token.mint(0, address(0x222));
        assertEq(token.previewRedeem(0), 0);
        vm.expectRevert("PSM3/invalid-amountIn");
        token.redeem(0, address(this), address(0x222));
    }

    function testMaxDeposit() public {
        deal(address(susds), psm, 10*9 * 10**18);
        deal(address(usdc), address(this), 10_000_000_000 * 10**6);
        uint256 maxDeposit = token.maxDeposit(address(this));
        assertEq(maxDeposit, PsmLike(psm).previewSwapExactIn(address(susds), address(usdc), 10*9 * 10**18));
        vm.expectRevert("SafeERC20/transfer-failed");
        token.deposit(maxDeposit + 1000, address(this));
        token.deposit(maxDeposit, address(this));
        assertLe(token.maxDeposit(address(this)), 2);
    }

    function testMaxMint() public {
        deal(address(susds), psm, 10*9 * 10**18);
        deal(address(usdc), address(this), 10_000_000_000 * 10**6);
        uint256 maxMint = token.maxMint(address(this));
        assertEq(maxMint, 10*9 * 10**18);
        vm.expectRevert("SafeERC20/transfer-failed");
        token.mint(maxMint + 10**12, address(this));
        token.mint(maxMint, address(this));
        assertEq(token.maxMint(address(this)), 0);
    }

    function testMaxWithdraw() public {
        uint256 shares = token.deposit(200 * 10**6, address(this));
        uint256 maxWithdraw = token.maxWithdraw(address(this));
        assertEq(maxWithdraw, PsmLike(psm).previewSwapExactIn(address(susds), address(usdc), shares));
        vm.expectRevert("SafeERC20/transfer-from-failed");
        token.withdraw(maxWithdraw + 1, address(this), address(this));
        token.withdraw(maxWithdraw, address(this), address(this));
        assertEq(token.maxWithdraw(address(this)), 0);
    }

    function testMaxWithdrawWithLowPocketBalance() public {
        token.deposit(200 * 10**6, address(this));
        deal(address(usdc), pocket, 10**6);
        uint256 maxWithdraw = token.maxWithdraw(address(this));
        assertEq(maxWithdraw, 10**6);
        vm.expectRevert("SafeERC20/transfer-failed");
        token.withdraw(maxWithdraw + 1, address(this), address(this));
        token.withdraw(maxWithdraw, address(this), address(this));
        assertEq(token.maxWithdraw(address(this)), 0);
    }

    function testMaxRedeem() public {
        uint256 shares = token.deposit(200 * 10**6, address(this));
        uint256 maxRedeem = token.maxRedeem(address(this));
        assertEq(maxRedeem, shares);
        vm.expectRevert("SafeERC20/transfer-from-failed");
        token.redeem(maxRedeem + 1, address(this), address(this));
        token.redeem(maxRedeem, address(this), address(this));
        assertEq(token.maxRedeem(address(this)), 0);
    }

    function testMaxRedeemWithLowPocketBalance() public {
        token.deposit(200 * 10**6, address(this));
        deal(address(usdc), pocket, 10**6);
        uint256 maxRedeem = token.maxRedeem(address(this));
        assertEq(maxRedeem, PsmLike(psm).previewSwapExactIn(address(usdc), address(susds), usdc.balanceOf(pocket)));
        assertLt(maxRedeem, token.balanceOf(address(this)));
        vm.expectRevert("SafeERC20/transfer-failed");
        token.redeem(maxRedeem + 2 * 10**12, address(this), address(this));
        token.redeem(maxRedeem, address(this), address(this));
        assertEq(token.maxRedeem(address(this)), 0);
    }

    function testMaxDeposit(uint256 psmSusdsBalance) public {
        psmSusdsBalance %= 1_000_000_000 ether;

        deal(address(susds), psm, psmSusdsBalance);
        deal(address(usdc), address(this), 10_000_000_000 * 10**6);

        uint256 maxDeposit = token.maxDeposit(address(this));

        assertEq(maxDeposit, PsmLike(psm).previewSwapExactIn(address(susds), address(usdc),psmSusdsBalance));
        vm.expectRevert("SafeERC20/transfer-failed");
        token.deposit(maxDeposit + 1000, address(this));
        if (maxDeposit == 0) vm.expectRevert("PSM3/invalid-amountIn");
        token.deposit(maxDeposit, address(this));
        assertLe(token.maxDeposit(address(this)), 2);
    }

    function testMaxMint(uint256 psmSusdsBalance) public {
        psmSusdsBalance %= 1_000_000_000 ether;

        deal(address(susds), psm, psmSusdsBalance);
        deal(address(usdc), address(this), 10_000_000_000 * 10**6);

        uint256 maxMint = token.maxMint(address(this));

        vm.expectRevert("SafeERC20/transfer-failed");
        token.mint(maxMint + 10**12, address(this));
        if (maxMint == 0) vm.expectRevert("PSM3/invalid-amountOut");
        token.mint(maxMint, address(this));
        assertEq(token.maxMint(address(this)), 0);
    }

    function testMaxWithdraw(uint256 depositAmount, uint256 warp) public {
        depositAmount = bound(depositAmount, 1, token.maxDeposit(address(this)));
        warp %= 365 days;

        deal(address(usdc), address(this), depositAmount);
        token.deposit(depositAmount, address(this));
        vm.warp(block.timestamp + warp);

        uint256 maxWithdraw = token.maxWithdraw(address(this));

        if (maxWithdraw < usdc.balanceOf(pocket)) {
            vm.expectRevert("SafeERC20/transfer-from-failed");
        } else {
            vm.expectRevert("SafeERC20/transfer-failed");
        }
        token.withdraw(maxWithdraw + 1, address(this), address(this));
        if (maxWithdraw == 0) vm.expectRevert("PSM3/invalid-amountOut");
        token.withdraw(maxWithdraw, address(this), address(this));
        assertEq(token.maxWithdraw(address(this)), 0);
    }

    function testMaxRedeem(uint256 depositAmount, uint256 warp) public {
        depositAmount = bound(depositAmount, 1, token.maxDeposit(address(this)));
        warp %= 365 days;

        deal(address(usdc), address(this), depositAmount);
        uint256 shares = token.deposit(depositAmount, address(this));
        vm.warp(block.timestamp + warp);

        uint256 maxRedeem = token.maxRedeem(address(this));

        if (maxRedeem < shares) {
            vm.expectRevert("SafeERC20/transfer-failed");
            token.redeem(maxRedeem + 10 * 10**12, address(this), address(this));
        } else {
            vm.expectRevert("SafeERC20/transfer-from-failed");
            token.redeem(maxRedeem + 1, address(this), address(this));
        }
        if (maxRedeem == 0) vm.expectRevert("PSM3/invalid-amountIn");
        token.redeem(maxRedeem, address(this), address(this));
        assertLe(token.maxRedeem(address(this)), 1e12);
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

        vm.expectRevert("UsdcVaultL2/insufficient-balance");
        token.exit(exitedShares, address(0x333), address(0xbad));
        vm.expectRevert("UsdcVaultL2/insufficient-allowance");
        token.exit(exitedShares, address(0x333), address(0x222));

        vm.expectEmit(true, true, true, true);
        emit Exit(address(0x222), address(0x333), address(0x222), exitedShares);
        vm.prank(address(0x222)); token.exit(exitedShares, address(0x333), address(0x222));

        vm.expectEmit(true, true, true, true);
        emit Approval(address(0x222), address(this), exitedShares);
        vm.prank(address(0x222)); token.approve(address(this), exitedShares);
        vm.expectRevert("UsdcVaultL2/insufficient-allowance");
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
