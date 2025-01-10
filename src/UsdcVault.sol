// SPDX-License-Identifier: AGPL-3.0-or-later

/// UsdcVault.sol

// Copyright (C) 2017, 2018, 2019 dbrock, rain, mrchico
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

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

interface IERC1271 {
    function isValidSignature(
        bytes32,
        bytes memory
    ) external view returns (bytes4);
}

interface GemLike {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external;
    function transferFrom(address, address, uint256) external;
}

interface SUsdsLike {
    function usds() external view returns (address);
    function chi() external view returns (uint192);
    function rho() external view returns (uint64);
    function ssr() external view returns (uint256);
    function convertToShares(uint256) external view returns (uint256);
    function convertToAssets(uint256) external view returns (uint256);
    function previewDeposit(uint256) external view returns (uint256);
    function previewMint(uint256) external view returns (uint256);
    function previewWithdraw(uint256) external view returns (uint256);
    function previewRedeem(uint256) external view returns (uint256);
    function deposit(uint256, address) external returns (uint256);
    function mint(uint256, address) external returns (uint256);
    function withdraw(uint256, address, address) external returns (uint256);
    function redeem(uint256, address, address) external returns (uint256);
    function transfer(address, uint256) external;
}

interface DaiLike {
    function balanceOf(address) external view returns (uint256);
}

interface DaiPsmLike {
    function dai() external view returns (address);
}

interface PsmLike {
    function psm() external view returns (address);
    function gem() external view returns (address);
    function pocket() external view returns (address);
    function tin() external view returns (uint256);
    function tout() external view returns (uint256);
    function sellGem(address, uint256) external returns (uint256);
    function buyGem(address, uint256) external returns (uint256);
}

contract UsdcVault is UUPSUpgradeable {

    // --- Storage Variables ---

    // Admin
    mapping (address => uint256) public wards;
    // ERC20
    uint256                                           public totalSupply;
    mapping (address => uint256)                      public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => uint256)                      public nonces;

    // --- Constants ---

    // ERC20
    string  public constant name     = "Spark USDC Vault";
    string  public constant symbol   = "sUSDC";
    string  public constant version  = "1";
    uint8   public constant decimals = 18;

    uint256 private constant WAD = 10 ** 18;
    uint256 private constant HALTED = type(uint256).max;

    // --- Immutables ---

    // EIP712
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    PsmLike   public  immutable psm; // UsdsPsmWrapper
    SUsdsLike public  immutable susds;
    GemLike   public  immutable usdc;
    address   private immutable pocket;
    address   private immutable daiPsm;
    DaiLike   private immutable dai;

    // --- Events ---

    // Admin
    event Rely(address indexed usr);
    event Deny(address indexed usr);
    // ERC20
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);
    // ERC4626
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
    // Escape Hatch
    event Exit(address indexed sender, address indexed receiver, address indexed owner, uint256 shares);
    // Referral
    event Referral(uint16 indexed referral, address indexed owner, uint256 assets, uint256 shares);

    // --- Modifiers ---

    modifier auth {
        require(wards[msg.sender] == 1, "UsdcVault/not-authorized");
        _;
    }

    // --- Constructor ---

    constructor(address psm_, address susds_) {
        _disableInitializers(); // Avoid initializing in the context of the implementation

        psm = PsmLike(psm_);
        usdc = GemLike(psm.gem());
        susds = SUsdsLike(susds_);

        pocket = psm.pocket();
        daiPsm = psm.psm();
        dai = DaiLike(DaiPsmLike(daiPsm).dai());
    }

    // --- Upgradability ---

    function initialize() initializer external {
        __UUPSUpgradeable_init();

        GemLike usds = GemLike(susds.usds());
        usdc.approve(address(psm),   type(uint256).max);
        usds.approve(address(psm),   type(uint256).max);
        usds.approve(address(susds), type(uint256).max);

        wards[msg.sender] = 1;
        emit Rely(msg.sender);
    }

    function _authorizeUpgrade(address newImplementation) internal override auth {}

    function getImplementation() external view returns (address) {
        return ERC1967Utils.getImplementation();
    }

    // --- Internals ---

    // EIP712

    function _calculateDomainSeparator(uint256 chainId) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                address(this)
            )
        );
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _calculateDomainSeparator(block.chainid);
    }

    // Math

    function _divup(uint256 x, uint256 y) internal pure returns (uint256 z) {
        // Note: _divup(0,0) will return 0 differing from natural solidity division
        unchecked {
            z = x != 0 ? ((x - 1) / y) + 1 : 0;
        }
    }

    function _min(uint256 x, uint256 y) internal pure returns (uint256) {
        return x < y ? x : y;
    }

    // --- Admin external functions ---

    function rely(address usr) external auth {
        wards[usr] = 1;
        emit Rely(usr);
    }

    function deny(address usr) external auth {
        wards[usr] = 0;
        emit Deny(usr);
    }

    // -- SUsds and PSM getters

    function chi()  external view returns (uint192) { return susds.chi(); }
    function rho()  external view returns (uint64)  { return susds.rho(); }
    function ssr()  external view returns (uint256) { return susds.ssr(); }
    function tin()  external view returns (uint256) { return psm.tin(); }
    function tout() external view returns (uint256) { return psm.tout(); }

    // --- ERC20 Mutations ---

    function transfer(address to, uint256 value) external returns (bool) {
        require(to != address(0) && to != address(this), "UsdcVault/invalid-address");
        uint256 balance = balanceOf[msg.sender];
        require(balance >= value, "UsdcVault/insufficient-balance");

        unchecked {
            balanceOf[msg.sender] = balance - value;
            balanceOf[to] += value; // note: we don't need an overflow check here b/c sum of all balances == totalSupply
        }

        emit Transfer(msg.sender, to, value);

        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(to != address(0) && to != address(this), "UsdcVault/invalid-address");
        uint256 balance = balanceOf[from];
        require(balance >= value, "UsdcVault/insufficient-balance");

        if (from != msg.sender) {
            uint256 allowed = allowance[from][msg.sender];
            if (allowed != type(uint256).max) {
                require(allowed >= value, "UsdcVault/insufficient-allowance");

                unchecked {
                    allowance[from][msg.sender] = allowed - value;
                }
            }
        }

        unchecked {
            balanceOf[from] = balance - value;
            balanceOf[to] += value; // note: we don't need an overflow check here b/c sum of all balances == totalSupply
        }

        emit Transfer(from, to, value);

        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;

        emit Approval(msg.sender, spender, value);

        return true;
    }

    // --- Mint/Burn Internal ---

    function _mint(address receiver, uint256 shares) internal {
        require(receiver != address(0) && receiver != address(this), "UsdcVault/invalid-address");

        unchecked {
            balanceOf[receiver] = balanceOf[receiver] + shares; // note: we don't need an overflow check here b/c balanceOf[receiver] <= totalSupply
            totalSupply = totalSupply + shares; // note: we don't need an overflow check here b/c shares totalSupply will always be <= susds totalSupply
        }

        emit Transfer(address(0), receiver, shares);
    }

    function _burn(address owner, uint256 shares) internal {
        uint256 balance = balanceOf[owner];
        require(balance >= shares, "UsdcVault/insufficient-balance");

        if (owner != msg.sender) {
            uint256 allowed = allowance[owner][msg.sender];
            if (allowed != type(uint256).max) {
                require(allowed >= shares, "UsdcVault/insufficient-allowance");

                unchecked {
                    allowance[owner][msg.sender] = allowed - shares;
                }
            }
        }

        unchecked {
            balanceOf[owner] = balance - shares; // note: we don't need overflow checks b/c require(balance >= shares) and balance <= totalSupply
            totalSupply      = totalSupply - shares;
        }

        emit Transfer(owner, address(0), shares);
    }

    // --- PSM ---

    function _psmUsdsInToGemOut(uint256 usdsAmount, uint256 tout_) internal pure returns (uint256 gemAmount) {
        // Note: this slightly overestimate the PSM fees, not taking into account the fact that they are rounded down, to simplify the calculation
        // This fee overestimation, as well as the loss of precision induced by converting the USDS amount into a USDC amount, can lead to USDS dust
        // accumulating in this contract after redeem()
        return usdsAmount * 10**6 / (WAD + tout_); // gemAmt = floor(usdsAmount * WAD / (10**12 * (WAD + tout))
    }

    function _psmGemOutToUsdsIn(uint256 gemAmount, uint256 tout_) internal pure returns (uint256 usdsAmount) {
        usdsAmount = gemAmount * 10**12;
        usdsAmount += usdsAmount * tout_ / WAD;
    }

    function _psmUsdsOutToGemInRoundingUp(uint256 usdsAmount, uint256 tin_) internal pure returns (uint256 gemAmount) {
        // Note: this slightly overestimate the PSM fees, not taking into account the fact that they are rounded down, to simplify the calculation
        // This fee overestimation, as well as the loss of precision induced by converting the USDS amount into a USDC amount, can lead to USDS dust
        // accumulating in this contract after mint()
        return _divup(usdsAmount * 10**6, WAD - tin_); // gemAmt = ceil(usdsAmount * WAD / (10**12 * (WAD - tin))
    }

    function _psmUsdsOutToGemInRoundingDown(uint256 usdsAmount, uint256 tin_) internal pure returns (uint256 gemAmount) {
        return usdsAmount * 10**6 / (WAD - tin_); // gemAmt = floor(usdsAmount * WAD / (10**12 * (WAD - tin))
    }

    function _psmGemInToUsdsOut(uint256 gemAmount, uint256 tin_) internal pure returns (uint256 usdsAmount) {
        usdsAmount = gemAmount * 10**12;
        usdsAmount -= usdsAmount * tin_ / WAD;
    }

    // --- ERC-4626 ---

    function asset() external view returns (address) {
        return address(usdc);
    }

    // Note that we choose to ignore fees here. The EIP stipulates that `totalAssets` "MUST be inclusive of any fees that are charged 
    // against assets in the Vault", but it is not clear if this refers to `totalAssets`'s returned value or to its implementation, as 
    // pointed out here https://github.com/transmissions11/solmate/issues/348#issue-1497404699. The ambiguity was acknowledged by one of
    // the EIP authors who suggested that fees should be ignored https://github.com/transmissions11/solmate/issues/348#issuecomment-1352241657.
    // This seems consistent with the EIP's note that `totalAssets` does "not have to confer the exact amount of underlying assets [...]".
    function totalAssets() external view returns (uint256) {
        return convertToAssets(totalSupply);
    }

    // Note that, as per the EIP, the amount of shares returned ignores PSM fees
    function convertToShares(uint256 assets) external view returns (uint256) {
        return susds.convertToShares(assets * 10**12);
    }

    // Note that, as per the EIP, the amount of assets returned ignores PSM fees
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return susds.convertToAssets(shares) / 10**12;
    }

    function maxDeposit(address) external view returns (uint256) {
        uint256 tin_ = psm.tin();
        return tin_ >= WAD ? 0 : _psmUsdsOutToGemInRoundingDown(dai.balanceOf(daiPsm), tin_);
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        uint256 tin_ = psm.tin();
        require(tin_ < WAD, "UsdcVault/psm-sell-gem-halted");
        return susds.previewDeposit(_psmGemInToUsdsOut(assets, tin_));
    }

    function _doDeposit(uint256 assets, address receiver, uint256 minShares) internal returns (uint256 shares) {
        require(psm.tin() < WAD, "UsdcVault/psm-sell-gem-halted");
        usdc.transferFrom(msg.sender, address(this), assets);
        uint256 usdsAmount = psm.sellGem(address(this), assets);
        shares = susds.deposit(usdsAmount, address(this));
        require(shares >= minShares, "UsdcVault/shares-too-low");
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = _doDeposit(assets, receiver, 0);
    }

    function deposit(uint256 assets, address receiver, uint256 minShares, uint16 referral) external returns (uint256 shares) {
        shares = _doDeposit(assets, receiver, minShares);
        emit Referral(referral, receiver, assets, shares);
    }

    function maxMint(address) external view returns (uint256) {
        uint256 tin_ = psm.tin();

        if (tin_ >= WAD) return 0;
        uint256 maxAssets = _psmUsdsOutToGemInRoundingDown(dai.balanceOf(daiPsm), tin_);

        return susds.previewDeposit(maxAssets * (WAD - tin_) / 10**6);
    }

    function previewMint(uint256 shares) public view returns (uint256) {
        uint256 tin_ = psm.tin();
        require(tin_ < WAD, "UsdcVault/psm-sell-gem-halted");
        return _psmUsdsOutToGemInRoundingUp(susds.previewMint(shares), tin_);
    }

    function _doMint(uint256 shares, address receiver, uint256 maxAssets) internal returns (uint256 assets) {
        assets = previewMint(shares);
        require(assets <= maxAssets, "UsdcVault/assets-too-high");
        usdc.transferFrom(msg.sender, address(this), assets);
        psm.sellGem(address(this), assets);
        susds.mint(shares, address(this));
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function mint(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = _doMint(shares, receiver, type(uint256).max);
    }

    function mint(uint256 shares, address receiver, uint256 maxAssets, uint16 referral) external returns (uint256 assets) {
        assets = _doMint(shares, receiver, maxAssets);
        emit Referral(referral, receiver, assets, shares);
    }

    function maxWithdraw(address owner) external view returns (uint256) {
        uint256 tout_ = psm.tout();
        return tout_ == HALTED ? 0 : _min(
            _psmUsdsInToGemOut(susds.previewRedeem(balanceOf[owner]), tout_),
            usdc.balanceOf(pocket)
        );
    }

    function previewWithdraw(uint256 assets) external view returns (uint256) {
        uint256 tout_ = psm.tout();
        require(tout_ != HALTED, "UsdcVault/psm-buy-gem-halted");
        return susds.previewWithdraw(_psmGemOutToUsdsIn(assets, tout_));
    }

    function _doWithdraw(uint256 assets, address receiver, address owner, uint256 maxShares) internal returns (uint256 shares) {
        uint256 tout_ = psm.tout();
        require(tout_ != HALTED, "UsdcVault/psm-buy-gem-halted");
        shares = susds.withdraw(_psmGemOutToUsdsIn(assets, tout_), address(this), address(this));
        require(shares <= maxShares, "UsdcVault/shares-too-high");
        _burn(owner, shares);
        psm.buyGem(receiver, assets);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        shares = _doWithdraw(assets, receiver, owner, type(uint256).max);
    }

    function withdraw(uint256 assets, address receiver, address owner, uint256 maxShares) external returns (uint256 shares) {
        shares = _doWithdraw(assets, receiver, owner, maxShares);
    }

    function maxRedeem(address owner) external view returns (uint256) {
        uint256 tout_ = psm.tout();
        return tout_ == HALTED ? 0 : _min(
            balanceOf[owner],
            susds.previewWithdraw(_psmGemOutToUsdsIn(usdc.balanceOf(pocket), tout_))
        );
    }

    function previewRedeem(uint256 shares) external view returns (uint256) {
        uint256 tout_ = psm.tout();
        require(tout_ != HALTED, "UsdcVault/psm-buy-gem-halted");
        return _psmUsdsInToGemOut(susds.previewRedeem(shares), tout_);
    }

    function _doRedeem(uint256 shares, address receiver, address owner, uint256 minAssets) internal returns (uint256 assets) {
        uint256 tout_ = psm.tout();
        require(tout_ != HALTED, "UsdcVault/psm-buy-gem-halted");
        uint256 usdsAmount = susds.redeem(shares, address(this), address(this));
        assets = _psmUsdsInToGemOut(usdsAmount, tout_);
        require(assets >= minAssets, "UsdcVault/assets-too-low");
        _burn(owner, shares);
        psm.buyGem(receiver, assets);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = _doRedeem(shares, receiver, owner, 0);
    }

    function redeem(uint256 shares, address receiver, address owner, uint256 minAssets) external returns (uint256 assets) {
        assets = _doRedeem(shares, receiver, owner, minAssets);
    }

    // --- Escape Hatch ---

    function exit(uint256 shares, address receiver, address owner) external {
        _burn(owner, shares);
        susds.transfer(receiver, shares);
        emit Exit(msg.sender, receiver, owner, shares);
    }

    // --- Approve by signature ---

    function _isValidSignature(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal view returns (bool valid) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            if (signer == ecrecover(digest, v, r, s)) {
                return true;
            }
        }

        if (signer.code.length > 0) {
            (bool success, bytes memory result) = signer.staticcall(
                abi.encodeCall(IERC1271.isValidSignature, (digest, signature))
            );
            valid = (success &&
                result.length == 32 &&
                abi.decode(result, (bytes4)) == IERC1271.isValidSignature.selector);
        }
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes memory signature
    ) public {
        require(block.timestamp <= deadline, "UsdcVault/permit-expired");
        require(owner != address(0), "UsdcVault/invalid-owner");

        uint256 nonce;
        unchecked { nonce = nonces[owner]++; }

        bytes32 digest =
            keccak256(abi.encodePacked(
                "\x19\x01",
                _calculateDomainSeparator(block.chainid),
                keccak256(abi.encode(
                    PERMIT_TYPEHASH,
                    owner,
                    spender,
                    value,
                    nonce,
                    deadline
                ))
            ));

        require(_isValidSignature(owner, digest, signature), "UsdcVault/invalid-permit");

        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        permit(owner, spender, value, deadline, abi.encodePacked(r, s, v));
    }
}
