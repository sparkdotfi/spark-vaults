// SPDX-License-Identifier: AGPL-3.0-or-later

/// UsdcVaultL2.sol

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
    function transfer(address, uint256) external;
    function transferFrom(address, address, uint256) external;
}
interface PsmLike {
    function rateProvider() external view returns (address);
    function usdc() external view returns (address);
    function susds() external view returns (address);
    function pocket() external view returns (address);
    function swapExactIn(
        address assetIn,
        address assetOut,
        uint256 amountIn,
        uint256 minAmountOut,
        address receiver,
        uint256 referralCode
    ) external returns (uint256 amountOut);
    function swapExactOut(
        address assetIn,
        address assetOut,
        uint256 amountOut,
        uint256 maxAmountIn,
        address receiver,
        uint256 referralCode
    ) external returns (uint256 amountIn);
    function previewSwapExactIn(address assetIn, address assetOut, uint256 amountIn)
        external view returns (uint256 amountOut);
    function previewSwapExactOut(address assetIn, address assetOut, uint256 amountOut)
        external view returns (uint256 amountIn);
}

interface RateProviderLike {
    function getConversionRate() external view returns (uint256);
}

contract UsdcVaultL2 is UUPSUpgradeable {

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

    // --- Immutables ---

    // EIP712
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    PsmLike          public immutable psm;
    RateProviderLike public immutable rateProvider;
    address          public immutable usdc;
    address          public immutable susds;

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
        require(wards[msg.sender] == 1, "UsdcVaultL2/not-authorized");
        _;
    }

    // --- Constructor ---

    constructor(address psm_) {
        _disableInitializers(); // Avoid initializing in the context of the implementation

        psm          = PsmLike(psm_);
        rateProvider = RateProviderLike(psm.rateProvider());
        usdc         = psm.usdc();
        susds        = psm.susds();
    }

    // --- Upgradability ---

    function initialize() initializer external {
        __UUPSUpgradeable_init();

        GemLike(usdc).approve(address(psm),  type(uint256).max);
        GemLike(susds).approve(address(psm), type(uint256).max);

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

    // --- ERC20 Mutations ---

    function transfer(address to, uint256 value) external returns (bool) {
        require(to != address(0) && to != address(this), "UsdcVaultL2/invalid-address");
        uint256 balance = balanceOf[msg.sender];
        require(balance >= value, "UsdcVaultL2/insufficient-balance");

        unchecked {
            balanceOf[msg.sender] = balance - value;
            balanceOf[to] += value; // note: we don't need an overflow check here b/c sum of all balances == totalSupply
        }

        emit Transfer(msg.sender, to, value);

        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(to != address(0) && to != address(this), "UsdcVaultL2/invalid-address");
        uint256 balance = balanceOf[from];
        require(balance >= value, "UsdcVaultL2/insufficient-balance");

        if (from != msg.sender) {
            uint256 allowed = allowance[from][msg.sender];
            if (allowed != type(uint256).max) {
                require(allowed >= value, "UsdcVaultL2/insufficient-allowance");

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
        require(receiver != address(0) && receiver != address(this), "UsdcVaultL2/invalid-address");

        unchecked {
            balanceOf[receiver] = balanceOf[receiver] + shares; // note: we don't need an overflow check here b/c balanceOf[receiver] <= totalSupply
            totalSupply = totalSupply + shares; // note: we don't need an overflow check here b/c shares totalSupply will always be <= susds totalSupply
        }

        emit Transfer(address(0), receiver, shares);
    }

    function _burn(address owner, uint256 shares) internal {
        uint256 balance = balanceOf[owner];
        require(balance >= shares, "UsdcVaultL2/insufficient-balance");

        if (owner != msg.sender) {
            uint256 allowed = allowance[owner][msg.sender];
            if (allowed != type(uint256).max) {
                require(allowed >= shares, "UsdcVaultL2/insufficient-allowance");

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

    // --- ERC-4626 ---

    function asset() external view returns (address) {
        return usdc;
    }

    function totalAssets() external view returns (uint256) {
        return convertToAssets(totalSupply);
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return psm.previewSwapExactIn(usdc, susds, assets);
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        return psm.previewSwapExactIn(susds, usdc, shares);
    }

    function maxDeposit(address) external view returns (uint256) {
        return psm.previewSwapExactIn(susds, usdc, GemLike(susds).balanceOf(address(psm)));
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        return psm.previewSwapExactIn(usdc, susds, assets);
    }

    function _doDeposit(uint256 assets, address receiver, uint256 minShares) internal returns (uint256 shares) {
        GemLike(usdc).transferFrom(msg.sender, address(this), assets);
        shares = psm.swapExactIn(usdc, susds, assets, minShares, address(this), 0);
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
        return GemLike(susds).balanceOf(address(psm));
    }

    function previewMint(uint256 shares) public view returns (uint256) {
        return psm.previewSwapExactOut(usdc, susds, shares);
    }

    function _doMint(uint256 shares, address receiver, uint256 maxAssets) internal returns (uint256 assets) {
        assets = previewMint(shares);
        GemLike(usdc).transferFrom(msg.sender, address(this), assets);
        psm.swapExactOut(usdc, susds, shares, maxAssets, address(this), 0);
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
        return _min(
            (balanceOf[owner] / 1e12) * rateProvider.getConversionRate() / 1e27,
            GemLike(usdc).balanceOf(psm.pocket())
        );
    }

    function previewWithdraw(uint256 assets) external view returns (uint256) {
        return psm.previewSwapExactOut(susds, usdc, assets);
    }

    function _doWithdraw(uint256 assets, address receiver, address owner, uint256 maxShares) internal returns (uint256 shares) {
        shares = psm.swapExactOut(susds, usdc, assets, maxShares, receiver, 0);
        _burn(owner, shares);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        shares = _doWithdraw(assets, receiver, owner, type(uint256).max);
    }

    function withdraw(uint256 assets, address receiver, address owner, uint256 maxShares) external returns (uint256 shares) {
        shares = _doWithdraw(assets, receiver, owner, maxShares);
    }

    function maxRedeem(address owner) external view returns (uint256) {
        return _min(
            balanceOf[owner],
            psm.previewSwapExactIn(usdc, susds, GemLike(usdc).balanceOf(psm.pocket()))
        );
    }

    function previewRedeem(uint256 shares) external view returns (uint256) {
        return psm.previewSwapExactIn(susds, usdc, shares);
    }

    function _doRedeem(uint256 shares, address receiver, address owner, uint256 minAssets) internal returns (uint256 assets) {
        assets = psm.swapExactIn(susds, usdc, shares, minAssets, receiver, 0);
        _burn(owner, shares);
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
        GemLike(susds).transfer(receiver, shares);
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
        require(block.timestamp <= deadline, "UsdcVaultL2/permit-expired");
        require(owner != address(0), "UsdcVaultL2/invalid-owner");

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

        require(_isValidSignature(owner, digest, signature), "UsdcVaultL2/invalid-permit");

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
