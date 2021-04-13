
// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/release-v3.4/contracts/token/ERC20/IERC20.sol";
interface IMigratorToQuicSwap {
    // Perform LP token migration from legacy UniswapV2 to QuicSwap.
    // Take the current LP token address and return the new LP token address.
    // Migrator should have full access to the caller's LP token.
    // Return the new LP token address.
    //
    // XXX Migrator must have allowance access to UniswapV2 LP tokens.
    // QuicSwap must mint EXACTLY the same amount of QuicSwap LP tokens or
    // else something bad will happen. Traditional UniswapV2 does not
    // do that so be careful!
    function migrate(IERC20 token) external returns (IERC20);
}