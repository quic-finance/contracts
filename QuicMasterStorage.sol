
// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

import "./QuicToken.sol";
import "./IMigratorToQuicSwap.sol";

contract QuicMasterStorage {
        // Info of each user.
    struct UserInfo {
        uint256 amount;     // How many LP tokens the user has provided.
        uint256 rewardDebt; // Reward debt. See explanation below.
        uint256 rewardDebtAtBlock; // the last block user stake
		uint256 lastWithdrawBlock; // the last block a user withdrew at.
		uint256 firstDepositBlock; // the last block a user deposited at.
		uint256 blockdelta; //time passed since withdrawals
		uint256 lastDepositBlock;
        //
        // We do some fancy math here. Basically, any point in time, the amount of Quics
        // entitled to a user but is pending to be distributed is:
        //
        //   pending reward = (user.amount * pool.accQuicPerShare) - user.rewardDebt
        //
        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
        //   1. The pool's `accQuicPerShare` (and `lastRewardBlock`) gets updated.
        //   2. User receives the pending reward sent to his/her address.
        //   3. User's `amount` gets updated.
        //   4. User's `rewardDebt` gets updated.
    }

    struct UserGlobalInfo {
        uint256 globalAmount;
        mapping(address => uint256) referrals;
        uint256 totalReferals;
        uint256 globalRefAmount;
    }

    // Info of each pool.
    struct PoolInfo {
        IERC20 lpToken;           // Address of LP token contract.
        uint256 allocPoint;       // How many allocation points assigned to this pool. Quic to distribute per block.
        uint256 lastRewardBlock;  // Last block number that Quic distribution occurs.
        uint256 accQuicPerShare;  // Accumulated Quic per share, times 1e12. See below.
    }
    // The Quic TOKEN!
    QuicToken public Quic;
    //An ETH/USDC Oracle (Chainlink)
    address public usdOracle;
    // Dev address.
    address public devaddr;
	// LP address
	address public liquidityaddr;
	// Community Fund Address
	address public comfundaddr;
	// Founder Reward
	address public founderaddr;
    // Quic tokens created per block.
    uint256 public REWARD_PER_BLOCK;
    // Bonus muliplier for early Quic makers.
    uint256[] public REWARD_MULTIPLIER =[4096, 2048, 2048, 1024, 1024, 512, 512, 256, 256, 256, 256, 256, 256, 256, 256, 128, 128, 128, 128, 128, 128, 128, 128, 128, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 16, 8, 8, 8, 8, 32, 32, 64, 64, 64, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 256, 256, 256, 128, 128, 128, 128, 128, 128, 128, 128, 128, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 16, 16, 16, 16, 8, 8, 8, 4, 2, 1, 0];
    uint256[] public HALVING_AT_BLOCK; // init in constructor function
    uint256[] public blockDeltaStartStage;
    uint256[] public blockDeltaEndStage;
    uint256[] public userFeeStage;
    uint256[] public devFeeStage;
    uint256 public FINISH_BONUS_AT_BLOCK;
    uint256 public userDepFee;

    // The block number when Quic mining starts.
    uint256 public START_BLOCK;

    uint256 public PERCENT_LOCK_BONUS_REWARD; // lock xx% of bounus reward in 3 year
    uint256 public PERCENT_FOR_DEV; // dev bounties + partnerships
	uint256 public PERCENT_FOR_LP; // LP fund
	uint256 public PERCENT_FOR_COM; // community fund
	uint256 public PERCENT_FOR_FOUNDERS; // founders fund
    uint256 public HALVING_AFTER;
    // The migrator contract. It has a lot of power. Can only be set through governance (owner).
    IMigratorToQuicSwap public migrator;

    // Info of each pool.
    PoolInfo[] public poolInfo;
    mapping(address => uint256) public poolId1; // poolId1 count from 1, subtraction 1 before using with poolInfo
    // Info of each user that stakes LP tokens. pid => user address => info
    mapping (uint256 => mapping (address => UserInfo)) public userInfo;
    mapping (address => UserGlobalInfo) public userGlobalInfo;
    // Total allocation poitns. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint = 0;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event SendQuicReward(address indexed user, uint256 indexed pid, uint256 amount, uint256 lockAmount);

}