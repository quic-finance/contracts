// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

import "./QuicMasterTransactions.sol";
// QuicMasterFarmer is the master of Quic. He can make Quic and he is a fair guy.
//
// Note that it's ownable and the owner wields tremendous power. The ownership
// will be transferred to a governance smart contract once Quic is sufficiently
// distributed and the community can show to govern itself.
//
contract QuicMasterFarmer is QuicMasterTransactions {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    // Set at contract creation and is not able to updated or changed
    address public transactionsContract;

    constructor(
        QuicToken _Quic,
        address _devaddr,
		address _liquidityaddr,
		address _comfundaddr,
		address _founderaddr,
        uint256 _rewardPerBlock,
        uint256 _startBlock,
        uint256 _halvingAfterBlock,
        uint256 _userDepFee,
        uint256[] memory _blockDeltaStartStage,
        uint256[] memory _blockDeltaEndStage,
        uint256[] memory _userFeeStage,
        uint256[] memory _devFeeStage
    ) public {
        Quic = _Quic;
        devaddr = _devaddr;
		liquidityaddr = _liquidityaddr;
		comfundaddr = _comfundaddr;
		founderaddr = _founderaddr;
        REWARD_PER_BLOCK = _rewardPerBlock;
        START_BLOCK = _startBlock;
        HALVING_AFTER = _halvingAfterBlock;
	    userDepFee = _userDepFee;
	    blockDeltaStartStage = _blockDeltaStartStage;
	    blockDeltaEndStage = _blockDeltaEndStage;
	    userFeeStage = _userFeeStage;
	    devFeeStage = _devFeeStage;
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    function setup() public onlyOwner {
        for (uint256 i = 0; i < REWARD_MULTIPLIER.length - 1; i++) {
            uint256 halvingAtBlock = HALVING_AFTER.add(i + 1).add(START_BLOCK);
            HALVING_AT_BLOCK.push(halvingAtBlock);
        }
        FINISH_BONUS_AT_BLOCK = 18333511;
        HALVING_AT_BLOCK.push(uint256(-1));
    }


    // Add a new lp to the pool. Can only be called by the owner.
    function add(uint256 _allocPoint, IERC20 _lpToken, bool _withUpdate) public onlyOwner {
        require(poolId1[address(_lpToken)] == 0, "QuicMasterFarmer::add: lp is already in pool");
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardBlock = block.number > START_BLOCK ? block.number : START_BLOCK;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolId1[address(_lpToken)] = poolInfo.length + 1;
        poolInfo.push(PoolInfo({
            lpToken: _lpToken,
            allocPoint: _allocPoint,
            lastRewardBlock: lastRewardBlock,
            accQuicPerShare: 0
        }));
    }

     // Update the given pool's Quic allocation point. Can only be called by the owner.
    function set(uint256 _pid, uint256 _allocPoint, bool _withUpdate) public onlyOwner {
        if (_withUpdate) {
            massUpdatePools();
        }
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        poolInfo[_pid].allocPoint = _allocPoint;
    }

    // Set the migrator contract. Can only be called by the owner.
    function setMigrator(IMigratorToQuicSwap _migrator) public onlyOwner {
        migrator = _migrator;
    }

    // Migrate lp token to another lp contract. Can be called by anyone. We trust that migrator contract is good.
    function migrate(uint256 _pid) public {
        require(address(migrator) != address(0), "migrate: no migrator");
        PoolInfo storage pool = poolInfo[_pid];
        IERC20 lpToken = pool.lpToken;
        uint256 bal = lpToken.balanceOf(address(this));
        lpToken.safeApprove(address(migrator), bal);
        IERC20 newLpToken = migrator.migrate(lpToken);
        require(bal == newLpToken.balanceOf(address(this)), "migrate: bad");
        pool.lpToken = newLpToken;
    }

    // Update reward variables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // View function to see pending Quic on frontend.
    function pendingReward(uint256 _pid, address _user) external view returns (uint256) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accQuicPerShare = pool.accQuicPerShare;
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (block.number > pool.lastRewardBlock && lpSupply > 0) {
            uint256 QuicForFarmer;
            (, QuicForFarmer, , ,) = getPoolReward(pool.lastRewardBlock, block.number, pool.allocPoint);
            accQuicPerShare = accQuicPerShare.add(QuicForFarmer.mul(1e12).div(lpSupply));

        }
        return user.amount.mul(accQuicPerShare).div(1e12).sub(user.rewardDebt);
    }

    function getGlobalAmount(address _user) public view returns(uint256) {
        UserGlobalInfo memory current = userGlobalInfo[_user];
        return current.globalAmount;
    }
    
     function getGlobalRefAmount(address _user) public view returns(uint256) {
        UserGlobalInfo memory current = userGlobalInfo[_user];
        return current.globalRefAmount;
    }
    
    function getTotalRefs(address _user) public view returns(uint256) {
        UserGlobalInfo memory current = userGlobalInfo[_user];
        return current.totalReferals;
    }
    
    function getRefValueOf(address _user, address _user2) public view returns(uint256) {
        UserGlobalInfo storage current = userGlobalInfo[_user];
        uint256 a = current.referrals[_user2];
        return a;
    }

    // Update dev address by the previous dev.
    function dev(address _devaddr) public onlyAuthorized {
        devaddr = _devaddr;
    }
    
    // Update Finish Bonus Block
    function bonusFinishUpdate(uint256 _newFinish) public onlyAuthorized {
        FINISH_BONUS_AT_BLOCK = _newFinish;
    }
    
    // Update Halving At Block
    function halvingUpdate(uint256[] memory _newHalving) public onlyAuthorized {
        HALVING_AT_BLOCK = _newHalving;
    }
    
    // Update Liquidityaddr
    function lpUpdate(address _newLP) public onlyAuthorized {
       liquidityaddr = _newLP;
    }
    
    // Update comfundaddr
    function comUpdate(address _newCom) public onlyAuthorized {
       comfundaddr = _newCom;
    }
    
    // Update founderaddr
    function founderUpdate(address _newFounder) public onlyAuthorized {
       founderaddr = _newFounder;
    }
    
    // Update Reward Per Block
    function rewardUpdate(uint256 _newReward) public onlyAuthorized {
       REWARD_PER_BLOCK = _newReward;
    }
    
    // Update Rewards Mulitplier Array
    function rewardMulUpdate(uint256[] memory _newMulReward) public onlyAuthorized {
       REWARD_MULTIPLIER = _newMulReward;
    }
    
    // Update % lock for general users
    function lockUpdate(uint _newlock) public onlyAuthorized {
       PERCENT_LOCK_BONUS_REWARD = _newlock;
    }
    
    // Update % lock for dev
    function lockdevUpdate(uint _newdevlock) public onlyAuthorized {
       PERCENT_FOR_DEV = _newdevlock;
    }
    
    // Update % lock for LP
    function locklpUpdate(uint _newlplock) public onlyAuthorized {
       PERCENT_FOR_LP = _newlplock;
    }
    
    // Update % lock for COM
    function lockcomUpdate(uint _newcomlock) public onlyAuthorized {
       PERCENT_FOR_COM = _newcomlock;
    }
    
    // Update % lock for Founders
    function lockfounderUpdate(uint _newfounderlock) public onlyAuthorized {
       PERCENT_FOR_FOUNDERS = _newfounderlock;
    }
    
    // Update START_BLOCK
    function starblockUpdate(uint _newstarblock) public onlyAuthorized {
       START_BLOCK = _newstarblock;
    }

    function getNewRewardPerBlock(uint256 pid1) public view returns (uint256) {
        uint256 multiplier = getMultiplier(block.number -1, block.number);
        if (pid1 == 0) {
            return multiplier.mul(REWARD_PER_BLOCK);
        }
        else {
            return multiplier
                .mul(REWARD_PER_BLOCK)
                .mul(poolInfo[pid1 - 1].allocPoint)
                .div(totalAllocPoint);
        }
    }
	
	function userDelta(uint256 _pid) public view returns (uint256) {
        UserInfo storage user = userInfo[_pid][msg.sender];
		if (user.lastWithdrawBlock > 0) {
			uint256 estDelta = block.number - user.lastWithdrawBlock;
			return estDelta;
		} else {
		    uint256 estDelta = block.number - user.firstDepositBlock;
			return estDelta;
		}
	}
	
	function reviseWithdraw(uint _pid, address _user, uint256 _block) public onlyAuthorized() {
	   UserInfo storage user = userInfo[_pid][_user];
	   user.lastWithdrawBlock = _block;
	    
	}
	
	function reviseDeposit(uint _pid, address _user, uint256 _block) public onlyAuthorized() {
	   UserInfo storage user = userInfo[_pid][_user];
	   user.firstDepositBlock = _block;
	    
	}
	
	function setStageStarts(uint[] memory _blockStarts) public onlyAuthorized() {
        blockDeltaStartStage = _blockStarts;
    }
    
    function setStageEnds(uint[] memory _blockEnds) public onlyAuthorized() {
        blockDeltaEndStage = _blockEnds;
    }
    
    function setUserFeeStage(uint[] memory _userFees) public onlyAuthorized() {
        userFeeStage = _userFees;
    }
    
    function setDevFeeStage(uint[] memory _devFees) public onlyAuthorized() {
        devFeeStage = _devFees;
    }
    
    function setUserDepFee(uint _usrDepFees) public onlyAuthorized() {
        userDepFee = _usrDepFees;
    }

}