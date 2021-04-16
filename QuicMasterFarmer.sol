// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

import "./QuicMasterStorage.sol";
// QuicMasterFarmer is the master of Quic. He can make Quic and he is a fair guy.
//
// Note that it's ownable and the owner wields tremendous power. The ownership
// will be transferred to a governance smart contract once Quic is sufficiently
// distributed and the community can show to govern itself.
//
contract QuicMasterFarmer is QuicMasterStorage, Ownable, Authorizable {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    // Set at contract creation and is not able to updated or changed
    address public transactionsContract;

    // Gas fees for calling delegate cals functions to the transactions contract
    uint256 GAS_FOR_UPDATE_POOL = 30000000;
    uint256 GAS_FOR_CLAIM_REWARD = 30000000;
    uint256 GAS_FOR_HARVEST = 30000000;
    uint256 GAS_FOR_DEPOSIT = 30000000;
    uint256 GAS_FOR_WITHDRAW = 30000000;
    uint256 GAS_FOR_EMERGENCY_WITHDRAW = 30000000;
    uint256 GAS_FOR_TRANSFER = 30000000;

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
        uint256[] memory _devFeeStage,
        address _transactionsContract
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
        transactionsContract = _transactionsContract;
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    function setup() public onlyOwner {
        for (uint256 i = 0; i < REWARD_MULTIPLIER.length - 1; i++) {
            uint256 halvingAtBlock = HALVING_AFTER.add(i + 1).add(START_BLOCK);
            HALVING_AT_BLOCK.push(halvingAtBlock);
        }
        FINISH_BONUS_AT_BLOCK = 26180756;
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

   // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
        (bool delegateCallStatus, bytes memory result) = transactionsContract.delegatecall{gas:GAS_FOR_UPDATE_POOL}(
            abi.encodeWithSignature("updatePool(uint256)", _pid)
        );
        require(delegateCallStatus, "delegatecall failed");
    }

    // |--------------------------------------|
    // [20, 30, 40, 50, 60, 70, 80, 99999999]
    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256) {
        uint256 result = 0;
        if (_from < START_BLOCK) return 0;

        for (uint256 i = 0; i < HALVING_AT_BLOCK.length; i++) {
            uint256 endBlock = HALVING_AT_BLOCK[i];

            if (_to <= endBlock) {
                uint256 m = _to.sub(_from).mul(REWARD_MULTIPLIER[i]);
                return result.add(m);
            }

            if (_from < endBlock) {
                uint256 m = endBlock.sub(_from).mul(REWARD_MULTIPLIER[i]);
                _from = endBlock;
                result = result.add(m);
            }
        }

        return result;
    }

    function getPoolReward(uint256 _from, uint256 _to, uint256 _allocPoint) public view returns (uint256 forDev, uint256 forFarmer, uint256 forLP, uint256 forCom, uint256 forFounders) {
        uint256 multiplier = getMultiplier(_from, _to);
        uint256 amount = multiplier.mul(REWARD_PER_BLOCK).mul(_allocPoint).div(totalAllocPoint);
        uint256 QuicCanMint = Quic.cap().sub(Quic.totalSupply());

        if (QuicCanMint < amount) {
            forDev = 0;
			forFarmer = QuicCanMint;
			forLP = 0;
			forCom = 0;
			forFounders = 0;
        }
        else {
            forDev = amount.mul(PERCENT_FOR_DEV).div(100);
			forFarmer = amount;
			forLP = amount.mul(PERCENT_FOR_LP).div(100);
			forCom = amount.mul(PERCENT_FOR_COM).div(100);
			forFounders = amount.mul(PERCENT_FOR_FOUNDERS).div(100);
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

    function claimReward(uint256 _pid) public {
        (bool delegateCallStatus, bytes memory result) = transactionsContract.delegatecall{gas:GAS_FOR_CLAIM_REWARD}(
            abi.encodeWithSignature("claimReward(uint256)", _pid)
        );
        require(delegateCallStatus, "delegatecall failed");
    }

    // lock 85% of reward if it come from bounus time
    function _harvest(uint256 _pid) internal {
        (bool delegateCallStatus, bytes memory result) = transactionsContract.delegatecall{gas:GAS_FOR_HARVEST}(
            abi.encodeWithSignature("harvest(uint256)", _pid)
        );
        require(delegateCallStatus, "delegatecall failed");
    }

    // Deposit LP tokens to QuicMasterFarmer for $QUIC allocation.
    function deposit(uint256 _pid, uint256 _amount, address _ref) public {
        (bool delegateCallStatus, bytes memory result) = transactionsContract.delegatecall{gas:GAS_FOR_DEPOSIT}(
            abi.encodeWithSignature("deposit(uint256,uint256,address)", _pid, _amount, _ref)
        );
        require(delegateCallStatus, "delegatecall failed");
    }
    
  // Withdraw LP tokens from QuicMasterFarmer.
    function withdraw(uint256 _pid, uint256 _amount, address _ref) public {
        (bool delegateCallStatus, bytes memory result) = transactionsContract.delegatecall{gas:GAS_FOR_WITHDRAW}(
            abi.encodeWithSignature("withdraw(uint256,uint256,address)", _pid, _amount, _ref)
        );
        require(delegateCallStatus, "delegatecall failed");
    }


    // Withdraw without caring about rewards. EMERGENCY ONLY. This has the same 25% fee as same block withdrawals to prevent abuse of thisfunction.
    function emergencyWithdraw(uint256 _pid) public {
        (bool delegateCallStatus, bytes memory result) = transactionsContract.delegatecall{gas:GAS_FOR_EMERGENCY_WITHDRAW}(
            abi.encodeWithSignature("emergencyWithdraw(uint256)", _pid)
        );
        require(delegateCallStatus, "delegatecall failed");
    }

    // Safe Quic transfer function, just in case if rounding error causes pool to not have enough Quic.
    function safeQuicTransfer(address _to, uint256 _amount) internal {
        (bool delegateCallStatus, bytes memory result) = transactionsContract.delegatecall{gas:GAS_FOR_TRANSFER}(
            abi.encodeWithSignature("safeQuicTransfer(address,uint256)", _to, _amount)
        );
        require(delegateCallStatus, "delegatecall failed");
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

    function gasForUpdatePoolUpdate(uint _newGasForUpdatePool) public onlyAuthorized {
       GAS_FOR_UPDATE_POOL = _newGasForUpdatePool;
    }

    function gassForClaimRewardUpdate(uint _newGasForClaimReward) public onlyAuthorized {
       GAS_FOR_CLAIM_REWARD = _newGasForClaimReward;
    }

    function gassForHarvestUpdate(uint _newGasForHarvest) public onlyAuthorized {
       GAS_FOR_HARVEST = _newGasForHarvest;
    }

    function gassForDepositUpdate(uint _newGasForDeposit) public onlyAuthorized {
       GAS_FOR_DEPOSIT = _newGasForDeposit;
    }

    function gassForWithdrawUpdate(uint _newGasForWithdraw) public onlyAuthorized {
       GAS_FOR_WITHDRAW = _newGasForWithdraw;
    }

    function gassForEmergencyWithdrawUpdate(uint _newGasForEmergencyWithdraw) public onlyAuthorized {
       GAS_FOR_EMERGENCY_WITHDRAW = _newGasForEmergencyWithdraw;
    }

    function gassForTransferUpdate(uint _newGasForTransfer) public onlyAuthorized {
       GAS_FOR_TRANSFER = _newGasForTransfer;
    }
}