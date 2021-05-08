// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

import "./QuicMasterStorage.sol";

contract QuicMasterTransactions is QuicMasterStorage,  Ownable, Authorizable {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    
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

   // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (lpSupply == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }
        uint256 QuicForDev;
        uint256 QuicForFarmer;
		uint256 QuicForLP;
		uint256 QuicForCom;
		uint256 QuicForFounders;
        (QuicForDev, QuicForFarmer, QuicForLP, QuicForCom, QuicForFounders) = getPoolReward(pool.lastRewardBlock, block.number, pool.allocPoint);
        Quic.mint(address(this), QuicForFarmer);
        pool.accQuicPerShare = pool.accQuicPerShare.add(QuicForFarmer.mul(1e12).div(lpSupply));
        pool.lastRewardBlock = block.number;
        if (QuicForDev > 0) {
            Quic.mint(address(devaddr), QuicForDev);
            //Dev fund has xx% locked during the starting bonus period. After which locked funds drip out linearly each block over 3 years.
            if (block.number <= FINISH_BONUS_AT_BLOCK) {
                Quic.lock(address(devaddr), QuicForDev.mul(75).div(100));
            }
        }
		if (QuicForLP > 0) {
            Quic.mint(liquidityaddr, QuicForLP);
			//LP + Partnership fund has only xx% locked over time as most of it is needed early on for incentives and listings. The locked amount will drip out linearly each block after the bonus period.
			if (block.number <= FINISH_BONUS_AT_BLOCK) {
                Quic.lock(address(liquidityaddr), QuicForLP.mul(45).div(100));
            }
        }
		if (QuicForCom > 0) {
            Quic.mint(comfundaddr, QuicForCom);
			//Community Fund has xx% locked during bonus period and then drips out linearly over 3 years.
            if (block.number <= FINISH_BONUS_AT_BLOCK) {
                Quic.lock(address(comfundaddr), QuicForCom.mul(85).div(100));
            }
        }
		if (QuicForFounders > 0) {
            Quic.mint(founderaddr, QuicForFounders);
			//The Founders reward has xx% of their funds locked during the bonus period which then drip out linearly per block over 3 years.
			if (block.number <= FINISH_BONUS_AT_BLOCK) {
                Quic.lock(address(founderaddr), QuicForFounders.mul(95).div(100));
            }
        }
        
    }
    function claimReward(uint256 _pid) public {
        updatePool(_pid);
        _harvest(_pid);
    }

    // lock 85% of reward if it come from bounus time
    function _harvest(uint256 _pid) internal {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        if (user.amount > 0) {
            uint256 pending = user.amount.mul(pool.accQuicPerShare).div(1e12).sub(user.rewardDebt);
            uint256 masterBal = Quic.balanceOf(address(this));

            if (pending > masterBal) {
                pending = masterBal;
            }
            
            if(pending > 0) {
                Quic.transfer(msg.sender, pending);
                uint256 lockAmount = 0;
                if (user.rewardDebtAtBlock <= FINISH_BONUS_AT_BLOCK) {
                    lockAmount = pending.mul(PERCENT_LOCK_BONUS_REWARD).div(100);
                    Quic.lock(msg.sender, lockAmount);
                }

                user.rewardDebtAtBlock = block.number;

                emit SendQuicReward(msg.sender, _pid, pending, lockAmount);
            }

            user.rewardDebt = user.amount.mul(pool.accQuicPerShare).div(1e12);
        }
    }



    
    // Deposit LP tokens to QuicMasterFarmer for $QUIC allocation.
    function deposit(uint256 _pid, uint256 _amount, address _ref) public {
        require(_amount > 0, "QuicMasterFarmer::deposit: amount must be greater than 0");

        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        UserInfo storage devr = userInfo[_pid][devaddr];
        UserGlobalInfo storage refer = userGlobalInfo[_ref];
        UserGlobalInfo storage current = userGlobalInfo[msg.sender];
        
        if(refer.referrals[msg.sender] > 0){
            refer.referrals[msg.sender] = refer.referrals[msg.sender] + _amount;
            refer.globalRefAmount = refer.globalRefAmount + _amount;
        } else {
            refer.referrals[msg.sender] = refer.referrals[msg.sender] + _amount;
            refer.totalReferals = refer.totalReferals + 1;
            refer.globalRefAmount = refer.globalRefAmount + _amount;
        }

        current.globalAmount = current.globalAmount + _amount.mul(userDepFee).div(100);
        
        updatePool(_pid);
        _harvest(_pid);
        pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
        if (user.amount == 0) {
            user.rewardDebtAtBlock = block.number;
        }
        // User amount is the amount deposited and deposit fee is reduced from the user and added
        // to the dev
        uint256 depositFee = _amount.mul(userDepFee).div(10000);
        //Add the Amount less the depositFee to the user
        user.amount = user.amount.add(_amount.sub(depositFee));
        // Ad the depositFee to the Dev
        devr.amount = devr.amount.add(depositFee);
        user.rewardDebt = user.amount.mul(pool.accQuicPerShare).div(1e12);
        devr.rewardDebt = devr.amount.mul(pool.accQuicPerShare).div(1e12);
        emit Deposit(msg.sender, _pid, _amount);
		if(user.firstDepositBlock > 0){
		} else {
			user.firstDepositBlock = block.number;
		}
		user.lastDepositBlock = block.number;
    }
    
  // Withdraw LP tokens from QuicMasterFarmer.
    function withdraw(uint256 _pid, uint256 _amount, address _ref) public {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        UserGlobalInfo storage refer = userGlobalInfo[_ref];
        UserGlobalInfo storage current = userGlobalInfo[msg.sender];
        require(user.amount >= _amount, "QuicMasterFarmer::withdraw: not good");
        if(_ref != address(0)){
                refer.referrals[msg.sender] = refer.referrals[msg.sender] - _amount;
                refer.globalRefAmount = refer.globalRefAmount - _amount;
            }
        current.globalAmount = current.globalAmount - _amount;
        
        updatePool(_pid);
        _harvest(_pid);

        if(_amount > 0) {
            user.amount = user.amount.sub(_amount);
			if(user.lastWithdrawBlock > 0){
				user.blockdelta = block.number - user.lastWithdrawBlock; }
			else {
				user.blockdelta = block.number - user.firstDepositBlock;
			}
			if(user.blockdelta == blockDeltaStartStage[0] || block.number == user.lastDepositBlock){
				//25% fee for withdrawals of LP tokens in the same block this is to prevent abuse from flashloans
				pool.lpToken.safeTransfer(address(msg.sender), _amount.mul(userFeeStage[0]).div(100));
				pool.lpToken.safeTransfer(address(devaddr), _amount.mul(devFeeStage[0]).div(100));
			} else if (user.blockdelta >= blockDeltaStartStage[1] && user.blockdelta <= blockDeltaEndStage[0]){
				//8% fee if a user deposits and withdraws in under between same block and 59 minutes.
				pool.lpToken.safeTransfer(address(msg.sender), _amount.mul(userFeeStage[1]).div(100));
				pool.lpToken.safeTransfer(address(devaddr), _amount.mul(devFeeStage[1]).div(100));
			} else if (user.blockdelta >= blockDeltaStartStage[2] && user.blockdelta <= blockDeltaEndStage[1]){
				//4% fee if a user deposits and withdraws after 1 hour but before 1 day.
				pool.lpToken.safeTransfer(address(msg.sender), _amount.mul(userFeeStage[2]).div(100));
				pool.lpToken.safeTransfer(address(devaddr), _amount.mul(devFeeStage[2]).div(100));
			} else if (user.blockdelta >= blockDeltaStartStage[3] && user.blockdelta <= blockDeltaEndStage[2]){
				//2% fee if a user deposits and withdraws between after 1 day but before 3 days.
				pool.lpToken.safeTransfer(address(msg.sender), _amount.mul(userFeeStage[3]).div(100));
				pool.lpToken.safeTransfer(address(devaddr), _amount.mul(devFeeStage[3]).div(100));
			} else if (user.blockdelta >= blockDeltaStartStage[4] && user.blockdelta <= blockDeltaEndStage[3]){
				//1% fee if a user deposits and withdraws after 3 days but before 5 days.
				pool.lpToken.safeTransfer(address(msg.sender), _amount.mul(userFeeStage[4]).div(100));
				pool.lpToken.safeTransfer(address(devaddr), _amount.mul(devFeeStage[4]).div(100));
			}  else if (user.blockdelta >= blockDeltaStartStage[5] && user.blockdelta <= blockDeltaEndStage[4]){
				//0.5% fee if a user deposits and withdraws if the user withdraws after 5 days but before 2 weeks.
				pool.lpToken.safeTransfer(address(msg.sender), _amount.mul(userFeeStage[5]).div(1000));
				pool.lpToken.safeTransfer(address(devaddr), _amount.mul(devFeeStage[5]).div(1000));
			} else if (user.blockdelta >= blockDeltaStartStage[6] && user.blockdelta <= blockDeltaEndStage[5]){
				//0.25% fee if a user deposits and withdraws after 2 weeks.
				pool.lpToken.safeTransfer(address(msg.sender), _amount.mul(userFeeStage[6]).div(10000));
				pool.lpToken.safeTransfer(address(devaddr), _amount.mul(devFeeStage[6]).div(10000));
			} else {
				//0.0% fee if a user deposits and withdraws after 4 weeks.
				pool.lpToken.safeTransfer(address(msg.sender), _amount);
			}
            user.rewardDebt = user.amount.mul(pool.accQuicPerShare).div(1e12);
            emit Withdraw(msg.sender, _pid, _amount);
            user.lastWithdrawBlock = block.number;
        }   
    }


    // Withdraw without caring about rewards. EMERGENCY ONLY. This has the same 25% fee as same block withdrawals to prevent abuse of thisfunction.
    function emergencyWithdraw(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        //reordered from Sushi function to prevent risk of reentrancy
        uint256 amountToSend = user.amount.mul(75).div(100);
        uint256 devToSend = user.amount.mul(25).div(100);
        user.amount = 0;
        user.rewardDebt = 0;
        pool.lpToken.safeTransfer(address(msg.sender), amountToSend);
        pool.lpToken.safeTransfer(address(devaddr), devToSend);
        emit EmergencyWithdraw(msg.sender, _pid, amountToSend);

    }

    // Safe Quic transfer function, just in case if rounding error causes pool to not have enough Quic.
    function safeQuicTransfer(address _to, uint256 _amount) internal {
        uint256 QuicBal = Quic.balanceOf(address(this));
        if (_amount > QuicBal) {
            Quic.transfer(_to, QuicBal);
        } else {
            Quic.transfer(_to, _amount);
        }
    }
}