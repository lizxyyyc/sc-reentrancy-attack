// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "./ReentrancyGuard.sol";

contract UnsafeResolutionHub is ReentrancyGuard {
    address public immutable owner;
    uint256 public disputeCounter;

    struct Dispute {
        uint256 purchaseId;
        address buyer;
        address seller;
        uint256 amount;
        bool resolved;
    }

    mapping(address => uint256) private balances;
    mapping(address => bool) public isMediator;
    mapping(uint256 => Dispute) public disputes;
    mapping(address => uint256[]) private unresolvedDisputes;

    error InsufficientBalance();
    error TransferFailed();
    error InvalidAmount();
    error DisputeAlreadyResolved();
    error OnlyOwner();
    error OnlyOwnerOrMediator();
    error NoBalanceToWithdraw();
    error InsufficientContractBalance();
    error InvalidRecipient();
    error CannotTransferToYourself();
    error AmountMustBeGreaterThanZero();
    error InsufficientUserBalance();
    error ContractWouldBecomeInsolvent();
    error DisputeNotFound();

    event DisputeCreated(
        uint256 indexed disputeId,
        uint256 purchaseId,
        address indexed buyer,
        address indexed seller,
        uint256 amount
    );
    event DisputeResolved(
        uint256 indexed disputeId,
        address indexed buyer,
        address indexed seller,
        bool resolution,
        uint256 amount
    );
    event BalanceUpdated(address indexed user, uint256 newBalance);
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    modifier onlyOwnerOrMediator() {
        if (msg.sender != owner && !isMediator[msg.sender]) {
            revert OnlyOwnerOrMediator();
        }
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable onlyOwner {
        emit Deposit(msg.sender, msg.value);
    }

    function withdrawAll() external onlyOwner nonReentrant {
        uint256 balance = address(this).balance;
        if (balance == 0) revert InsufficientBalance();
        (bool success, ) = payable(owner).call{value: balance}("");
        if (!success) revert TransferFailed();
        emit Withdrawal(owner, balance);
    }

    function setMediator(address _mediator, bool _isActive) external onlyOwner {
        if (_mediator == address(0)) revert InvalidRecipient();
        isMediator[_mediator] = _isActive;
    }

    function createDispute(
        uint256 _purchaseId,
        address _buyer,
        address _seller,
        uint256 _amount
    ) external onlyOwnerOrMediator {
        if (_amount == 0) revert InvalidAmount();
        if (_buyer == address(0) || _seller == address(0))
            revert InvalidRecipient();
        if (_buyer == _seller) revert CannotTransferToYourself();

        uint256 disputeId;
        unchecked {
            disputeId = ++disputeCounter;
        }

        disputes[disputeId] = Dispute({
            purchaseId: _purchaseId,
            buyer: _buyer,
            seller: _seller,
            amount: _amount,
            resolved: false
        });

        unresolvedDisputes[_buyer].push(disputeId);
        emit DisputeCreated(disputeId, _purchaseId, _buyer, _seller, _amount);
    }

    function resolveDispute(
        uint256 _disputeId,
        bool _resolution
    ) external onlyOwnerOrMediator nonReentrant {
        Dispute storage dispute = disputes[_disputeId];
        if (dispute.buyer == address(0)) revert DisputeNotFound();
        if (dispute.resolved) revert DisputeAlreadyResolved();

        dispute.resolved = true;

        if (_resolution) {
            unchecked {
                balances[dispute.buyer] += dispute.amount;
            }
            emit BalanceUpdated(dispute.buyer, balances[dispute.buyer]);
        }

        uint256[] storage unresolved = unresolvedDisputes[dispute.buyer];
        uint256 length = unresolved.length;
        for (uint256 i; i < length; ) {
            if (unresolved[i] == _disputeId) {
                unresolved[i] = unresolved[length - 1];
                unresolved.pop();
                break;
            }
            unchecked {
                ++i;
            }
        }

        emit DisputeResolved(
            _disputeId,
            dispute.buyer,
            dispute.seller,
            _resolution,
            dispute.amount
        );
    }

    function getRefund() external nonReentrant {
        uint256 balance = balances[msg.sender];
        if (balance == 0) revert NoBalanceToWithdraw();
        if (address(this).balance < balance)
            revert InsufficientContractBalance();
            
        // External call before state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // State update after external call
        balances[msg.sender] = 0;
        emit BalanceUpdated(msg.sender, 0);
        emit Withdrawal(msg.sender, balance);
    }

    // No reentrancy protection
    function donate(address _to, uint256 _amount) external {
        if (_to == address(0)) revert InvalidRecipient();
        if (_to == msg.sender) revert CannotTransferToYourself();
        if (_amount == 0) revert AmountMustBeGreaterThanZero();
        if (balances[msg.sender] < _amount) revert InsufficientUserBalance();

        unchecked {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
        }

        emit BalanceUpdated(msg.sender, balances[msg.sender]);
        emit BalanceUpdated(_to, balances[_to]);
    }

    function userBalance() external view returns (uint256) {
        return balances[msg.sender];
    }

    function getOpenDisputes(
        address _buyer
    ) external view returns (uint256[] memory) {
        return unresolvedDisputes[_buyer];
    }

    function getDisputeDetails(
        uint256 _disputeId
    )
        external
        view
        returns (
            uint256 purchaseId,
            address buyer,
            address seller,
            uint256 amount,
            bool resolved
        )
    {
        Dispute storage dispute = disputes[_disputeId];
        return (
            dispute.purchaseId,
            dispute.buyer,
            dispute.seller,
            dispute.amount,
            dispute.resolved
        );
    }
}
