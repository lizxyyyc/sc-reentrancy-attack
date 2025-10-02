Security in smart contracts represents a critical concern, with numerous vulnerability types posing significant risks. Among these, reentrancy stands as one of the most pernicious and critical vulnerabilities. Reentrancy vulnerabilities exist across multiple levels of sophistication and complexity.

This analysis exposes, explains, and exploits a reentrancy vulnerability in a smart contract that could be termed a **shared-state cross-function reentrancy vulnerability**, or simply **cross-function reentrancy vulnerability**. The root cause stems from multiple functions sharing the same state variable, with certain functions updating that variable insecurely, thereby creating exploitable inconsistencies in state protection.

Initial [testing](https://github.com/borj404/sc-reentrancy-attack/blob/master/logs/foundry_test_output.txt) was performed with Foundry; however, its controlled, deterministic environment substantially obscures the vulnerability’s practical impact, verging on rendering it theoretical. Given these limitations, I decided to perform the attack on a public testnet to observe real-world effects that Foundry's controlled environment cannot reproduce. The Base Sepolia testnet was chosen for its low gas costs and fast transaction confirmation times due to its Optimistic Rollup architecture.

This project implements every component from scratch using only essential cryptographic libraries such as secp256k1 and ethash, deliberately avoiding frameworks to maintain direct control and flexibility.

## The Vulnerable Contract Logic

_Throughout this explanation and the codebase, I refer to this contract as either "vulnerable" or "target" interchangeably._

The [`UnsafeResolutionHub`](https://github.com/borj404/sc-reentrancy-attack/blob/master/contracts/UnsafeResolutionHub.sol) contract is designed as a dispute resolution system for an e-commerce platform. Moderators can create disputes and determine beneficiaries and payout amounts, essentially providing a refund mechanism for dissatisfied buyers.

The contract provides users with two primary mechanisms to manage their funds:

- [`getRefund()` function](https://github.com/borj404/sc-reentrancy-attack/blob/master/contracts/UnsafeResolutionHub.sol#L156-L170): Allows callers (buyers) to withdraw their entire ETH balance from the contract's `balances` mapping. This balance is obtained through favorable dispute resolutions.

- [`donate()` function](https://github.com/borj404/sc-reentrancy-attack/blob/master/contracts/UnsafeResolutionHub.sol#L172-L186): Enables callers (buyers) to credit specified ETH amounts to other addresses. This function only modifies the internal `balances` mapping within the smart contract, requiring beneficiaries to call `getRefund()` later to withdraw the actual ETH. It could serve various purposes, including allocating resolution funds to different addresses, compensating sellers for shipping expenses, or donating to charitable causes.

_Note: To manipulate dispute resolutions in favor of buyers and obtain funds in the internal contract mapping, the seller and buyers could be the same person. For instance, an attacker, acting as seller, could list a product, purchase it multiple times using different attacker contract addresses, and then report defects to administrators, prompting dispute resolution in favor of the buyers. However, these social engineering tactics fall outside the scope of this reentrancy vulnerability analysis._

## The Vulnerability in the Contract

The vulnerability arises from inconsistent reentrancy protection across functions that manipulate shared state, enabling a cross-function reentrancy attack. The core flaw lies in the `getRefund` function's violation of the Checks-Effects-Interactions pattern, where it performs an external call before updating critical state variables.

The `getRefund` function executes the following sequence:

- Reads the user's balance from the `balances` mapping.
- Validates that sufficient contract balance exists.
- Performs external call to send ETH to `msg.sender`.
- Updates state by setting `balances[msg.sender] = 0`.

```solidity
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
```

Notwithstanding the `nonReentrant` modifier (via [ReentrancyGuard](https://github.com/borj404/sc-reentrancy-attack/blob/master/contracts/ReentrancyGuard.sol)) on `getRefund`, this safeguard is insufficient, as the unprotected `donate` function also manipulates the same `balances` mapping.

```solidity
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
```

Cross-function reentrancy becomes possible because the architecture creates a fundamental inconsistency in state protection. The `balances` mapping serves as a shared critical resource accessed by both functions, yet only one implements reentrancy protection. When `getRefund` executes its external call, the contract's state remains inconsistent (the ETH balance has been transferred, but the internal balance has not yet been zeroed). During this window, the unprotected `donate` function provides an alternative pathway to manipulate the same shared state that `getRefund` attempts to modify.

This architectural flaw allows an attacker to reassign their recorded balance to another address in the interval between the external ETH transfer and the subsequent state update. As a result, the attacker can withdraw ETH while simultaneously redirecting their internal balance, effectively executing a functional double-spend.

## The Reentrancy Attack Workflow

The attack employs a two-contract coordination mechanism to systematically drain the vulnerable contract through alternating exploitation cycles. The attack setup requires deploying two instances of the [attacker contract](https://github.com/borj404/sc-reentrancy-attack/blob/master/contracts/FancyReentrancy.sol), each configured as peers. When the external call in `getRefund` triggers the malicious contract's `receive` function, the attacker can invoke `donate` to manipulate the shared `balances` mapping before `getRefund` completes its state update.

_This analysis assumes both attacker contracts have 0.01 ETH each in the target contract’s balances mapping (obtained through the dispute-resolution process). Having 0.01 ETH in each contract doubles the attack's drain rate._

_From here, the two attacker contract peers will be referred to as **Attacker1** and **Attacker2**, respectively._

### First Transaction Cycle (Attacker1 → Attacker2)

**Initial State:**

- Attacker1 & Attacker2: 0.01 ETH each in `balances` mapping.

**Initiation:**

- The attacker calls [`attacker1.attack()`](https://github.com/borj404/sc-reentrancy-attack/blob/master/contracts/FancyReentrancy.sol#L45-L49), triggering `resolutionHub.getRefund()`.

**Vulnerability Window Creation:**

- `getRefund` reads Attacker1's balance (0.01 ETH).
- Validates contract has sufficient funds.
- Executes external call: `msg.sender.call{value: balance}("")`.

**Exploitation Phase:**

- External call triggers [`attacker1.receive()`](https://github.com/borj404/sc-reentrancy-attack/blob/master/contracts/FancyReentrancy.sol#L31-L43).
- Attacker1's balance remains 0.01 ETH in mapping (not yet updated).
- `receive()` function calls `resolutionHub.donate(address(attackPeer), drainAmount)`.
- `donate` transfers 0.01 ETH from Attacker1 to Attacker2 in mapping.
- Balance state: Attacker1 = 0 ETH, Attacker2 = 0.02 ETH.

**Result:**

- Attacker1 receives 0.01 actual ETH.
- Attacker2 holds 0.02 ETH in mapping.

### Subsequent Cycles

The attack maintains a consistent extraction pattern after the initial round. Following the first transaction where Attacker1 extracts 0.01 ETH, Attacker2 now holds 0.02 ETH in the mapping. When `attacker2.attack()` is called, Attacker2 withdraws the full 0.02 ETH as actual ETH while simultaneously transferring this 0.02 ETH balance to Attacker1 through the `donate` function.

Each subsequent `attack()` call, alternating between the two attacker contracts, extracts 0.02 ETH from the contract's balance while maintaining the total internal balance of both attacker contracts at 0.02 ETH.

### Attack Termination

The attack continues with this consistent 0.02 ETH extraction per transaction until the contract's funds are completely drained or fall below [0.0001 ETH](https://github.com/borj404/sc-reentrancy-attack/blob/master/contracts/FancyReentrancy.sol#L14).

## Setup and Execution

### Prerequisites

*Note: These instructions are for Ubuntu Noble 24.04 and may vary for other distributions.*

**Install dependencies:**

Run the provided [installation script](https://github.com/borj404/sc-reentrancy-attack/edit/master/install_prerequisites.sh).

**Manual installation (alternative):**

If you prefer to install dependencies manually:

```bash
# Add repositories
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor - | sudo tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null
sudo apt-add-repository "deb https://apt.kitware.com/ubuntu/ noble main" -y
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor - | sudo tee /etc/apt/trusted.gpg.d/llvm-snapshot.gpg >/dev/null
echo "deb https://apt.llvm.org/noble/ llvm-toolchain-noble-18 main" | sudo tee /etc/apt/sources.list.d/llvm-18.list

# Install packages
sudo apt update && sudo apt install -y curl git cmake ninja-build clang-18 clang-tools-18 libcurl4-openssl-dev nlohmann-json3-dev libspdlog-dev libssl-dev
```

### Repository Structure

The repository files are organized with clear separation of concerns. Smart contracts are located in the `contracts` directory, while their corresponding bytecodes are placed in the `build` directory. The `include` directory contains the libraries, with the [`evm_utils` module](https://github.com/borj404/sc-reentrancy-attack/blob/master/include/evm_utils.cppm) grouping shared functions for the scripts. All scripts are placed in the `src` directory and should be executed in the specified order:

- [`deploy_vulnerable.cpp`](https://github.com/borj404/sc-reentrancy-attack/blob/master/src/deploy_vulnerable.cpp): Deploys the [vulnerable contract](https://github.com/borj404/sc-reentrancy-attack/blob/master/contracts/UnsafeResolutionHub.sol) and adds the contract address to the .env file.

- [`deploy_attackers.cpp`](https://github.com/borj404/sc-reentrancy-attack/blob/master/src/deploy_attackers.cpp): Deploys two instances of the [attacker contract](https://github.com/borj404/sc-reentrancy-attack/blob/master/contracts/FancyReentrancy.sol), adds their addresses to the .env file, and configures each as the other's peer for the attack workflow.

- [`setup_vulnerable.cpp`](https://github.com/borj404/sc-reentrancy-attack/blob/master/src/setup_vulnerable.cpp): Funds the vulnerable contract (with 6.39 ETH in this case), creates disputes for both attacker contracts, and resolves them in favor of the attackers, allocating 0.01 ETH each in the balance mapping.

- [`execute_attack.cpp`](https://github.com/borj404/sc-reentrancy-attack/blob/master/src/execute_attack.cpp): Calculates the necessary calls to drain the entire vulnerable contract balance, precomputes all transactions, launches the attack, withdraws the stolen funds to the attacker wallet, and provides a final summary with the results. 

[Here you can check the entire execution workflow logs.](https://github.com/borj404/sc-reentrancy-attack/blob/master/logs/testnet_attack_results.txt)

The attack time measures the complete end-to-end duration from when the first transaction send operation is initiated (including all network propagation delays and processing time) until the last transaction is confirmed (or in this case, reverted by the safety extra transactions added) on-chain, capturing the complete attack execution time from the attacker's perspective.

_The [`withdraw.cpp`](https://github.com/borj404/sc-reentrancy-attack/blob/master/src/withdraw.cpp) script is for emergency use only. It allows for the withdrawal of all funds from all contracts in case of issues during the process. It was used during the development phase, but I left it as a precautionary measure._

The compilation and execution of this entire process is automated with [`run.sh`](https://github.com/borj404/sc-reentrancy-attack/blob/master/run.sh). To replicate the attack, ensure all fields in the [`.env`](https://github.com/borj404/sc-reentrancy-attack/edit/master/.env) file are properly filled.

Some constant values are adjusted to be executed on an L2 as Base Sepolia (low gas fees and short confirmation times), so if you intend to use a different network, you will probably have to modify these constants in the [`evm_utils` module](https://github.com/borj404/sc-reentrancy-attack/blob/master/include/evm_utils.cppm).

## Conclusion

The complete reentrancy attack (320 transactions) was executed in less than 10 seconds, draining the entire vulnerable contract balance (6.39 ETH). The precomputed transaction sequence completed within a timeframe that challenged even modern monitoring systems' ability to identify attack patterns and trigger automated defensive responses. This precomputed approach demonstrates the double-edged nature of L2 efficiency: the same near-instant transaction confirmation that enhances user experience also accelerates attack execution, potentially transforming smart contract vulnerabilities into attack vectors with drastically reduced detection and intervention timeframes.

At its core, smart contract security is ultimately determined by the logic deployed on-chain. The blockchain executes exactly what we have written, not what we intended. In an immutable ecosystem, this gap between code and intent can prove devastatingly expensive.

## A Bit of History

On June 17th, 2016, an attacker executed the most consequential smart contract exploit in blockchain history, draining 3.6 million ETH from [The DAO](https://etherscan.io/address/0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413) through a reentrancy attack. This event ultimately led to the Ethereum hard fork.

The target was The DAO's `splitDAO` function, which made external calls before updating its internal state. The attacker deployed a malicious contract with a fallback function that recursively called `splitDAO` whenever it received ETH. Since the attacker's balance wasn't zeroed until after the external call completed, each recursive invocation found them still eligible for withdrawal, allowing rapid fund drainage.

The attack exploited Ethereum's transaction processing: external calls pass control to the receiving contract, which can execute arbitrary code before returning control to the original caller. The attacker drained over 3.6 million ETH, representing almost one-third of The DAO's total funds.

I won't expand further on the technical aspects, but if you're interested, here is [The DAO contract](https://github.com/TheDAO/DAO-1.0/blob/master/DAO.sol).

All evidence points to the attacker voluntarily stopping the attack the next day, leaving the remaining 9 million ETH untouched. Days later, amid community panic about whether the original attacker might return or copycat attackers might emerge, a group of white hat hackers called the Robin Hood Group used the same vulnerability to drain the remaining funds into their own child DAOs to "rescue" them. The ultimate solution came through Ethereum's controversial hard fork, which reversed the entire attack.

What made the situation particularly troubling was that security researchers had identified this vulnerability during The DAO's funding period, but their warnings were not adequately addressed.

The attack precipitated a fundamental crisis about blockchain technology itself. The Ethereum community split between two philosophies: one faction argued that blockchain immutability was sacred, even accepting the theft, as reversing it would undermine the trustless system and set a dangerous precedent. The opposing faction contended that allowing the theft would destroy confidence in smart contracts and set back decentralized application development by years. But this text does not aim to delve into that philosophical dilemma.

After intense community debate, Ethereum underwent a hard fork that reversed the attack by redirecting stolen funds to a recovery contract. However, a significant minority rejected this intervention and continued mining the original chain, now called Ethereum Classic.

The attack led directly to industry-wide adoption of the Checks-Effects-Interactions pattern, requiring smart contracts to update internal state before making external calls. It also catalyzed an entire security ecosystem: automated vulnerability scanners, specialized audit firms, and development frameworks with built-in protections.

Most importantly, the attack transformed smart contract development from experimental practice into disciplined engineering. It established that blockchain's immutability makes mistakes potentially catastrophic, requiring unprecedented rigor in development.

Despite the widespread adoption of security best practices, reentrancy vulnerabilities continue to be exploited at a concerning rate; more than 80 documented reentrancy attacks have been carried out, the vast majority on EVM-based blockchains. As new protocols emerge, potential vulnerabilities grow, expanding the ecosystem's attack surface.

## Disclaimer

This repository is intended exclusively for educational and research purposes to enhance understanding of smart contract security vulnerabilities. The exploitation techniques and methodologies presented must not be used for malicious purposes, including unauthorized access to smart contracts, theft of digital assets, or any activities that violate applicable laws and regulations.

The author expressly disclaims all responsibility and liability for any damages arising from the use or misuse of this information. Users assume full responsibility for their actions and any legal consequences thereof. Users are solely responsible for ensuring their activities comply with all applicable local, national, and international laws and regulations.

This repository's content is under the [MIT license](https://github.com/borj404/sc-reentrancy-attack/blob/master/LICENSE).

By accessing this repository, you acknowledge that you have read, understood, and agree to be bound by these terms.
