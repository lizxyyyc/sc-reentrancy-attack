/**
 * This script is for emergency use only. It allows for the withdrawal of all funds from all contracts in case of issues
 * during the process. It was used during the development phase, but I left it as a precautionary measure.
 */
#include <chrono>
#include <cstring>
#include <future>
#include <string>
#include <vector>
#include <openssl/rand.h>
#include <spdlog/spdlog.h>
#include "dotenv.h"

import evm_utils;

static std::future<std::pair<std::string, bool>>
withdrawFromTarget(const std::string_view rpcEndpoint, const SecureString &privateKey, const std::string_view chainIdHex,
                   const std::string_view contractAddress, const std::string_view fromAddress) {
    AddressValidator::validateOrThrow(contractAddress, "vulnerable contract");
    AddressValidator::validateOrThrow(fromAddress, "withdraw from");
    auto rpcEndpointStr = std::string(rpcEndpoint);
    auto chainIdHexStr = std::string(chainIdHex);
    auto contractAddressStr = std::string(contractAddress);
    auto fromAddressStr = std::string(fromAddress);
    SecureString privateKeyCopy(privateKey);
    return std::async(std::launch::async,
                      [rpcEndpointStr, chainIdHexStr, contractAddressStr, fromAddressStr,
                       privateKeyCopy]() -> std::pair<std::string, bool> {
                          const uint64_t currentNonce = g_nonceManager.allocateNonce();
                          constexpr std::string_view functionSignature = "withdrawAll()";
                          const auto encodedCall
                                  = evm_codec::FunctionEncoder::encodeFunctionCall(std::string{functionSignature}, {}, {},
                                                                                   keccakHash);
                          std::string gasEstimate = FALLBACK_WITHDRAW_GAS;
                          try {
                              if (const auto tempEstimate
                                  = estimateTxGas(rpcEndpointStr, fromAddressStr, contractAddressStr, "0x0", encodedCall);
                                  !tempEstimate.empty() && tempEstimate != "null" && tempEstimate.length() > 2) {
                                  gasEstimate = tempEstimate;
                              }
                          } catch (const std::exception &e) {
                              spdlog::warn("Gas estimation failed for withdrawAll, using fallback: {}", e.what());
                          }
                          const uint64_t gasLimitInt = evm_codec::safeHexToUint64(gasEstimate);
                          const auto gasLimitWithBuffer
                                  = static_cast<uint64_t>(static_cast<double>(gasLimitInt) * GAS_LIMIT_BUFFER);
                          const auto gasLimitHex = formatHexValue(gasLimitWithBuffer);
                          const uint64_t chainId = evm_codec::safeHexToUint64(chainIdHexStr);
                          const auto [maxPriorityFeePerGas, maxFeePerGas] = getGasFees(rpcEndpointStr);
                          const auto nonceHex = formatHexValue(currentNonce);
                          std::string txHash;
                          try {
                              const auto signedTx
                                      = createSignedTx(privateKeyCopy, chainId, nonceHex, maxPriorityFeePerGas,
                                                       maxFeePerGas, gasLimitHex, contractAddressStr, "0x0", encodedCall);
                              txHash = sendRawTx(rpcEndpointStr, signedTx).get();
                              g_nonceManager.confirmNonce(currentNonce + 1);
                          } catch (const std::exception &e) {
                              if (const auto errorMsg = std::string(e.what());
                                  errorMsg.find("nonce too low") != std::string::npos
                                  || errorMsg.find("already known") != std::string::npos
                                  || errorMsg.find("replacement transaction") != std::string::npos) {
                                  spdlog::debug("Non-retryable transaction error: {}", errorMsg);
                              }
                              return std::make_pair(std::string(""), false);
                          }
                          if (txHash.empty() || txHash.length() < 66)
                              return std::make_pair(std::string(""), false);
                          bool confirmed = waitForConfirmationSync(rpcEndpointStr, txHash);
                          if (!confirmed)
                              spdlog::warn("Vulnerable contract withdrawal transaction failed or timed out: {}", txHash);
                          return std::make_pair(txHash, confirmed);
                      });
}

int main() {
    try {
        spdlog::set_level(spdlog::level::info);
        bool attackerWithdrawSuccess = false;
        bool attackerWithdrawAttempted = false;
        bool targetWithdrawSuccess = false;
        bool targetWithdrawAttempted = false;
        dotenv::init("../.env");
        const auto chainIdStr = dotenv::getenv("CHAIN_ID");
        const uint64_t chainId = std::stoull(chainIdStr);
        const auto chainIdHex = formatHexValue(chainId);
        const auto rpcEndpoint = dotenv::getenv("RPC_URL");
        if (chainIdStr.empty() || rpcEndpoint.empty()) {
            throw std::runtime_error("Required environment variables not found");
        }
        const auto targetContract = dotenv::getenv("TARGET_CONTRACT");
        const auto attackerContract1 = dotenv::getenv("ATTACKER_CONTRACT_1");
        const auto attackerContract2 = dotenv::getenv("ATTACKER_CONTRACT_2");
        std::future<std::pair<std::string, bool>> targetWithdrawal;
        if (!targetContract.empty()) {
            AddressValidator::validateOrThrow(targetContract, "vulnerable contract");
            auto targetBalanceCheck
                    = std::async(std::launch::async, [&] { return getContractBalance(rpcEndpoint, targetContract); });
            if (const uint64_t targetBalance = targetBalanceCheck.get(); targetBalance > 0) {
                targetWithdrawAttempted = true;
                spdlog::info("Vulnerable contract balance: {:.2f} ETH", weiToEth(targetBalance));
                const auto privateKey = loadPrivateKey("VICTIM_PRIVATE_KEY");
                const auto victimAddress = dotenv::getenv("VICTIM_ADDRESS");
                if (victimAddress.empty())
                    throw std::runtime_error("VICTIM_ADDRESS not found in .env file");
                AddressValidator::validateOrThrow(victimAddress, "victim sender");
                g_nonceManager.setCurrentAddress(victimAddress);
                auto nonceRetrieve
                        = std::async(std::launch::async, [&] { return getAddressNonce(rpcEndpoint, victimAddress); });
                const auto nonceStr = nonceRetrieve.get();
                g_nonceManager.initialize(victimAddress, evm_codec::safeHexToUint64(nonceStr));
                targetWithdrawal = withdrawFromTarget(rpcEndpoint, privateKey, chainIdHex, targetContract, victimAddress);
            } else {
                spdlog::info("Vulnerable contract has zero balance");
            }
        }
        if (!attackerContract1.empty() || !attackerContract2.empty()) {
            if (!attackerContract1.empty())
                AddressValidator::validateOrThrow(attackerContract1, "attacker contract 1");
            if (!attackerContract2.empty())
                AddressValidator::validateOrThrow(attackerContract2, "attacker contract 2");
            auto attackerBalancesCheck = std::async(std::launch::async, [&] {
                uint64_t total = 0;
                if (!attackerContract1.empty()) {
                    auto contract1Balance = std::async(std::launch::async,
                                                       [&] { return getContractBalance(rpcEndpoint, attackerContract1); });
                    total += contract1Balance.get();
                }
                if (!attackerContract2.empty()) {
                    auto contract2Balance = std::async(std::launch::async,
                                                       [&] { return getContractBalance(rpcEndpoint, attackerContract2); });
                    total += contract2Balance.get();
                }
                return total;
            });
            if (const uint64_t totalAttackerBalance = attackerBalancesCheck.get(); totalAttackerBalance > 0) {
                attackerWithdrawAttempted = true;
                spdlog::info("Attacker contracts total balance: {:.2f} ETH", weiToEth(totalAttackerBalance));
                const auto attackerPrivateKey = loadPrivateKey("ATTACKER_PRIVATE_KEY");
                const auto attackerAddress = dotenv::getenv("ATTACKER_ADDRESS");
                if (attackerAddress.empty())
                    throw std::runtime_error("ATTACKER_ADDRESS not found in .env file");
                AddressValidator::validateOrThrow(attackerAddress, "attacker sender");
                g_nonceManager.setCurrentAddress(attackerAddress);
                auto nonceRetrieve
                        = std::async(std::launch::async, [&] { return getAddressNonce(rpcEndpoint, attackerAddress); });
                const auto nonceStr = nonceRetrieve.get();
                g_nonceManager.initialize(attackerAddress, evm_codec::safeHexToUint64(nonceStr));
                try {
                    withdrawAttackerContracts(rpcEndpoint, attackerPrivateKey, chainIdHex, attackerContract1,
                                              attackerContract2, attackerAddress);
                    attackerWithdrawSuccess = true;
                } catch (const std::exception &e) {
                    spdlog::error("Attacker withdrawal failed: {}", e.what());
                    attackerWithdrawSuccess = false;
                }
            } else {
                spdlog::info("Attacker contracts have zero balance");
            }
        }
        if (targetWithdrawAttempted && targetWithdrawal.valid()) {
            try {
                if (const auto [txHash, success] = targetWithdrawal.get(); success) {
                    spdlog::info("Vulnerable contract withdrawal successful: {}", txHash);
                    targetWithdrawSuccess = true;
                } else if (!txHash.empty()) {
                    spdlog::error("Vulnerable withdrawal transaction sent but failed: {}", txHash);
                } else {
                    spdlog::error("Vulnerable withdrawal failed to send transaction");
                }
            } catch (const std::exception &e) {
                spdlog::error("Vulnerable withdrawal failed: {}", e.what());
            }
        }
        if (!targetWithdrawAttempted && !attackerWithdrawAttempted) {
            spdlog::info("No withdrawals needed. All contracts have zero balance");
        } else if (targetWithdrawAttempted == targetWithdrawSuccess
                   && attackerWithdrawAttempted == attackerWithdrawSuccess) {
            if (targetWithdrawAttempted && attackerWithdrawAttempted) {
                spdlog::info("All attempted withdrawals completed successfully");
            } else if (targetWithdrawAttempted) {
                spdlog::info("Vulnerable contract withdrawal completed successfully");
            } else {
                spdlog::info("Attacker withdrawal completed successfully");
            }
        } else {
            std::vector<std::string> results;
            results.reserve(2);
            if (targetWithdrawAttempted) {
                results.push_back(std::format("Vulnerable: {}", targetWithdrawSuccess ? "SUCCESS" : "FAILED"));
            }
            if (attackerWithdrawAttempted) {
                results.push_back(std::format("Attacker: {}", attackerWithdrawSuccess ? "SUCCESS" : "FAILED"));
            }
            std::string status;
            for (size_t i = 0; i < results.size(); ++i) {
                if (i > 0)
                    status += ", ";
                status += results[i];
            }
            spdlog::warn("Withdrawal results: {}", status);
        }
        return 0;
    } catch (const std::exception &e) {
        spdlog::error("Critical error: {}", e.what());
        return 1;
    }
}
