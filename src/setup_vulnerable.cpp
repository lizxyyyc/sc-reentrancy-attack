#include <chrono>
#include <cstring>
#include <future>
#include <string>
#include <vector>
#include <openssl/rand.h>
#include <spdlog/spdlog.h>
#include "dotenv.h"

import evm_utils;

static std::string deposit(const std::string_view rpcEndpoint, const SecureString &privateKey, const uint64_t chainId,
                           const std::string_view contractAddress, const std::string_view fromAddress) {
    AddressValidator::validateOrThrow(contractAddress, "deposit contract");
    AddressValidator::validateOrThrow(fromAddress, "deposit from");
    const uint64_t nonce = g_nonceManager.allocateNonce();
    constexpr std::string_view functionSignature = "deposit()";
    const auto encodedCall
            = evm_codec::FunctionEncoder::encodeFunctionCall(std::string{functionSignature}, {}, {}, keccakHash);
    const auto gasEstimate
            = estimateTxGas(rpcEndpoint, fromAddress, contractAddress, formatHexValue(DEPOSIT_AMOUNT_WEI), encodedCall);
    const uint64_t gasInt = evm_codec::safeHexToUint64(gasEstimate);
    const auto gasLimit = formatHexValue(static_cast<uint64_t>(static_cast<double>(gasInt) * GAS_LIMIT_BUFFER));
    const auto [maxPriorityFeePerGas, maxFeePerGas] = getGasFees(rpcEndpoint);
    const auto signedTx = createSignedTx(privateKey, chainId, formatHexValue(nonce), maxPriorityFeePerGas, maxFeePerGas,
                                         gasLimit, contractAddress, formatHexValue(DEPOSIT_AMOUNT_WEI), encodedCall);
    const auto txHash = sendRawTx(rpcEndpoint, signedTx).get();
    g_nonceManager.confirmNonce(nonce + 1);
    return txHash;
}

static std::string createDispute(const std::string_view rpcEndpoint, const SecureString &privateKey,
                                 const uint64_t chainId, const std::string_view contractAddress, const uint64_t purchaseId,
                                 const std::string_view buyerAddress, const std::string_view sellerAddress,
                                 const std::string_view fromAddress) {
    AddressValidator::validateOrThrow(contractAddress, "dispute contract");
    AddressValidator::validateOrThrow(buyerAddress, "buyer");
    AddressValidator::validateOrThrow(sellerAddress, "seller");
    AddressValidator::validateOrThrow(fromAddress, "dispute from");
    const uint64_t nonce = g_nonceManager.allocateNonce();
    constexpr std::string_view functionSignature = "createDispute(uint256,address,address,uint256)";
    const std::vector<std::string> paramTypes = {"uint256", "address", "address", "uint256"};
    const std::vector params = {formatHexValue(purchaseId), std::string(buyerAddress), std::string(sellerAddress),
                                formatHexValue(DISPUTE_AMOUNT_WEI)};
    const auto encodedCall = evm_codec::FunctionEncoder::encodeFunctionCall(std::string{functionSignature}, paramTypes,
                                                                            params, keccakHash);
    const auto gasEstimate = estimateTxGas(rpcEndpoint, fromAddress, contractAddress, "0x0", encodedCall);
    const uint64_t gasInt = evm_codec::safeHexToUint64(gasEstimate);
    const auto gasLimit = formatHexValue(static_cast<uint64_t>(static_cast<double>(gasInt) * GAS_LIMIT_BUFFER));
    const auto [maxPriorityFeePerGas, maxFeePerGas] = getGasFees(rpcEndpoint);
    const auto signedTx = createSignedTx(privateKey, chainId, formatHexValue(nonce), maxPriorityFeePerGas, maxFeePerGas,
                                         gasLimit, contractAddress, "0x0", encodedCall);
    const auto txHash = sendRawTx(rpcEndpoint, signedTx).get();
    g_nonceManager.confirmNonce(nonce + 1);
    return txHash;
}

static std::string resolveDispute(const std::string_view rpcEndpoint, const SecureString &privateKey,
                                  const uint64_t chainId, const std::string_view contractAddress, const uint64_t disputeId,
                                  const std::string_view fromAddress) {
    AddressValidator::validateOrThrow(contractAddress, "resolve contract");
    AddressValidator::validateOrThrow(fromAddress, "resolve from");
    const uint64_t nonce = g_nonceManager.allocateNonce();
    constexpr std::string_view functionSignature = "resolveDispute(uint256,bool)";
    const std::vector<std::string> paramTypes = {"uint256", "bool"};
    const std::vector<std::string> params = {formatHexValue(disputeId), "1"};
    const auto encodedCall = evm_codec::FunctionEncoder::encodeFunctionCall(std::string{functionSignature}, paramTypes,
                                                                            params, keccakHash);
    const auto gasEstimate = estimateTxGas(rpcEndpoint, fromAddress, contractAddress, "0x0", encodedCall);
    const uint64_t gasInt = evm_codec::safeHexToUint64(gasEstimate);
    const auto gasLimit = formatHexValue(static_cast<uint64_t>(static_cast<double>(gasInt) * GAS_LIMIT_BUFFER));
    const auto [maxPriorityFeePerGas, maxFeePerGas] = getGasFees(rpcEndpoint);
    const auto signedTx = createSignedTx(privateKey, chainId, formatHexValue(nonce), maxPriorityFeePerGas, maxFeePerGas,
                                         gasLimit, contractAddress, "0x0", encodedCall);
    const auto txHash = sendRawTx(rpcEndpoint, signedTx).get();
    g_nonceManager.confirmNonce(nonce + 1);
    return txHash;
}

static std::vector<uint64_t> getOpenDisputes(const std::string_view rpcEndpoint, const std::string_view contractAddress,
                                             const std::string_view buyerAddress) {
    try {
        AddressValidator::validateOrThrow(contractAddress, "getOpenDisputes contract");
        AddressValidator::validateOrThrow(buyerAddress, "getOpenDisputes buyer");
        constexpr std::string_view functionSignature = "getOpenDisputes(address)";
        const std::vector<std::string> paramTypes = {"address"};
        const std::vector params = {std::string(buyerAddress)};
        const auto encodedCall = evm_codec::FunctionEncoder::encodeFunctionCall(std::string{functionSignature}, paramTypes,
                                                                                params, keccakHash);
        const auto result = callReadFunction(rpcEndpoint, contractAddress, encodedCall);
        if (result == "0x" || result.length() < MIN_ENCODED_RESULT_LENGTH)
            return {};
        return evm_codec::FunctionDecoder::decodeUint256Array(result);
    } catch (const std::exception &) {
        return {};
    }
}

static std::string getDisputeDetails(const std::string_view rpcEndpoint, const std::string_view contractAddress,
                                     const uint64_t disputeId) {
    try {
        AddressValidator::validateOrThrow(contractAddress, "getDisputeDetails contract");
        constexpr std::string_view functionSignature = "getDisputeDetails(uint256)";
        const std::vector<std::string> paramTypes = {"uint256"};
        const std::vector params = {std::to_string(disputeId)};
        const auto encodedCall = evm_codec::FunctionEncoder::encodeFunctionCall(std::string{functionSignature}, paramTypes,
                                                                                params, keccakHash);
        return callReadFunction(rpcEndpoint, contractAddress, encodedCall);
    } catch (const std::exception &) {
        return "";
    }
}

struct DisputeInfo {
    std::string buyer;
    uint64_t amount;
    bool resolved;
};

static DisputeInfo parseDisputeDetails(const std::string &detailsResult) {
    if (detailsResult.empty() || detailsResult.length() < MIN_ENCODED_RESULT_LENGTH || !detailsResult.starts_with("0x")) {
        throw std::runtime_error("Invalid dispute details format");
    }
    const std::vector<std::string> returnTypes = {"uint256", "address", "address", "uint256", "bool"};
    const auto decoded = evm_codec::FunctionDecoder::decodeParameters(returnTypes, detailsResult);
    if (decoded.size() != 5)
        throw std::runtime_error("Invalid dispute details structure");
    return {decoded[1], std::stoull(decoded[3]), decoded[4] == "true"};
}

int main() {
    try {
        spdlog::set_level(spdlog::level::info);
        dotenv::init("../.env");
        const auto chainIdStr = dotenv::getenv("CHAIN_ID");
        const uint64_t chainId = std::stoull(chainIdStr);
        const auto rpcEndpoint = dotenv::getenv("RPC_URL");
        const auto privateKey = loadPrivateKey("VICTIM_PRIVATE_KEY");
        const auto victimAddress = dotenv::getenv("VICTIM_ADDRESS");
        if (chainIdStr.empty() || rpcEndpoint.empty() || victimAddress.empty()) {
            throw std::runtime_error("Required environment variables not found");
        }
        AddressValidator::validateOrThrow(victimAddress, "victim wallet");
        g_nonceManager.setCurrentAddress(victimAddress);
        spdlog::info("Setting up Vulnerable contract with exploit prerequisites...");
        const auto nonceStr = getAddressNonce(rpcEndpoint, victimAddress);
        g_nonceManager.initialize(victimAddress, evm_codec::safeHexToUint64(nonceStr));
        const auto targetContract = dotenv::getenv("TARGET_CONTRACT");
        const auto attackerContract1 = dotenv::getenv("ATTACKER_CONTRACT_1");
        const auto attackerContract2 = dotenv::getenv("ATTACKER_CONTRACT_2");
        const auto sellerAddress = dotenv::getenv("SELLER");
        if (targetContract.empty()) {
            spdlog::error("TARGET_CONTRACT not found in .env file");
            return 1;
        }
        AddressValidator::validateOrThrow(targetContract, "target contract");
        spdlog::info("- DEPOSIT -");
        const auto depositHash = deposit(rpcEndpoint, privateKey, chainId, targetContract, victimAddress);
        spdlog::info("Deposit tx: {}", depositHash);
        if (!waitForConfirmationSync(rpcEndpoint, depositHash)) {
            spdlog::error("Deposit transaction failed");
            return 1;
        }
        if (!attackerContract1.empty() && !attackerContract2.empty() && !sellerAddress.empty()) {
            AddressValidator::validateOrThrow(attackerContract1, "attacker contract 1");
            AddressValidator::validateOrThrow(attackerContract2, "attacker contract 2");
            AddressValidator::validateOrThrow(sellerAddress, "seller");
            spdlog::info("- CREATE DISPUTES -");
            auto dispute1 = std::async(std::launch::async, [&] {
                return createDispute(rpcEndpoint, privateKey, chainId, targetContract, PURCHASE_ID_1, attackerContract1,
                                     sellerAddress, victimAddress);
            });
            auto dispute2 = std::async(std::launch::async, [&] {
                return createDispute(rpcEndpoint, privateKey, chainId, targetContract, PURCHASE_ID_2, attackerContract2,
                                     sellerAddress, victimAddress);
            });
            const auto dispute1Hash = dispute1.get();
            const auto dispute2Hash = dispute2.get();
            spdlog::info("Dispute nº{} tx: {}", PURCHASE_ID_1, dispute1Hash);
            spdlog::info("Dispute nº{} tx: {}", PURCHASE_ID_2, dispute2Hash);
            auto confirmation1 = waitForConfirmation(rpcEndpoint, dispute1Hash);
            auto confirmation2 = waitForConfirmation(rpcEndpoint, dispute2Hash);
            if (!confirmation1.get() || !confirmation2.get()) {
                spdlog::error("Failed to create disputes");
                return 1;
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
            const auto openDisputes1 = getOpenDisputes(rpcEndpoint, targetContract, attackerContract1);
            const auto openDisputes2 = getOpenDisputes(rpcEndpoint, targetContract, attackerContract2);
            if (openDisputes1.empty() || openDisputes2.empty()) {
                spdlog::error("No open disputes found");
                return 1;
            }
            spdlog::info("- RESOLVE DISPUTES -");
            std::vector<std::future<std::string>> resolutions;
            for (uint64_t disputeId: openDisputes1) {
                resolutions.push_back(std::async(std::launch::async, [&, disputeId] {
                    return resolveDispute(rpcEndpoint, privateKey, chainId, targetContract, disputeId, victimAddress);
                }));
            }
            for (uint64_t disputeId: openDisputes2) {
                resolutions.push_back(std::async(std::launch::async, [&, disputeId] {
                    return resolveDispute(rpcEndpoint, privateKey, chainId, targetContract, disputeId, victimAddress);
                }));
            }
            std::vector<std::string> resolutionHashes;
            for (auto &resolution: resolutions) {
                resolutionHashes.push_back(resolution.get());
            }
            size_t resIdx = 0;
            for (size_t i = 0; i < openDisputes1.size(); ++i) {
                spdlog::info("Resolution for dispute nº{} tx: {}", PURCHASE_ID_1, resolutionHashes[resIdx++]);
            }
            for (size_t i = 0; i < openDisputes2.size(); ++i) {
                spdlog::info("Resolution for dispute nº{} tx: {}", PURCHASE_ID_2, resolutionHashes[resIdx++]);
            }
            std::vector<std::future<bool>> confirmations;
            for (const auto &hash: resolutionHashes) {
                confirmations.push_back(waitForConfirmation(rpcEndpoint, hash));
            }
            bool allResolved = true;
            for (auto &confirmation: confirmations) {
                if (!confirmation.get()) {
                    allResolved = false;
                }
            }
            if (!allResolved) {
                spdlog::error("Some resolutions failed");
                const auto chainNonce = getAddressNonce(rpcEndpoint, victimAddress);
                g_nonceManager.syncWithChain(evm_codec::safeHexToUint64(chainNonce));
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
            std::vector<uint64_t> allDisputeIds;
            std::vector<std::string> expectedBuyers;
            std::vector<uint64_t> purchaseIds;
            for (uint64_t disputeId: openDisputes1) {
                allDisputeIds.push_back(disputeId);
                expectedBuyers.push_back(attackerContract1);
                purchaseIds.push_back(PURCHASE_ID_1);
            }
            for (uint64_t disputeId: openDisputes2) {
                allDisputeIds.push_back(disputeId);
                expectedBuyers.push_back(attackerContract2);
                purchaseIds.push_back(PURCHASE_ID_2);
            }
            for (size_t i = 0; i < allDisputeIds.size(); ++i) {
                const uint64_t disputeId = allDisputeIds[i];
                const uint64_t purchaseId = purchaseIds[i];
                const std::string &expectedBuyer = expectedBuyers[i];
                if (const auto detailsResult = getDisputeDetails(rpcEndpoint, targetContract, disputeId);
                    !detailsResult.empty()) {
                    try {
                        if (const auto [buyer, amount, resolved] = parseDisputeDetails(detailsResult);
                            buyer == expectedBuyer && amount == DISPUTE_AMOUNT_WEI && resolved) {
                            spdlog::info("✓ Dispute nº{} resolved in favor of the buyer", purchaseId);
                        } else {
                            spdlog::error("✗ Dispute nº{} verification failed", purchaseId);
                            return 1;
                        }
                    } catch (const std::exception &e) {
                        spdlog::error("Failed to parse dispute {} details: {}", purchaseId, e.what());
                        return 1;
                    }
                } else {
                    spdlog::error("Failed to get details for dispute {}", purchaseId);
                    return 1;
                }
            }
        } else {
            spdlog::warn("Skipping dispute operations... Missing environment variables");
        }
        spdlog::info("Setup completed successfully!\n");
        return 0;
    } catch (const std::exception &e) {
        spdlog::error("Critical error: {}", e.what());
        return 1;
    }
}
