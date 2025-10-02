#include <future>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <openssl/rand.h>
#include <spdlog/spdlog.h>
#include "dotenv.h"

import evm_utils;

int main() {
    try {
        spdlog::set_level(spdlog::level::info);
        constexpr std::string_view envFile = "../.env";
        dotenv::init(envFile.data());
        const auto chainIdStr = dotenv::getenv("CHAIN_ID");
        const uint64_t chainId = std::stoull(chainIdStr);
        const auto chainIdHex = formatHexValue(chainId);
        const auto rpcEndpoint = dotenv::getenv("RPC_URL");
        const auto privateKey = loadPrivateKey("VICTIM_PRIVATE_KEY");
        const auto senderAddress = dotenv::getenv("VICTIM_ADDRESS");
        if (chainIdStr.empty() || rpcEndpoint.empty() || senderAddress.empty()) {
            throw std::runtime_error("Required environment variables not found");
        }
        AddressValidator::validateOrThrow(senderAddress, "victim");
        g_nonceManager.setCurrentAddress(senderAddress);
        auto networkVerification = std::async(std::launch::async, [&rpcEndpoint, &chainIdHex] {
            if (const auto networkChainId = verifyChainId(rpcEndpoint); networkChainId != chainIdHex) {
                spdlog::warn("Chain ID mismatch... Configured: {}, Network: {}", chainIdHex, networkChainId);
            }
        });
        auto bytecodeLoad
                = std::async(std::launch::async, [] { return loadBytecode("UnsafeResolutionHub_bytecode.json"); });
        auto initialization = std::async(std::launch::async, [&] {
            const auto balance = getAccountBalance(rpcEndpoint, senderAddress);
            const auto nonce = getAddressNonce(rpcEndpoint, senderAddress);
            return std::make_pair(balance, nonce);
        });
        networkVerification.wait();
        const auto [accountBalance, currentNonceStr] = initialization.get();
        const uint64_t balanceInt = evm_codec::safeHexToUint64(accountBalance);
        const double balanceEth = weiToEth(balanceInt);
        spdlog::info("- VULNERABLE CONTRACT DEPLOYMENT -");
        spdlog::info("Victim wallet balance: {:.2f} ETH", balanceEth);
        if (balanceInt == 0)
            throw std::runtime_error("Account has zero balance");
        g_nonceManager.initialize(senderAddress, evm_codec::safeHexToUint64(currentNonceStr));
        const auto bytecode = bytecodeLoad.get();
        spdlog::info("Deploying UnsafeResolutionHub contract...");
        auto deployment = executeDeployment(rpcEndpoint, privateKey, senderAddress, chainId, bytecode,
                                            std::span<const std::string>{}, std::span<const std::string>{}, true);
        const auto [success, responseJson] = deployment.get();
        if (!success) {
            std::string errorMsg = "Failed to deploy UnsafeResolutionHub contract";
            if (responseJson.contains("error")) {
                errorMsg += ": " + responseJson["error"].get<std::string>();
            }
            throw std::runtime_error(errorMsg);
        }
        const auto contractAddress = responseJson["contractAddress"].get<std::string>();
        const auto txHash = responseJson["txHash"].get<std::string>();
        spdlog::info("Deployment tx: {}", txHash);
        spdlog::info("Vulnerable contract address: {}", contractAddress);
        spdlog::info("Adding vulnerable contract to the .env file...\n");
        if (!updateEnvFile(envFile, {{"TARGET_CONTRACT", contractAddress}})) {
            throw std::runtime_error("Failed to update .env file with vulnerable contract address");
        }
        return 0;
    } catch (const std::exception &e) {
        spdlog::error("Critical error: {}", e.what());
        return 1;
    }
}
