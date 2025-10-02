module;

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <fstream>
#include <future>
#include <list>
#include <map>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <optional>
#include <queue>
#include <regex>
#include <semaphore>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>
#include <curl/curl.h>
#include <ethash/keccak.hpp>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <spdlog/spdlog.h>
#include <sys/mman.h>
#include "dotenv.h"

export module evm_utils;
export import EVM_CODEC;
export using json = nlohmann::json;
using namespace std::literals;
using namespace evm_codec;

export constexpr int RPC_CONNECT_TIMEOUT_SECONDS = 10;
export constexpr int RPC_TIMEOUT_SECONDS = 30;
export constexpr int MAX_TX_RETRIES = 3;
export constexpr int RECEIPT_MAX_RETRIES = 30;
export constexpr int MAX_CONFIRMATION_ATTEMPTS = 60;
export constexpr int BASE_RETRY_DELAY_MS = 1000;
export constexpr int CONFIRMATION_DELAY_MS = 500;
export constexpr int RECEIPT_RETRY_DELAY_MS = 100;
export constexpr int MAX_RETRY_BACKOFF_MS = 30000;
export constexpr int POST_ATTACK_DELAY_SECONDS = 3;
export constexpr double GAS_LIMIT_BUFFER = 1.3;
export constexpr double BASE_FEE_MULTIPLIER_NORMAL = 1.5;
export constexpr double BASE_FEE_MULTIPLIER_FAST = 2.0;
export constexpr uint64_t MIN_PRIORITY_FEE = 10000ULL;
export constexpr uint64_t MAX_PRIORITY_FEE = 100000ULL;
export constexpr uint64_t DEPOSIT_AMOUNT_WEI = 6390000000000000000ULL;
export constexpr uint64_t DISPUTE_AMOUNT_WEI = 10000000000000000ULL;
export constexpr uint64_t PURCHASE_ID_1 = 13658;
export constexpr uint64_t PURCHASE_ID_2 = 13661;
export constexpr uint64_t MIN_ATTACK_THRESHOLD_WEI = 100000000000000ULL;
export constexpr uint64_t MAX_ATTACK_TRANSACTIONS = 999;
export constexpr uint64_t ATTACK_SAFETY_BUFFER_TXS = 3;
export constexpr size_t MIN_ENCODED_RESULT_LENGTH = 66;
export constexpr size_t MAX_COMPUTE_THREADS = 64;
export constexpr size_t PMR_BUFFER_SIZE = 1024 * 1024;
export constexpr size_t CURL_POOL_SIZE = 32;
export constexpr size_t MAX_CACHE_ENTRIES = 1000;
export constexpr size_t MAX_FILE_SIZE = 100'000'000;
export constexpr size_t MAX_SIZE = 10'000'000;
export constexpr auto FALLBACK_VULNERABLE_DEPLOYMENT_GAS = "0x1dc130";
export constexpr auto FALLBACK_ATTACKER_DEPLOYMENT_GAS = "0x94ed0";
export constexpr auto FALLBACK_SETPEER_GAS = "0xbb80";
export constexpr auto FALLBACK_WITHDRAW_GAS = "0x7918";

export template<typename T>
struct SecureAllocator {
    using value_type = T;
    template<typename U>
    struct rebind {
        using other = SecureAllocator<U>;
    };
    SecureAllocator() = default;
    template<typename U>
    explicit SecureAllocator(const SecureAllocator<U> &) noexcept {}
    static T *allocate(const std::size_t n) {
        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
            throw std::bad_alloc();
        void *ptr = std::aligned_alloc(alignof(T), n * sizeof(T));
        if (!ptr)
            throw std::bad_alloc();
        if (mlock(ptr, n * sizeof(T)) != 0) {
            std::free(ptr);
            throw std::runtime_error("Failed to lock memory");
        }
        return static_cast<T *>(ptr);
    }
    static void deallocate(T *ptr, const std::size_t n) noexcept {
        if (!ptr)
            return;
        OPENSSL_cleanse(ptr, n * sizeof(T));
        munlock(ptr, n * sizeof(T));
        std::free(ptr);
    }
    bool operator==(const SecureAllocator &) const noexcept { return true; }
    bool operator!=(const SecureAllocator &) const noexcept { return false; }
};

export using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
export using SecureBytes = std::vector<uint8_t, SecureAllocator<uint8_t>>;

export class NonceManager {
    struct NonceState {
        alignas(64) std::atomic<uint64_t> next{0};
        alignas(64) std::atomic<uint64_t> confirmed{0};
        alignas(64) std::atomic<bool> initialized{false};
    };
    mutable std::shared_mutex mtx;
    std::unordered_map<std::string, std::unique_ptr<NonceState>> addressStates;
    std::string currentAddress;
    std::atomic<NonceState *> currentState{nullptr};

public:
    void setCurrentAddress(const std::string_view address) {
        std::unique_lock lock(mtx);
        currentAddress = std::string(address);
        if (const auto it = addressStates.find(currentAddress); it == addressStates.end()) {
            addressStates[currentAddress] = std::make_unique<NonceState>();
            currentState.store(addressStates[currentAddress].get(), std::memory_order_release);
        } else {
            currentState.store(it->second.get(), std::memory_order_release);
        }
    }
    void initialize(const std::string_view address, const uint64_t nonce) {
        std::unique_lock lock(mtx);
        auto &state = addressStates[std::string(address)];
        if (!state) {
            state = std::make_unique<NonceState>();
        }
        state->next.store(nonce, std::memory_order_relaxed);
        state->confirmed.store(nonce, std::memory_order_relaxed);
        state->initialized.store(true, std::memory_order_release);
        if (address == currentAddress) {
            currentState.store(state.get(), std::memory_order_release);
        }
    }
    uint64_t allocateNonce() const {
        auto *state = currentState.load(std::memory_order_acquire);
        if (!state || !state->initialized.load(std::memory_order_acquire)) {
            throw std::runtime_error("NonceManager not initialized for current address");
        }
        return state->next.fetch_add(1, std::memory_order_acq_rel);
    }
    void confirmNonce(const uint64_t nonce) const {
        auto *state = currentState.load(std::memory_order_acquire);
        if (!state)
            return;
        uint64_t expected = state->confirmed.load(std::memory_order_acquire);
        while (expected < nonce) {
            if (state->confirmed.compare_exchange_weak(expected, nonce, std::memory_order_release,
                                                       std::memory_order_relaxed)) {
                break;
            }
        }
    }
    uint64_t getCurrentNonce() const {
        const auto *state = currentState.load(std::memory_order_acquire);
        return state ? state->next.load(std::memory_order_acquire) : 0;
    }
    uint64_t getConfirmedNonce() const {
        const auto *state = currentState.load(std::memory_order_acquire);
        return state ? state->confirmed.load(std::memory_order_acquire) : 0;
    }
    void syncWithChain(const uint64_t chainNonce) const {
        auto *state = currentState.load(std::memory_order_acquire);
        if (!state)
            return;
        uint64_t current = state->next.load(std::memory_order_acquire);
        while (chainNonce > current) {
            if (state->next.compare_exchange_weak(current, chainNonce, std::memory_order_acq_rel,
                                                  std::memory_order_relaxed)) {
                state->confirmed.store(chainNonce, std::memory_order_release);
                break;
            }
        }
    }
    void reset(const uint64_t nonce) const {
        auto *state = currentState.load(std::memory_order_acquire);
        if (!state) {
            throw std::runtime_error("NonceManager not initialized... call setCurrentAddress first");
        }
        state->next.store(nonce, std::memory_order_relaxed);
        state->confirmed.store(nonce, std::memory_order_relaxed);
        state->initialized.store(true, std::memory_order_release);
    }
    bool isInitialized() const {
        const auto *state = currentState.load(std::memory_order_acquire);
        return state && state->initialized.load(std::memory_order_acquire);
    }
};

class JsonParser {
    static constexpr size_t MAX_CONCURRENT = 16;
    static constexpr auto TIMEOUT = std::chrono::seconds(30);
    static inline std::counting_semaphore<> limiter{MAX_CONCURRENT};
    struct Guard {
        std::counting_semaphore<> *sem;
        bool owns;
        explicit Guard(std::counting_semaphore<> &s) : sem(&s), owns(false) {
            if (!sem->try_acquire_for(TIMEOUT)) {
                throw std::runtime_error("Parser timeout");
            }
            owns = true;
        }
        Guard(const Guard &) = delete;
        Guard &operator=(const Guard &) = delete;
        Guard(Guard &&other) noexcept : sem(std::exchange(other.sem, nullptr)), owns(std::exchange(other.owns, false)) {}
        Guard &operator=(Guard &&other) noexcept {
            if (this != &other) {
                release();
                sem = std::exchange(other.sem, nullptr);
                owns = std::exchange(other.owns, false);
            }
            return *this;
        }
        ~Guard() noexcept { release(); }

    private:
        void release() noexcept {
            if (owns && sem) {
                sem->release();
                owns = false;
            }
        }
    };

public:
    static json parse(std::string_view input) {
        if (input.empty()) {
            return json{};
        }
        if (input.size() > MAX_SIZE) {
            throw std::runtime_error("Input exceeds size limit");
        }
        Guard guard(limiter);
        return json::parse(input);
    }
    static std::optional<json> try_parse(std::string_view input) noexcept {
        if (input.empty()) {
            return json{};
        }
        if (input.size() > MAX_SIZE) {
            return std::nullopt;
        }
        if (!limiter.try_acquire()) {
            return std::nullopt;
        }
        try {
            auto result = json::parse(input);
            limiter.release();
            return result;
        } catch (...) {
            limiter.release();
            return std::nullopt;
        }
    }
};

class MemoryPool {
    alignas(64) std::array<std::byte, PMR_BUFFER_SIZE> buffer = {};
    std::pmr::monotonic_buffer_resource resource{buffer.data(), buffer.size()};

public:
    std::pmr::memory_resource *get() { return &resource; }
    void reset() { resource.release(); }
};

export class AddressValidator {
    static inline const std::regex hexPattern{"^0x[0-9a-fA-F]{40}$"};

public:
    static bool isValidEthereumAddress(const std::string_view addr) {
        return std::regex_match(addr.begin(), addr.end(), hexPattern);
    }
    static void validateOrThrow(std::string_view addr, std::string_view name) {
        if (!isValidEthereumAddress(addr)) {
            throw std::invalid_argument(std::format("Invalid {} address: {}", name, addr));
        }
    }
};

export class Secp256k1Manager {
    static inline std::shared_ptr<secp256k1_context> globalContext;
    static inline std::once_flag initFlag;

public:
    static secp256k1_context *getContext() {
        std::call_once(initFlag, [] {
            globalContext.reset(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY),
                                secp256k1_context_destroy);
            std::array<uint8_t, 32> seed;
            if (!RAND_bytes(seed.data(), seed.size())) {
                throw std::runtime_error("Failed to generate random seed");
            }
            if (!secp256k1_context_randomize(globalContext.get(), seed.data())) {
                throw std::runtime_error("Failed to randomize secp256k1 context");
            }
            OPENSSL_cleanse(seed.data(), seed.size());
        });
        return globalContext.get();
    }
};

struct CurlCallbackData {
    std::string *response;
    size_t max_size;
    std::atomic<size_t> current_size{0};
};

export size_t curlWriteCallback(const void *contents, const size_t size, size_t nmemb, void *userp) noexcept {
    auto *data = static_cast<CurlCallbackData *>(userp);
    const auto totalSize = size * nmemb;
    if (data->current_size.load() + totalSize > data->max_size) {
        return 0;
    }
    data->response->append(static_cast<const char *>(contents), totalSize);
    data->current_size.fetch_add(totalSize);
    return totalSize;
}

class CurlPool {
    struct CurlDeleter {
        void operator()(CURL *curl) const noexcept {
            if (curl)
                curl_easy_cleanup(curl);
        }
    };
    using CurlPtr = std::unique_ptr<CURL, CurlDeleter>;
    std::queue<CurlPtr> handles;
    mutable std::mutex mtx;
    std::condition_variable cv;
    std::atomic<bool> shutdown{false};
    std::atomic<size_t> activeHandles{0};
    std::atomic<size_t> totalCreated{0};
    static constexpr size_t MAX_HANDLES = CURL_POOL_SIZE;
    static constexpr size_t MIN_HANDLES = 4;

public:
    class Handle {
        CurlPool *pool;
        CurlPtr curl;

    public:
        Handle(CurlPool *p, CurlPtr c) : pool(p), curl(std::move(c)) {}
        Handle(const Handle &) = delete;
        Handle &operator=(const Handle &) = delete;
        Handle(Handle &&) = default;
        Handle &operator=(Handle &&) = default;
        ~Handle() {
            if (curl && pool)
                pool->release(std::move(curl));
        }
        CURL *get() const { return curl.get(); }
        CURL *operator->() const { return curl.get(); }
        explicit operator bool() const { return curl != nullptr; }
    };
    CurlPool() {
        for (size_t i = 0; i < MIN_HANDLES; ++i) {
            if (auto *h = curl_easy_init()) {
                setupCurlHandle(h);
                handles.emplace(h);
                ++totalCreated;
            }
        }
    }
    ~CurlPool() {
        shutdown.store(true, std::memory_order_release);
        cv.notify_all();
        std::unique_lock lock(mtx);
        cv.wait(lock, [this] { return activeHandles.load(std::memory_order_acquire) == 0; });
    }
    Handle acquire() {
        std::unique_lock lock(mtx);
        if (handles.empty() && totalCreated < MAX_HANDLES) {
            lock.unlock();
            if (auto *h = curl_easy_init()) {
                setupCurlHandle(h);
                ++totalCreated;
                activeHandles.fetch_add(1, std::memory_order_acq_rel);
                return Handle(this, CurlPtr(h));
            }
            lock.lock();
        }
        if (!cv.wait_for(lock, std::chrono::seconds(RPC_TIMEOUT_SECONDS),
                         [this] { return !handles.empty() || shutdown.load(std::memory_order_acquire); })) {
            throw std::runtime_error("Timeout acquiring CURL handle");
        }
        if (shutdown.load(std::memory_order_acquire))
            throw std::runtime_error("Pool is shutting down");
        auto handle = std::move(handles.front());
        handles.pop();
        activeHandles.fetch_add(1, std::memory_order_acq_rel);
        return Handle(this, std::move(handle));
    }

private:
    static void setupCurlHandle(CURL *h) {
        curl_easy_setopt(h, CURLOPT_TIMEOUT, static_cast<long>(RPC_TIMEOUT_SECONDS));
        curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, static_cast<long>(RPC_CONNECT_TIMEOUT_SECONDS));
        curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(h, CURLOPT_TCP_NODELAY, 1L);
        curl_easy_setopt(h, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(h, CURLOPT_TCP_KEEPIDLE, 120L);
        curl_easy_setopt(h, CURLOPT_TCP_KEEPINTVL, 60L);
        curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(h, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_easy_setopt(h, CURLOPT_FORBID_REUSE, 0L);
        curl_easy_setopt(h, CURLOPT_MAXCONNECTS, 10L);
    }
    void release(CurlPtr h) {
        if (!h)
            return;
        curl_easy_reset(h.get());
        setupCurlHandle(h.get());
        std::lock_guard lock(mtx);
        if (handles.size() < MAX_HANDLES) {
            handles.push(std::move(h));
        }
        activeHandles.fetch_sub(1, std::memory_order_acq_rel);
        cv.notify_one();
    }
};

template<typename K, typename V>
class BoundedLRUCache {
    struct Node {
        K key;
        V value;
        std::chrono::steady_clock::time_point timestamp;
    };
    mutable std::shared_mutex mtx;
    std::unordered_map<K, typename std::list<Node>::iterator> map;
    std::list<Node> list;
    size_t max_size;
    void evict() {
        if (list.empty())
            return;
        map.erase(list.back().key);
        list.pop_back();
    }

public:
    explicit BoundedLRUCache(const size_t size = MAX_CACHE_ENTRIES) : max_size(size) {}
    std::optional<V> get(const K &key) const {
        std::shared_lock lock(mtx);
        auto it = map.find(key);
        if (it == map.end())
            return std::nullopt;
        return it->second->value;
    }
    void put(const K &key, V value) {
        std::unique_lock lock(mtx);
        auto it = map.find(key);
        if (it != map.end()) {
            list.erase(it->second);
            map.erase(it);
        }
        while (map.size() >= max_size) {
            evict();
        }
        list.emplace_front(Node{key, std::move(value), std::chrono::steady_clock::now()});
        map[key] = list.begin();
    }
};

struct TransactionCache {
    BoundedLRUCache<std::string, std::string> encodedFunctions;
    BoundedLRUCache<std::string, uint64_t> gasEstimates;
    mutable std::shared_mutex mtx;
    std::pair<uint64_t, uint64_t> lastGasFees{0, 0};
    std::chrono::steady_clock::time_point lastGasFeesTime;
    static constexpr auto GAS_FEES_CACHE_DURATION = std::chrono::seconds(10);
    std::optional<std::string> getCachedFunction(const std::string &signature) const {
        return encodedFunctions.get(signature);
    }
    void cacheFunction(const std::string &signature, const std::string &encoded) {
        encodedFunctions.put(signature, encoded);
    }
    std::optional<std::pair<uint64_t, uint64_t>> getCachedGasFees() const {
        std::shared_lock lock(mtx);
        if (std::chrono::steady_clock::now() - lastGasFeesTime < GAS_FEES_CACHE_DURATION)
            return lastGasFees;
        return std::nullopt;
    }
    void cacheGasFees(uint64_t priority, uint64_t max) {
        std::unique_lock lock(mtx);
        lastGasFees = {priority, max};
        lastGasFeesTime = std::chrono::steady_clock::now();
    }
};

export inline TransactionCache g_transactionCache;
export inline NonceManager g_nonceManager;
export inline JsonParser g_jsonParser;
inline thread_local MemoryPool t_memoryPool;

inline CurlPool &getCurlPool() {
    static CurlPool pool;
    return pool;
}

export SecureBytes parsePrivateKey(const SecureString &keyHex) {
    if (keyHex.size() != 64)
        throw std::runtime_error("Invalid private key length");
    SecureBytes bytes(32);
    for (size_t i = 0; i < 32; ++i) {
        const char h = keyHex[i * 2];
        const char l = keyHex[i * 2 + 1];
        const auto high = h >= '0' && h <= '9'   ? h - '0'
                          : h >= 'a' && h <= 'f' ? h - 'a' + 10
                          : h >= 'A' && h <= 'F' ? h - 'A' + 10
                                                 : throw std::runtime_error("Invalid hex character");
        const auto low = l >= '0' && l <= '9'   ? l - '0'
                         : l >= 'a' && l <= 'f' ? l - 'a' + 10
                         : l >= 'A' && l <= 'F' ? l - 'A' + 10
                                                : throw std::runtime_error("Invalid hex character");
        bytes[i] = static_cast<uint8_t>(high << 4 | low);
    }
    return bytes;
}

export SecureString loadPrivateKey(std::string_view envKey) {
    auto key = dotenv::getenv(envKey.data());
    if (key.empty())
        throw std::runtime_error(std::format("{} not found in .env file", envKey));
    SecureString secureKey(key.begin(), key.end());
    OPENSSL_cleanse(key.data(), key.size());
    if (secureKey.starts_with("0x")) {
        return SecureString(secureKey.begin() + 2, secureKey.end());
    }
    return secureKey;
}

export template<typename Func>
auto executeWithRetry(Func &&func, const std::string_view operation, const int maxRetries = MAX_TX_RETRIES) {
    return std::async(std::launch::async,
                      [func = std::forward<Func>(func), op = std::string(operation), maxRetries]() -> decltype(func()) {
                          int attemptCount = 0;
                          auto backoff = std::chrono::milliseconds(BASE_RETRY_DELAY_MS);
                          while (true) {
                              ++attemptCount;
                              try {
                                  return func();
                              } catch (const std::exception &e) {
                                  if (attemptCount >= maxRetries) {
                                      spdlog::error("Fatal error in {} after {} attempts: {}", op, attemptCount, e.what());
                                      throw;
                                  }
                                  spdlog::warn("{} attempt {} failed: {}", op, attemptCount, e.what());
                                  std::this_thread::sleep_for(backoff);
                                  backoff = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          std::min(backoff * 2, std::chrono::milliseconds(MAX_RETRY_BACKOFF_MS)));
                              } catch (...) {
                                  spdlog::error("Unknown error in {}", op);
                                  throw;
                              }
                          }
                      });
}

export template<typename Func>
std::string executeWithRetrySync(Func &&func, std::string_view operation, const int maxRetries = MAX_TX_RETRIES) {
    int attemptCount = 0;
    auto backoff = std::chrono::milliseconds(BASE_RETRY_DELAY_MS);
    while (true) {
        ++attemptCount;
        try {
            return func();
        } catch (const std::exception &e) {
            if (attemptCount >= maxRetries) {
                spdlog::error("Fatal error in {} after {} attempts: {}", operation, attemptCount, e.what());
                throw;
            }
            spdlog::warn("{} attempt {} failed: {}", operation, attemptCount, e.what());
            std::this_thread::sleep_for(backoff);
            backoff = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::min(backoff * 2, std::chrono::milliseconds(MAX_RETRY_BACKOFF_MS)));
        }
    }
}

export std::string loadBytecode(std::string_view filePath) {
    std::ifstream file{filePath.data(), std::ios::binary | std::ios::ate};
    if (!file) {
        throw std::runtime_error(std::format("Cannot open file: {}", filePath));
    }
    const auto size = file.tellg();
    if (size <= 0 || static_cast<size_t>(size) > MAX_FILE_SIZE) {
        throw std::runtime_error(std::format("Invalid file size: {} bytes", static_cast<size_t>(size)));
    }
    file.seekg(0, std::ios::beg);
    std::string buffer(size, '\0');
    if (!file.read(buffer.data(), size)) {
        throw std::runtime_error(std::format("Failed to read file: {}", filePath));
    }
    try {
        auto data = g_jsonParser.parse(buffer);
        std::string bytecode;
        if (data.contains("bytecode")) {
            bytecode = std::move(data["bytecode"].get_ref<std::string &>());
        } else if (data.is_string()) {
            bytecode = std::move(data.get_ref<std::string &>());
        } else if (data.is_object() && data.size() == 1) {
            bytecode = std::move(data.begin().value().get_ref<std::string &>());
        } else {
            throw std::runtime_error(std::format("Invalid bytecode format in: {}", filePath));
        }
        if (!bytecode.starts_with("0x"))
            bytecode = "0x" + std::move(bytecode);
        t_memoryPool.reset();
        return bytecode;
    } catch (const json::exception &e) {
        t_memoryPool.reset();
        throw std::runtime_error(std::format("JSON parse error in {}: {}", filePath, e.what()));
    }
}

export bool updateEnvFile(std::string_view filePath, const std::map<std::string, std::string> &updates) {
    std::map<std::string, std::string> env;
    if (std::ifstream file{filePath.data()}; file.is_open()) {
        for (std::string line; std::getline(file, line);) {
            dotenv::trim(line);
            if (line.empty() || line.starts_with('#'))
                continue;
            if (auto delimiterPos = line.find('='); delimiterPos != std::string::npos) {
                auto key = dotenv::trim_copy(line.substr(0, delimiterPos));
                auto value = dotenv::strip_quotes(dotenv::trim_copy(line.substr(delimiterPos + 1)));
                env[std::move(key)] = std::move(value);
            }
        }
    }
    std::ranges::for_each(updates, [&env](const auto &pair) { env[pair.first] = pair.second; });
    if (std::ofstream outFile{filePath.data()}; outFile.is_open()) {
        std::ranges::for_each(env, [&outFile](const auto &pair) { outFile << pair.first << '=' << pair.second << '\n'; });
        return true;
    }
    return false;
}

export constexpr double weiToEth(const uint64_t wei) noexcept { return static_cast<double>(wei) / 1e18; }
export std::string formatHexValue(uint64_t value) { return std::format("0x{:x}", value); }

export std::vector<uint8_t> keccakHash(const std::span<const uint8_t> data) {
    const auto hash = ethash::keccak256(data.data(), data.size());
    std::vector<uint8_t> result(32);
    std::memcpy(result.data(), &hash, 32);
    return result;
}

export std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, int> signHash(const std::span<const uint8_t> hash,
                                                                            const std::span<const uint8_t> privateKey) {
    if (privateKey.size() != 32)
        throw std::runtime_error("Invalid private key size");
    const auto *ctx = Secp256k1Manager::getContext();
    if (!ctx || !secp256k1_ec_seckey_verify(ctx, privateKey.data())) {
        throw std::runtime_error("Invalid private key");
    }
    secp256k1_ecdsa_recoverable_signature rSignature;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &rSignature, hash.data(), privateKey.data(), nullptr, nullptr)) {
        throw std::runtime_error("Failed to sign hash");
    }
    int recoveryId = 0;
    uint8_t output[64];
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output, &recoveryId, &rSignature);
    return {std::vector(output, output + 32), std::vector(output + 32, output + 64), recoveryId};
}

export json parseJsonRpcResponse(const std::string_view rpcEndpoint, const json &payload) {
    const auto result = executeWithRetrySync(
            [&] {
                const auto handle = getCurlPool().acquire();
                if (!handle)
                    throw std::runtime_error("Failed to acquire CURL handle");
                std::string response;
                response.reserve(8192);
                CurlCallbackData callbackData{&response, MAX_SIZE, 0};
                const auto payloadStr = payload.dump();
                curl_slist *raw_headers = curl_slist_append(nullptr, "Content-Type: application/json");
                const std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(raw_headers,
                                                                                          &curl_slist_free_all);
                if (!headers)
                    throw std::runtime_error("Failed to create headers");
                curl_easy_setopt(handle.get(), CURLOPT_URL, rpcEndpoint.data());
                curl_easy_setopt(handle.get(), CURLOPT_POST, 1L);
                curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDS, payloadStr.c_str());
                curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(payloadStr.size()));
                curl_easy_setopt(handle.get(), CURLOPT_HTTPHEADER, headers.get());
                curl_easy_setopt(handle.get(), CURLOPT_WRITEFUNCTION, curlWriteCallback);
                curl_easy_setopt(handle.get(), CURLOPT_WRITEDATA, &callbackData);
                if (const auto res = curl_easy_perform(handle.get()); res != CURLE_OK)
                    throw std::runtime_error(std::format("CURL request failed: {}", curl_easy_strerror(res)));
                long http_code = 0;
                curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &http_code);
                if (http_code < 200 || http_code >= 300)
                    throw std::runtime_error(std::format("HTTP error: {}", http_code));
                return response;
            },
            "JSON RPC call");
    auto parsed = g_jsonParser.parse(result);
    t_memoryPool.reset();
    return parsed;
}

export std::string verifyChainId(const std::string_view rpcEndpoint) {
    const json payload = {{"jsonrpc", "2.0"}, {"method", "eth_chainId"}, {"params", json::array()}, {"id", 1}};
    const auto jsonResponse = parseJsonRpcResponse(rpcEndpoint, payload);
    if (jsonResponse.contains("error")) {
        throw std::runtime_error(
                std::format("Error fetching chain ID: {}", jsonResponse["error"]["message"].get<std::string>()));
    }
    return jsonResponse["result"].get<std::string>();
}

export std::string getAccountBalance(const std::string_view rpcEndpoint, std::string_view address) {
    AddressValidator::validateOrThrow(address, "account");
    const json payload = {{"jsonrpc", "2.0"}, {"method", "eth_getBalance"}, {"params", {address, "latest"}}, {"id", 1}};
    const auto jsonResponse = parseJsonRpcResponse(rpcEndpoint, payload);
    if (jsonResponse.contains("error")) {
        throw std::runtime_error(
                std::format("Error fetching balance: {}", jsonResponse["error"]["message"].get<std::string>()));
    }
    return jsonResponse["result"].get<std::string>();
}

export uint64_t getContractBalance(const std::string_view rpcEndpoint, const std::string_view contractAddress,
                                   const int maxRetries = MAX_TX_RETRIES) {
    AddressValidator::validateOrThrow(contractAddress, "contract balance query");
    return safeHexToUint64(executeWithRetrySync(
            [&] {
                const auto balance = getAccountBalance(rpcEndpoint, contractAddress);
                return balance;
            },
            "Get contract balance", maxRetries));
}

export std::string getAddressNonce(const std::string_view rpcEndpoint, std::string_view address) {
    AddressValidator::validateOrThrow(address, "nonce query");
    return executeWithRetrySync(
            [&] {
                const json payload = {{"jsonrpc", "2.0"},
                                      {"method", "eth_getTransactionCount"},
                                      {"params", {address, "latest"}},
                                      {"id", 1}};
                const auto jsonResponse = parseJsonRpcResponse(rpcEndpoint, payload);
                if (jsonResponse.contains("error")) {
                    throw std::runtime_error(
                            std::format("Error fetching nonce: {}", jsonResponse["error"]["message"].get<std::string>()));
                }
                if (!jsonResponse.contains("result") || jsonResponse["result"].is_null()) {
                    spdlog::warn("RPC returning null nonce, trying 'pending' state");
                    const json fallbackPayload = {{"jsonrpc", "2.0"},
                                                  {"method", "eth_getTransactionCount"},
                                                  {"params", {address, "pending"}},
                                                  {"id", 1}};
                    if (const auto fallbackJson = parseJsonRpcResponse(rpcEndpoint, fallbackPayload);
                        fallbackJson.contains("result") && !fallbackJson["result"].is_null()) {
                        if (const auto nonce = fallbackJson["result"].get<std::string>();
                            nonce.length() >= 2 && nonce.starts_with("0x")) {
                            return nonce;
                        }
                    }
                    return "0x0"s;
                }
                const auto nonce = jsonResponse["result"].get<std::string>();
                if (nonce.length() < 2 || !nonce.starts_with("0x")) {
                    spdlog::warn("Invalid nonce format, defaulting to 0x0");
                    return "0x0"s;
                }
                return nonce;
            },
            "Nonce fetch", MAX_TX_RETRIES);
}

export std::string getGasPrice(const std::string_view rpcEndpoint) {
    const json payload = {{"jsonrpc", "2.0"}, {"method", "eth_gasPrice"}, {"params", json::array()}, {"id", 1}};
    const auto jsonResponse = parseJsonRpcResponse(rpcEndpoint, payload);
    if (jsonResponse.contains("error")) {
        throw std::runtime_error(
                std::format("Error fetching gas price: {}", jsonResponse["error"]["message"].get<std::string>()));
    }
    return jsonResponse["result"].get<std::string>();
}

export std::pair<uint64_t, uint64_t> getGasFees(const std::string_view rpcEndpoint, const bool urgent = false) {
    if (auto cached = g_transactionCache.getCachedGasFees(); cached.has_value() && !urgent) {
        return cached.value();
    }
    try {
        const json payload
                = {{"jsonrpc", "2.0"}, {"method", "eth_feeHistory"}, {"params", {1, "latest", json::array()}}, {"id", 1}};
        if (const auto jsonResponse = parseJsonRpcResponse(rpcEndpoint, payload);
            !jsonResponse.contains("error") && jsonResponse.contains("result")) {
            if (const auto &result = jsonResponse["result"];
                result.contains("baseFeePerGas") && !result["baseFeePerGas"].empty()) {
                const auto baseFeeHex = result["baseFeePerGas"][0].get<std::string>();
                const auto baseFee = safeHexToUint64(baseFeeHex);
                const auto maxPriorityFeePerGas = urgent ? MAX_PRIORITY_FEE : MIN_PRIORITY_FEE;
                const double multiplier = urgent ? BASE_FEE_MULTIPLIER_FAST : BASE_FEE_MULTIPLIER_NORMAL;
                const auto maxFeePerGas
                        = static_cast<uint64_t>(static_cast<double>(baseFee) * multiplier) + maxPriorityFeePerGas;
                if (!urgent)
                    g_transactionCache.cacheGasFees(maxPriorityFeePerGas, maxFeePerGas);
                return {maxPriorityFeePerGas, maxFeePerGas};
            }
        }
    } catch (const std::exception &e) {
        spdlog::debug("eth_feeHistory failed, falling back to eth_gasPrice: {}", e.what());
    }
    const auto fallbackGasPrice = getGasPrice(rpcEndpoint);
    const auto gasPriceWei = safeHexToUint64(fallbackGasPrice);
    const auto maxPriorityFeePerGas = urgent ? MAX_PRIORITY_FEE : MIN_PRIORITY_FEE;
    const double multiplier = urgent ? BASE_FEE_MULTIPLIER_FAST : BASE_FEE_MULTIPLIER_NORMAL;
    const auto maxFeePerGas = static_cast<uint64_t>(static_cast<double>(gasPriceWei) * multiplier) + maxPriorityFeePerGas;
    if (!urgent)
        g_transactionCache.cacheGasFees(maxPriorityFeePerGas, maxFeePerGas);
    return {maxPriorityFeePerGas, maxFeePerGas};
}

export std::string estimateDeploymentGas(const std::string_view rpcEndpoint, std::string_view from,
                                         std::string_view bytecode, std::string_view value) {
    AddressValidator::validateOrThrow(from, "deployment from");
    const json transaction = {{"from", from}, {"data", bytecode}, {"value", value}};
    const json payload = {{"jsonrpc", "2.0"}, {"method", "eth_estimateGas"}, {"params", {transaction}}, {"id", 1}};
    const auto jsonResponse = parseJsonRpcResponse(rpcEndpoint, payload);
    if (jsonResponse.contains("error")) {
        throw std::runtime_error(
                std::format("Error estimating deployment gas: {}", jsonResponse["error"]["message"].get<std::string>()));
    }
    return jsonResponse["result"].get<std::string>();
}

export std::string estimateTxGas(const std::string_view rpcEndpoint, std::string_view from, std::string_view to,
                                 std::string_view value, std::string_view encodedCall) {
    AddressValidator::validateOrThrow(from, "transaction from");
    AddressValidator::validateOrThrow(to, "transaction to");
    json transaction = {{"from", from}, {"to", to}, {"value", value}};
    if (!encodedCall.empty() && encodedCall != "0x")
        transaction["data"] = encodedCall;
    const json payload = {{"jsonrpc", "2.0"}, {"method", "eth_estimateGas"}, {"params", {transaction}}, {"id", 1}};
    const auto jsonResponse = parseJsonRpcResponse(rpcEndpoint, payload);
    if (jsonResponse.contains("error")) {
        throw std::runtime_error(
                std::format("Error estimating transaction gas: {}", jsonResponse["error"]["message"].get<std::string>()));
    }
    return jsonResponse["result"].get<std::string>();
}

export std::string callReadFunction(const std::string_view rpcEndpoint, std::string_view contractAddress,
                                    std::string_view encodedCall) {
    AddressValidator::validateOrThrow(contractAddress, "contract");
    const json payload = {{"jsonrpc", "2.0"},
                          {"method", "eth_call"},
                          {"params", {{{"to", contractAddress}, {"data", encodedCall}}, "latest"}},
                          {"id", 1}};
    const auto jsonResponse = parseJsonRpcResponse(rpcEndpoint, payload);
    if (jsonResponse.contains("error")) {
        throw std::runtime_error(
                std::format("Error calling contract function: {}", jsonResponse["error"]["message"].get<std::string>()));
    }
    return jsonResponse["result"].get<std::string>();
}

export std::future<std::string> sendRawTx(const std::string_view rpcEndpoint, const std::string_view signedTransaction) {
    return executeWithRetry(
            [url = std::string(rpcEndpoint), tx = std::string(signedTransaction)] {
                const json payload
                        = {{"jsonrpc", "2.0"}, {"method", "eth_sendRawTransaction"}, {"params", {tx}}, {"id", 1}};
                const auto jsonResponse = parseJsonRpcResponse(url, payload);
                if (jsonResponse.contains("error")) {
                    const auto errorMsg = jsonResponse["error"]["message"].get<std::string>();
                    if (errorMsg.contains("nonce") || errorMsg.contains("replacement")
                        || errorMsg.contains("already known")) {
                        throw std::runtime_error(std::format("Non-retryable error: {}", errorMsg));
                    }
                    throw std::runtime_error(std::format("Error from Ethereum node: {}", errorMsg));
                }
                return jsonResponse["result"].get<std::string>();
            },
            "Send transaction");
}

export std::string sendRawTxSync(const std::string_view rpcEndpoint, const std::string_view signedTx) {
    return sendRawTx(rpcEndpoint, signedTx).get();
}

export json getTxReceipt(const std::string_view rpcEndpoint, std::string_view txHash) {
    const json payload = {{"jsonrpc", "2.0"}, {"method", "eth_getTransactionReceipt"}, {"params", {txHash}}, {"id", 1}};
    const auto jsonResponse = parseJsonRpcResponse(rpcEndpoint, payload);
    if (jsonResponse.contains("error")) {
        throw std::runtime_error(std::format("Error fetching transaction receipt: {}",
                                             jsonResponse["error"]["message"].get<std::string>()));
    }
    return jsonResponse["result"];
}

export std::future<bool> waitForConfirmation(const std::string_view rpcEndpoint, const std::string_view txHash) {
    return std::async(std::launch::async, [url = std::string(rpcEndpoint), hash = std::string(txHash)] {
        for (int attempts = 0; attempts < MAX_CONFIRMATION_ATTEMPTS; ++attempts) {
            try {
                if (json receipt = getTxReceipt(url, hash); !receipt.is_null()) {
                    if (receipt.contains("status")) {
                        std::string statusStr = "0x0";
                        if (receipt["status"].is_string()) {
                            statusStr = receipt["status"].get<std::string>();
                        } else if (receipt["status"].is_number()) {
                            statusStr = receipt["status"].get<int>() == 1 ? "0x1" : "0x0";
                        } else if (receipt["status"].is_boolean()) {
                            statusStr = receipt["status"].get<bool>() ? "0x1" : "0x0";
                        }
                        return statusStr == "0x1" || statusStr == "1" || statusStr == "true";
                    }
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(CONFIRMATION_DELAY_MS));
            } catch (const std::exception &) {
                if (attempts == MAX_CONFIRMATION_ATTEMPTS - 1)
                    return false;
                std::this_thread::sleep_for(std::chrono::milliseconds(CONFIRMATION_DELAY_MS));
            }
        }
        return false;
    });
}

export bool waitForConfirmationSync(const std::string_view rpcEndpoint, const std::string_view txHash) {
    return waitForConfirmation(rpcEndpoint, txHash).get();
}

export std::string buildConstructorBytecode(const std::string_view bytecode, std::span<const std::string> constructorTypes,
                                            std::span<const std::string> constructorValues) {
    if (constructorTypes.empty() || constructorValues.empty())
        return std::string{bytecode};
    const auto encodedParams
            = FunctionEncoder::encodeConstructorParams(std::vector(constructorTypes.begin(), constructorTypes.end()),
                                                       std::vector(constructorValues.begin(), constructorValues.end()));
    auto cleanBytecode = std::string{bytecode};
    if (cleanBytecode.starts_with("0x"))
        cleanBytecode.erase(0, 2);
    auto cleanParams = encodedParams;
    if (cleanParams.starts_with("0x"))
        cleanParams.erase(0, 2);
    return std::format("0x{}{}", cleanBytecode, cleanParams);
}

export std::string createSignedDeployment(const SecureString &privateKeyHex, const uint64_t chainId,
                                          const std::string_view nonce, const uint64_t maxPriorityFeePerGas,
                                          const uint64_t maxFeePerGas, const std::string_view gasLimit,
                                          const std::string_view bytecode, std::span<const std::string> constructorTypes,
                                          std::span<const std::string> constructorValues) {
    SecureBytes privateKeyBytes = parsePrivateKey(privateKeyHex);
    const auto nonceInt = safeHexToUint64(nonce);
    const auto gasLimitInt = safeHexToUint64(gasLimit);
    std::string constructorParams;
    if (!constructorTypes.empty() && !constructorValues.empty()) {
        if (constructorTypes.size() != constructorValues.size()) {
            throw std::runtime_error("Constructor types and values count mismatch");
        }
        constructorParams
                = FunctionEncoder::encodeConstructorParams(std::vector(constructorTypes.begin(), constructorTypes.end()),
                                                           std::vector(constructorValues.begin(),
                                                                       constructorValues.end()));
    }
    auto tx = TypedTransaction::createEIP1559Deployment(chainId, nonceInt, maxPriorityFeePerGas, maxFeePerGas, gasLimitInt,
                                                        std::string{bytecode}, constructorParams);
    tx.signTransaction(privateKeyBytes, keccakHash, signHash);
    OPENSSL_cleanse(privateKeyBytes.data(), privateKeyBytes.size());
    return tx.toHex();
}

export std::string createSignedTx(const SecureString &privateKeyHex, const uint64_t chainId, const std::string_view nonce,
                                  const uint64_t maxPriorityFeePerGas, const uint64_t maxFeePerGas,
                                  const std::string_view gasLimit, const std::string_view to, const std::string_view value,
                                  const std::string_view encodedCall) {
    AddressValidator::validateOrThrow(to, "transaction recipient");
    SecureBytes privateKeyBytes = parsePrivateKey(privateKeyHex);
    const auto nonceInt = safeHexToUint64(nonce);
    const auto gasLimitInt = safeHexToUint64(gasLimit);
    const auto valueInt = safeHexToUint64(value);
    auto tx = TypedTransaction::createEIP1559Transaction(chainId, nonceInt, maxPriorityFeePerGas, maxFeePerGas,
                                                         gasLimitInt, std::string{to}, valueInt, std::string{encodedCall});
    tx.signTransaction(privateKeyBytes, keccakHash, signHash);
    OPENSSL_cleanse(privateKeyBytes.data(), privateKeyBytes.size());
    return tx.toHex();
}

export std::future<std::pair<bool, json>>
executeDeployment(const std::string_view rpcEndpoint, const SecureString &privateKey, const std::string_view senderAddress,
                  const uint64_t chainId, const std::string_view bytecode,
                  const std::span<const std::string> constructorTypes,
                  const std::span<const std::string> constructorValues, const bool isVulnerableContract = false) {
    AddressValidator::validateOrThrow(senderAddress, "sender");
    return std::async(std::launch::async, [=]() -> std::pair<bool, json> {
        try {
            if (!g_nonceManager.isInitialized()) {
                const auto chainNonce = getAddressNonce(rpcEndpoint, senderAddress);
                g_nonceManager.initialize(senderAddress, safeHexToUint64(chainNonce));
            }
            const uint64_t deployNonce = g_nonceManager.allocateNonce();
            const auto nonceStr = formatHexValue(deployNonce);
            const auto [maxPriorityFeePerGas, maxFeePerGas] = getGasFees(rpcEndpoint, false);
            const auto deploymentBytecode = buildConstructorBytecode(bytecode, constructorTypes, constructorValues);
            const auto gasEstimate = [&]() -> uint64_t {
                try {
                    const auto estimate = estimateDeploymentGas(rpcEndpoint, senderAddress, deploymentBytecode, "0x0");
                    return safeHexToUint64(estimate);
                } catch (const std::exception &e) {
                    spdlog::warn("Gas estimation failed, using fallback: {}", e.what());
                    const auto fallbackGas
                            = isVulnerableContract ? FALLBACK_VULNERABLE_DEPLOYMENT_GAS : FALLBACK_ATTACKER_DEPLOYMENT_GAS;
                    return safeHexToUint64(fallbackGas);
                }
            }();
            const auto gasLimit = static_cast<uint64_t>(static_cast<double>(gasEstimate) * GAS_LIMIT_BUFFER);
            const auto gasLimitHex = formatHexValue(gasLimit);
            const auto signedTx = createSignedDeployment(privateKey, chainId, nonceStr, maxPriorityFeePerGas, maxFeePerGas,
                                                         gasLimitHex, bytecode, constructorTypes, constructorValues);
            const auto txHash = sendRawTx(rpcEndpoint, signedTx).get();
            if (!waitForConfirmationSync(rpcEndpoint, txHash)) {
                throw std::runtime_error("Contract deployment transaction failed or timed out");
            }
            json receipt;
            for (int attempts = 0; attempts < RECEIPT_MAX_RETRIES; ++attempts) {
                receipt = getTxReceipt(rpcEndpoint, txHash);
                if (!receipt.is_null() && receipt.contains("contractAddress") && !receipt["contractAddress"].is_null()) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(RECEIPT_RETRY_DELAY_MS));
            }
            if (receipt.is_null() || !receipt.contains("contractAddress") || receipt["contractAddress"].is_null()) {
                throw std::runtime_error("No contract address in receipt after retries");
            }
            g_nonceManager.confirmNonce(deployNonce + 1);
            json responseJson = {{"contractAddress", receipt["contractAddress"].get<std::string>()},
                                 {"txHash", txHash},
                                 {"gasUsed", receipt.contains("gasUsed") ? receipt["gasUsed"] : "0x0"}};
            return {true, responseJson};
        } catch (const std::exception &e) {
            spdlog::error("Deployment failed: {}", e.what());
            return {false, json{{"error", e.what()}}};
        }
    });
}

export void withdrawAttackerContracts(const std::string_view rpcEndpoint, const SecureString &privateKey,
                                      const std::string_view chainIdHex, const std::string_view contract1,
                                      const std::string_view contract2, const std::string_view fromAddress) {
    AddressValidator::validateOrThrow(fromAddress, "withdraw from");
    struct ContractInfo {
        std::string address;
        uint64_t balance;
        std::string name;
        std::future<std::string> txHashFuture;
        std::future<bool> confirmationFuture;
        std::string txHash;
        bool sent{false};
        bool confirmed{false};
    };
    std::vector<ContractInfo> contracts;
    contracts.reserve(2);
    const std::array contractPairs = {std::make_pair(std::string{contract1}, "Attacker contract 1"s),
                                      std::make_pair(std::string{contract2}, "Attacker contract 2"s)};
    std::vector<std::future<std::optional<ContractInfo>>> balanceCheckFutures;
    for (const auto &[addr, name]: contractPairs) {
        if (addr.empty())
            continue;
        try {
            AddressValidator::validateOrThrow(addr, name);
        } catch (const std::exception &e) {
            spdlog::warn("Invalid address for {}: {}", name, e.what());
            continue;
        }
        auto rpcEndpointCopy = std::string(rpcEndpoint);
        balanceCheckFutures.push_back(
                std::async(std::launch::async, [rpcEndpointCopy, addr, name]() -> std::optional<ContractInfo> {
                    try {
                        if (const auto balance = getContractBalance(rpcEndpointCopy, addr); balance > 0) {
                            spdlog::info("{} balance: {:.2f} ETH", name, weiToEth(balance));
                            return ContractInfo{addr, balance, name, {}, {}, "", false, false};
                        }
                    } catch (const std::exception &e) {
                        spdlog::warn("Failed to check {} balance: {}", name, e.what());
                    }
                    return std::nullopt;
                }));
    }
    for (auto &future: balanceCheckFutures) {
        if (auto result = future.get(); result.has_value()) {
            contracts.push_back(std::move(result.value()));
        }
    }
    if (contracts.empty()) {
        spdlog::info("No contracts have withdrawable balance");
        return;
    }
    if (!g_nonceManager.isInitialized()) {
        const auto chainNonce = getAddressNonce(rpcEndpoint, fromAddress);
        g_nonceManager.initialize(fromAddress, safeHexToUint64(chainNonce));
    } else {
        const auto chainNonce = getAddressNonce(rpcEndpoint, fromAddress);
        g_nonceManager.syncWithChain(safeHexToUint64(chainNonce));
    }
    for (auto &contract: contracts) {
        auto contractAddr = contract.address;
        auto rpcEndpointCopy = std::string(rpcEndpoint);
        auto fromAddressCopy = std::string(fromAddress);
        auto chainIdHexCopy = std::string(chainIdHex);
        SecureString privateKeyCopy(privateKey);
        contract.txHashFuture = std::async(std::launch::async, [contractAddr, rpcEndpointCopy, fromAddressCopy,
                                                                chainIdHexCopy, privateKeyCopy]() {
            const uint64_t nonce = g_nonceManager.allocateNonce();
            constexpr auto functionSignature = "withdraw()"sv;
            const auto encodedCall
                    = FunctionEncoder::encodeFunctionCall(std::string{functionSignature}, {}, {}, keccakHash);
            std::string gasEstimate = FALLBACK_WITHDRAW_GAS;
            try {
                if (const auto tempEstimate
                    = estimateTxGas(rpcEndpointCopy, fromAddressCopy, contractAddr, "0x0", encodedCall);
                    !tempEstimate.empty() && tempEstimate != "null" && tempEstimate.length() > 2) {
                    gasEstimate = tempEstimate;
                }
            } catch (const std::exception &e) {
                spdlog::warn("Gas estimation failed for withdraw, using fallback: {}", e.what());
            }
            const auto gasLimitInt = safeHexToUint64(gasEstimate);
            const auto gasLimitWithBuffer = static_cast<uint64_t>(static_cast<double>(gasLimitInt) * GAS_LIMIT_BUFFER);
            const auto chainId = safeHexToUint64(chainIdHexCopy);
            const auto [maxPriorityFeePerGas, maxFeePerGas] = getGasFees(rpcEndpointCopy, false);
            const auto nonceHex = formatHexValue(nonce);
            const auto gasLimitHex = formatHexValue(gasLimitWithBuffer);
            const auto signedTx = createSignedTx(privateKeyCopy, chainId, nonceHex, maxPriorityFeePerGas, maxFeePerGas,
                                                 gasLimitHex, contractAddr, "0x0", encodedCall);
            const auto txHash = sendRawTx(rpcEndpointCopy, signedTx).get();
            g_nonceManager.confirmNonce(nonce + 1);
            return txHash;
        });
    }
    size_t successCount = 0;
    for (auto &contract: contracts) {
        try {
            contract.txHash = contract.txHashFuture.get();
            if (!contract.txHash.empty()) {
                contract.sent = true;
                ++successCount;
                spdlog::info("Withdrawal transaction for {}: {}", contract.name, contract.txHash);
            }
        } catch (const std::exception &e) {
            spdlog::error("Failed to send withdrawal for {}: {}", contract.name, e.what());
        }
    }
    if (successCount == 0) {
        throw std::runtime_error("Failed to send any withdrawal transactions");
    }
    spdlog::info("Sent {}/{} withdrawal transactions, waiting for confirmations...", successCount, contracts.size());
    for (auto &contract: contracts) {
        if (contract.sent && !contract.txHash.empty()) {
            contract.confirmationFuture = waitForConfirmation(rpcEndpoint, contract.txHash);
        }
    }
    size_t confirmedCount = 0;
    for (auto &contract: contracts) {
        if (contract.sent && contract.confirmationFuture.valid()) {
            if (contract.confirmed = contract.confirmationFuture.get(); contract.confirmed) {
                ++confirmedCount;
                spdlog::debug("{} withdrawal confirmed", contract.name);
            } else {
                spdlog::error("{} withdrawal transaction failed or timed out", contract.name);
            }
        }
    }
    if (confirmedCount == 0 && successCount > 0) {
        throw std::runtime_error("Failed to confirm any withdrawals");
    }
    if (confirmedCount == contracts.size()) {
        spdlog::info("Successfully withdrew funds from all {} contracts", contracts.size());
    } else if (confirmedCount > 0) {
        spdlog::warn("Withdrew funds from {}/{} contracts", confirmedCount, contracts.size());
    }
    uint64_t totalWithdrawn = 0;
    for (const auto &contract: contracts) {
        if (contract.confirmed)
            totalWithdrawn += contract.balance;
    }
    if (totalWithdrawn > 0) {
        spdlog::info("Total withdrawn: {:.2f} ETH", weiToEth(totalWithdrawn));
    }
}
