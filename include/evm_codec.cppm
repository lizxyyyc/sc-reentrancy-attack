/**
 * RLP and ABI encoding/decoding module for EVM transactions.
 * Provides serialization, transaction building (LEGACY, EIP-2930, EIP-1559),
 * signing integration, and hex/byte utilities.
 *
 * Beware: This is a self-made library for this project. Do not use in production.
 */
module;

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <exception>
#include <functional>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

export module EVM_CODEC;

namespace evm_codec {
    inline constexpr uint8_t OFFSET_SHORT_ITEM = 0x80;
    inline constexpr uint8_t OFFSET_LONG_ITEM = 0xb7;
    inline constexpr uint8_t OFFSET_SHORT_LIST = 0xc0;
    inline constexpr uint8_t OFFSET_LONG_LIST = 0xf7;
    inline constexpr size_t SIZE_THRESHOLD = 56;
    inline constexpr size_t WORD_SIZE = 32;

    export class RLPException : public std::exception {
        std::string message_;

    public:
        explicit RLPException(std::string msg) : message_(std::move(msg)) {}
        [[nodiscard]] const char *what() const noexcept override { return message_.c_str(); }
    };

    export class RLPEncodingException final : public RLPException {
    public:
        explicit RLPEncodingException(std::string msg) : RLPException("RLP Encoding error: " + std::move(msg)) {}
    };

    export class RLPDecodingException final : public RLPException {
    public:
        explicit RLPDecodingException(std::string msg) : RLPException("RLP Decoding error: " + std::move(msg)) {}
    };

    constexpr std::array<uint8_t, 256> generateHexLookup() noexcept {
        std::array<uint8_t, 256> table{};
        for (auto &elem: table)
            elem = 0xFF;
        for (uint8_t i = 0; i < 10; ++i)
            table['0' + i] = i;
        for (uint8_t i = 0; i < 6; ++i) {
            table['a' + i] = table['A' + i] = 10 + i;
        }
        return table;
    }

    inline constexpr auto hexLookupTable = generateHexLookup();
    inline constexpr std::string_view hexChars = "0123456789abcdef";

    inline uint8_t safeHexLookup(const int c) noexcept {
        return c >= 0 && c < 256 ? hexLookupTable[static_cast<size_t>(c)] : 0xFF;
    }

    constexpr uint8_t getByteCount(uint64_t value) noexcept {
        if (value == 0)
            return 0;
        uint8_t count = 0;
        while (value > 0) {
            count++;
            value >>= 8;
        }
        return count;
    }

    inline std::string_view stripHexPrefix(const std::string_view hex) noexcept {
        if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
            return hex.substr(2);
        }
        return hex;
    }

    inline void ensureEvenLength(std::string &hex) {
        if (hex.length() & 1)
            hex.insert(0, 1, '0');
    }

    export [[nodiscard]] std::string normalizeHex(const std::string_view hex, const bool preserveLeadingZeros = false) {
        if (hex.empty())
            return preserveLeadingZeros ? "00" : "0";
        const std::string_view stripped = stripHexPrefix(hex);
        if (stripped.empty())
            return preserveLeadingZeros ? "00" : "0";
        std::string result;
        result.reserve(stripped.length());
        for (const char c: stripped) {
            const uint8_t val = safeHexLookup(c);
            if (val == 0xFF) {
                throw RLPException("Invalid hex character: " + std::string(1, c));
            }
            result += hexChars[val];
        }
        if (!preserveLeadingZeros && !result.empty()) {
            const size_t firstNonZero = result.find_first_not_of('0');
            if (firstNonZero == std::string::npos)
                return "0";
            if (firstNonZero > 0)
                result.erase(0, firstNonZero);
        }
        ensureEvenLength(result);
        return result.empty() ? "0" : result;
    }

    export [[nodiscard]] std::vector<uint8_t> hexToBytes(const std::string_view hex,
                                                         const bool preserveLeadingZeros = false) {
        std::string_view stripped = stripHexPrefix(hex);
        if (stripped.empty() || (!preserveLeadingZeros && stripped.find_first_not_of('0') == std::string::npos)) {
            return {};
        }
        const size_t start = preserveLeadingZeros ? 0 : stripped.find_first_not_of('0');
        if (start == std::string::npos)
            return {};
        stripped = stripped.substr(start);
        const size_t len = stripped.length();
        std::vector<uint8_t> bytes;
        bytes.reserve((len + 1) / 2);
        if (len & 1) {
            const uint8_t low = safeHexLookup(stripped[0]);
            if (low == 0xFF)
                throw RLPException("Invalid hex character");
            bytes.push_back(low);
            stripped = stripped.substr(1);
        }
        for (size_t i = 0; i < stripped.length(); i += 2) {
            const uint8_t high = safeHexLookup(stripped[i]);
            const uint8_t low = safeHexLookup(stripped[i + 1]);
            if (high == 0xFF || low == 0xFF) {
                throw RLPException("Invalid hex character");
            }
            bytes.push_back(static_cast<uint8_t>(high << 4 | low));
        }
        return bytes;
    }

    export [[nodiscard]] std::string bytesToHex(const std::span<const uint8_t> bytes) {
        if (bytes.empty())
            return "0x0";
        std::string result;
        result.reserve(bytes.size() * 2 + 2);
        result = "0x";
        for (const uint8_t byte: bytes) {
            result += hexChars[byte >> 4];
            result += hexChars[byte & 0xf];
        }
        return result;
    }

    export [[nodiscard]] uint64_t safeHexToUint64(const std::string_view hex) {
        if (hex.empty())
            return 0;
        const std::string_view stripped = stripHexPrefix(hex);
        if (stripped.empty())
            return 0;
        for (const char c: stripped) {
            if (safeHexLookup(c) == 0xFF) {
                throw RLPException("Invalid hex character in value");
            }
        }
        if (stripped.length() > 16) {
            throw RLPException("Hex value exceeds uint64_t range");
        }
        uint64_t result = 0;
        for (const char c: stripped) {
            const uint8_t val = safeHexLookup(c);
            if (result > UINT64_MAX >> 4) {
                throw RLPException("Integer overflow in hex conversion");
            }
            result = result << 4 | val;
        }
        return result;
    }

    export [[nodiscard]] std::pair<std::string, std::string> validateAndNormalizeSignature(const std::string_view r,
                                                                                           const std::string_view s) {
        for (const char c: stripHexPrefix(r)) {
            if (safeHexLookup(c) == 0xFF) [[unlikely]]
                throw RLPException("Invalid hex character in signature r");
        }
        for (const char c: stripHexPrefix(s)) {
            if (safeHexLookup(c) == 0xFF) [[unlikely]]
                throw RLPException("Invalid hex character in signature s");
        }
        auto rBytes = hexToBytes(r, true);
        auto sBytes = hexToBytes(s, true);
        if (rBytes.size() < 32) {
            rBytes.insert(rBytes.begin(), 32 - rBytes.size(), 0);
        }
        if (sBytes.size() < 32) {
            sBytes.insert(sBytes.begin(), 32 - sBytes.size(), 0);
        }
        if (rBytes.size() != 32 || sBytes.size() != 32) [[unlikely]]
            throw RLPException("Signature r and s must be 32 bytes each");
        return {bytesToHex(rBytes), bytesToHex(sBytes)};
    }

    export class RLPItem {
    public:
        enum Type { BYTES, LIST };

    private:
        Type type_ = BYTES;
        std::vector<uint8_t> data_;
        std::vector<RLPItem> items_;

    public:
        RLPItem() = default;
        explicit RLPItem(std::vector<uint8_t> data) : data_(std::move(data)) {}
        explicit RLPItem(std::vector<RLPItem> items) : type_(LIST), items_(std::move(items)) {}

        [[nodiscard]] const std::vector<uint8_t> &getBytes() const {
            if (type_ != BYTES) [[unlikely]]
                throw RLPException("Item is not a byte array");
            return data_;
        }

        [[nodiscard]] const std::vector<RLPItem> &getItems() const {
            if (type_ != LIST) [[unlikely]]
                throw RLPException("Item is not a list");
            return items_;
        }

        void setBytes(std::vector<uint8_t> data) noexcept {
            if (type_ != BYTES) {
                type_ = BYTES;
                items_.clear();
                items_.shrink_to_fit();
            }
            data_ = std::move(data);
        }

        void setHex(const std::string_view hex) {
            if (type_ != BYTES) {
                type_ = BYTES;
                items_.clear();
                items_.shrink_to_fit();
            }
            if (hex.empty() || hex == "0" || hex == "0x" || hex == "0x0") {
                data_.clear();
                return;
            }
            data_ = hexToBytes(hex, false);
            if (data_.size() == 1 && data_[0] == 0) {
                data_.clear();
            }
        }

        void setInteger(const uint64_t value) noexcept {
            if (type_ != BYTES) {
                type_ = BYTES;
                items_.clear();
                items_.shrink_to_fit();
            }
            data_.clear();
            if (value == 0)
                return;
            const uint8_t bytes_needed = getByteCount(value);
            if (bytes_needed > 8)
                return;
            data_.reserve(bytes_needed);
            for (int i = bytes_needed - 1; i >= 0; --i) {
                data_.push_back(static_cast<uint8_t>(value >> (i * 8) & 0xFF));
            }
        }

        void setItems(std::vector<RLPItem> items) noexcept {
            if (type_ != LIST) {
                type_ = LIST;
                data_.clear();
                data_.shrink_to_fit();
            }
            items_ = std::move(items);
        }

        void addItem(RLPItem item) {
            if (type_ != LIST) [[unlikely]]
                throw RLPException("Cannot add item to non-list");
            items_.push_back(std::move(item));
        }

        [[nodiscard]] uint64_t toInteger() const {
            if (type_ != BYTES) [[unlikely]]
                throw RLPException("Cannot convert list to integer");
            if (data_.empty())
                return 0;
            if (data_.size() > 8) [[unlikely]]
                throw RLPException("Integer too large for uint64_t");
            uint64_t result = 0;
            for (size_t i = 0; i < data_.size(); ++i) {
                result = result << 8 | data_[i];
            }
            return result;
        }

        [[nodiscard]] std::string toHex() const {
            if (type_ != BYTES) [[unlikely]]
                throw RLPException("Cannot convert list to hex");
            return bytesToHex(data_);
        }

        [[nodiscard]] bool empty() const noexcept { return type_ == BYTES ? data_.empty() : items_.empty(); }
        [[nodiscard]] bool isList() const noexcept { return type_ == LIST; }
        [[nodiscard]] Type getType() const noexcept { return type_; }
        [[nodiscard]] size_t size() const noexcept { return type_ == BYTES ? data_.size() : items_.size(); }
    };

    export class RLPEncoder {
        static std::vector<uint8_t> encodeLength(const size_t length, const uint8_t offset) {
            std::vector<uint8_t> result;
            if (length < SIZE_THRESHOLD) {
                const size_t encoded = length + offset;
                if (encoded > 255) [[unlikely]]
                    throw RLPEncodingException("Length encoding overflow");
                result.push_back(static_cast<uint8_t>(encoded));
            } else {
                const uint8_t lengthOfLength = getByteCount(length);
                if (lengthOfLength == 0 || lengthOfLength > 8) [[unlikely]]
                    throw RLPEncodingException("Invalid length encoding");
                const size_t prefix = offset + SIZE_THRESHOLD - 1 + lengthOfLength;
                if (prefix > 255) [[unlikely]]
                    throw RLPEncodingException("Length prefix overflow");
                result.reserve(1 + lengthOfLength);
                result.push_back(static_cast<uint8_t>(prefix));
                for (int i = lengthOfLength - 1; i >= 0; --i) {
                    if (i >= 8) [[unlikely]]
                        break;
                    result.push_back(static_cast<uint8_t>(length >> (i * 8) & 0xFF));
                }
            }
            return result;
        }

        static std::vector<uint8_t> encodeItem(std::span<const uint8_t> data) {
            if (data.empty())
                return {OFFSET_SHORT_ITEM};
            if (data.size() == 1 && data[0] < OFFSET_SHORT_ITEM)
                return {data[0]};
            auto lengthBytes = encodeLength(data.size(), OFFSET_SHORT_ITEM);
            std::vector<uint8_t> result;
            result.reserve(lengthBytes.size() + data.size());
            result.insert(result.end(), lengthBytes.begin(), lengthBytes.end());
            result.insert(result.end(), data.begin(), data.end());
            return result;
        }

        static std::vector<uint8_t> encodeList(const std::span<const std::vector<uint8_t>> items) {
            size_t totalSize = 0;
            for (const auto &item: items) {
                if (totalSize > SIZE_MAX - item.size()) [[unlikely]]
                    throw RLPEncodingException("List size overflow");
                totalSize += item.size();
            }
            auto lengthBytes = encodeLength(totalSize, OFFSET_SHORT_LIST);
            std::vector<uint8_t> result;
            result.reserve(lengthBytes.size() + totalSize);
            result.insert(result.end(), lengthBytes.begin(), lengthBytes.end());
            for (const auto &item: items) {
                result.insert(result.end(), item.begin(), item.end());
            }
            return result;
        }

    public:
        [[nodiscard]] static std::vector<uint8_t> encode(const RLPItem &item) {
            if (item.isList()) {
                const auto &subItems = item.getItems();
                std::vector<std::vector<uint8_t>> encodedItems;
                encodedItems.reserve(subItems.size());
                for (const auto &subItem: subItems) {
                    encodedItems.emplace_back(encode(subItem));
                }
                return encodeList(encodedItems);
            }
            return encodeItem(item.getBytes());
        }

        [[nodiscard]] static std::vector<uint8_t> encode(const std::span<const RLPItem> items) {
            std::vector<std::vector<uint8_t>> encodedItems;
            encodedItems.reserve(items.size());
            for (const auto &item: items) {
                encodedItems.emplace_back(encode(item));
            }
            return encodeList(encodedItems);
        }

        [[nodiscard]] static std::vector<uint8_t> encodeBytes(const std::span<const uint8_t> data) {
            return encodeItem(data);
        }

        [[nodiscard]] static std::vector<uint8_t> encodeInteger(const uint64_t value) {
            if (value == 0)
                return {OFFSET_SHORT_ITEM};
            if (value < OFFSET_SHORT_ITEM)
                return {static_cast<uint8_t>(value)};
            const uint8_t bytes_needed = getByteCount(value);
            if (bytes_needed > 8) [[unlikely]]
                throw RLPEncodingException("Integer too large");
            std::vector<uint8_t> data;
            data.reserve(bytes_needed);
            for (int i = bytes_needed - 1; i >= 0; --i) {
                data.push_back(static_cast<uint8_t>(value >> (i * 8) & 0xFF));
            }
            return encodeItem(data);
        }

        [[nodiscard]] static std::vector<uint8_t> encodeHex(const std::string_view hex) {
            if (hex.empty() || hex == "0" || hex == "0x" || hex == "0x0") {
                return {OFFSET_SHORT_ITEM};
            }
            return encodeItem(hexToBytes(hex, false));
        }

        [[nodiscard]] static std::vector<uint8_t> encodeString(const std::string_view str) {
            return encodeItem(std::span(reinterpret_cast<const uint8_t *>(str.data()), str.size()));
        }
    };

    export class RLPDecoder {
        static constexpr size_t MAX_DEPTH = 1024;

        static size_t decodeLengthValue(const std::span<const uint8_t> data, const size_t offset,
                                        const size_t lengthOfLength) {
            if (lengthOfLength == 0 || lengthOfLength > 8) [[unlikely]]
                throw RLPDecodingException("Invalid length encoding");
            if (offset > data.size() || lengthOfLength > data.size() - offset) [[unlikely]]
                throw RLPDecodingException("Invalid length encoding");
            size_t length = 0;
            for (size_t i = 0; i < lengthOfLength; i++) {
                if (length > SIZE_MAX >> 8) [[unlikely]]
                    throw RLPDecodingException("Length overflow");
                length = length << 8 | data[offset + i];
            }
            return length;
        }

        static std::vector<RLPItem> decodeListItems(const std::span<const uint8_t> data, const size_t start,
                                                    const size_t end, const size_t depth = 0) {
            if (depth > MAX_DEPTH) [[unlikely]]
                throw RLPDecodingException("Maximum nesting depth exceeded");
            std::vector<RLPItem> items;
            size_t pos = start;
            while (pos < end) {
                auto [item, consumed] = decodeItem(data, pos, depth + 1);
                items.push_back(std::move(item));
                if (consumed > end - pos) [[unlikely]]
                    throw RLPDecodingException("Item consumed more than available");
                pos += consumed;
            }
            if (pos != end) [[unlikely]]
                throw RLPDecodingException("List length mismatch");
            return items;
        }

        static std::pair<RLPItem, size_t> decodeItem(std::span<const uint8_t> data, const size_t offset,
                                                     const size_t depth = 0) {
            if (depth > MAX_DEPTH) [[unlikely]]
                throw RLPDecodingException("Maximum nesting depth exceeded");
            if (offset >= data.size()) [[unlikely]]
                throw RLPDecodingException("Offset exceeds data size");
            const uint8_t firstByte = data[offset];
            if (firstByte < OFFSET_SHORT_ITEM) {
                return {RLPItem(std::vector{firstByte}), 1};
            }
            if (firstByte < OFFSET_LONG_ITEM) {
                const size_t length = firstByte - OFFSET_SHORT_ITEM;
                if (length == 0)
                    return {RLPItem(std::vector<uint8_t>{}), 1};
                if (length > data.size() - offset - 1) [[unlikely]]
                    throw RLPDecodingException("Item length exceeds data size");
                if (length == 1 && data[offset + 1] < OFFSET_SHORT_ITEM) [[unlikely]]
                    throw RLPDecodingException("Invalid encoding: single byte should not be string-encoded");
                return {RLPItem(std::vector(data.begin() + static_cast<std::ptrdiff_t>(offset + 1),
                                            data.begin() + static_cast<std::ptrdiff_t>(offset + 1 + length))),
                        1 + length};
            }
            if (firstByte < OFFSET_SHORT_LIST) {
                const size_t lengthOfLength = firstByte - OFFSET_LONG_ITEM;
                const size_t length = decodeLengthValue(data, offset + 1, lengthOfLength);
                if (length < SIZE_THRESHOLD) [[unlikely]]
                    throw RLPDecodingException("Length should use short form");
                if (lengthOfLength > data.size() - offset - 1 || length > data.size() - offset - 1 - lengthOfLength)
                        [[unlikely]]
                    throw RLPDecodingException("Item length exceeds data size");
                return {RLPItem(std::vector(data.begin() + static_cast<std::ptrdiff_t>(offset + 1 + lengthOfLength),
                                            data.begin()
                                                    + static_cast<std::ptrdiff_t>(offset + 1 + lengthOfLength + length))),
                        1 + lengthOfLength + length};
            }
            if (firstByte < OFFSET_LONG_LIST) {
                const size_t length = firstByte - OFFSET_SHORT_LIST;
                if (length > data.size() - offset - 1) [[unlikely]]
                    throw RLPDecodingException("List length exceeds data size");
                auto items = decodeListItems(data, offset + 1, offset + 1 + length, depth);
                return {RLPItem(std::move(items)), 1 + length};
            }
            const size_t lengthOfLength = firstByte - OFFSET_LONG_LIST;
            const size_t length = decodeLengthValue(data, offset + 1, lengthOfLength);
            if (length < SIZE_THRESHOLD) [[unlikely]]
                throw RLPDecodingException("Length should use short form");
            if (lengthOfLength > data.size() - offset - 1 || length > data.size() - offset - 1 - lengthOfLength)
                    [[unlikely]]
                throw RLPDecodingException("List length exceeds data size");
            auto items = decodeListItems(data, offset + 1 + lengthOfLength, offset + 1 + lengthOfLength + length, depth);
            return {RLPItem(std::move(items)), 1 + lengthOfLength + length};
        }

    public:
        [[nodiscard]] static RLPItem decode(const std::span<const uint8_t> data) {
            if (data.empty()) [[unlikely]]
                throw RLPDecodingException("Cannot decode empty data");
            auto [item, consumed] = decodeItem(data, 0);
            if (consumed != data.size()) [[unlikely]]
                throw RLPDecodingException("Not all data was consumed during decoding");
            return item;
        }

        [[nodiscard]] static RLPItem decode(const std::string_view hex) { return decode(hexToBytes(hex)); }

        [[nodiscard]] static std::vector<RLPItem> decodeList(const std::span<const uint8_t> data) {
            const RLPItem item = decode(data);
            if (!item.isList()) [[unlikely]]
                throw RLPDecodingException("Data does not represent a list");
            return std::move(const_cast<std::vector<RLPItem> &>(item.getItems()));
        }

        [[nodiscard]] static std::pair<size_t, size_t> decodeLength(const std::span<const uint8_t> data,
                                                                    const size_t offset) {
            if (offset >= data.size()) [[unlikely]]
                throw RLPDecodingException("Offset exceeds data size");
            const uint8_t firstByte = data[offset];
            if (firstByte < OFFSET_SHORT_ITEM)
                return {1, 1};
            if (firstByte < OFFSET_LONG_ITEM)
                return {firstByte - OFFSET_SHORT_ITEM, 1};
            if (firstByte < OFFSET_SHORT_LIST) {
                const size_t lengthOfLength = firstByte - OFFSET_LONG_ITEM;
                size_t length = decodeLengthValue(data, offset + 1, lengthOfLength);
                if (lengthOfLength > SIZE_MAX - 1) [[unlikely]]
                    throw RLPDecodingException("Overflow in length calculation");
                return {length, 1 + lengthOfLength};
            }
            if (firstByte < OFFSET_LONG_LIST)
                return {firstByte - OFFSET_SHORT_LIST, 1};
            const size_t lengthOfLength = firstByte - OFFSET_LONG_LIST;
            size_t length = decodeLengthValue(data, offset + 1, lengthOfLength);
            if (lengthOfLength > SIZE_MAX - 1) [[unlikely]]
                throw RLPDecodingException("Overflow in length calculation");
            return {length, 1 + lengthOfLength};
        }
    };

    export struct AccessListEntry {
        std::string address;
        std::vector<std::string> storageKeys;
        AccessListEntry() = default;
        AccessListEntry(std::string addr, std::vector<std::string> keys) :
            address(std::move(addr)), storageKeys(std::move(keys)) {}

        [[nodiscard]] RLPItem toRLPItem() const {
            std::vector<RLPItem> items;
            items.reserve(2);
            RLPItem addressItem;
            addressItem.setHex(address);
            items.push_back(std::move(addressItem));
            std::vector<RLPItem> keyItems;
            keyItems.reserve(storageKeys.size());
            for (const auto &key: storageKeys) {
                RLPItem keyItem;
                keyItem.setHex(key);
                keyItems.push_back(std::move(keyItem));
            }
            items.emplace_back(std::move(keyItems));
            return RLPItem(std::move(items));
        }

        [[nodiscard]] static AccessListEntry fromRLPItem(const RLPItem &item) {
            if (!item.isList() || item.getItems().size() != 2)
                throw RLPDecodingException("Invalid access list entry format");
            const auto &items = item.getItems();
            std::string address = items[0].empty() ? std::string{} : items[0].toHex();
            if (!address.empty()) {
                if (const std::string_view addrView = stripHexPrefix(address); addrView.length() != 40)
                    throw RLPDecodingException("Invalid address length in access list");
            }
            std::vector<std::string> storageKeys;
            if (items[1].isList()) {
                const auto &keyItems = items[1].getItems();
                storageKeys.reserve(keyItems.size());
                for (const auto &keyItem: keyItems) {
                    std::string key = keyItem.empty() ? std::string{} : keyItem.toHex();
                    if (!key.empty()) {
                        if (std::string_view keyView = stripHexPrefix(key); keyView.length() != 64)
                            throw RLPDecodingException("Invalid storage key length");
                    }
                    storageKeys.push_back(std::move(key));
                }
            }
            return AccessListEntry(std::move(address), std::move(storageKeys));
        }
    };

    export class EthereumTransaction {
        uint64_t nonce_ = 0;
        uint64_t gasPrice_ = 0;
        uint64_t gasLimit_ = 0;
        std::string to_;
        uint64_t value_ = 0;
        std::string data_;
        uint64_t chainId_ = 1;
        uint64_t v_ = 0;
        std::string r_;
        std::string s_;
        bool isSigned_ = false;

        [[nodiscard]] std::vector<RLPItem> buildTransactionItems(bool includeSignature) const {
            std::vector<RLPItem> items;
            items.reserve(9);
            RLPItem nonceItem;
            nonceItem.setInteger(nonce_);
            items.push_back(std::move(nonceItem));
            RLPItem gasPriceItem;
            gasPriceItem.setInteger(gasPrice_);
            items.push_back(std::move(gasPriceItem));
            RLPItem gasLimitItem;
            gasLimitItem.setInteger(gasLimit_);
            items.push_back(std::move(gasLimitItem));
            if (!to_.empty()) {
                auto toBytes = hexToBytes(to_);
                if (toBytes.size() != 20) [[unlikely]]
                    throw RLPException("Invalid address length: must be 20 bytes");
                items.emplace_back(std::move(toBytes));
            } else {
                items.emplace_back(std::vector<uint8_t>{});
            }
            RLPItem valueItem;
            valueItem.setInteger(value_);
            items.push_back(std::move(valueItem));
            items.emplace_back(data_.empty() ? std::vector<uint8_t>{} : hexToBytes(data_));
            if (includeSignature && isSigned_) {
                RLPItem vItem;
                vItem.setInteger(v_);
                items.push_back(std::move(vItem));
                RLPItem rItem;
                rItem.setHex(r_);
                items.push_back(std::move(rItem));
                RLPItem sItem;
                sItem.setHex(s_);
                items.push_back(std::move(sItem));
            } else {
                RLPItem chainItem;
                chainItem.setInteger(chainId_);
                items.push_back(std::move(chainItem));
                items.emplace_back(std::vector<uint8_t>{});
                items.emplace_back(std::vector<uint8_t>{});
            }
            return items;
        }

        static void validateHex(const std::string_view hex) {
            if (hex.empty())
                return;
            for (const std::string_view stripped = stripHexPrefix(hex); const char c: stripped) {
                if (safeHexLookup(static_cast<unsigned char>(c)) == 0xFF) {
                    throw RLPException("Invalid hex string");
                }
            }
        }

    public:
        EthereumTransaction() = default;

        void setNonce(const uint64_t nonce) noexcept { nonce_ = nonce; }
        void setGasPrice(const uint64_t gasPrice) noexcept { gasPrice_ = gasPrice; }
        void setGasLimit(const uint64_t gasLimit) noexcept { gasLimit_ = gasLimit; }

        void setTo(std::string to) {
            if (!to.empty()) {
                validateHex(to);
                if (const std::string_view stripped = stripHexPrefix(to); stripped.length() != 40) {
                    throw RLPException("Address must be 40 hex characters");
                }
            }
            to_ = std::move(to);
        }

        void setValue(const uint64_t value) noexcept { value_ = value; }

        void setData(std::string data) {
            validateHex(data);
            data_ = std::move(data);
        }

        void setChainId(const uint64_t chainId) {
            if (chainId > (UINT64_MAX - 36) / 2) [[unlikely]]
                throw RLPException("Chain ID too large");
            chainId_ = chainId;
        }

        void setSignature(const uint64_t v, const std::string_view r, const std::string_view s) {
            auto [r_normalized, s_normalized] = validateAndNormalizeSignature(r, s);
            v_ = v;
            r_ = std::move(r_normalized);
            s_ = std::move(s_normalized);
            isSigned_ = true;
        }

        [[nodiscard]] uint64_t getNonce() const noexcept { return nonce_; }
        [[nodiscard]] uint64_t getGasPrice() const noexcept { return gasPrice_; }
        [[nodiscard]] uint64_t getGasLimit() const noexcept { return gasLimit_; }
        [[nodiscard]] const std::string &getTo() const noexcept { return to_; }
        [[nodiscard]] uint64_t getValue() const noexcept { return value_; }
        [[nodiscard]] const std::string &getData() const noexcept { return data_; }
        [[nodiscard]] uint64_t getChainId() const noexcept { return chainId_; }
        [[nodiscard]] bool getIsSigned() const noexcept { return isSigned_; }

        [[nodiscard]] std::vector<uint8_t> buildForSigning() const {
            return RLPEncoder::encode(buildTransactionItems(false));
        }

        [[nodiscard]] std::vector<uint8_t> buildSigned() const {
            if (!isSigned_) [[unlikely]]
                throw RLPException("Transaction is not signed");
            return RLPEncoder::encode(buildTransactionItems(true));
        }

        [[nodiscard]] std::string toHex() const { return bytesToHex(buildSigned()); }

        void signTransaction(const std::span<const uint8_t> privateKey,
                             const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash,
                             const std::function<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, int>(
                                     std::span<const uint8_t>, std::span<const uint8_t>)> &signFunction) {
            if (privateKey.size() != 32) [[unlikely]]
                throw RLPException("Private key must be exactly 32 bytes");
            if (!keccakHash || !signFunction) [[unlikely]]
                throw RLPException("Hash and sign functions must be provided");
            auto txData = buildForSigning();
            auto hash = keccakHash(txData);
            if (hash.size() != 32) [[unlikely]]
                throw RLPException("Hash function must return 32 bytes");
            auto [r, s, recoveryId] = signFunction(hash, privateKey);
            if (r.size() != 32 || s.size() != 32) [[unlikely]]
                throw RLPException("Signature components must be 32 bytes each");
            if (recoveryId < 0 || recoveryId > 1) [[unlikely]]
                throw RLPException("Recovery ID must be 0 or 1");
            if (chainId_ > (UINT64_MAX - 36) / 2) [[unlikely]]
                throw RLPException("Chain ID too large for v calculation");

            const uint64_t v = chainId_ * 2 + 35 + static_cast<uint64_t>(recoveryId);
            setSignature(v, bytesToHex(r), bytesToHex(s));
        }

        [[nodiscard]] static std::string processDeploymentBytecode(const std::string_view bytecode,
                                                                   const std::string_view constructorParams) {
            validateHex(bytecode);
            if (!constructorParams.empty()) {
                validateHex(constructorParams);
            }
            std::string processedBytecode(stripHexPrefix(bytecode));
            if (!constructorParams.empty()) {
                processedBytecode.append(stripHexPrefix(constructorParams));
            }
            return "0x" + processedBytecode;
        }

        [[nodiscard]] static EthereumTransaction createDeployment(const uint64_t nonce, const uint64_t gasPrice,
                                                                  const uint64_t gasLimit, const std::string_view bytecode,
                                                                  const uint64_t chainId,
                                                                  const std::string_view constructorParams = "") {
            EthereumTransaction tx;
            tx.setNonce(nonce);
            tx.setGasPrice(gasPrice);
            tx.setGasLimit(gasLimit);
            tx.setChainId(chainId);
            tx.setData(processDeploymentBytecode(bytecode, constructorParams));
            return tx;
        }

        [[nodiscard]] static EthereumTransaction createFunctionCall(const uint64_t nonce, const uint64_t gasPrice,
                                                                    const uint64_t gasLimit, std::string to,
                                                                    std::string data, const uint64_t chainId,
                                                                    const uint64_t value = 0) {
            EthereumTransaction tx;
            tx.setNonce(nonce);
            tx.setGasPrice(gasPrice);
            tx.setGasLimit(gasLimit);
            tx.setTo(std::move(to));
            tx.setValue(value);
            tx.setData(std::move(data));
            tx.setChainId(chainId);
            return tx;
        }
    };

    export class TypedTransaction {
    public:
        enum TransactionType : uint8_t { LEGACY = 0x00, EIP2930 = 0x01, EIP1559 = 0x02 };

    private:
        TransactionType type_ = EIP2930;
        uint64_t chainId_ = 1;
        uint64_t nonce_ = 0;
        uint64_t gasLimit_ = 0;
        std::optional<uint64_t> gasPrice_;
        std::optional<uint64_t> maxPriorityFeePerGas_;
        std::optional<uint64_t> maxFeePerGas_;
        std::string to_;
        uint64_t value_ = 0;
        std::string data_;
        std::vector<AccessListEntry> accessList_;
        uint64_t v_ = 0;
        std::string r_;
        std::string s_;
        bool isSigned_ = false;

        static void validateHex(const std::string_view hex) {
            if (hex.empty())
                return;
            for (const std::string_view stripped = stripHexPrefix(hex); const char c: stripped) {
                if (safeHexLookup(static_cast<unsigned char>(c)) == 0xFF) {
                    throw RLPException("Invalid hex string");
                }
            }
        }

        void validateRequiredFields() const {
            if (type_ == LEGACY) [[unlikely]]
                throw RLPException("Use EthereumTransaction for legacy transactions");
            if (type_ == EIP1559) {
                if (!maxPriorityFeePerGas_.has_value() || !maxFeePerGas_.has_value())
                    throw RLPException("EIP-1559 requires priority fee and max fee");
            } else if (type_ == EIP2930) {
                if (!gasPrice_.has_value())
                    throw RLPException("EIP-2930 requires gas price");
            }
        }

        [[nodiscard]] std::vector<RLPItem> buildTransactionItems(bool includeSignature) const {
            validateRequiredFields();
            std::vector<RLPItem> items;
            items.reserve(includeSignature && isSigned_ ? 12 : 9);
            RLPItem chainItem;
            chainItem.setInteger(chainId_);
            items.push_back(std::move(chainItem));
            RLPItem nonceItem;
            nonceItem.setInteger(nonce_);
            items.push_back(std::move(nonceItem));
            if (type_ == EIP1559) {
                RLPItem priorityFeeItem;
                priorityFeeItem.setInteger(maxPriorityFeePerGas_.value());
                items.push_back(std::move(priorityFeeItem));
                RLPItem maxFeeItem;
                maxFeeItem.setInteger(maxFeePerGas_.value());
                items.push_back(std::move(maxFeeItem));
            } else if (type_ == EIP2930) {
                RLPItem gasPriceItem;
                gasPriceItem.setInteger(gasPrice_.value());
                items.push_back(std::move(gasPriceItem));
            }
            RLPItem gasLimitItem;
            gasLimitItem.setInteger(gasLimit_);
            items.push_back(std::move(gasLimitItem));
            if (!to_.empty()) {
                auto toBytes = hexToBytes(to_);
                if (toBytes.size() != 20) [[unlikely]]
                    throw RLPException("Invalid address length: must be 20 bytes");
                items.emplace_back(std::move(toBytes));
            } else {
                items.emplace_back(std::vector<uint8_t>{});
            }
            RLPItem valueItem;
            valueItem.setInteger(value_);
            items.push_back(std::move(valueItem));
            items.emplace_back(data_.empty() ? std::vector<uint8_t>{} : hexToBytes(data_));
            std::vector<RLPItem> accessListItems;
            accessListItems.reserve(accessList_.size());
            for (const auto &entry: accessList_) {
                accessListItems.push_back(entry.toRLPItem());
            }
            items.emplace_back(std::move(accessListItems));
            if (includeSignature && isSigned_) {
                RLPItem vItem;
                vItem.setInteger(v_);
                items.push_back(std::move(vItem));
                RLPItem rItem;
                rItem.setHex(r_);
                items.push_back(std::move(rItem));
                RLPItem sItem;
                sItem.setHex(s_);
                items.push_back(std::move(sItem));
            }
            return items;
        }

    public:
        TypedTransaction() = default;
        explicit TypedTransaction(const TransactionType type) : type_(type) {
            if (type == LEGACY) [[unlikely]]
                throw RLPException("Use EthereumTransaction for legacy transactions");
        }

        void setType(const TransactionType type) {
            if (type == LEGACY) [[unlikely]]
                throw RLPException("Use EthereumTransaction for legacy transactions");
            type_ = type;
        }

        void setChainId(const uint64_t chainId) noexcept { chainId_ = chainId; }
        void setNonce(const uint64_t nonce) noexcept { nonce_ = nonce; }
        void setGasLimit(const uint64_t gasLimit) noexcept { gasLimit_ = gasLimit; }
        void setGasPrice(uint64_t gasPrice) noexcept { gasPrice_ = gasPrice; }
        void setMaxPriorityFeePerGas(uint64_t fee) noexcept { maxPriorityFeePerGas_ = fee; }
        void setMaxFeePerGas(uint64_t fee) noexcept { maxFeePerGas_ = fee; }

        void setTo(std::string to) {
            if (!to.empty()) {
                validateHex(to);
                if (const std::string_view stripped = stripHexPrefix(to); stripped.length() != 40) {
                    throw RLPException("Address must be 40 hex characters");
                }
            }
            to_ = std::move(to);
        }

        void setValue(const uint64_t value) noexcept { value_ = value; }

        void setData(std::string data) {
            validateHex(data);
            data_ = std::move(data);
        }

        void setAccessList(std::vector<AccessListEntry> accessList) noexcept { accessList_ = std::move(accessList); }

        void addAccessListEntry(const std::string &address, const std::vector<std::string> &storageKeys) {
            accessList_.emplace_back(address, storageKeys);
        }

        void setSignature(const uint64_t v, const std::string_view r, const std::string_view s) {
            auto [r_normalized, s_normalized] = validateAndNormalizeSignature(r, s);
            v_ = v;
            r_ = std::move(r_normalized);
            s_ = std::move(s_normalized);
            isSigned_ = true;
        }

        [[nodiscard]] TransactionType getType() const noexcept { return type_; }
        [[nodiscard]] uint64_t getChainId() const noexcept { return chainId_; }
        [[nodiscard]] uint64_t getNonce() const noexcept { return nonce_; }
        [[nodiscard]] uint64_t getGasLimit() const noexcept { return gasLimit_; }
        [[nodiscard]] std::optional<uint64_t> getGasPrice() const noexcept { return gasPrice_; }
        [[nodiscard]] std::optional<uint64_t> getMaxPriorityFeePerGas() const noexcept { return maxPriorityFeePerGas_; }
        [[nodiscard]] std::optional<uint64_t> getMaxFeePerGas() const noexcept { return maxFeePerGas_; }
        [[nodiscard]] const std::string &getTo() const noexcept { return to_; }
        [[nodiscard]] uint64_t getValue() const noexcept { return value_; }
        [[nodiscard]] const std::string &getData() const noexcept { return data_; }
        [[nodiscard]] const std::vector<AccessListEntry> &getAccessList() const noexcept { return accessList_; }
        [[nodiscard]] bool getIsSigned() const noexcept { return isSigned_; }

        [[nodiscard]] std::vector<uint8_t> buildForSigning() const {
            validateRequiredFields();
            auto items = buildTransactionItems(false);
            auto rlpEncoded = RLPEncoder::encode(items);
            std::vector<uint8_t> result;
            result.reserve(rlpEncoded.size() + 1);
            result.push_back(type_);
            result.insert(result.end(), rlpEncoded.begin(), rlpEncoded.end());
            return result;
        }

        [[nodiscard]] std::vector<uint8_t> buildSigned() const {
            if (!isSigned_) [[unlikely]]
                throw RLPException("Transaction is not signed");
            validateRequiredFields();
            auto items = buildTransactionItems(true);
            auto rlpEncoded = RLPEncoder::encode(items);
            std::vector<uint8_t> result;
            result.reserve(rlpEncoded.size() + 1);
            result.push_back(type_);
            result.insert(result.end(), rlpEncoded.begin(), rlpEncoded.end());
            return result;
        }

        [[nodiscard]] std::string toHex() const { return bytesToHex(buildSigned()); }

        void signTransaction(const std::span<const uint8_t> privateKey,
                             const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash,
                             const std::function<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, int>(
                                     std::span<const uint8_t>, std::span<const uint8_t>)> &signFunction) {
            if (privateKey.size() != 32) [[unlikely]]
                throw RLPException("Private key must be exactly 32 bytes");
            if (!keccakHash || !signFunction) [[unlikely]]
                throw RLPException("Hash and sign functions must be provided");
            auto txData = buildForSigning();
            auto hash = keccakHash(txData);
            if (hash.size() != 32) [[unlikely]]
                throw RLPException("Hash function must return 32 bytes");
            auto [r, s, recoveryId] = signFunction(hash, privateKey);
            if (r.size() != 32 || s.size() != 32) [[unlikely]]
                throw RLPException("Signature components must be 32 bytes each");
            if (recoveryId < 0 || recoveryId > 1) [[unlikely]]
                throw RLPException("Recovery ID must be 0 or 1");
            setSignature(static_cast<uint64_t>(recoveryId), bytesToHex(r), bytesToHex(s));
        }

        [[nodiscard]] static TypedTransaction
        createEIP1559Transaction(const uint64_t chainId, const uint64_t nonce, const uint64_t maxPriorityFeePerGas,
                                 const uint64_t maxFeePerGas, const uint64_t gasLimit, std::string to,
                                 const uint64_t value, std::string data, std::vector<AccessListEntry> accessList = {}) {
            TypedTransaction tx(EIP1559);
            tx.setChainId(chainId);
            tx.setNonce(nonce);
            tx.setMaxPriorityFeePerGas(maxPriorityFeePerGas);
            tx.setMaxFeePerGas(maxFeePerGas);
            tx.setGasLimit(gasLimit);
            tx.setTo(std::move(to));
            tx.setValue(value);
            tx.setData(std::move(data));
            tx.setAccessList(std::move(accessList));
            return tx;
        }

        [[nodiscard]] static TypedTransaction createEIP2930Transaction(const uint64_t chainId, const uint64_t nonce,
                                                                       const uint64_t gasPrice, const uint64_t gasLimit,
                                                                       std::string to, const uint64_t value,
                                                                       std::string data,
                                                                       std::vector<AccessListEntry> accessList = {}) {
            TypedTransaction tx(EIP2930);
            tx.setChainId(chainId);
            tx.setNonce(nonce);
            tx.setGasPrice(gasPrice);
            tx.setGasLimit(gasLimit);
            tx.setTo(std::move(to));
            tx.setValue(value);
            tx.setData(std::move(data));
            tx.setAccessList(std::move(accessList));
            return tx;
        }

        [[nodiscard]] static TypedTransaction createEIP1559Deployment(const uint64_t chainId, const uint64_t nonce,
                                                                      const uint64_t maxPriorityFeePerGas,
                                                                      const uint64_t maxFeePerGas, const uint64_t gasLimit,
                                                                      const std::string_view bytecode,
                                                                      const std::string_view constructorParams = "") {
            TypedTransaction tx(EIP1559);
            tx.setChainId(chainId);
            tx.setNonce(nonce);
            tx.setMaxPriorityFeePerGas(maxPriorityFeePerGas);
            tx.setMaxFeePerGas(maxFeePerGas);
            tx.setGasLimit(gasLimit);
            tx.setValue(0);
            tx.setData(EthereumTransaction::processDeploymentBytecode(bytecode, constructorParams));
            return tx;
        }

        [[nodiscard]] static TypedTransaction createEIP2930Deployment(const uint64_t chainId, const uint64_t nonce,
                                                                      const uint64_t gasPrice, const uint64_t gasLimit,
                                                                      const std::string_view bytecode,
                                                                      const std::string_view constructorParams = "",
                                                                      std::vector<AccessListEntry> accessList = {}) {
            TypedTransaction tx(EIP2930);
            tx.setChainId(chainId);
            tx.setNonce(nonce);
            tx.setGasPrice(gasPrice);
            tx.setGasLimit(gasLimit);
            tx.setValue(0);
            tx.setData(EthereumTransaction::processDeploymentBytecode(bytecode, constructorParams));
            tx.setAccessList(std::move(accessList));
            return tx;
        }

        [[nodiscard]] static TypedTransaction decodeTypedTransaction(std::span<const uint8_t> data) {
            if (data.empty()) [[unlikely]]
                throw RLPDecodingException("Cannot decode empty transaction data");
            const uint8_t txType = data[0];
            if (txType != 0x01 && txType != 0x02)
                throw RLPDecodingException("Unsupported transaction type: " + std::to_string(txType));
            std::vector rlpData(data.begin() + 1, data.end());
            const auto items = RLPDecoder::decodeList(rlpData);
            if (constexpr size_t minItems = 9; items.size() < minItems) [[unlikely]]
                throw RLPDecodingException("Invalid transaction format");
            TypedTransaction tx(txType == 0x02 ? EIP1559 : EIP2930);
            tx.setChainId(items[0].empty() ? 0 : items[0].toInteger());
            tx.setNonce(items[1].empty() ? 0 : items[1].toInteger());
            size_t idx = 2;
            if (txType == 0x02) {
                tx.setMaxPriorityFeePerGas(items[idx].empty() ? 0 : items[idx].toInteger());
                idx++;
                tx.setMaxFeePerGas(items[idx].empty() ? 0 : items[idx].toInteger());
                idx++;
            } else {
                tx.setGasPrice(items[idx].empty() ? 0 : items[idx].toInteger());
                idx++;
            }
            tx.setGasLimit(items[idx].empty() ? 0 : items[idx].toInteger());
            idx++;
            tx.setTo(items[idx].empty() ? "" : items[idx].toHex());
            idx++;
            tx.setValue(items[idx].empty() ? 0 : items[idx].toInteger());
            idx++;
            tx.setData(items[idx].empty() ? "" : items[idx].toHex());
            idx++;
            if (idx < items.size() && items[idx].isList()) {
                std::vector<AccessListEntry> accessList;
                for (const auto &accessItem: items[idx].getItems()) {
                    accessList.push_back(AccessListEntry::fromRLPItem(accessItem));
                }
                tx.setAccessList(std::move(accessList));
                idx++;
            }
            if (idx + 2 < items.size()) {
                tx.setSignature(items[idx].empty() ? 0 : items[idx].toInteger(),
                                items[idx + 1].empty() ? "" : items[idx + 1].toHex(),
                                items[idx + 2].empty() ? "" : items[idx + 2].toHex());
            }
            return tx;
        }

        [[nodiscard]] static TypedTransaction decodeTypedTransaction(const std::string_view hex) {
            return decodeTypedTransaction(hexToBytes(hex));
        }
    };

    export class FunctionEncoder {
    public:
        [[nodiscard]] static std::string padLeft(const std::string_view str, const size_t totalLength,
                                                 const char padChar = '0') {
            if (str.length() >= totalLength)
                return std::string(str);
            return std::string(totalLength - str.length(), padChar) + std::string(str);
        }

        [[nodiscard]] static std::string padRight(const std::string_view str, const size_t totalLength,
                                                  const char padChar = '0') {
            if (str.length() >= totalLength)
                return std::string(str);
            return std::string(str) + std::string(totalLength - str.length(), padChar);
        }

        [[nodiscard]] static std::string
        encodeFunctionSelector(const std::string_view signature,
                               const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash) {
            if (!keccakHash) [[unlikely]]
                throw RLPEncodingException("Hash function not provided");
            const auto hash = keccakHash(std::span(reinterpret_cast<const uint8_t *>(signature.data()), signature.size()));
            if (hash.size() < 4) [[unlikely]]
                throw RLPEncodingException("Hash function must return at least 4 bytes");
            std::string selector;
            selector.reserve(10);
            selector = "0x";
            for (size_t i = 0; i < 4; i++) {
                selector += hexChars[static_cast<size_t>(hash[i] >> 4)];
                selector += hexChars[static_cast<size_t>(hash[i] & 0xf)];
            }
            return selector;
        }

        [[nodiscard]] static std::string encodeAddress(const std::string_view address) {
            const std::string_view addr = stripHexPrefix(address);
            if (addr.length() != 40) [[unlikely]]
                throw RLPEncodingException("Invalid address length: " + std::string(address));
            for (const char c: addr) {
                if (safeHexLookup(c) == 0xFF) [[unlikely]]
                    throw RLPEncodingException("Invalid address format: " + std::string(address));
            }
            return "0x" + padLeft(addr, 64);
        }

        [[nodiscard]] static std::string encodeUint256(uint64_t value) {
            if (value == 0)
                return "0x" + std::string(64, '0');
            std::string hex;
            hex.reserve(16);
            while (value > 0) {
                hex = hexChars[value & 0xF] + hex;
                value >>= 4;
            }
            return "0x" + padLeft(hex, 64);
        }

        [[nodiscard]] static std::string encodeUint256(const std::string_view hexValue) {
            std::string_view hex = stripHexPrefix(hexValue);
            if (hex.empty())
                hex = "0";
            for (const char c: hex) {
                if (safeHexLookup(c) == 0xFF) [[unlikely]]
                    throw RLPEncodingException("Invalid hex value: " + std::string(hexValue));
            }
            if (hex.length() > 64) [[unlikely]]
                throw RLPEncodingException("Value exceeds uint256 range");
            return "0x" + padLeft(hex, 64);
        }

        [[nodiscard]] static std::string encodeBool(const bool value) {
            return "0x" + std::string(63, '0') + (value ? '1' : '0');
        }

        [[nodiscard]] static std::string encodeFixedBytes(const std::string_view value, const size_t byteSize) {
            if (byteSize == 0 || byteSize > 32) [[unlikely]]
                throw RLPEncodingException("Fixed bytes size must be between 1 and 32");
            const std::string_view hex = stripHexPrefix(value);
            if (hex.length() > byteSize * 2) [[unlikely]]
                throw RLPEncodingException("Value exceeds fixed bytes size");
            return "0x" + padRight(hex, 64);
        }

        [[nodiscard]] static std::string encodeBytes(const std::span<const uint8_t> data) {
            return encodeDynamicType("bytes", bytesToHex(data));
        }

        [[nodiscard]] static std::string encodeString(const std::string_view str) {
            return encodeDynamicType("string", std::string(str));
        }

        [[nodiscard]] static std::string encodeDynamicType(const std::string_view type, const std::string_view value) {
            if (type == "string") {
                const std::string lengthEncoded = encodeUint256(value.size());
                const std::string dataHex
                        = bytesToHex(std::span(reinterpret_cast<const uint8_t *>(value.data()), value.size()));
                const std::string_view dataHexView = stripHexPrefix(dataHex);
                const size_t padding = (64 - dataHexView.length() % 64) % 64;
                std::string result;
                result.reserve(64 + dataHexView.length() + padding);
                result = lengthEncoded.substr(2);
                result += dataHexView;
                if (padding > 0)
                    result.append(padding, '0');
                return result;
            }
            if (type == "bytes") {
                std::vector<uint8_t> bytes = hexToBytes(value);
                const std::string lengthEncoded = encodeUint256(bytes.size());
                const std::string dataHex = bytesToHex(bytes);
                const std::string_view dataHexView = stripHexPrefix(dataHex);
                const size_t padding = (64 - dataHexView.length() % 64) % 64;
                std::string result;
                result.reserve(64 + dataHexView.length() + padding);
                result = lengthEncoded.substr(2);
                result += dataHexView;
                if (padding > 0)
                    result.append(padding, '0');
                return result;
            }
            throw RLPEncodingException("Unsupported dynamic type: " + std::string(type));
        }

        [[nodiscard]] static std::string encodeParameters(const std::vector<std::string> &types,
                                                          const std::vector<std::string> &values) {
            if (types.size() != values.size()) [[unlikely]]
                throw RLPEncodingException("Types and values count mismatch");
            if (types.empty())
                return "0x";
            std::vector<std::string> staticParts;
            std::vector<std::string> dynamicParts;
            std::vector<bool> isDynamic;
            staticParts.reserve(types.size());
            dynamicParts.reserve(types.size());
            isDynamic.reserve(types.size());
            for (size_t i = 0; i < types.size(); i++) {
                const auto &type = types[i];
                const auto &value = values[i];
                if (type == "string" || type == "bytes" || type.find("[]") != std::string::npos) {
                    isDynamic.push_back(true);
                    staticParts.emplace_back();
                    dynamicParts.push_back(encodeDynamicType(type, value));
                } else {
                    isDynamic.push_back(false);
                    dynamicParts.emplace_back();
                    if (type == "address") {
                        staticParts.push_back(encodeAddress(value).substr(2));
                    } else if ((type.size() >= 4 && type.substr(0, 4) == "uint")
                               || (type.size() >= 3 && type.substr(0, 3) == "int")) {
                        staticParts.push_back(encodeUint256(value).substr(2));
                    } else if (type == "bool") {
                        staticParts.push_back(encodeBool(value == "true" || value == "1").substr(2));
                    } else if (type.size() > 5 && type.substr(0, 5) == "bytes") {
                        std::string sizeStr = type.substr(5);
                        size_t byteSize = 0;
                        if (auto [ptr, ec] = std::from_chars(sizeStr.data(), sizeStr.data() + sizeStr.size(), byteSize);
                            ec != std::errc{} || byteSize == 0 || byteSize > 32) [[unlikely]]
                            throw RLPEncodingException("Invalid fixed bytes type: " + type);
                        staticParts.push_back(encodeFixedBytes(value, byteSize).substr(2));
                    } else {
                        throw RLPEncodingException("Unsupported parameter type: " + type);
                    }
                }
            }
            size_t dynamicOffset = types.size() * 32;
            for (size_t i = 0; i < types.size(); i++) {
                if (isDynamic[i]) {
                    staticParts[i] = encodeUint256(dynamicOffset).substr(2);
                    dynamicOffset += dynamicParts[i].length() / 2;
                }
            }
            std::string result;
            result.reserve(2 + staticParts.size() * 64 + dynamicOffset);
            result = "0x";
            for (const auto &part: staticParts)
                result += part;
            for (const auto &part: dynamicParts) {
                if (!part.empty())
                    result += part;
            }
            return result;
        }

        [[nodiscard]] static std::string
        encodeFunctionCall(const std::string_view signature, const std::vector<std::string> &types,
                           const std::vector<std::string> &values,
                           const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash) {
            std::string selector = encodeFunctionSelector(signature, keccakHash);
            if (const std::string parameters = encodeParameters(types, values); parameters.size() > 2) {
                return selector + parameters.substr(2);
            }
            return selector;
        }

        [[nodiscard]] static std::string encodeConstructorParams(const std::vector<std::string> &types,
                                                                 const std::vector<std::string> &values) {
            return encodeParameters(types, values);
        }
    };

    export class FunctionDecoder {
        [[nodiscard]] static std::vector<uint8_t> extractBytes(const std::string_view hexData, const size_t offsetInBytes,
                                                               const size_t length) {
            const std::string_view data = stripHexPrefix(hexData);
            const size_t dataStart = offsetInBytes * 2;
            const size_t dataLength = length * 2;
            if (dataStart > data.size() || dataLength > data.size() - dataStart) [[unlikely]]
                throw RLPDecodingException("Offset exceeds data bounds");
            return hexToBytes(data.substr(dataStart, dataLength), true);
        }

        [[nodiscard]] static uint64_t decodeUint256FromOffset(const std::string_view hexData, const size_t offsetInBytes) {
            const auto bytes = extractBytes(hexData, offsetInBytes, WORD_SIZE);
            uint64_t result = 0;
            size_t startIdx = 0;
            while (startIdx < bytes.size() && bytes[startIdx] == 0)
                ++startIdx;
            if (bytes.size() - startIdx > 8) [[unlikely]]
                throw RLPDecodingException("Uint256 value too large for uint64_t");
            for (size_t i = startIdx; i < bytes.size(); ++i) {
                if (result > UINT64_MAX >> 8) [[unlikely]]
                    throw RLPDecodingException("Integer overflow in uint256 decode");
                result = result << 8 | bytes[i];
            }
            return result;
        }

        [[nodiscard]] static int64_t decodeInt256FromOffset(const std::string_view hexData, const size_t offsetInBytes) {
            const auto bytes = extractBytes(hexData, offsetInBytes, WORD_SIZE);
            if (bytes.empty())
                return 0;
            if ((bytes[0] & 0x80) != 0) {
                uint64_t magnitude = 0;
                for (size_t i = 0; i < bytes.size(); ++i) {
                    magnitude = magnitude << 8 | (0xFF ^ bytes[i]);
                }
                magnitude++;
                if (magnitude > static_cast<uint64_t>(INT64_MAX) + 1) [[unlikely]]
                    throw RLPDecodingException("Int256 value out of int64_t range");
                return -static_cast<int64_t>(magnitude);
            }
            size_t idx = 0;
            while (idx < bytes.size() && bytes[idx] == 0x00)
                ++idx;
            if (bytes.size() - idx > 8) [[unlikely]]
                throw RLPDecodingException("Int256 value out of int64_t range");
            int64_t result = 0;
            for (size_t i = idx; i < bytes.size(); ++i) {
                if (result > INT64_MAX >> 8) [[unlikely]]
                    throw RLPDecodingException("Integer overflow in int256 decode");
                result = result << 8 | bytes[i];
            }
            return result;
        }

    public:
        [[nodiscard]] static bool hasFunctionSelector(const std::string_view data) noexcept {
            if (data.size() < 10)
                return false;
            if (data.substr(0, 2) != "0x")
                return false;
            for (size_t i = 2; i < 10; ++i) {
                if (safeHexLookup(data[i]) == 0xFF)
                    return false;
            }
            return true;
        }

        [[nodiscard]] static std::string decodeFunctionSelector(const std::string_view data) {
            if (!hasFunctionSelector(data)) [[unlikely]]
                throw RLPDecodingException("Invalid function selector");
            return std::string(data.substr(0, 10));
        }

        [[nodiscard]] static std::vector<std::string> decodeParameters(const std::vector<std::string> &types,
                                                                       const std::string_view data) {
            if (types.empty())
                return {};
            const std::string_view cleanData = stripHexPrefix(data);
            if (cleanData.empty()) [[unlikely]]
                throw RLPDecodingException("Empty data for parameter decoding");
            std::vector<std::string> results;
            results.reserve(types.size());
            size_t offsetInBytes = 0;
            for (const auto &type: types) {
                if (offsetInBytes > SIZE_MAX - WORD_SIZE) [[unlikely]]
                    throw RLPDecodingException("Offset overflow");
                if (type == "string" || type == "bytes" || type.find("[]") != std::string::npos) {
                    const uint64_t dataOffset = decodeUint256FromOffset(data, offsetInBytes);
                    if (dataOffset * 2 >= cleanData.size()) [[unlikely]]
                        throw RLPDecodingException("Invalid data offset for dynamic type");
                    const uint64_t length = decodeUint256FromOffset(data, dataOffset);
                    if (type == "bytes") {
                        if (length > 0) {
                            if (length > cleanData.size() / 2 - dataOffset - WORD_SIZE) [[unlikely]]
                                throw RLPDecodingException("Bytes length exceeds data bounds");
                            auto bytes = extractBytes(data, dataOffset + WORD_SIZE, length);
                            results.push_back(bytesToHex(bytes));
                        } else {
                            results.push_back("0x");
                        }
                    } else if (type == "string") {
                        if (length > 0) {
                            if (length > cleanData.size() / 2 - dataOffset - WORD_SIZE) [[unlikely]]
                                throw RLPDecodingException("String length exceeds data bounds");
                            auto bytes = extractBytes(data, dataOffset + WORD_SIZE, length);
                            results.emplace_back(bytes.begin(), bytes.end());
                        } else {
                            results.emplace_back();
                        }
                    } else {
                        throw RLPDecodingException("Array decoding not implemented: " + type);
                    }
                } else if (type == "address") {
                    auto bytes = extractBytes(data, offsetInBytes, WORD_SIZE);
                    if (bytes.size() != WORD_SIZE) [[unlikely]]
                        throw RLPDecodingException("Invalid address encoding");
                    std::vector addressBytes(bytes.end() - 20, bytes.end());
                    results.push_back(bytesToHex(addressBytes));
                } else if (type == "bool") {
                    results.push_back(decodeUint256FromOffset(data, offsetInBytes) != 0 ? "true" : "false");
                } else if (type.size() > 5 && type.substr(0, 5) == "bytes" && type.find('[') == std::string::npos) {
                    std::string sizeStr = type.substr(5);
                    size_t byteSize = 0;
                    if (auto [ptr, ec] = std::from_chars(sizeStr.data(), sizeStr.data() + sizeStr.size(), byteSize);
                        ec != std::errc{} || byteSize == 0 || byteSize > 32) [[unlikely]]
                        throw RLPDecodingException("Invalid fixed bytes size");
                    auto bytes = extractBytes(data, offsetInBytes, byteSize);
                    results.push_back(bytesToHex(bytes));
                } else if (type == "uint" || type == "uint256" || (type.size() > 4 && type.substr(0, 4) == "uint")) {
                    results.push_back(std::to_string(decodeUint256FromOffset(data, offsetInBytes)));
                } else if (type == "int" || type == "int256" || (type.size() > 3 && type.substr(0, 3) == "int")) {
                    results.push_back(std::to_string(decodeInt256FromOffset(data, offsetInBytes)));
                } else {
                    throw RLPDecodingException("Unsupported parameter type: " + type);
                }
                offsetInBytes += WORD_SIZE;
            }
            return results;
        }

        [[nodiscard]] static std::string decodeAddress(const std::string_view encodedData) {
            const std::string_view data = stripHexPrefix(encodedData);
            if (data.size() != 64) [[unlikely]]
                throw RLPDecodingException("Invalid encoded address length");
            const std::string_view addrHex = data.substr(24, 40);
            for (const char c: addrHex) {
                if (safeHexLookup(c) == 0xFF) [[unlikely]]
                    throw RLPDecodingException("Invalid hex in address");
            }
            return "0x" + std::string(addrHex);
        }

        [[nodiscard]] static uint64_t decodeUint256(const std::string_view encodedData) {
            return decodeUint256FromOffset(encodedData, 0);
        }

        [[nodiscard]] static int64_t decodeInt256(const std::string_view encodedData) {
            return decodeInt256FromOffset(encodedData, 0);
        }

        [[nodiscard]] static bool decodeBool(const std::string_view encodedData) {
            return decodeUint256(encodedData) != 0;
        }

        [[nodiscard]] static std::string decodeFixedBytes(const std::string_view encodedData, const size_t byteSize) {
            if (byteSize == 0 || byteSize > 32) [[unlikely]]
                throw RLPDecodingException("Invalid fixed bytes size");
            const std::string_view data = stripHexPrefix(encodedData);
            if (data.size() != 64) [[unlikely]]
                throw RLPDecodingException("Invalid encoded fixed bytes length");
            return "0x" + std::string(data.substr(0, byteSize * 2));
        }

        [[nodiscard]] static std::string decodeBytes(const std::string_view encodedData) {
            const uint64_t length = decodeUint256FromOffset(encodedData, 0);
            if (length == 0)
                return "0x";
            if (const std::string_view dataView = stripHexPrefix(encodedData); length > dataView.size() / 2 - WORD_SIZE)
                    [[unlikely]]
                throw RLPDecodingException("Bytes length exceeds data bounds");
            auto bytes = extractBytes(encodedData, WORD_SIZE, length);
            return bytesToHex(bytes);
        }

        [[nodiscard]] static std::string decodeString(const std::string_view encodedData) {
            const uint64_t length = decodeUint256FromOffset(encodedData, 0);
            if (length == 0)
                return "";
            if (const std::string_view dataView = stripHexPrefix(encodedData); length > dataView.size() / 2 - WORD_SIZE)
                    [[unlikely]]
                throw RLPDecodingException("String length exceeds data bounds");
            auto bytes = extractBytes(encodedData, WORD_SIZE, length);
            return std::string(bytes.begin(), bytes.end());
        }

        [[nodiscard]] static std::vector<uint64_t> decodeUint256Array(const std::string_view encodedData) {
            const std::string_view data = stripHexPrefix(encodedData);
            if (data.length() < 128)
                return {};
            const uint64_t offset = decodeUint256FromOffset(encodedData, 0);
            if (offset > data.length() / 2)
                return {};
            const uint64_t arrayLength = decodeUint256FromOffset(encodedData, offset);
            if (arrayLength == 0 || arrayLength > 10000)
                return {};
            std::vector<uint64_t> result;
            result.reserve(arrayLength);
            for (uint64_t i = 0; i < arrayLength; ++i) {
                const size_t elementOffset = offset + WORD_SIZE + i * WORD_SIZE;
                if (elementOffset + WORD_SIZE > data.length() / 2)
                    break;
                result.push_back(decodeUint256FromOffset(encodedData, elementOffset));
            }
            return result;
        }

        [[nodiscard]] static std::vector<std::string> decodeFunctionReturn(
                const std::string_view signature, const std::vector<std::string> &returnTypes,
                const std::string_view returnData,
                const std::function<bool(std::string_view, const std::vector<std::string> &)> &validateSignature
                = nullptr) {
            if (validateSignature && !validateSignature(signature, returnTypes)) [[unlikely]]
                throw RLPDecodingException("Return types don't match function signature");
            if (returnData.empty() || returnData == "0x") {
                return std::vector<std::string>(returnTypes.size(), "");
            }
            return decodeParameters(returnTypes, returnData);
        }

        [[nodiscard]] static bool isErrorResponse(const std::string_view data) noexcept {
            return data.size() >= 10 && data.substr(0, 10) == "0x08c379a0";
        }

        [[nodiscard]] static std::string decodeRevertReason(const std::string_view errorData) {
            if (!isErrorResponse(errorData)) [[unlikely]]
                throw RLPDecodingException("Not an error response");
            const std::string_view data = stripHexPrefix(errorData);
            if (data.size() < 8) [[unlikely]]
                throw RLPDecodingException("Invalid error data");
            return decodeString("0x" + std::string(data.substr(8)));
        }
    };

    export class TransactionBuilder {
        static constexpr size_t KECCAK_HASH_SIZE = 32;
        static constexpr size_t PRIVATE_KEY_SIZE = 32;

        static void validatePrivateKey(const std::string_view privateKeyHex) {
            const std::string_view privateKey = stripHexPrefix(privateKeyHex);
            if (privateKey.length() != 64) [[unlikely]]
                throw RLPException("Private key must be exactly 64 hex characters");
            for (const char c: privateKey) {
                if (safeHexLookup(c) == 0xFF) [[unlikely]]
                    throw RLPException("Invalid hex character in private key");
            }
        }

    public:
        [[nodiscard]] static std::vector<uint8_t> buildDeploymentTransaction(const uint64_t nonce, const uint64_t gasPrice,
                                                                             const uint64_t gasLimit,
                                                                             const std::string_view bytecode,
                                                                             const uint64_t chainId) {
            const auto tx = EthereumTransaction::createDeployment(nonce, gasPrice, gasLimit, bytecode, chainId);
            return tx.buildForSigning();
        }

        [[nodiscard]] static std::vector<uint8_t>
        buildEIP1559DeploymentTransaction(const uint64_t nonce, const uint64_t maxPriorityFeePerGas,
                                          const uint64_t maxFeePerGas, const uint64_t gasLimit,
                                          const std::string_view bytecode, const uint64_t chainId,
                                          const std::string_view constructorParams = "") {
            const auto tx = TypedTransaction::createEIP1559Deployment(chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
                                                                      gasLimit, bytecode, constructorParams);
            return tx.buildForSigning();
        }

        [[nodiscard]] static std::vector<uint8_t> buildFunctionCallTransaction(
                const uint64_t nonce, const uint64_t gasPrice, const uint64_t gasLimit, const std::string_view to,
                const std::string_view functionSignature, const std::vector<std::string> &paramTypes,
                const std::vector<std::string> &paramValues, const uint64_t chainId, const uint64_t value,
                const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash) {
            if (!keccakHash) [[unlikely]]
                throw RLPException("Hash function not provided");
            const std::string data
                    = FunctionEncoder::encodeFunctionCall(functionSignature, paramTypes, paramValues, keccakHash);
            const auto tx = EthereumTransaction::createFunctionCall(nonce, gasPrice, gasLimit, std::string(to), data,
                                                                    chainId, value);
            return tx.buildForSigning();
        }

        [[nodiscard]] static std::vector<uint8_t> buildEIP1559FunctionCallTransaction(
                const uint64_t nonce, const uint64_t maxPriorityFeePerGas, const uint64_t maxFeePerGas,
                const uint64_t gasLimit, const std::string_view to, const std::string_view functionSignature,
                const std::vector<std::string> &paramTypes, const std::vector<std::string> &paramValues,
                const uint64_t chainId, const uint64_t value,
                const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash,
                const std::vector<AccessListEntry> &accessList = {}) {
            if (!keccakHash) [[unlikely]]
                throw RLPException("Hash function not provided");
            const std::string data
                    = FunctionEncoder::encodeFunctionCall(functionSignature, paramTypes, paramValues, keccakHash);
            const auto tx = TypedTransaction::createEIP1559Transaction(chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
                                                                       gasLimit, std::string(to), value, data, accessList);
            return tx.buildForSigning();
        }

        [[nodiscard]] static std::string
        signTransaction(const std::span<const uint8_t> unsignedTxRlp, const std::span<const uint8_t> privateKey,
                        const uint64_t chainId,
                        const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash,
                        const std::function<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, int>(
                                std::span<const uint8_t>, std::span<const uint8_t>)> &signFunction) {
            if (!keccakHash || !signFunction) [[unlikely]]
                throw RLPException("Hash and sign functions must be provided");
            const auto items = RLPDecoder::decodeList(unsignedTxRlp);
            if (items.size() < 9) [[unlikely]]
                throw RLPDecodingException("Invalid transaction RLP format");
            EthereumTransaction tx;
            tx.setNonce(items[0].empty() ? 0 : items[0].toInteger());
            tx.setGasPrice(items[1].empty() ? 0 : items[1].toInteger());
            tx.setGasLimit(items[2].empty() ? 0 : items[2].toInteger());
            tx.setTo(items[3].empty() ? "" : items[3].toHex());
            tx.setValue(items[4].empty() ? 0 : items[4].toInteger());
            tx.setData(items[5].empty() ? "" : items[5].toHex());
            tx.setChainId(chainId);
            tx.signTransaction(privateKey, keccakHash, signFunction);
            return tx.toHex();
        }

        [[nodiscard]] static std::string
        signEIP1559Transaction(const std::span<const uint8_t> unsignedTxData, const std::span<const uint8_t> privateKey,
                               const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash,
                               const std::function<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, int>(
                                       std::span<const uint8_t>, std::span<const uint8_t>)> &signFunction) {
            if (!keccakHash || !signFunction) [[unlikely]]
                throw RLPException("Hash and sign functions must be provided");
            auto tx = TypedTransaction::decodeTypedTransaction(unsignedTxData);
            tx.signTransaction(privateKey, keccakHash, signFunction);
            return tx.toHex();
        }

        [[nodiscard]] static std::string
        createSignedFunctionCall(const std::string_view privateKeyHex, const uint64_t chainId,
                                 const std::string_view nonce, const std::string_view gasPrice,
                                 const std::string_view gasLimit, const std::string_view to, const std::string_view value,
                                 const std::string_view data,
                                 const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash,
                                 const std::function<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, int>(
                                         std::span<const uint8_t>, std::span<const uint8_t>)> &signFunction) {
            if (!keccakHash || !signFunction) [[unlikely]]
                throw RLPException("Hash and sign functions must be provided");
            validatePrivateKey(privateKeyHex);
            std::vector<uint8_t> privateKeyBytes = hexToBytes(privateKeyHex);
            const uint64_t nonceInt = parseHexToUint64(nonce, "nonce");
            const uint64_t gasPriceInt = parseHexToUint64(gasPrice, "gasPrice");
            const uint64_t gasLimitInt = parseHexToUint64(gasLimit, "gasLimit");
            const uint64_t valueInt = parseHexToUint64(value, "value");
            EthereumTransaction tx
                    = EthereumTransaction::createFunctionCall(nonceInt, gasPriceInt, gasLimitInt, std::string(to),
                                                              std::string(data), chainId, valueInt);
            tx.signTransaction(privateKeyBytes, keccakHash, signFunction);
            return tx.toHex();
        }

        [[nodiscard]] static std::string
        createSignedEIP1559FunctionCall(const std::string_view privateKeyHex, const uint64_t chainId,
                                        const std::string_view nonce, const std::string_view maxPriorityFeePerGas,
                                        const std::string_view maxFeePerGas, const std::string_view gasLimit,
                                        const std::string_view to, const std::string_view value,
                                        const std::string_view data,
                                        const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash,
                                        const std::function<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, int>(
                                                std::span<const uint8_t>, std::span<const uint8_t>)> &signFunction,
                                        const std::vector<AccessListEntry> &accessList = {}) {
            if (!keccakHash || !signFunction) [[unlikely]]
                throw RLPException("Hash and sign functions must be provided");
            validatePrivateKey(privateKeyHex);
            std::vector<uint8_t> privateKeyBytes = hexToBytes(privateKeyHex);
            const uint64_t nonceInt = parseHexToUint64(nonce, "nonce");
            const uint64_t maxPriorityFeeInt = parseHexToUint64(maxPriorityFeePerGas, "maxPriorityFeePerGas");
            const uint64_t maxFeeInt = parseHexToUint64(maxFeePerGas, "maxFeePerGas");
            const uint64_t gasLimitInt = parseHexToUint64(gasLimit, "gasLimit");
            const uint64_t valueInt = parseHexToUint64(value, "value");
            TypedTransaction tx = TypedTransaction::createEIP1559Transaction(chainId, nonceInt, maxPriorityFeeInt,
                                                                             maxFeeInt, gasLimitInt, std::string(to),
                                                                             valueInt, std::string(data), accessList);
            tx.signTransaction(privateKeyBytes, keccakHash, signFunction);
            return tx.toHex();
        }

        [[nodiscard]] static std::string formatHexValue(uint64_t value) {
            if (value == 0)
                return "0x0";
            std::string temp;
            temp.reserve(18);
            while (value > 0) {
                temp = hexChars[value & 0xF] + temp;
                value >>= 4;
            }
            return "0x" + temp;
        }

        [[nodiscard]] static bool isValidHexString(const std::string_view hex) noexcept {
            if (hex.empty())
                return false;
            for (const std::string_view cleaned = stripHexPrefix(hex); const char c: cleaned) {
                if (safeHexLookup(c) == 0xFF)
                    return false;
            }
            return true;
        }

        [[nodiscard]] static uint64_t parseHexToUint64(const std::string_view hex, const std::string_view fieldName) {
            if (hex.empty() || hex == "0x" || hex == "0x0")
                return 0;
            const std::string_view cleaned = stripHexPrefix(hex);
            if (cleaned.empty())
                return 0;
            for (const char c: cleaned) {
                if (safeHexLookup(c) == 0xFF) [[unlikely]]
                    throw RLPException("Invalid hex in " + std::string(fieldName) + ": " + std::string(hex));
            }
            uint64_t result = 0;
            if (auto [ptr, ec] = std::from_chars(cleaned.data(), cleaned.data() + cleaned.size(), result, 16);
                ec != std::errc{}) [[unlikely]]
                throw RLPException("Failed to parse " + std::string(fieldName) + ": " + std::string(hex));
            return result;
        }

        [[nodiscard]] static bool isTypedTransaction(const std::span<const uint8_t> data) noexcept {
            return !data.empty() && (data[0] == 0x01 || data[0] == 0x02);
        }

        [[nodiscard]] static bool isTypedTransaction(const std::string_view hex) noexcept {
            if (hex.size() < 4)
                return false;
            if (!isValidHexString(hex))
                return false;
            try {
                auto data = hexToBytes(hex);
                return isTypedTransaction(data);
            } catch (...) {
                return false;
            }
        }
    };

    export class RLPValidator {
    public:
        [[nodiscard]] static bool isValidRLP(const std::span<const uint8_t> data) noexcept {
            try {
                [[maybe_unused]] auto result = RLPDecoder::decode(data);
                return true;
            } catch (...) {
                return false;
            }
        }

        [[nodiscard]] static bool isValidRLP(const std::string_view hex) noexcept {
            try {
                [[maybe_unused]] auto result = RLPDecoder::decode(hex);
                return true;
            } catch (...) {
                return false;
            }
        }

        [[nodiscard]] static bool isValidTypedTransaction(const std::span<const uint8_t> data) noexcept {
            try {
                [[maybe_unused]] auto result = TypedTransaction::decodeTypedTransaction(data);
                return true;
            } catch (...) {
                return false;
            }
        }

        [[nodiscard]] static bool isValidTypedTransaction(const std::string_view hex) noexcept {
            try {
                [[maybe_unused]] auto result = TypedTransaction::decodeTypedTransaction(hex);
                return true;
            } catch (...) {
                return false;
            }
        }

        [[nodiscard]] static std::optional<size_t> getRLPLength(const std::span<const uint8_t> data,
                                                                const size_t offset = 0) noexcept {
            try {
                auto [length, headerSize] = RLPDecoder::decodeLength(data, offset);
                if (length > SIZE_MAX - headerSize)
                    return std::nullopt;
                return length + headerSize;
            } catch (...) {
                return std::nullopt;
            }
        }

        [[nodiscard]] static std::optional<TypedTransaction::TransactionType>
        getTransactionType(const std::span<const uint8_t> data) noexcept {
            if (data.empty())
                return std::nullopt;
            const uint8_t firstByte = data[0];
            if (firstByte == 0x01)
                return TypedTransaction::EIP2930;
            if (firstByte == 0x02)
                return TypedTransaction::EIP1559;
            if (firstByte >= 0xc0)
                return TypedTransaction::LEGACY;
            return std::nullopt;
        }

        [[nodiscard]] static std::optional<TypedTransaction::TransactionType>
        getTransactionType(const std::string_view hex) noexcept {
            try {
                auto data = hexToBytes(hex);
                return getTransactionType(data);
            } catch (...) {
                return std::nullopt;
            }
        }

        [[nodiscard]] static bool isLegacyTransaction(const std::span<const uint8_t> data) noexcept {
            const auto type = getTransactionType(data);
            return type.has_value() && type.value() == TypedTransaction::LEGACY;
        }

        [[nodiscard]] static bool isEIP2930Transaction(const std::span<const uint8_t> data) noexcept {
            return !data.empty() && data[0] == 0x01;
        }

        [[nodiscard]] static bool isEIP1559Transaction(const std::span<const uint8_t> data) noexcept {
            return !data.empty() && data[0] == 0x02;
        }
    };

    export class TransactionDecoder {
    public:
        struct DecodedTransaction {
            bool isTyped;
            std::optional<TypedTransaction::TransactionType> type;
            uint64_t chainId;
            uint64_t nonce;
            std::optional<uint64_t> gasPrice;
            std::optional<uint64_t> maxPriorityFeePerGas;
            std::optional<uint64_t> maxFeePerGas;
            uint64_t gasLimit;
            std::string to;
            uint64_t value;
            std::string data;
            std::vector<AccessListEntry> accessList;
            bool isSigned;
            uint64_t v;
            std::string r;
            std::string s;
        };

        [[nodiscard]] static DecodedTransaction decode(const std::span<const uint8_t> rawTransaction) {
            DecodedTransaction result{};
            if (rawTransaction.empty()) [[unlikely]]
                throw RLPDecodingException("Empty transaction data");
            if (const uint8_t firstByte = rawTransaction[0]; firstByte == 0x01 || firstByte == 0x02) {
                result.isTyped = true;
                const auto typedTx = TypedTransaction::decodeTypedTransaction(rawTransaction);
                result.type = typedTx.getType();
                result.chainId = typedTx.getChainId();
                result.nonce = typedTx.getNonce();
                result.gasPrice = typedTx.getGasPrice();
                result.maxPriorityFeePerGas = typedTx.getMaxPriorityFeePerGas();
                result.maxFeePerGas = typedTx.getMaxFeePerGas();
                result.gasLimit = typedTx.getGasLimit();
                result.to = typedTx.getTo();
                result.value = typedTx.getValue();
                result.data = typedTx.getData();
                result.accessList = typedTx.getAccessList();
                result.isSigned = typedTx.getIsSigned();
                if (result.isSigned) {
                    result.v = 0;
                    result.r = "";
                    result.s = "";
                }
            } else if (firstByte >= 0xc0) {
                result.isTyped = false;
                result.type = TypedTransaction::LEGACY;
                const auto items = RLPDecoder::decodeList(rawTransaction);
                if (items.size() < 6) [[unlikely]]
                    throw RLPDecodingException("Invalid legacy transaction format");
                result.nonce = items[0].empty() ? 0 : items[0].toInteger();
                result.gasPrice = items[1].empty() ? 0 : items[1].toInteger();
                result.gasLimit = items[2].empty() ? 0 : items[2].toInteger();
                result.to = items[3].empty() ? "" : items[3].toHex();
                result.value = items[4].empty() ? 0 : items[4].toInteger();
                result.data = items[5].empty() ? "" : items[5].toHex();
                if (items.size() >= 9) {
                    result.isSigned = true;
                    result.v = items[6].empty() ? 0 : items[6].toInteger();
                    result.r = items[7].empty() ? "" : items[7].toHex();
                    result.s = items[8].empty() ? "" : items[8].toHex();
                    if (result.v == 27 || result.v == 28) {
                        result.chainId = 0;
                    } else if (result.v >= 35) {
                        result.chainId = (result.v - 35) / 2;
                    } else {
                        throw RLPDecodingException("Invalid signature v value");
                    }
                } else {
                    result.isSigned = false;
                    result.chainId = items.size() >= 7 ? (items[6].empty() ? 1 : items[6].toInteger()) : 1;
                }
            } else {
                throw RLPDecodingException("Invalid transaction format: unknown type byte");
            }
            return result;
        }

        [[nodiscard]] static DecodedTransaction decode(const std::string_view hexTransaction) {
            return decode(hexToBytes(hexTransaction));
        }

        [[nodiscard]] static std::string getTransactionSummary(const DecodedTransaction &decoded) {
            std::ostringstream ss;
            ss << "Transaction Type: ";
            if (decoded.type.has_value()) {
                switch (decoded.type.value()) {
                    case TypedTransaction::LEGACY:
                        ss << "Legacy (Type 0)";
                        break;
                    case TypedTransaction::EIP2930:
                        ss << "EIP-2930 (Type 1)";
                        break;
                    case TypedTransaction::EIP1559:
                        ss << "EIP-1559 (Type 2)";
                        break;
                    default:
                        ss << "Unknown";
                        break;
                }
            } else {
                ss << "Unknown";
            }
            ss << "\nChain ID: " << decoded.chainId << "\nNonce: " << decoded.nonce;
            if (decoded.gasPrice.has_value()) {
                ss << "\nGas Price: " << decoded.gasPrice.value();
            }
            if (decoded.maxPriorityFeePerGas.has_value()) {
                ss << "\nMax Priority Fee: " << decoded.maxPriorityFeePerGas.value();
            }
            if (decoded.maxFeePerGas.has_value()) {
                ss << "\nMax Fee: " << decoded.maxFeePerGas.value();
            }
            ss << "\nGas Limit: " << decoded.gasLimit
               << "\nTo: " << (decoded.to.empty() ? "Contract Creation" : decoded.to) << "\nValue: " << decoded.value
               << "\nData: "
               << (decoded.data.empty()         ? "None"
                   : decoded.data.length() > 66 ? decoded.data.substr(0, 66) + "..."
                                                : decoded.data);
            if (!decoded.accessList.empty()) {
                ss << "\nAccess List Entries: " << decoded.accessList.size();
            }
            ss << "\nSigned: " << (decoded.isSigned ? "Yes" : "No");
            if (decoded.isSigned && !decoded.r.empty() && !decoded.s.empty()) {
                ss << "\nSignature v: " << decoded.v;
            }
            return ss.str();
        }
    };

    export class RLPUtils {
    public:
        [[nodiscard]] static std::string encodeTransactionForBroadcast(const std::span<const uint8_t> signedTransaction) {
            return bytesToHex(signedTransaction);
        }

        [[nodiscard]] static bool validateTransactionSignature(
                const std::span<const uint8_t> signedTransaction,
                const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash,
                const std::function<bool(std::span<const uint8_t>, std::span<const uint8_t>, std::span<const uint8_t>,
                                         std::span<const uint8_t>, int)> &verifyFunction) {
            if (!keccakHash || !verifyFunction)
                return false;
            try {
                const auto decoded = TransactionDecoder::decode(signedTransaction);
                if (!decoded.isSigned)
                    return false;
                if (decoded.r.empty() || decoded.s.empty())
                    return false;
                std::vector<uint8_t> hashForSigning;
                if (decoded.isTyped) {
                    const auto tx = TypedTransaction::decodeTypedTransaction(signedTransaction);
                    auto unsignedTx = tx;
                    unsignedTx.setSignature(0, "", "");
                    hashForSigning = unsignedTx.buildForSigning();
                } else {
                    EthereumTransaction tx;
                    tx.setNonce(decoded.nonce);
                    tx.setGasPrice(decoded.gasPrice.value_or(0));
                    tx.setGasLimit(decoded.gasLimit);
                    tx.setTo(decoded.to);
                    tx.setValue(decoded.value);
                    tx.setData(decoded.data);
                    tx.setChainId(decoded.chainId);
                    hashForSigning = tx.buildForSigning();
                }
                auto hash = keccakHash(hashForSigning);
                if (hash.size() != 32)
                    return false;
                auto rBytes = hexToBytes(decoded.r);
                auto sBytes = hexToBytes(decoded.s);
                if (rBytes.size() != 32 || sBytes.size() != 32)
                    return false;
                int recoveryId;
                if (decoded.isTyped) {
                    recoveryId = static_cast<int>(decoded.v);
                } else if (decoded.v == 27 || decoded.v == 28) {
                    recoveryId = static_cast<int>(decoded.v - 27);
                } else if (decoded.v >= 35) {
                    recoveryId = static_cast<int>(decoded.v - 35 - decoded.chainId * 2);
                } else {
                    return false;
                }
                return verifyFunction(hash, rBytes, sBytes, hash, recoveryId);
            } catch (...) {
                return false;
            }
        }

        [[nodiscard]] static std::string
        calculateTransactionHash(const std::span<const uint8_t> signedTransaction,
                                 const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash) {
            if (!keccakHash) [[unlikely]]
                throw RLPException("Hash function not provided");
            auto hash = keccakHash(signedTransaction);
            if (hash.empty()) [[unlikely]]
                throw RLPException("Hash function returned empty result");
            return bytesToHex(hash);
        }

        [[nodiscard]] static size_t
        estimateSerializedSize(const TransactionDecoder::DecodedTransaction &decoded) noexcept {
            size_t size = decoded.isTyped ? 1 : 0;
            size += 9;
            size += decoded.to.empty() ? 1 : 21;
            size += 9;
            if (!decoded.data.empty()) {
                size_t dataLen = decoded.data.length();
                if (dataLen >= 2 && decoded.data[0] == '0' && decoded.data[1] == 'x') {
                    dataLen -= 2;
                }
                size += dataLen / 2 + 5;
            } else {
                size += 1;
            }
            if (!decoded.accessList.empty()) {
                size += 3;
                for (const auto &entry: decoded.accessList) {
                    size += 24;
                    size += entry.storageKeys.size() * 35;
                }
            }
            if (decoded.isSigned) {
                size += 3 + 33 + 33;
            }
            return size;
        }

        [[nodiscard]] static std::vector<std::string>
        batchEncodeTransactions(const std::span<const std::vector<uint8_t>> transactions) {
            std::vector<std::string> encoded;
            encoded.reserve(transactions.size());
            for (const auto &tx: transactions) {
                encoded.push_back(encodeTransactionForBroadcast(tx));
            }
            return encoded;
        }

        [[nodiscard]] static std::vector<TransactionDecoder::DecodedTransaction>
        batchDecodeTransactions(const std::span<const std::string> hexTransactions) {
            std::vector<TransactionDecoder::DecodedTransaction> decoded;
            decoded.reserve(hexTransactions.size());
            for (const auto &hex: hexTransactions) {
                decoded.push_back(TransactionDecoder::decode(hex));
            }
            return decoded;
        }

        [[nodiscard]] static bool isContractCreation(const TransactionDecoder::DecodedTransaction &decoded) noexcept {
            return decoded.to.empty();
        }

        [[nodiscard]] static uint64_t extractNonce(const std::span<const uint8_t> transaction) {
            try {
                const auto decoded = TransactionDecoder::decode(transaction);
                return decoded.nonce;
            } catch (...) {
                return 0;
            }
        }
    };

    export [[nodiscard]] inline std::string
    encodeLocalFunctionSelector(const std::string_view signature,
                                const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash) {
        if (!keccakHash) [[unlikely]]
            throw RLPEncodingException("Hash function not provided");
        const auto hash = keccakHash(std::span(reinterpret_cast<const uint8_t *>(signature.data()), signature.size()));
        if (hash.size() < 4) [[unlikely]]
            throw RLPEncodingException("Hash must be at least 4 bytes");
        std::string result;
        result.reserve(8);
        for (size_t i = 0; i < 4; ++i) {
            result += hexChars[static_cast<size_t>(hash[i] >> 4)];
            result += hexChars[static_cast<size_t>(hash[i] & 0xf)];
        }
        return result;
    }

    export [[nodiscard]] inline std::string encodeLocalParameters(const std::vector<std::string> &types,
                                                                  const std::vector<std::string> &values) {
        if (types.size() != values.size()) [[unlikely]]
            throw RLPEncodingException("Types and values count mismatch");
        std::string result;
        result.reserve(types.size() * 64);
        for (size_t i = 0; i < types.size(); ++i) {
            if (types[i] == "uint256" || types[i] == "uint") {
                uint64_t value = 0;
                if (auto [ptr, ec] = std::from_chars(values[i].data(), values[i].data() + values[i].size(), value);
                    ec != std::errc{}) [[unlikely]]
                    throw RLPEncodingException("Invalid uint256 value");
                std::string hex;
                hex.reserve(64);
                if (value == 0) {
                    hex = std::string(64, '0');
                } else {
                    std::string temp;
                    while (value > 0) {
                        temp = hexChars[value & 0xF] + temp;
                        value >>= 4;
                    }
                    hex = FunctionEncoder::padLeft(temp, 64);
                }
                result += hex;
            } else if (types[i] == "address") {
                std::string_view addr = stripHexPrefix(values[i]);
                if (addr.length() != 40) [[unlikely]]
                    throw RLPEncodingException("Address must be 40 hex characters");
                for (const char c: addr) {
                    if (safeHexLookup(c) == 0xFF) [[unlikely]]
                        throw RLPEncodingException("Invalid hex in address");
                }
                result += FunctionEncoder::padLeft(addr, 64);
            } else if (types[i] == "bool") {
                const bool boolValue = (values[i] == "true" || values[i] == "1");
                result += std::string(63, '0') + (boolValue ? '1' : '0');
            } else {
                throw RLPEncodingException("Unsupported parameter type: " + types[i]);
            }
        }
        return result;
    }

    export [[nodiscard]] inline std::string
    encodeLocalFunctionCall(const std::string_view signature, const std::vector<std::string> &types,
                            const std::vector<std::string> &values,
                            const std::function<std::vector<uint8_t>(std::span<const uint8_t>)> &keccakHash) {
        const std::string selector = encodeLocalFunctionSelector(signature, keccakHash);
        const std::string parameters = encodeLocalParameters(types, values);
        return "0x" + selector + parameters;
    }
} // namespace evm_codec
