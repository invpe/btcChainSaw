// This compiles with libbitcoin so that we can retrieve addresses of sender/receiver
// Per transaction
#include <bitcoin/system/wallet/payment_address.hpp>
#include <bitcoin/system/chain/transaction.hpp>
#include <sys/select.h>
#include <algorithm>
#include <math.h>
#include <iostream>
#include <iostream>    
#include <iomanip>     
#include <vector>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <openssl/sha.h>  
#include <openssl/ripemd.h>
#include <unordered_set>
#include <fstream>
#include <sstream>
 
uint64_t uiTxRequestTimer = static_cast<uint64_t>(time(0));; 
std::vector<std::vector<uint8_t>> vTXIDs;

const size_t HEADER_SIZE = 24;
const size_t MAX_PAYLOAD_SIZE = 32 * 1024 * 1024; // 32 MB 
struct MessageHeader {
    std::string command;
    uint32_t payloadSize;
    std::vector<uint8_t> payload;
};
// Function to convert the timestamp to a human-readable format
std::string getTimestamp() {
    std::time_t t = std::time(nullptr);
    std::tm* tm = std::localtime(&t);
    char buf[100];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
    return std::string(buf);
}  

std::string hashToString(const std::vector<uint8_t>& hash) {
    std::ostringstream oss;
    for (const auto& byte : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

uint64_t parseVarInt(const std::vector<uint8_t>& buffer, size_t& offset) {
    if (offset >= buffer.size()) {
        throw std::runtime_error("Buffer underflow in parseVarInt");
    }

    uint8_t prefix = buffer[offset];
    offset += 1; // Move past the prefix byte

    if (prefix < 0xfd) {
        // Single byte varint
        return prefix;
    } else if (prefix == 0xfd) {
        // 16-bit varint
        if (offset + 2 > buffer.size()) {
            throw std::runtime_error("Buffer underflow for 16-bit varint");
        }
        uint16_t value = *reinterpret_cast<const uint16_t*>(&buffer[offset]);
        offset += 2;
        return value;
    } else if (prefix == 0xfe) {
        // 32-bit varint
        if (offset + 4 > buffer.size()) {
            throw std::runtime_error("Buffer underflow for 32-bit varint");
        }
        uint32_t value = *reinterpret_cast<const uint32_t*>(&buffer[offset]);
        offset += 4;
        return value;
    } else if (prefix == 0xff) {
        // 64-bit varint
        if (offset + 8 > buffer.size()) {
            throw std::runtime_error("Buffer underflow for 64-bit varint");
        }
        uint64_t value = *reinterpret_cast<const uint64_t*>(&buffer[offset]);
        offset += 8;
        return value;
    }

    throw std::runtime_error("Invalid varint prefix");
}

std::vector<std::string> resolveDNSSeed(const std::string& seed) {
    std::vector<std::string> ipList;
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(seed.c_str(), nullptr, &hints, &res);
    if (status != 0) return ipList;

    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        char ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &((struct sockaddr_in*)p->ai_addr)->sin_addr, ip, sizeof(ip))) {
            ipList.emplace_back(ip);
        }
    }
    freeaddrinfo(res);
    return ipList;
}

void sha256(const uint8_t* data, size_t len, uint8_t* out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out, &ctx);
}

std::vector<uint8_t> calculateChecksum(const uint8_t* data, size_t len) 
{
    uint8_t hash1[SHA256_DIGEST_LENGTH];
    uint8_t hash2[SHA256_DIGEST_LENGTH];

    // First pass of SHA256
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data, len);
    SHA256_Final(hash1, &sha256_ctx);

    // Second pass of SHA256
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, hash1, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash2, &sha256_ctx);

    // Return the first 4 bytes of the second hash as the checksum
    return std::vector<uint8_t>(hash2, hash2 + 4);
}

std::vector<uint8_t> createMempoolMessage() {
    const uint8_t magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
    const char command[] = "mempool";
    const uint8_t hardcodedChecksum[] = {0xe2, 0xe0, 0xf6, 0x99}; // Precomputed checksum for empty payload
    const uint32_t payloadLength = 0; // No payload

    std::vector<uint8_t> message;
    message.insert(message.end(), magic, magic + sizeof(magic)); // Magic bytes
    message.insert(message.end(), command, command + strlen(command)); // Command
    message.insert(message.end(), 12 - strlen(command), 0); // Pad command to 12 bytes
    message.insert(message.end(), reinterpret_cast<const uint8_t*>(&payloadLength), reinterpret_cast<const uint8_t*>(&payloadLength) + sizeof(payloadLength)); // Payload length
    message.insert(message.end(), hardcodedChecksum, hardcodedChecksum + sizeof(hardcodedChecksum)); // Checksum (hardcoded)

    return message;
}

// Reverse the byte order (little-endian format)
std::vector<uint8_t> reverseBytes(uint32_t value) {
    std::vector<uint8_t> reversed(4);
    reversed[0] = (value >> 0) & 0xFF;
    reversed[1] = (value >> 8) & 0xFF;
    reversed[2] = (value >> 16) & 0xFF;
    reversed[3] = (value >> 24) & 0xFF;
    return reversed;
}
// https://en.bitcoin.it/wiki/Protocol_documentation#getdata
std::vector<uint8_t> createGetDataMessage(const std::vector<uint8_t>& hash) {
    const uint8_t magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
    const char command[] = "getdata";  // 8 bytes long
    std::vector<uint8_t> commandHex(command, command + strlen(command));
    commandHex.resize(12, 0);  // Resize to 12 bytes, filling with zeroes if necessary

    std::vector<uint8_t> payload;


   // PAYLOAD    
    // Add the count (var_int) for a single transaction
    uint8_t count = 1;  // We only request one transaction
    payload.push_back(count);

    // Add the inventory vector
    uint32_t type = 1;  // Transaction type (MSG_TX)
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&type), reinterpret_cast<uint8_t*>(&type) + sizeof(type));

    // Add the transaction hash (32 bytes)
    payload.insert(payload.end(), hash.begin(), hash.end());

    // Calculate checksum
    std::vector<uint8_t> checksum = calculateChecksum(payload.data(), payload.size());

    // Construct the full message
    std::vector<uint8_t> message;
    message.insert(message.end(), magic, magic + sizeof(magic)); 
    message.insert(message.end(), commandHex.begin(), commandHex.end());  // Insert the padded commandHex


    // Convert payload length to uint32_t, reverse bytes, and add it to the message
    uint32_t payloadLength = static_cast<uint32_t>(payload.size());
    std::vector<uint8_t> reversedPayloadLength = reverseBytes(payloadLength);
    message.insert(message.end(), reversedPayloadLength.begin(), reversedPayloadLength.end());
    message.insert(message.end(), checksum.begin(), checksum.end());
    message.insert(message.end(), payload.begin(), payload.end());

    return message;
}

  
std::vector<uint8_t> createPingMessage(uint64_t nonce) {
    const uint8_t magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
    const char command[] = "ping";
    std::vector<uint8_t> payload(reinterpret_cast<uint8_t*>(&nonce), reinterpret_cast<uint8_t*>(&nonce) + sizeof(nonce));
    std::vector<uint8_t> checksum = calculateChecksum(payload.data(), payload.size());
    std::vector<uint8_t> message;

    message.insert(message.end(), magic, magic + sizeof(magic));
    message.insert(message.end(), command, command + strlen(command));
    message.insert(message.end(), 12 - strlen(command), 0);
    uint32_t payloadLength = payload.size();
    message.insert(message.end(), reinterpret_cast<uint8_t*>(&payloadLength), reinterpret_cast<uint8_t*>(&payloadLength) + sizeof(payloadLength));
    message.insert(message.end(), checksum.begin(), checksum.end());
    message.insert(message.end(), payload.begin(), payload.end());

    return message;
}
std::vector<uint8_t> createVerackMessage() {
    const uint8_t magic[] = {0xf9, 0xbe, 0xb4, 0xd9}; // Mainnet magic bytes
    const char command[] = "verack";                  // Command name
    uint32_t payloadLength = 0;                       // No payload
    const uint8_t checksum[] = {0x5d, 0xf6, 0xe0, 0xe2}; // Precomputed checksum for empty payload

    std::vector<uint8_t> message;
    message.insert(message.end(), magic, magic + sizeof(magic));
    message.insert(message.end(), command, command + strlen(command));
    message.insert(message.end(), 12 - strlen(command), 0); // Pad command to 12 bytes
    message.insert(message.end(), reinterpret_cast<const uint8_t*>(&payloadLength), 
                   reinterpret_cast<const uint8_t*>(&payloadLength) + sizeof(payloadLength));
    message.insert(message.end(), checksum, checksum + sizeof(checksum));
    return message;
}

std::vector<uint8_t> createVersionMessage() {
    std::vector<uint8_t> payload;
    int32_t version = 70016;
    uint64_t services = 0x09; // NODE_NETWORK + NODE_WITNESS

    int64_t timestamp = time(nullptr);
    uint64_t addrServices = 0x01; // Advertise NODE_NETWORK for the recipient

    uint8_t addrIP[16] = {0};
    uint16_t addrPort = htons(8333); // Default Bitcoin port in network byte order

    uint64_t nonce = rand(); // Use a random value

    std::string userAgent = "/ChainQuants:0.0.1/";
    int32_t startHeight = 876357; // Use a recent block height


    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&version), reinterpret_cast<uint8_t*>(&version) + sizeof(version));
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&services), reinterpret_cast<uint8_t*>(&services) + sizeof(services));
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&addrServices), reinterpret_cast<uint8_t*>(&addrServices) + sizeof(addrServices));
    payload.insert(payload.end(), addrIP, addrIP + sizeof(addrIP));
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&addrPort), reinterpret_cast<uint8_t*>(&addrPort) + sizeof(addrPort));
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&addrServices), reinterpret_cast<uint8_t*>(&addrServices) + sizeof(addrServices));
    payload.insert(payload.end(), addrIP, addrIP + sizeof(addrIP));
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&addrPort), reinterpret_cast<uint8_t*>(&addrPort) + sizeof(addrPort));
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&nonce), reinterpret_cast<uint8_t*>(&nonce) + sizeof(nonce));
    payload.push_back(userAgent.size());
    payload.insert(payload.end(), userAgent.begin(), userAgent.end());
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&startHeight), reinterpret_cast<uint8_t*>(&startHeight) + sizeof(startHeight));

    const uint8_t magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
    const char command[] = "version";
    std::vector<uint8_t> checksum = calculateChecksum(payload.data(), payload.size());
    std::vector<uint8_t> message;

    message.insert(message.end(), magic, magic + sizeof(magic));
    message.insert(message.end(), command, command + strlen(command));
    message.insert(message.end(), 12 - strlen(command), 0);
    uint32_t payloadLength = payload.size();
    message.insert(message.end(), reinterpret_cast<uint8_t*>(&payloadLength), reinterpret_cast<uint8_t*>(&payloadLength) + sizeof(payloadLength));
    message.insert(message.end(), checksum.begin(), checksum.end());
    message.insert(message.end(), payload.begin(), payload.end());

    return message;
}

std::vector<uint8_t> createPongMessage(uint64_t nonce) {
    const uint8_t magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
    const char command[] = "pong";
    std::vector<uint8_t> payload(reinterpret_cast<uint8_t*>(&nonce), reinterpret_cast<uint8_t*>(&nonce) + sizeof(nonce));
    std::vector<uint8_t> checksum = calculateChecksum(payload.data(), payload.size());
    std::vector<uint8_t> message;

    message.insert(message.end(), magic, magic + sizeof(magic));
    message.insert(message.end(), command, command + strlen(command));
    message.insert(message.end(), 12 - strlen(command), 0);
    uint32_t payloadLength = payload.size();
    message.insert(message.end(), reinterpret_cast<uint8_t*>(&payloadLength), reinterpret_cast<uint8_t*>(&payloadLength) + sizeof(payloadLength));
    message.insert(message.end(), checksum.begin(), checksum.end());
    message.insert(message.end(), payload.begin(), payload.end());

    return message;
}

MessageHeader parseMessageHeader(const std::vector<uint8_t>& buffer, size_t offset) {
    const uint8_t magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
    if (memcmp(&buffer[offset], magic, sizeof(magic)) != 0) {
        throw std::runtime_error("Invalid magic bytes");
    }

    MessageHeader header;
    char command[13] = {0};
    memcpy(command, &buffer[offset + 4], 12);
    header.command = std::string(command).substr(0, std::string(command).find('\0'));
    header.payloadSize = *reinterpret_cast<const uint32_t*>(&buffer[offset + 16]);

    if (header.payloadSize > MAX_PAYLOAD_SIZE) {
        throw std::runtime_error("Payload size exceeds protocol limits");
    }

    return header;
}


// Base58 encoding table
const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string toBase58(const std::vector<uint8_t>& data) {
    uint64_t value = 0;
    for (uint8_t byte : data) {
        value = (value << 8) + byte;
    }

    std::string result;
    while (value > 0) {
        result = BASE58_ALPHABET[value % 58] + result;
        value /= 58;
    }

    // Add leading '1' for each leading 0 byte
    for (uint8_t byte : data) {
        if (byte == 0) {
            result = "1" + result;
        } else {
            break;
        }
    }

    return result;
}

 
// Function to identify the script type
std::string identifyScriptType(const std::vector<uint8_t>& script) {
        if (script.empty()) return "No scriptSig available";  // Handle empty script

    if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac) {
        return "P2PKH (Pay-to-Public-Key-Hash)";
    }
    if (script.size() == 22 && script[0] == 0x00 && script[1] == 0x14) {
        return "P2WPKH (Pay-to-Witness-PubKey-Hash)";
    }
    if (script.size() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87) {
        return "P2SH (Pay-to-Script-Hash)";
    }
    if (script.size() == 34 && script[0] == 0x00 && script[1] == 0x20) {
        return "P2WSH (Pay-to-Witness-Script-Hash)";
    }
    if (script[0] >= 0x51 && script[0] <= 0x53 && script.back() == 0xae) {
        return "Bare Multisig";
    }
    return "Unknown/Non-standard type";
}
  

void parseVersionPayload(const std::vector<uint8_t>& payload) {
    if (payload.size() < 80) {
        std::cerr << "Invalid version payload size" << std::endl;
        return;
    }

    size_t offset = 0;
    int32_t version = *reinterpret_cast<const int32_t*>(&payload[offset]);
    offset += 4;
    uint64_t services = *reinterpret_cast<const uint64_t*>(&payload[offset]);
    offset += 8;
    int64_t timestamp = *reinterpret_cast<const int64_t*>(&payload[offset]);
    offset += 8;
    offset += 26; // Skip recipient address
    offset += 26; // Skip sender address
    uint64_t nonce = *reinterpret_cast<const uint64_t*>(&payload[offset]);
    offset += 8;
    uint8_t userAgentLen = payload[offset];
    offset += 1;
    std::string userAgent(payload.begin() + offset, payload.begin() + offset + userAgentLen);
    offset += userAgentLen;
    int32_t startHeight = *reinterpret_cast<const int32_t*>(&payload[offset]);

    std::cout << "Version Message Details:" << std::endl;
    std::cout << "  Protocol Version: " << version << std::endl;
    std::cout << "  Services: " << services << std::endl;
    std::cout << "  Timestamp: " << timestamp << std::endl;
    std::cout << "  Nonce: " << nonce << std::endl;
    std::cout << "  User Agent: " << userAgent << std::endl;
    std::cout << "  Start Height: " << startHeight << std::endl;
}
void parseInvPayload(const std::vector<uint8_t>& payload, int sock) {
    size_t offset = 0;

    // Parse the count of inventory items
    uint64_t count = parseVarInt(payload, offset);
    std::cout << "Inventory Count: " << count << std::endl;

    if (count == 0 || count > 50000) {
        std::cerr << "Invalid or excessive inventory count: " << count << std::endl;
        return;
    }


    for (uint64_t i = 0; i < count; ++i) 
    {
        if (offset + 36 > payload.size()) {
            std::cerr << "Truncated inv payload at entry " << i << std::endl;
            return;
        }

        // Parse the type (4 bytes, little-endian)
        uint32_t type = *reinterpret_cast<const uint32_t*>(&payload[offset]);
        offset += 4;

        // Parse the hash (32 bytes)
        std::vector<uint8_t> hash(payload.begin() + offset, payload.begin() + offset + 32);
        offset += 32;

        // Log the parsed inventory item
        std::cout << "Parsed inventory item: type = " << type << ", hash = ";
        for (const auto& byte : hash) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << std::endl;

        // Reverse the hash for display or external searches
        /*
        std::vector<uint8_t> reversedHash = hash;
        std::reverse(reversedHash.begin(), reversedHash.end());
        std::cout << "Reversed hash for explorer: ";
        for (const auto& byte : reversedHash) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << std::endl;
        */

        // Process only transactions (type = 1)
        if (type == 1) 
        { 
            vTXIDs.push_back( hash );

        } else {
            std::cout << "Skipping non-transaction inventory item of type " << type << std::endl;
        }
    } 
}


void parseAddrPayload(const std::vector<uint8_t>& payload) {
    size_t offset = 0;

    // Parse the count of address entries
    uint64_t count = 0;
    if (payload[offset] < 0xfd) { // Single byte varint
        count = payload[offset];
        offset += 1;
    } else if (payload[offset] == 0xfd) { // 16-bit varint
        count = *reinterpret_cast<const uint16_t*>(&payload[offset + 1]);
        offset += 3;
    } else if (payload[offset] == 0xfe) { // 32-bit varint
        count = *reinterpret_cast<const uint32_t*>(&payload[offset + 1]);
        offset += 5;
    } else { // 64-bit varint
        count = *reinterpret_cast<const uint64_t*>(&payload[offset + 1]);
        offset += 9;
    }

    std::cout << "Addr Message Details:" << std::endl;
    std::cout << "  Count: " << count << std::endl;

    // Parse each address entry
    for (uint64_t i = 0; i < count; ++i) {
        if (offset + 30 > payload.size()) {
            std::cerr << "Truncated addr payload" << std::endl;
            break;
        }

        uint32_t timestamp = *reinterpret_cast<const uint32_t*>(&payload[offset]);
        offset += 4;
        uint64_t services = *reinterpret_cast<const uint64_t*>(&payload[offset]);
        offset += 8;

        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &payload[offset], ip, sizeof(ip));
        offset += 16;

        uint16_t port = ntohs(*reinterpret_cast<const uint16_t*>(&payload[offset]));
        offset += 2;

        std::cout << "  Address " << i + 1 << ":" << std::endl;
        std::cout << "    Timestamp: " << timestamp << std::endl;
        std::cout << "    Services: " << services << std::endl;
        std::cout << "    IP Address: " << ip << std::endl;
        std::cout << "    Port: " << port << std::endl;
    }
}

void handlePingMessage(const std::vector<uint8_t>& payload, int sock) {
    if (payload.size() != 8) {
        std::cerr << "Invalid ping payload size" << std::endl;
        return;
    }

    uint64_t nonce = *reinterpret_cast<const uint64_t*>(payload.data());
    auto pongMessage = createPongMessage(nonce);
    send(sock, pongMessage.data(), pongMessage.size(), 0);
    std::cout << "Responded to ping with pong" << std::endl;
}
void handlePongMessage(const std::vector<uint8_t>& payload) {
    if (payload.size() != 8) {
        std::cerr << "Invalid pong payload size" << std::endl;
        return;
    }

    uint64_t nonce = *reinterpret_cast<const uint64_t*>(payload.data());
    std::cout << "Received pong with nonce: " << nonce << std::endl;
} 
void handleMessage(const MessageHeader& header, int sock) {
    printf("[MSG] %s\n", header.command.data());

    if (header.command == "version") {
        parseVersionPayload(header.payload);

         // Send verack message to the peer
        auto verackMessage = createVerackMessage();
        if (send(sock, verackMessage.data(), verackMessage.size(), 0) > 0) {
            std::cout << "Sent verack message to peer" << std::endl;
        } else {
            perror("Failed to send verack message");
        } 
    } else if (header.command == "verack") {
        std::cout << "Handshake completed with verack!" << std::endl; 
    } else if (header.command == "ping") {
        handlePingMessage(header.payload, sock);
    } else if (header.command == "pong") {
        handlePongMessage(header.payload);
    } else if (header.command == "inv") {
        parseInvPayload(header.payload, sock);
    } else if (header.command == "addr") {
        parseAddrPayload(header.payload);
    } else if (header.command == "tx") {

            
            if (!vTXIDs.empty()) 
            {
                // Append to file
                std::ofstream file("transactions.csv", std::ios::app);

                // Take the first transaction hash and decode
                std::vector<uint8_t> txid = vTXIDs.front();

                // Decode the raw transaction payload into a Bitcoin transaction object
                bc::chain::transaction tx;
                if (!tx.from_data(header.payload)) {  // Correct method to decode
                    std::cerr << "Error decoding transaction" << std::endl;
                    return;
                }

                // Compute the transaction hash

                bc::hash_digest tx_hash = tx.hash();
                std::cout << "Transaction Hash: " << bc::encode_base16(tx_hash) << std::endl;

                // Get current timestamp
                std::string strTimestamp = std::to_string(time(0));
                
                // Iterate over inputs (to extract sending wallets)
                for (size_t i = 0; i < tx.inputs().size(); ++i) 
                {
                    const auto& input = tx.inputs()[i];

                    // The input contains a previous output's transaction ID and index
                    const bc::chain::output_point& prev_output = input.previous_output();

                    // Extract the ScriptSig and attempt to decode the sender's address
                    bc::chain::script script_sig = input.script();
                    bc::wallet::payment_address sender_address(script_sig);
                    
                    // Default sender wallet is "Unknown"
                    std::string strSenderWallet = "Unknown";
                    if (sender_address) {
                        strSenderWallet = sender_address.encoded();
                    }

                    // Iterate over outputs (to extract receiving wallets and amounts)
                    for (size_t j = 0; j < tx.outputs().size(); ++j) 
                    {
                        const auto& output = tx.outputs()[j];

                        std::string strOutputWallet = "Unknown";

                        // Output contains the script (destination address) and the amount in satoshis
                        bc::chain::script output_script = output.script();
                        uint64_t amount = output.value();  // Amount in satoshis

                        // Decode the output script to obtain the address
                        bc::wallet::payment_address payment_address(output_script);
                        
                        if (payment_address) {
                            strOutputWallet = payment_address.encoded();
                        }

                        // Convert the amount from satoshis to BTC (human-readable format)
                        double btc_amount = static_cast<double>(amount) / 100000000.0;

                        // Get the transaction hash and payload
                        std::string strTransactionHash = hashToString(txid);
                        std::string strTransactionPayload = hashToString(header.payload);

                        // Prepare the CSV row for this input-output pair
                        std::string strOutput = strTimestamp +
                                               "," + strSenderWallet +
                                               "," + strOutputWallet +
                                               "," + std::to_string(btc_amount) +
                                               "," + strTransactionHash +
                                               //"," + strTransactionPayload +
                                               "," + std::to_string(i) +  // Input index
                                               "," + std::to_string(j) +  // Output index
                                               "\n";

                        // Write the row to the CSV
                        file << strOutput;
                    }
                }

                // Remove the processed txid from the list
                vTXIDs.erase(vTXIDs.begin());
            }



    }
    // Simply the node has 'forgot' the tx already - might happen if
    // we ask for a txid that was long time before
    else if (header.command == "notfound") {
        std::cout << "Peer responded with notfound for requested data." << std::endl;

        // Remove it
        vTXIDs.erase(vTXIDs.begin()); 
    }
    else if (header.command == "wtxidrelay" || header.command == "sendaddrv2" || header.command == "sendcmpct" || header.command == "feefilter") {
    std::cout << "Acknowledged message: " << header.command << std::endl;
    }
    else {
        std::cout << "Unhandled message: " << header.command << std::endl;
    }
}

int main() {
    std::vector<std::string> dnsSeeds = {
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "seed.bitcoinstats.com",
        "seed.bitnodes.io"
    };

    std::vector<std::string> nodes;
    for (const auto& seed : dnsSeeds) {
        auto resolved = resolveDNSSeed(seed);
        nodes.insert(nodes.end(), resolved.begin(), resolved.end());
    }

    if (nodes.empty()) {
        std::cerr << "No nodes resolved. Exiting." << std::endl;
        return 1;
    }

    srand(time(nullptr));
    std::string selectedNode = nodes[rand() % nodes.size()];
    std::cout << "Connecting to node: " << selectedNode << std::endl;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8333);
    inet_pton(AF_INET, selectedNode.c_str(), &serverAddr.sin_addr);

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }

    std::cout << "Connected to " << selectedNode << std::endl;
    
    auto versionMessage = createVersionMessage();
    send(sock, versionMessage.data(), versionMessage.size(), 0);
 
    std::vector<uint8_t> buffer;
    buffer.reserve(8192);

    uint64_t lastPingTime = time(nullptr); // Ensure initialized before the loop
    
    // Adjust the main loop
    while (true) 
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 1; // 1-second timeout
        timeout.tv_usec = 0;

        int activity = select(sock + 1, &readfds, nullptr, nullptr, &timeout);

        if (activity < 0) {
            perror("Select failed");
            break;
        }

        if (activity == 0) {
            // Timeout occurred, no data available, check for ping
            uint64_t currentTime = time(nullptr);
            if (currentTime - lastPingTime >= 30) { // Send ping every 10 seconds
                 
                uint64_t nonce = rand();
                auto pingMessage = createPingMessage(nonce);
                if (send(sock, pingMessage.data(), pingMessage.size(), 0) > 0) {
                    std::cout << "Sent ping with nonce: " << nonce << std::endl;
                    lastPingTime = currentTime; // Update lastPingTime only on successful send
                } else {
                    perror("Ping send failed");
                    break; // Exit if the connection is broken
                } 
            }

            // Periodically request tx from vTXIDs if available
            if(time(0) - uiTxRequestTimer >= 1)
            {
                printf("[TX] There are %i hashes to process\n", vTXIDs.size());

                if(!vTXIDs.empty())
                {

                    printf("[TX] Requesting for tx data %s\n",hashToString(vTXIDs.front()).data());
                    std::vector<uint8_t> getDataMessage = createGetDataMessage(vTXIDs.front());
                    send(sock, getDataMessage.data(), getDataMessage.size(), 0);

                } 

                uiTxRequestTimer = static_cast<uint64_t>(time(0));
            }
        
            continue; // Go back to waiting for activity
        }

        if (FD_ISSET(sock, &readfds)) 
        {
            uint8_t tempBuffer[1024];
            ssize_t bytesRead = recv(sock, tempBuffer, sizeof(tempBuffer), 0);
            if (bytesRead <= 0) {
                perror("Receive failed or connection closed");
                std::cerr << "Total bytes received so far: " << buffer.size() << std::endl;
                break;
            }

            buffer.insert(buffer.end(), tempBuffer, tempBuffer + bytesRead);

            // Process messages in the buffer
            while (buffer.size() >= HEADER_SIZE) {
                try {
                    auto header = parseMessageHeader(buffer, 0);
                    if (buffer.size() >= HEADER_SIZE + header.payloadSize) {
                        header.payload = std::vector<uint8_t>(buffer.begin() + HEADER_SIZE, buffer.begin() + HEADER_SIZE + header.payloadSize);
                        handleMessage(header, sock);
                        buffer.erase(buffer.begin(), buffer.begin() + HEADER_SIZE + header.payloadSize);
                    } else {
                        break; // Wait for more data
                    }
                } catch (const std::runtime_error& e) {
                    std::cerr << "Error: " << e.what() << std::endl;
                    buffer.erase(buffer.begin()); // Remove invalid byte
                }
            }
        }

        
    }

    // We get disconnected - either due to the node we connect to unable to reach us 
    // or we're sending something wrong, even though we get verack!

    close(sock);
    return 0;
}
