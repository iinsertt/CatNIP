
#include "packet.h"
#include <cstring>

namespace catnip {

    std::map<PacketID, PacketHandler>& PacketRegistry::get_map() {
        static std::map<PacketID, PacketHandler> map;
        return map;
    }

    std::mutex& PacketRegistry::get_mutex() {
        static std::mutex mtx;
        return mtx;
    }

    void PacketRegistry::register_packet(PacketID id, PacketHandler handler) {
        std::lock_guard<std::mutex> lock(get_mutex());
        get_map()[id] = handler;
    }

    bool PacketRegistry::handle(PacketID id, const uint8_t* data, size_t size) {
        std::lock_guard<std::mutex> lock(get_mutex());
        auto it = get_map().find(id);
        if (it == get_map().end()) return false;
        return it->second(data, size);
    }

    PacketContext::PacketContext(CatSession& session) : session(session) {}

    bool PacketContext::encrypt_and_package(PacketID id, const uint8_t* payload, size_t payload_size,
                                            std::vector<uint8_t>& out_packet) {
        std::lock_guard<std::mutex> lock(mutex);

        if (!initialized) {
            uint8_t salt[NONCE_SIZE];
            random_bytes(salt, NONCE_SIZE);
            stream.initialize(session.get_shared_secret(), salt, NONCE_SIZE);
            out_packet.insert(out_packet.end(), salt, salt + NONCE_SIZE);
            initialized = true;
        }

        uint8_t tag[HMAC_SIZE];
        std::vector<uint8_t> buffer(sizeof(PacketID) + payload_size);
        memcpy(buffer.data(), &id, sizeof(PacketID));
        memcpy(buffer.data() + sizeof(PacketID), payload, payload_size);

        stream.encrypt(buffer.data(), buffer.size(), tag);

        out_packet.insert(out_packet.end(), buffer.begin(), buffer.end());
        out_packet.insert(out_packet.end(), tag, tag + HMAC_SIZE);
        return true;
    }

    bool PacketContext::decrypt_and_dispatch(const uint8_t* packet, size_t packet_size) {
        std::lock_guard<std::mutex> lock(mutex);

        if (!initialized) {
            if (packet_size < NONCE_SIZE) return false;
            const uint8_t* salt = packet;
            stream.initialize(session.get_shared_secret(), salt, NONCE_SIZE);
            packet += NONCE_SIZE;
            packet_size -= NONCE_SIZE;
            initialized = true;
        }

        if (packet_size < sizeof(PacketID) + HMAC_SIZE) return false;
        size_t encrypted_len = packet_size - HMAC_SIZE;
        const uint8_t* tag = packet + encrypted_len;

        std::vector<uint8_t> decrypted(encrypted_len);
        memcpy(decrypted.data(), packet, encrypted_len);

        if (!stream.decrypt(decrypted.data(), encrypted_len, tag)) return false;

        PacketID id;
        memcpy(&id, decrypted.data(), sizeof(PacketID));
        return PacketRegistry::handle(id, decrypted.data() + sizeof(PacketID), encrypted_len - sizeof(PacketID));
    }

}
