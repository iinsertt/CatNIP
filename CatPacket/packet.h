

#ifndef PACKET_H
#define PACKET_H

#include "session.h"
#include "stream.h"
#include <cstdint>
#include <cstddef>
#include <map>
#include <mutex>
#include <vector>

namespace catnip {

    using PacketID = uint16_t;
    using PacketHandler = bool(*)(const uint8_t* data, size_t size);

    class PacketRegistry {
    public:
        static void register_packet(PacketID id, PacketHandler handler);
        static bool handle(PacketID id, const uint8_t* data, size_t size);

    private:
        static std::map<PacketID, PacketHandler>& get_map();
        static std::mutex& get_mutex();
    };

    inline void dump_bytes(const std::string& label, const uint8_t* data, size_t len) {
        std::cout << label << ": ";
        for (size_t i = 0; i < len; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        std::cout << std::dec << std::endl;
    }

    class PacketContext {
    public:
        explicit PacketContext(CatSession& session);

        bool encrypt_and_package(PacketID id, const uint8_t* payload, size_t payload_size,
                                 std::vector<uint8_t>& out_packet);

        bool decrypt_and_dispatch(const uint8_t* packet, size_t packet_size);

    private:
        CatSession& session;
        StreamCipher stream;
        bool initialized = false;
        std::mutex mutex;
    };

}

#endif // PACKET_H
