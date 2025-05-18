#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include "CatSession/session.h"
#include "CatPacket/packet.h"

using boost::asio::ip::tcp;

#define CATNIP_SERVER_IP "127.0.0.1"
#define CATNIP_SERVER_PORT 12345
#define CATNIP_PACKET_ID_MESSAGE 1
#define CATNIP_STATUS_OK 200
#define CATNIP_STATUS_FAIL 500
#define CATNIP_STATUS_FORBIDDEN 403


bool handle_message_packet(const uint8_t* data, size_t size) {
    std::string msg(reinterpret_cast<const char*>(data), size);
    std::cout << "[SERVER] DECRYPTED: " << msg << std::endl;
    return true;
}

void perform_handshake(tcp::socket& socket, catnip::CatSession& session, bool is_server) {
    uint8_t buffer[CAT_KEY_SIZE];

    if (is_server) {
        boost::asio::read(socket, boost::asio::buffer(buffer));
        session.load_peer_public_key(buffer);
        session.generate_keypair();
        session.get_public_key(buffer);
        boost::asio::write(socket, boost::asio::buffer(buffer));
        session.derive_shared_secret();
        session.initiate_handshake();
        session.get_challenge(buffer);
        boost::asio::write(socket, boost::asio::buffer(buffer));
        boost::asio::read(socket, boost::asio::buffer(buffer));
        if (!session.verify_challenge_response(buffer)) {
            uint32_t error_code = CATNIP_STATUS_FORBIDDEN;
            boost::asio::write(socket, boost::asio::buffer(&error_code, sizeof(error_code)));
            throw std::runtime_error("Handshake failed");
        }
    } else {
        session.generate_keypair();
        session.get_public_key(buffer);
        boost::asio::write(socket, boost::asio::buffer(buffer));
        boost::asio::read(socket, boost::asio::buffer(buffer));
        session.load_peer_public_key(buffer);
        session.derive_shared_secret();
        boost::asio::read(socket, boost::asio::buffer(buffer));
        session.writeServer_challenge_response(buffer);
        session.generate_challenge_response(buffer);
        boost::asio::write(socket, boost::asio::buffer(buffer));
    }
}

void server_session(tcp::socket socket) {
    catnip::CatSession session;
    catnip::PacketContext context(session);

    try {
        perform_handshake(socket, session, true);
        catnip::PacketRegistry::register_packet(CATNIP_PACKET_ID_MESSAGE, handle_message_packet);

        while (true) {
            uint32_t packet_size;
            boost::asio::read(socket, boost::asio::buffer(&packet_size, sizeof(packet_size)));
            std::vector<uint8_t> packet(packet_size);
            boost::asio::read(socket, boost::asio::buffer(packet));
            bool ok = context.decrypt_and_dispatch(packet.data(), packet.size());
            uint32_t status = ok ? CATNIP_STATUS_OK : CATNIP_STATUS_FAIL;
            boost::asio::write(socket, boost::asio::buffer(&status, sizeof(status)));
        }

    } catch (...) {
        uint32_t error_code = CATNIP_STATUS_FAIL;
        try { boost::asio::write(socket, boost::asio::buffer(&error_code, sizeof(error_code))); } catch (...) {}
    }
}

void run_server() {
    boost::asio::io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), CATNIP_SERVER_PORT));
    while (true) {
        tcp::socket socket(io_context);
        acceptor.accept(socket);
        std::thread(server_session, std::move(socket)).detach();
    }
}

int run_client() {
    try {
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(socket, resolver.resolve(CATNIP_SERVER_IP, std::to_string(CATNIP_SERVER_PORT)));

        catnip::CatSession session;
        perform_handshake(socket, session, false);
        catnip::PacketContext context(session);

        while (true) {
            std::string msg;
            std::cout << "[CLIENT] Enter message: ";
            std::getline(std::cin, msg);
            if (msg.empty()) continue;

            std::vector<uint8_t> packet;
            if (!context.encrypt_and_package(CATNIP_PACKET_ID_MESSAGE,
                                             reinterpret_cast<const uint8_t*>(msg.data()),
                                             msg.size(), packet))
                continue;

            uint32_t packet_size = static_cast<uint32_t>(packet.size());
            boost::asio::write(socket, boost::asio::buffer(&packet_size, sizeof(packet_size)));
            boost::asio::write(socket, boost::asio::buffer(packet));

            uint32_t status_code;
            boost::asio::read(socket, boost::asio::buffer(&status_code, sizeof(status_code)));
            std::cout << "[CLIENT] Server response status: " << status_code << std::endl;
        }

    } catch (std::exception& e) {
        std::cerr << "[CLIENT] Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}



int main() {
    int mode = 0;
    std::cout << "Enter mode (0 = server, 1 = client): ";
    std::cin >> mode;
    std::cin.ignore();

    if (mode == 0) {
        try {
            run_server();
        } catch (const std::exception& e) {
            std::cerr << "[SERVER] Fatal: " << e.what() << std::endl;
        }
    } else {
        return run_client();
    }

    return 0;
}
