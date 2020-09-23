#pragma once

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/message.h>

#include <log/log.h>
#include <rc6/mode/aead.h>

#include "commands.pb.h"

using namespace google::protobuf::io;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::system_clock;
using std::chrono::time_point;

// TODO: Support/deduce IPv4/6

namespace sockpuppet
{
    /// RC6 encrypted socket client using protobuf. (Inherits non-blocking behavior from server)
    class client
    {
      public:
        /**
         * Constructor for socket client
         * @param port: TCP port to connect to on server
         */
        client(u16 port = 31337)
        {
            // Create socket
            if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                log::fatal("Timeout waiting for socket creation");
            }

            // Set option to put out of band data in the normal input queue
            int optval = 1;
            if ((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*) &optval, sizeof(int)) == -1) ||
                (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (char*) &optval, sizeof(int)) == -1)) {
                log::fatal("Unable to set socket options");
            }

            // Assign IP/port
            servaddr.sin_family = AF_INET;
            servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
            servaddr.sin_port = htons(port);
        }

        /**
         * Send request to server
         * @param request: protobuf message
         */
        void send_request(const Request& request)
        {
            size_t size = request.ByteSizeLong() + HEADER_SIZE;
            vector<u8> socket_buffer(size);

            socket_connect();
            create_request(request, socket_buffer, size);

            // Encrypt request
            const vector<u8> KEY = vector<u8>(32, 0);
            AEAD<BlockType::BLOCK_128> aead = AEAD<BlockType::BLOCK_128>(KEY);
            aead.seal(socket_buffer, aad);

            // Read size as little-endian bytes
            u32 encrypted_size = socket_buffer.size();
            u8* encrypted_size_bytes = (u8*) &encrypted_size;

            // Insert encryption size header
            for (int i = HEADER_SIZE - 1; i >= 0; i--)
                socket_buffer.insert(socket_buffer.begin(), encrypted_size_bytes[i]);

            try {
                int byte_count;

                // Send data
                while (true) {
                    if ((byte_count = send(sockfd, socket_buffer.data(), socket_buffer.size(), 0)) == -1) {
                        log::error("Failed to send data");
                        continue;
                    } else {
                        log::info("Sent %d bytes", byte_count);
                        break;
                    }
                }
            } catch (runtime_error& e) {
                log::error(string(e.what()));
            } catch (exception& e) {
                log::error(string(e.what()));
            }

            log::info("Close socket");
            close(sockfd);
        }

      private:
        // TODO: Remove key and use B-MQKD for key exchange
        vector<u8> aad = vector<u8>(255, 0);

        const size_t HEADER_SIZE = sizeof(u32);
        int sockfd;
        struct sockaddr_in servaddr;

        /// Connect to socket
        void socket_connect()
        {
            // Connect
            time_point<system_clock> start = system_clock::now();
            time_point<system_clock> end;
            auto millis = duration_cast<milliseconds>(end - start);

            log::info("Attempting to connect...");

            // While unable to connect and timeout < 30s
            while (connect(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) &&
                   (millis.count() / 1000) < 30) {
                end = system_clock::now();
                millis = duration_cast<milliseconds>(end - start);
            }

            // Timeout reached
            if ((millis.count() / 1000) >= 30) {
                log::fatal("connect() timeout");
            }

            log::info("--- SEND ---");
            log::info("Connection established");
        }

        /**
         * Serialize request to vector of bytes
         * @param request: protobuf message
         * @param socket_buffer: vector of bytes for output
         * @param size: byte size of output
         */
        void create_request(const Request& request, vector<u8>& socket_buffer, size_t size)
        {
            // Serialize object to vector of bytes
            ArrayOutputStream aos(socket_buffer.data(), size);
            CodedOutputStream coded_output = CodedOutputStream(&aos);
            coded_output.WriteVarint32(request.ByteSizeLong());
            request.SerializeToCodedStream(&coded_output);
        }
    };
} // namespace sockpuppet
