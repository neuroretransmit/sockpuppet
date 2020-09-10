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

// TODO: Remove me and create handshake for key negotiation
static const vector<u8> KEY(32, 0);
static const int HEADER_SIZE = sizeof(int);

class client
{
  public:
    client(u16 port = 31337)
    {
        // Create socket
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            log::warn("Socket creation failed, waiting for socket to be ready");
            std::chrono::time_point<std::chrono::system_clock> start = std::chrono::system_clock::now();
            std::chrono::time_point<std::chrono::system_clock> end = std::chrono::system_clock::now();

            // Store the time difference between start and end
            auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() / 1000;
            
            while (diff <= 30) {
                stringstream ss;
                ss << "Client socket create timeout: " << diff << "s\n";
                log::info(ss.str());
                
                if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    continue;
                else
                    break;
                
                end = std::chrono::system_clock::now();
                diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() / 1000;
            }
            
            log::error("Timeout waiting for socket creation, terminating");
            exit(1);
        }
        
        if (sockfd == -1) {
            log::error("Socket creation failed");
            exit(1);
        }
        // TODO: Check if port in use
        // TODO: Check if default port or ephemeral
        int optval = 1;
        //struct timeval tv;
        //tv.tv_sec = 30;
        
        // Set option to put out of band data in the normal input queue
        if ((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*) &optval, sizeof(int)) == -1) ||
            (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (char*) &optval, sizeof(int)) == -1)) {
            log::error("Unable to set socket options");
            exit(1);
        }
        
        // Assign IP/port
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(port);
    }

    void send_request(const Request& request)
    {
        // Connect
        
        if (connect(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr))) {
            log::warn("Socket creation failed, retrying");
            std::chrono::time_point<std::chrono::system_clock> start = std::chrono::system_clock::now();
            std::chrono::time_point<std::chrono::system_clock> end = std::chrono::system_clock::now();

            // Store the time difference between start and end
            auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() / 1000;
            
            while (diff <= 30) {
                stringstream ss;
                ss << "Connect timeout: " << diff << "s\n";
                log::info(ss.str());
                
                if (connect(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr)))
                    continue;
                else
                    break;
                
                end = std::chrono::system_clock::now();
                diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() / 1000;
            }
            
            log::error("Timeout reached. Connection failed to establish");
            exit(1);
        } else {
            log::info("Connection established");
        }

        AEAD<BlockType::BLOCK_128> aead(KEY);
        vector<u8> aad(255, 0);

        // Construct packet with leading header for size
        size_t size = request.ByteSizeLong() + HEADER_SIZE;
        vector<u8> socket_buffer(size);

        // Serialize object to vector of bytes
        ArrayOutputStream aos(socket_buffer.data(), size);
        CodedOutputStream coded_output = CodedOutputStream(&aos);
        coded_output.WriteVarint32(request.ByteSizeLong());
        request.SerializeToCodedStream(&coded_output);

        // Encrypt
        log::data(socket_buffer);
        stringstream ss;
        ss << "Decrypted size " << socket_buffer.size();
        log::info(ss.str());
        aead.seal(socket_buffer, aad);
        u32 encrypted_size = socket_buffer.size();
        u8* encrypted_size_bytes = (u8*) &encrypted_size;

        for (int i = HEADER_SIZE - 1; i >= 0; i--)
            socket_buffer.insert(socket_buffer.begin(), encrypted_size_bytes[i]);

        try {
            int byte_count;

            while (true) {
                if ((byte_count = send(sockfd, socket_buffer.data(), socket_buffer.size(), 0)) == -1) {
                    log::error("Failed to send data");
                    continue;
                }

                stringstream ss;
                ss << "Encrypted size " << socket_buffer.size();
                log::info(ss.str());
                ss = stringstream();
                ss << "Sent " << byte_count << " bytes";
                log::info(ss.str());
                log::data(socket_buffer);
                break;
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
    const vector<u8> KEY = vector<u8>(32, 0);
    const size_t HEADER_SIZE = sizeof(u32);

    int sockfd;
    struct sockaddr_in servaddr;
};
