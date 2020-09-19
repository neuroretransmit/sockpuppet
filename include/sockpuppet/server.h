#pragma once

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include "client.h"
#include <log/log.h>
#include <rc6/mode/aead.h>

#include "commands.pb.h"

using std::atomic;
using std::cerr;
using std::cout;
using std::thread;

using namespace google::protobuf::io;

// TODO: Support/deduce IPv6
namespace sockpuppet
{
    /// RC6 encrypted non-blocking socket server using protobuf
    class server
    {
      public:
        /**
         * Constructor for socket server
         * @param port: TCP port to listen on
         */
        server(u16 port = 31337) : port(port) {}

        /** Start server */
        void start() { handle(); }

        /** Stop server */
        void stop()
        {
            if (!detached) {
                t.join();
            } else {
                client c(port);
                Request request;
                request.set_type(EXIT);
                c.send_request(request);
            }

            thread_stopped = true;
            wait();
        }

        /** Start server detached */
        void start_detached() { handle(true); }

        /** Check if server is stopped */
        bool is_stopped() const { return thread_stopped; }

        /** Wait for server to stop */
        void wait()
        {
            while (!thread_stopped)
                ;
        }

      private:
        thread t;
        u16 port;
        bool detached = false;
        atomic<bool> thread_stopped = atomic<bool>(true);
        static const int HEADER_SIZE = sizeof(u32);

        /** Main handler that spawns server thread
         * @param detached: detach from server and leave running on thread
         */
        void handle(bool detached = false)
        {
            this->detached = detached;
            signal(SIGINT, sigint_handler);

            try {
                thread_stopped = false;
                t = thread([this] {
                    socket_handler(this->port);
                    thread_stopped = true;
                });

                detached ? t.detach() : t.join();
            } catch (runtime_error& e) {
                log::error(string(e.what()));
            } catch (exception& e) {
                log::error(string(e.what()));
            }
        }

        /**
         * Handle CTRL+C event
         * @param sig: signal
         */
        static void sigint_handler(int sig)
        {
            char c;
            signal(sig, SIG_IGN);
            cout << "\nCTRL-C Detected, abort? [y/n] ";
            c = getchar();

            if (c == 'y' || c == 'Y') {
                exit(0);
            } else {
                signal(SIGINT, sigint_handler);
            }
        }

        /**
         * Start listening on socket
         * @param port: TCP Port to listen on
         */
        static int socket_listen(int port)
        {
            int sockfd;
            int optval = 1;

            // Create socket
            if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                perror("Failed to create socket, socket() failed. Terminating");
                // error("Failed to create socket (perror: %d), terminating",);
                exit(1);
            }

            // Set option to put out of band data in the normal input queue
            if ((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*) &optval, sizeof(int)) == -1) ||
                (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (char*) &optval, sizeof(int)) == -1)) {
                log::error("Unable to set socket options");
                close(sockfd);
                exit(1);
            }

            // Set socket to non-blocking
            int on = 1;
            if (ioctl(sockfd, FIONBIO, (char*) &on) < 0) {
                perror("ioctl() failed");
                close(sockfd);
                exit(-1);
            }

            // Assign IP/port
            struct sockaddr_in servaddr;
            servaddr.sin_family = AF_INET;
            servaddr.sin_addr.s_addr = INADDR_ANY;
            servaddr.sin_port = htons(port);

            // Bind socket to IP
            if (bind(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) < 0) {
                log::error("Socket bind failed");
                close(sockfd);
                exit(1);
            }

            // TODO: What is 32?
            // Start listener
            if ((listen(sockfd, 32))) {
                log::error("Socket listen failed");
                close(sockfd);
                exit(1);
            }

            log::info("Listening on port %d...", port);
            return sockfd;
        }

        /**
         * Close connection and adjust master set
         * @param connfd: connection file descriptor
         * @param fdmax: reference to file descriptor max
         * @param master_set: reference to file descriptor master set
         */
        static void socket_close(int connfd, int& fdmax, fd_set& master_set)
        {
            close(connfd);
            FD_CLR(connfd, &master_set);

            if (connfd == fdmax) {
                while (FD_ISSET(fdmax, &master_set) == false)
                    fdmax -= 1;
            }

            log::info("socket close");
        }

        /**
         * Handler for incoming requests executed on its own thread
         * @param port: server listening port
         */
        static void socket_handler(u16 port)
        {
            int socket_return_code = 0;
            int file_descriptor_max, new_file_descriptor;
            int descriptor_ready;
            int recv_byte_count = 0;
            fd_set master_set, working_set;
            struct sockaddr_in cli;
            struct timeval timeout;
            vector<u8> socket_bytes(HEADER_SIZE);
            socklen_t len;
            bool close_conn = false;
            bool server_exit = false;

            // Listen
            int sockfd = socket_listen(port);

            // Initialize master set
            FD_ZERO(&master_set);
            file_descriptor_max = sockfd;
            FD_SET(sockfd, &master_set);

            // Set 3 minute timeout
            timeout.tv_sec = 3 * 60;
            timeout.tv_usec = 0;
            len = sizeof(cli);

            do {
                memcpy(&working_set, &master_set, sizeof(master_set));
                log::info("Waiting on select()...");

                if ((socket_return_code =
                         select(file_descriptor_max + 1, &working_set, NULL, NULL, &timeout)) < 0) {
                    perror("select() failed");
                    break;
                } else if (socket_return_code == 0) {
                    log::error("select() timed out. Terminating");
                    break;
                }

                descriptor_ready = socket_return_code;
                for (int connfd = 0; connfd <= file_descriptor_max && descriptor_ready > 0; connfd++) {
                    if (FD_ISSET(connfd, &working_set)) {
                        descriptor_ready -= 1;

                        // If listening socket
                        if (connfd == sockfd) {
                            log::info("Listening socket is readable");

                            do {
                                // Accept each incoming connection.
                                new_file_descriptor = accept(sockfd, NULL, NULL);

                                if (new_file_descriptor < 0) {
                                    // EWOULDBLOCK means all were accepted,
                                    // other failures terminate the server.
                                    if (errno != EWOULDBLOCK) {
                                        perror("accept() failed");
                                        server_exit = true;
                                    }

                                    break;
                                }

                                // Add incoming connection to master set
                                log::info("New incoming connection - %d", new_file_descriptor);
                                FD_SET(new_file_descriptor, &master_set);

                                if (new_file_descriptor > file_descriptor_max)
                                    file_descriptor_max = new_file_descriptor;
                            } while (new_file_descriptor != -1);
                        } else {
                            log::info("Descriptor %d is readable", connfd);
                            close_conn = false;

                            while (true) {
                                socket_bytes.clear();

                                // Read header
                                if ((recv_byte_count =
                                         recv(connfd, socket_bytes.data(), HEADER_SIZE, MSG_PEEK)) == -1) {
                                    log::error("Couldn't receive data");
                                    continue;
                                } else if (recv_byte_count == 0) {
                                    break;
                                }

                                // Read body and get protobuf request
                                Request request;
                                int rc = read_body(connfd, read_size_header(socket_bytes), request);

                                // See if connection closed by client
                                if (rc == -1) {
                                    log::info("Connection closed");
                                    close_conn = true;
                                    break;
                                }

                                handle_request(request, server_exit);

                                len = rc;
                                log::info("%d bytes received", len);

                                // TODO: Add response or don't echo back.
                                if ((rc = send(connfd, socket_bytes.data(), len, 0)) < 0) {
                                    perror("send() failed");
                                    close_conn = true;
                                    break;
                                }
                            }

                            // Cleanup connections
                            if (close_conn)
                                close_connections(connfd, file_descriptor_max, master_set);
                        } // END existing connection is readable
                    }     // END (FD_ISSET(i, &working_set))
                }         // END loop through selectable descriptors

            } while (!server_exit);
        }

        static void handle_request(const Request& request, bool& server_exit)
        {
            // Handle request
            switch (request.type()) {
            case DOWNLOAD:
                log::info("Download command");
                break;
            case EXIT:
                log::info("Exit command. Terminating");
                server_exit = true;
                break;
            case RUN_COMMAND:
                log::info("Run command");
                break;
            default:
                break;
            }
        }

        /**
         * Close active socket connections
         * @param connfd: connection file descriptor
         * @param fdmax: file descriptor max
         * @param fd_set: file descriptor set
         */
        static void close_connections(int connfd, int fdmax, fd_set& master_set)
        {
            socket_close(connfd, fdmax, master_set);
        }

        /**
         * Read 4 byte unsigned integer noting data size from packet header
         * @param header: header bytes
         * @return size of packet body
         */
        static size_t read_size_header(const vector<u8>& header) { return ((u32*) header.data())[0]; }

        /**
         * Decrypt packet
         * @param packet_body: received bytes after header
         */
        static void decrypt(vector<u8>& packet_body)
        {
            // TODO: Remove me and create handshake for key negotiation
            const vector<u8> KEY(32, 0);
            AEAD<BlockType::BLOCK_128> aead(KEY);
            vector<u8> aad(255, 0);
            aead.open(packet_body, aad);
        }

        /**
         * Deserialize packet into request object
         * @param decrypted: received bytes after header
         * @param size: protobuf size header
         * @param request: request message to deserialize into
         * @param recv_size: received packet size
         * @
         */
        static void deserialize(vector<u8>& decrypted, google::protobuf::uint32 size, Request& request,
                                size_t recv_size)
        {
            ArrayInputStream ais(decrypted.data(), recv_size);
            CodedInputStream coded_input(&ais);
            coded_input.ReadVarint32(&size);
            CodedInputStream::Limit message_limit = coded_input.PushLimit(size);
            request.ParseFromCodedStream(&coded_input);
            coded_input.PopLimit(message_limit);
            log::info("\n\n%s", request.DebugString().c_str());
        }

        /**
         * Decrypt/read protobuf message from packet
         * @param connfd: connection file descriptor
         * @param size: encoded protobuf header
         * @param request: output object for protobuf message
         * @return: number of bytes received
         */
        static int read_body(int connfd, google::protobuf::uint32 size, Request& request)
        {
            const size_t RECV_SIZE = size + HEADER_SIZE;
            vector<u8> socket_bytes(RECV_SIZE);
            int bytes_received = 0;

            // Receive data
            if ((bytes_received = recv(connfd, socket_bytes.data(), socket_bytes.size(), 0)) < 0) {
                if (errno != EWOULDBLOCK) {
                    perror("recv() failed");
                    return -1;
                }
            }

            log::info("Received %lu bytes", RECV_SIZE);
            vector<u8> without_header(socket_bytes.begin() + HEADER_SIZE, socket_bytes.end());
            decrypt(without_header);
            deserialize(without_header, size, request, RECV_SIZE);
            return bytes_received;
        }
    };
} // namespace sockpuppet
