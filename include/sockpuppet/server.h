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
// TODO: Non-blocking/select

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
                // log::error("Failed to create socket (perror: %d), terminating",);
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
            int fdmax, newfd;
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
            fdmax = sockfd;
            FD_SET(sockfd, &master_set);

            // Set 3 minute timeout
            timeout.tv_sec = 3 * 60;
            timeout.tv_usec = 0;
            len = sizeof(cli);

            do {
                memcpy(&working_set, &master_set, sizeof(master_set));
                log::info("Waiting on select()...");

                int rc = 0;
                if ((rc = select(fdmax + 1, &working_set, NULL, NULL, &timeout)) < 0) {
                    perror("select() failed");
                    break;
                } else if (rc == 0) {
                    log::error("select() timed out. Terminating");
                    break;
                }

                descriptor_ready = rc;
                for (int connfd = 0; connfd <= fdmax && descriptor_ready > 0; connfd++) {
                    if (FD_ISSET(connfd, &working_set)) {
                        descriptor_ready -= 1;

                        // If listening socket
                        if (connfd == sockfd) {
                            log::info("Listening socket is readable");

                            do {
                                // Accept each incoming connection.
                                newfd = accept(sockfd, NULL, NULL);

                                if (newfd < 0) {
                                    // EWOULDBLOCK means all were accepted,
                                    // other failures terminate the server.
                                    if (errno != EWOULDBLOCK) {
                                        perror("accept() failed");
                                        server_exit = true;
                                    }

                                    break;
                                }

                                // Add incoming connection to master set
                                log::info("New incoming connection - %d", newfd);
                                FD_SET(newfd, &master_set);

                                if (newfd > fdmax)
                                    fdmax = newfd;
                            } while (newfd != -1);
                        } else {
                            log::info("Descriptor %d is readable", connfd);
                            close_conn = false;

                            do {
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

                                len = rc;
                                log::info("%d bytes received", len);

                                // TODO: Add response or don't echo back.
                                rc = send(connfd, socket_bytes.data(), len, 0);

                                if (rc < 0) {
                                    perror("  send() failed");
                                    close_conn = true;
                                    break;
                                }

                            } while (true);

                            // Cleanup connections
                            if (close_conn)
                                socket_close(connfd, fdmax, master_set);
                        } // END existing connection is readable
                    }     // END (FD_ISSET(i, &working_set))
                }         // END loop through selectable descriptors

            } while (!server_exit);
        }

        /**
         * Read 4 byte unsigned integer noting data size from packet header
         * @param header: header bytes
         */
        static size_t read_size_header(const vector<u8>& header) { return ((u32*) header.data())[0]; }

        /**
         * Decrypt/read protobuf message from packet
         * @param connfd: connection file descriptor
         * @param size: encoded protobuf header
         * @param request: output object for protobuf message
         */
        static int read_body(int connfd, google::protobuf::uint32 size, Request& request)
        {
            // TODO: Remove me and create handshake for key negotiation
            const vector<u8> KEY(32, 0);
            const size_t RECV_SIZE = size + HEADER_SIZE;
            AEAD<BlockType::BLOCK_128> aead(KEY);
            vector<u8> aad(255, 0);
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

            // Strip header
            vector<u8> without_header(socket_bytes.begin() + HEADER_SIZE, socket_bytes.end());

            // Decrypt
            aead.open(without_header, aad);

            // Deserialize
            ArrayInputStream ais(without_header.data(), RECV_SIZE);
            CodedInputStream coded_input(&ais);
            coded_input.ReadVarint32(&size);
            CodedInputStream::Limit message_limit = coded_input.PushLimit(size);
            request.ParseFromCodedStream(&coded_input);
            coded_input.PopLimit(message_limit);
            log::info("\n\n%s", request.DebugString().c_str());

            return bytes_received;
        }
    };
} // namespace sockpuppet
