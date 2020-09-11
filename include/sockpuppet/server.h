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

/// RC6 encrypted socket server using protobuf
namespace sockpuppet
{
    class server
    {
      public:
        server(u16 port = 31337) : port(port) {}

        void start() { handle(); }

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

        void start_detached() { handle(true); }

        bool is_stopped() const { return thread_stopped; }

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
         * Handler for incoming requests executed on its own thread
         * @param port: server listening port
         */
        static void socket_handler(u16 port)
        {
            int optval = 1;
            int sockfd;

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

            /*************************************************************/
            /* Initialize the master fd_set                              */
            /*************************************************************/
            int max_sd, new_sd;
            fd_set master_set, working_set;
            struct timeval timeout;
            int descriptor_ready;
            bool close_conn;
            FD_ZERO(&master_set);
            max_sd = sockfd;
            FD_SET(sockfd, &master_set);
            timeout.tv_sec = 3 * 60;
            timeout.tv_usec = 0;

            struct sockaddr_in cli;
            vector<u8> socket_bytes(HEADER_SIZE);
            socklen_t len;
            int recv_byte_count = 0;
            // int connfd;
            bool exit = false;

            len = sizeof(cli);

            do {
                memcpy(&working_set, &master_set, sizeof(master_set));
                log::info("Waiting on select()...");

                /**********************************************************/
                /* Check to see if the select call failed.                */
                /**********************************************************/
                int rc = 0;
                if ((rc = select(max_sd + 1, &working_set, NULL, NULL, &timeout)) < 0) {
                    perror("select() failed");
                    break;
                }

                if (rc == 0) {
                    log::error("select() timed out. Terminating");
                    break;
                }

                descriptor_ready = rc;
                for (int i = 0; i <= max_sd && descriptor_ready > 0; i++) {
                    if (FD_ISSET(i, &working_set)) {
                        descriptor_ready -= 1;

                        // Check if listening socket
                        if (i == sockfd) {
                            log::info("Listening socket is readable");

                            do {
                                // Accept each incoming connection. Failure with EWOULDBLOCK means all were
                                // accepted, other failures terminate the server.

                                new_sd = accept(sockfd, NULL, NULL);

                                if (new_sd < 0) {
                                    if (errno != EWOULDBLOCK) {
                                        perror("accept() failed");
                                        exit = true;
                                    }

                                    break;
                                }

                                /**********************************************/
                                /* Add the new incoming connection to the     */
                                /* master read set                            */
                                /**********************************************/
                                log::info("New incoming connection - %d", new_sd);
                                FD_SET(new_sd, &master_set);

                                if (new_sd > max_sd)
                                    max_sd = new_sd;

                                /**********************************************/
                                /* Loop back up and accept another incoming   */
                                /* connection                                 */
                                /**********************************************/
                            } while (new_sd != -1);
                        } else {
                            log::info("Descriptor %d is readable", i);
                            close_conn = false;
                            /*************************************************/
                            /* Receive all incoming data on this socket      */
                            /* before we loop back and call select again.    */
                            /*************************************************/
                            do {
                                socket_bytes.clear();

                                // Read header
                                if ((recv_byte_count = recv(i, socket_bytes.data(), HEADER_SIZE, MSG_PEEK)) ==
                                    -1) {
                                    log::error("Couldn't receive data");
                                    continue;
                                } else if (recv_byte_count == 0) {
                                    break;
                                }

                                // Read body and get protobuf request
                                Request request;
                                int rc = read_body(i, read_size_header(socket_bytes), request);

                                /**********************************************/
                                /* Check to see if the connection has been    */
                                /* closed by the client                       */
                                /**********************************************/
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
                                    exit = true;
                                    break;
                                case RUN_COMMAND:
                                    log::info("Run command");
                                    break;
                                default:
                                    break;
                                }

                                /**********************************************/
                                /* Data was received                          */
                                /**********************************************/
                                len = rc;
                                log::info("%d bytes received", len);

                                /**********************************************/
                                /* Echo the data back to the client           */
                                /**********************************************/
                                rc = send(i, socket_bytes.data(), len, 0);

                                if (rc < 0) {
                                    perror("  send() failed");
                                    close_conn = true;
                                    break;
                                }

                            } while (true);

                            /*************************************************/
                            /* If the close_conn flag was turned on, we need */
                            /* to clean up this active connection.  This     */
                            /* clean up process includes removing the        */
                            /* descriptor from the master set and            */
                            /* determining the new maximum descriptor value  */
                            /* based on the bits that are still turned on in */
                            /* the master set.                               */
                            /*************************************************/
                            if (close_conn) {
                                close(i);
                                FD_CLR(i, &master_set);

                                if (i == max_sd) {
                                    while (FD_ISSET(max_sd, &master_set) == false)
                                        max_sd -= 1;
                                }
                            }
                        } /* End of existing connection is readable */
                    }     /* End of if (FD_ISSET(i, &working_set)) */
                }         /* End of loop through selectable descriptors */

            } while (!exit);

            log::info("close socket");
            close(sockfd);
        }

        static size_t read_size_header(const vector<u8>& header) { return ((u32*) header.data())[0]; }

        static int read_body(int connfd, google::protobuf::uint32 size, Request& request)
        {
            // TODO: Remove me and create handshake for key negotiation
            const vector<u8> KEY(32, 0);
            AEAD<BlockType::BLOCK_128> aead(KEY);
            vector<u8> aad(255, 0);

            int bytes_received = 0;
            const size_t RECV_SIZE = size + HEADER_SIZE;
            vector<u8> socket_bytes(RECV_SIZE);

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
