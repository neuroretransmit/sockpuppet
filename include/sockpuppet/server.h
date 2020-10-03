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

#include <log/log.h>
#include <rc6/mode/aead.h>

#include "client.h"
#include "commands.pb.h"

using std::atomic;
using std::cerr;
using std::cout;
using std::thread;

using namespace google::protobuf::io;

// TODO: Support/deduce IPv6
namespace sockpuppet
{
    typedef struct {
        int fd;
        int return_code;
        vector<u8> socket_bytes;
        socklen_t socket_bytes_len;
        bool close;
    } connection_ctx;

    typedef struct {
        int max, incoming;
        int ready;
        // File descriptor sets for multiple connections
        fd_set master, working;
    } file_descriptor_ctx;

    typedef struct {
        struct sockaddr_in cli;
        int return_code = 0;
        int recv_byte_count = 0;
        int fd;
        // Set 3 minute timeout
        // TODO: Make configurable
        struct timeval timeout = {.tv_sec = 3 * 60, .tv_usec = 0};
    } socket_ctx;

    typedef enum { NOP = 0, CONTINUE = 1, BREAK = -1 } loop_decision;

    /// RC6 encrypted/authenticated non-blocking socket using protobuf for messaging
    class server
    {
      public:
        /**
         * Constructor for socket server
         * @param port: TCP port to listen on
         */
        server(u16 port = 31337) : port(port) {}

        /* Start server
         * @param detached: detach from server and leave running on thread
         */
        void start(bool detached = false)
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

        /// Stop server
        void stop()
        {
            if (!detached) {
                t.join();
            } else {
                // Send request to detached thread to cleanly terminate
                client c(port);
                Request request;
                request.set_type(EXIT);
                c.send_request(request);
            }

            thread_stopped = true;
            wait();
        }

        /// Start server running in background
        void start_detached() { start(true); }

        /// Check if server is stopped
        bool is_stopped() const { return thread_stopped; }

        /// Wait for server to stop
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

        /**
         * Handle CTRL+C event
         * @param sig: signal
         */
        // TODO: Not friendly if you type more than a character
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
            if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                log::fatal("Failed to create socket, socket() failed");

            // Set option to put out of band data in the normal input queue
            if ((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*) &optval, sizeof(int)) == -1) ||
                (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (char*) &optval, sizeof(int)) == -1)) {
                close(sockfd);
                log::fatal("Unable to set socket options");
            }

            // Set socket to non-blocking
            int on = 1;
            if (ioctl(sockfd, FIONBIO, (char*) &on) < 0) {
                close(sockfd);
                log::fatal("ioctl() failed");
            }

            // Assign IP/port
            struct sockaddr_in servaddr;
            servaddr.sin_family = AF_INET;
            servaddr.sin_addr.s_addr = INADDR_ANY;
            servaddr.sin_port = htons(port);

            // Bind socket to IP
            if (bind(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) < 0) {
                close(sockfd);
                log::fatal("Socket bind() failed");
            }

            // TODO: What is 32?
            // Start listener
            if ((listen(sockfd, 32))) {
                close(sockfd);
                log::error("Socket listen() failed");
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

            log::info("Socket close");
        }

        /**
         * Prepare new file descriptor for connection
         * @param sock: socket context
         * @param fd: file descriptor
         * @return break or NOP
         */
        static bool prepare_descriptors(socket_ctx& sock, file_descriptor_ctx& fd)
        {
            if ((sock.return_code = select(fd.max + 1, &fd.working, NULL, NULL, &sock.timeout)) < 0) {
                log::error("select() failed");
                return true;
            } else if (sock.return_code == 0) {
                log::error("select() timed out. Terminating");
                return true;
            }

            fd.ready = sock.return_code;
            return false;
        }

        /**
         * Activate incoming connection on new file descriptor
         * @param sock: socket context
         * @param fd: file descriptor context
         * @param server_exit: boolean to exit server
         * @return break or NOP
         */
        static bool connect(const socket_ctx& sock, file_descriptor_ctx& fd, bool& server_exit)
        {
            do {
                fd.incoming = accept(sock.fd, NULL, NULL);

                if (fd.incoming < 0) {
                    // EWOULDBLOCK means all were accepted, other failures terminate the server.
                    if (errno != EWOULDBLOCK) {
                        log::error("accept() failed");
                        server_exit = true;
                    }

                    return true;
                }

                log::info("New incoming connection - %d", fd.incoming);
                FD_SET(fd.incoming, &fd.master);

                if (fd.incoming > fd.max)
                    fd.max = fd.incoming;
            } while (fd.incoming != -1);

            return false;
        }

        /**
         * Receive packet and decode protobuf message
         * @param sock: socket context
         * @param conn: connection context
         * @return loop decision (continue, break, NOP)
         */
        static loop_decision read_raw_request(socket_ctx& sock, connection_ctx& conn)
        {
            // Read header
            if ((sock.recv_byte_count = recv(conn.fd, conn.socket_bytes.data(), HEADER_SIZE, MSG_PEEK)) ==
                -1) {
                log::error("Couldn't receive data");
                return CONTINUE;
            } else if (sock.recv_byte_count == 0) {
                return BREAK;
            }

            return NOP;
        }

        /**
         * Handler for incoming requests executed on its own thread
         * @param port: server listening port
         */
        static void socket_handler(u16 port)
        {
            bool server_exit = false;
            socket_ctx sock;

            connection_ctx conn = {
                .fd = -1,
                .return_code = 0,
                .socket_bytes = vector<u8>(HEADER_SIZE),
                .socket_bytes_len = sizeof(sock.cli),
                .close = false,
            };

            // Listen
            sock.fd = socket_listen(port);

            // Initialize master set
            file_descriptor_ctx fd;
            fd.max = sock.fd;
            FD_ZERO(&fd.master);
            FD_SET(fd.max, &fd.master);

            do {
                // Copy master file descriptor set into working set
                memcpy(&fd.working, &fd.master, sizeof(fd.master));

                // Prepare file descriptors with select()
                if (prepare_descriptors(sock, fd))
                    break;

                fd.ready = sock.return_code;
                // Loop over all file descriptors and receive/transmit
                // FIXME, have iterative FD be a different descriptor than context so we only process new
                for (conn.fd = 0; conn.fd <= fd.max && fd.ready > 0; conn.fd++) {
                    if (FD_ISSET(conn.fd, &fd.working)) {
                        fd.ready -= 1;

                        // If socket listening
                        if (conn.fd == sock.fd) {
                            log::info("Listening socket is readable");
                            connect(sock, fd, server_exit);
                        } else {
                            conn.close = false;

                            while (true) {
                                conn.socket_bytes.clear();
                                Request request;

                                loop_decision decision = read_raw_request(sock, conn);
                                if (decision == CONTINUE)
                                    continue;
                                else if (decision == BREAK)
                                    break;

                                // Read protobuf message/decode header
                                conn.return_code = read_body(
                                    conn.fd, read_encrypted_size_header(conn.socket_bytes), request);

                                // See if connection closed by client
                                if (conn.return_code == -1) {
                                    log::info("Connection closed");
                                    conn.close = true;
                                    break;
                                }

                                Response response = handle_request(request, server_exit);

                                // TODO: Created encrypted buffer for response
                                // TODO: Modify client to wait for response
                                if (send_response(conn) < 0)
                                    break;
                            }

                            // Cleanup connections
                            if (conn.close)
                                close_connections(conn.fd, fd.max, fd.master);
                        } // END existing connection is readable
                    }     // END (FD_ISSET(i, &working_set))
                }         // END loop through selectable descriptors

            } while (!server_exit);
        }

        static int send_response(connection_ctx& ctx)
        {
            if ((ctx.return_code = send(ctx.fd, ctx.socket_bytes.data(), ctx.return_code, 0)) < 0) {
                log::error("send() failed");
                ctx.close = true;
            }

            return ctx.return_code;
        }

        static Response handle_request(const Request& request, bool& server_exit)
        {
            Response response = Response();
            auto attributes = response.mutable_attributes();
            // Figure out how to anonymously identify server origins amongst the network or be k-anonymously
            // used
            response.set_origin("127.0.0.1");
            response.set_request_id(request.id());

            // Handle request
            switch (request.type()) {
                case EXIT:
                    log::info("Exit command. Terminating");
                    server_exit = true;
                    break;
                case INFO:
                    // TODO
                    (*attributes)["TODO"] = "write this code";
                    break;
                case DOWNLOAD:
                    // TODO: Link curl and modify request to handle threaded bulk
                    (*attributes)["TODO"] = "write this code";
                    break;
                case RUN_COMMAND:
                    // TODO
                    (*attributes)["TODO"] = "write this code";
                    break;
                case COLLECT:
                    (*attributes)["TODO"] = "write this code";
                    break;
                case MONITOR:
                    // TODO: Start monitoring network activity/other future additions
                    (*attributes)["TODO"] = "write this code";
                    break;
                default:
                    break;
            }

            return response;
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
        static size_t read_encrypted_size_header(const vector<u8>& header)
        {
            u32 encrypted_size = ((u32*) header.data())[0];
            return is_big_endian() ? encrypted_size : swap_endian(encrypted_size);
        }

        /**
         * Decrypt packet
         * @param packet_body: received bytes after header
         */
        static void decrypt(vector<u8>& packet_body)
        {
            // TODO: Remove me and create handshake for key negotiation
            const vector<u8> KEY(32, 0);
            AEAD<BlockWordSize::BLOCK_128> aead(KEY);
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
        static void deserialize_protobuf(vector<u8>& decrypted, google::protobuf::uint32 size,
                                         Request& request, size_t recv_size)
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
        static int read_body(int conn_fd, google::protobuf::uint32 size, Request& request)
        {
            const size_t RECV_SIZE = size + HEADER_SIZE;
            vector<u8> socket_bytes(RECV_SIZE);
            int bytes_received = 0;

            // Receive data
            if ((bytes_received = recv(conn_fd, socket_bytes.data(), socket_bytes.size(), 0)) < 0) {
                if (errno != EWOULDBLOCK) {
                    log::error("recv() failed");
                    return -1;
                }
            }

            log::info("Received %lu bytes", RECV_SIZE);
            vector<u8> without_header(socket_bytes.begin() + HEADER_SIZE, socket_bytes.end());
            decrypt(without_header);
            deserialize_protobuf(without_header, size, request, RECV_SIZE);
            return bytes_received;
        }
    };
} // namespace sockpuppet
