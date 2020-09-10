#pragma once

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
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
using namespace std::chrono_literals;

/// RC6 encrypted socket server using protobuf
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

        wait();
    }

    void start_detached() { handle(true); }

    void handle(bool detached = false)
    {
        this->detached = detached;
        signal(SIGINT, sigint_handler);

        try {
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

    bool is_stopped() { return thread_stopped; }

    void wait()
    {
        while (!thread_stopped)
            ;
    }

  private:
    thread t;
    u16 port;
    bool detached = false;
    atomic<bool> thread_stopped = atomic<bool>(false);
    static const int HEADER_SIZE = sizeof(u32);

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
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            log::error("socket creation failed");
            exit(1);
        }

        // Set option to put out of band data in the normal input queue
        if ((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*) &optval, sizeof(int)) == -1) ||
            (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (char*) &optval, sizeof(int)) == -1)) {
            log::error("unable to set socket options");
            exit(1);
        }

        // Assign IP/port
        struct sockaddr_in servaddr;
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = INADDR_ANY;
        servaddr.sin_port = htons(port);

        // Bind socket to IP
        if (bind(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) == -1) {
            log::error("socket bind failed");
            exit(1);
        }

        // Start listener
        if ((listen(sockfd, 10))) {
            log::error("socket listen failed");
            exit(1);
        }

        stringstream ss;
        ss << "Listening on port " << port << "...\n";
        log::info(ss.str());

        struct sockaddr_in cli;
        vector<u8> socket_bytes(HEADER_SIZE);
        socklen_t len;
        int recv_byte_count = 0;
        int connfd;
        bool exit = false;

        len = sizeof(cli);

        while (!exit) {
            if ((connfd = accept(sockfd, (struct sockaddr*) &cli, &len)) != -1) {
                log::info("--- RECV ---");
                struct in_addr client_ip = cli.sin_addr;
                char* addr = inet_ntoa(client_ip);
                int port = cli.sin_port;

                stringstream ss;
                ss << "incoming connection: " << addr << ":" << port;
                log::info(ss.str());
            }

            socket_bytes.clear();

            if ((recv_byte_count = recv(connfd, socket_bytes.data(), HEADER_SIZE, MSG_PEEK)) == -1) {
                log::error("couldn't receive data");
                continue;
            } else if (recv_byte_count == 0) {
                break;
            }

            Request request = read_body(connfd, read_size_header(socket_bytes));

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
        }

        log::info("close socket");
        close(sockfd);
    }

    static size_t read_size_header(const vector<u8>& header)
    {
        size_t recv_size = ((u32*) header.data())[0];
        stringstream ss;
        ss << "receive size " << recv_size;
        log::data(vector<u8>((u32*) header.data(), (u32*) header.data() + HEADER_SIZE));
        log::info(ss.str());
        return recv_size;
    }

    static Request read_body(int connfd, google::protobuf::uint32 size)
    {
        // TODO: Remove me and create handshake for key negotiation
        const vector<u8> KEY(32, 0);
        AEAD<BlockType::BLOCK_128> aead(KEY);
        vector<u8> aad(255, 0);

        int bytes_received = 0;
        const size_t RECV_SIZE = size + HEADER_SIZE;
        vector<u8> socket_bytes(RECV_SIZE);

        // Receive data
        if ((bytes_received = recv(connfd, socket_bytes.data(), RECV_SIZE, MSG_WAITALL)) == -1)
            log::error("failed to receive data");

        log::data(socket_bytes);
        stringstream ss;
        ss << "encrypted size " << RECV_SIZE;
        log::info(ss.str());

        // Strip header
        vector<u8> without_header(socket_bytes.begin() + HEADER_SIZE, socket_bytes.end());

        // Decrypt
        aead.open(without_header, aad);
        ss = stringstream();
        ss << "decrypted size " << socket_bytes.size();
        log::info(ss.str());
        log::data(socket_bytes);

        Request request;

        // Deserialize
        ArrayInputStream ais(without_header.data(), RECV_SIZE);
        CodedInputStream coded_input(&ais);
        coded_input.ReadVarint32(&size);
        CodedInputStream::Limit message_limit = coded_input.PushLimit(size);
        request.ParseFromCodedStream(&coded_input);
        coded_input.PopLimit(message_limit);

        log::info(request.DebugString());
        return request;
    }
};
