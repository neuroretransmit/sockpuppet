#pragma once

#include <arpa/inet.h>
#include <cmath>
#include <cstdint>
#include <fcntl.h>
#include <future>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using std::async;
using std::cout;
using std::future;
using std::string;
using std::vector;

namespace scanner
{
    namespace tcp
    {
        class syn
        {
          private:
            // Socket timeout
            static const int TIMEOUT_SECONDS = 3;
            static const int TIMEOUT_USECONDS = 0;

            // TODO: Remove and make configurable
            static constexpr uint16_t HIGH_INTEREST[25] = {
                22,  2222, /* SSH */
                23,  2323, /* Telnet */
                25,        /* SMTP */
                53,        /* DNS */
                80,  8080, /* HTTP */
                445, 3306, /* MySQL */
                3389       /* RDP */
            };

          public:
            /**
             * SYN scan port on target
             * @param target: target IP address
             * @param port: port to scan
             */
            static bool is_open(const string& target, uint16_t port)
            {
                struct sockaddr_in address;
                short int sock = -1;
                fd_set fdset;
                struct timeval tv;

                address.sin_family = AF_INET;
                address.sin_addr.s_addr = inet_addr(target.c_str()); /* assign the address */
                address.sin_port = htons(port);

                sock = socket(AF_INET, SOCK_STREAM, 0);
                fcntl(sock, F_SETFL, O_NONBLOCK);

                connect(sock, (struct sockaddr*) &address, sizeof(address));

                FD_ZERO(&fdset);
                FD_SET(sock, &fdset);
                tv.tv_sec = TIMEOUT_SECONDS;
                tv.tv_usec = TIMEOUT_USECONDS;

                if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
                    int so_error = -1;
                    socklen_t len = sizeof so_error;

                    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

                    if (so_error == 0) {
                        close(sock);
                        return true;
                    } else if (so_error != 111) {
                        return false;
                    } else {
                        close(sock);
                        return false;
                    }
                }

                return false;
            }

            /**
             * Scan an inclusive range of ports
             * @param target: target ip address
             * @param lower: lower bound of inclusive range
             * @param higher: higher bound of inclusive range
             */
            static vector<bool> range_scan(const string& target, int lower, int higher)
            {
                vector<bool> ports;

                for (int i = 0; i < lower - 1; i++)
                    ports.push_back(false);

                for (int port = lower; port <= higher; port++) {
                    auto future = async(is_open, target, port);
                    ports.push_back(future.get());
                }

                return ports;
            }

            /**
             * Scan the first 2000 ports of a target
             * @param target: target IP address
             */
            static vector<bool> quick_scan(const string& target)
            {
                cout << "Quick scan on " << target << "..."
                     << "\n";
                return range_scan(target, 0, 2000);
            }

            /**
             * Scan specified "high interest" ports on target
             * @param target: target IP address
             */
            static vector<bool> high_interest_scan(const string& target)
            {
                cout << "High interest scan on " << target << "..."
                     << "\n";
                vector<bool> ports;

                for (int i = 0; i < HIGH_INTEREST[0] - 1; i++)
                    ports.push_back(false);

                for (int port : HIGH_INTEREST) {
                    auto future = async(task, target, port);
                    ports.push_back(future.get());
                }

                return ports;
            }
        };
    } // namespace tcp
} // namespace scanner
