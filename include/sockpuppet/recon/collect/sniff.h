#pragma once

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sstream>
#include <sys/socket.h>
#include <thread>

#include <pcap.h>

#include <log/log.h>

#include "../../util/privs.h"

using std::atomic;
using std::hex;
using std::setfill;
using std::setw;
using std::stringstream;
using std::thread;
using std::chrono::duration;
using std::chrono::system_clock;
using std::this_thread::sleep_for;

namespace recon
{
    namespace collect
    {
        typedef struct {
            pcap_t* handle;
            pcap_dumper_t* dumper;
        } pcap_ctx;

        /// Packet type enumeration
        typedef enum { ICMP = 1, IGMP = 2, TCP = 6, UDP = 17 } packet_type;

        // Packet capture interfaces detected by libpcap
        class packet_capture
        {
          public:
            /// Enumerate available interfaces for packet capture
            int enumerate()
            {
                char err[100];

                if (!is_root())
                    log::fatal("Root/sudo required for device enumeration");

                if (pcap_findalldevs(&all_interfaces, err))
                    log::fatal("Unable to enumerate devices, terminating. > %s", err);

                pcap_if_t* device;

                for (device = all_interfaces; device != NULL; device = device->next) {
                    // Create vector of string for easier searching
                    if (device->name != NULL)
                        _interfaces.push_back(device->name);
                }

                return 0;
            }

            /// Enumerate available interfaces for packet capture
            vector<string> interfaces()
            {
                // Lazy load
                if (_interfaces.size() == 0)
                    enumerate();

                return _interfaces;
            }

            /// Log enumerated interfaces
            void dump_interfaces()
            {
                if (_interfaces.size() == 0)
                    enumerate();

                pcap_if_t* device;
                log::info("--- ENUMERATED CAPTURE INTERFACES ---");

                int i = 1;
                for (device = all_interfaces; device != NULL; device = device->next)
                    log::info("%d. %s - %s", i++, device->name, device->description);

                log::info("--- END ENUMERATED CAPTURE INTERFACES ---");
            }

            /**
             * Start packet capture on interface
             * @param interface_descriptor: interface name
             */
            static void sniff(const string& interface_descriptor, size_t seconds)
            {
                char err[100] = {0};
                pcap_t* handle = pcap_open_live(interface_descriptor.c_str(), 65536, 1, 0, err);
                pcap_dumper_t* pcap_dumper = pcap_dump_open(handle, "/tmp/session.pcap");
                log::info("--- SNIFFING %s ---", interface_descriptor.c_str());

                if (handle == NULL) {
                    log::fatal("Couldn't open %s : %s", interface_descriptor.c_str(), err);
                }

                if (pcap_dumper == NULL) {
                    log::fatal("Failed to open session PCAP file");
                }

                pcap_ctx ctx = {.handle = handle, .dumper = pcap_dumper};
                auto start = system_clock::now();
                auto end = system_clock::now();
                duration<double> elapsed = end - start;
                log::info("Running capture for %lus...", seconds);

                while (elapsed.count() < seconds) {
                    end = system_clock::now();
                    elapsed = end - start;
                    pcap_dispatch(handle, -1, process_packet, (u_char*) &ctx);
                }

                // pcap_dump_close(pcap_dumper);
                log::info("--- END SNIFFING %s ---", interface_descriptor.c_str());
            }

            /**
             * Start packet capture on interface names
             * @param interface_descriptors: interface names
             */
            void sniff(const vector<string>& interface_descriptors, size_t seconds)
            {
                // TODO: Vector of threads/atomic bool
                if (interface_descriptors.size() > 1) {
                    log::error("TODO: Multiple threads unsupported");
                    exit(-1);
                }

                for (const string& interface_descriptor : interface_descriptors) {
                    threads.push_back(thread([this, interface_descriptor, seconds] {
                        sniff(interface_descriptor, seconds);
                        thread_stopped = true;
                    }));
                }
            }

            /* TODO:
            void stop()
            {
                for (thread& t : threads)
                    t.join();

                thread_stopped = true;
                wait();
            }*/

            /* TODO:
            void wait()
            {
                while (!thread_stopped)
                    ;
            }*/

          private:
            vector<thread> threads;
            pcap_if_t* all_interfaces;
            atomic<bool> thread_stopped;
            vector<string> _interfaces;
            static pcap_dumper_t* pcap_dumper;

            /**
             * Main handler for different packet types
             * @param args: unused
             * @param pcap_pkthdr: header for packet from pcap
             * @param header: packet body
             */
            static void process_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* body)
            {

                pcap_ctx* ctx = (pcap_ctx*) args;
                pcap_dump((u_char*) ctx->dumper, header, body);

                struct iphdr* iph = (struct iphdr*) (body + sizeof(struct ethhdr));
                switch (iph->protocol) {
                    case ICMP:
                        dump_icmp_packet(body);
                        break;
                    case TCP:
                        dump_tcp_packet(body);
                        break;
                    case UDP:
                        dump_udp_packet(body);
                        break;
                    case IGMP: // TODO
                    default:
                        break;
                }
            }

            /**
             * Dump ethernet header
             * @param header: packet header
             */
            static void dump_ethernet_header(const u_char* header)
            {
                struct ethhdr* eth = (struct ethhdr*) header;
                log::info("Ethernet Header");
                log::info("   |-Destination Address  : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->h_dest[0],
                          eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
                log::info("   |-Source Address       : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->h_source[0],
                          eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4],
                          eth->h_source[5]);
                log::info("   |-Protocol             : %u ", (unsigned short) eth->h_proto);
            }

            /**
             * Dump IP header
             * @param packet: header
             */
            static void dump_ip_header(const u_char* header)
            {
                dump_ethernet_header(header);
                struct iphdr* iph = (struct iphdr*) (header + sizeof(struct ethhdr));
                struct sockaddr_in source, dest;
                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = iph->saddr;
                memset(&dest, 0, sizeof(dest));
                dest.sin_addr.s_addr = iph->daddr;
                log::info("IP Header");
                log::info("   |-IP Version           : %d", (unsigned int) iph->version);
                log::info("   |-IP Header Length     : %d DWORDS or %d Bytes", (unsigned int) iph->ihl,
                          ((unsigned int) (iph->ihl)) * 4);
                log::info("   |-Type Of Service      : %d", (unsigned int) iph->tos);
                log::info("   |-IP Total Length      : %d  Bytes(Size of Packet)", ntohs(iph->tot_len));
                log::info("   |-Identification       : %d", ntohs(iph->id));
                log::info("   |-TTL                  : %d", (unsigned int) iph->ttl);
                log::info("   |-Protocol             : %d", (unsigned int) iph->protocol);
                log::info("   |-Checksum             : %d", ntohs(iph->check));
                log::info("   |-Source IP            : %s", inet_ntoa(source.sin_addr));
                log::info("   |-Destination IP       : %s", inet_ntoa(dest.sin_addr));
            }

            /**
             * Dump TCP packet
             * @param packet: packet
             */
            static void dump_tcp_packet(const u_char* packet)
            {
                unsigned short iphdrlen;
                struct iphdr* iph = (struct iphdr*) (packet + sizeof(struct ethhdr));
                iphdrlen = iph->ihl * 4;
                struct tcphdr* tcph = (struct tcphdr*) (packet + iphdrlen + sizeof(struct ethhdr));
                log::info("--- TCP ---");
                dump_ip_header(packet);
                log::info("TCP Header");
                log::info("   |-Source Port          : %u", ntohs(tcph->source));
                log::info("   |-Destination Port     : %u", ntohs(tcph->dest));
                log::info("   |-Sequence Number      : %u", ntohl(tcph->seq));
                log::info("   |-Acknowledge Number   : %u", ntohl(tcph->ack_seq));
                log::info("   |-Header Length        : %d DWORDS or %d BYTES", (unsigned int) tcph->doff,
                          (unsigned int) tcph->doff * 4);
                log::info("   |-Urgent Flag          : %d", (unsigned int) tcph->urg);
                log::info("   |-Acknowledgement Flag : %d", (unsigned int) tcph->ack);
                log::info("   |-Push Flag            : %d", (unsigned int) tcph->psh);
                log::info("   |-Reset Flag           : %d", (unsigned int) tcph->rst);
                log::info("   |-Synchronise Flag     : %d", (unsigned int) tcph->syn);
                log::info("   |-Finish Flag          : %d", (unsigned int) tcph->fin);
                log::info("   |-Window               : %d", ntohs(tcph->window));
                log::info("   |-Checksum             : %d", ntohs(tcph->check));
                log::info("   |-Urgent Pointer       : %d", tcph->urg_ptr);
                log::info("--- END TCP ---");
            }

            /**
             * Dump UDP packet
             * @param buffer: packet
             */
            static void dump_udp_packet(const u_char* packet)
            {
                unsigned short iphdrlen;
                struct iphdr* iph = (struct iphdr*) (packet + sizeof(struct ethhdr));
                iphdrlen = iph->ihl * 4;
                struct udphdr* udph = (struct udphdr*) (packet + iphdrlen + sizeof(struct ethhdr));
                log::info("--- UDP ---");
                dump_ip_header(packet);
                log::info("UDP Header");
                log::info("   |-Source Port          : %d", ntohs(udph->source));
                log::info("   |-Destination Port     : %d", ntohs(udph->dest));
                log::info("   |-UDP Length           : %d", ntohs(udph->len));
                log::info("   |-UDP Checksum         : %d", ntohs(udph->check));
                log::info("--- END UDP ---");
            }

            /**
             * Dump ICMP packet
             * @param packet: packet
             */
            static void dump_icmp_packet(const u_char* packet)
            {
                unsigned short iphdrlen;
                struct iphdr* iph = (struct iphdr*) (packet + sizeof(struct ethhdr));
                iphdrlen = iph->ihl * 4;
                struct icmphdr* icmph = (struct icmphdr*) (packet + iphdrlen + sizeof(struct ethhdr));
                log::info("--- ICMP ---");
                dump_ip_header(packet);
                log::info("ICMP Header");
                log::info("   |-Type                 : %d", (unsigned int) (icmph->type));

                if ((unsigned int) (icmph->type) == 11) {
                    log::info("  (TTL Expired)");
                } else if ((unsigned int) (icmph->type) == ICMP_ECHOREPLY) {
                    log::info("  (ICMP Echo Reply)");
                }

                log::info("   |-Code                 : %d", (unsigned int) (icmph->code));
                log::info("   |-Checksum             : %d", ntohs(icmph->checksum));
                log::info("--- END ICMP ---");
            }
        };
    } // namespace collect
} // namespace recon
