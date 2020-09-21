#pragma once

#include <arpa/inet.h>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <map>
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

using std::atomic;
using std::hex;
using std::make_pair;
using std::map;
using std::setfill;
using std::setw;
using std::stringstream;
using std::thread;

// TODO: Dump to pcap file. Allow appending
// https://stackoverflow.com/questions/10133017/stop-capture-data-with-libpcap-and-save-it-in-a-file
namespace recon
{
    namespace collect
    {
        /// Packet type enumeration
        typedef enum { ICMP = 1, IGMP = 2, TCP = 6, UDP = 17 } packet_type;

        // Packet capture interfaces detected by libpcap
        class packet_capture
        {
          private:
            vector<thread> threads;
            pcap_if_t* all_interfaces;
            atomic<bool> thread_stopped;
            vector<string> _interfaces;

            /**
             * Main handler for different packet types
             * @param args: unused
             * @param pcap_pkthdr: header for packet from pcap
             * @param buffer: packet body
             */
            static void process_packet(__attribute__((unused)) u_char* args,
                                       __attribute__((unused)) const struct pcap_pkthdr* header,
                                       const u_char* buffer)
            {
                struct iphdr* iph = (struct iphdr*) (buffer + sizeof(struct ethhdr));
                switch (iph->protocol) {
                    case ICMP:
                        dump_icmp_packet(buffer);
                        break;
                    case TCP:
                        dump_tcp_packet(buffer);
                        break;
                    case UDP:
                        dump_udp_packet(buffer);
                        break;
                    case IGMP: // TODO
                    default:
                        break;
                }
            }

            /**
             * Dump ethernet header
             * @param buffer: packet header
             */
            static void dump_ethernet_header(const u_char* buffer)
            {
                struct ethhdr* eth = (struct ethhdr*) buffer;
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
             * @param buffer: header
             */
            static void dump_ip_header(const u_char* buffer)
            {
                dump_ethernet_header(buffer);
                struct iphdr* iph = (struct iphdr*) (buffer + sizeof(struct ethhdr));
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
                // fprintf(logfile , "   |-Reserved ZERO Field   : %d",(unsigned
                // int)iphdr->ip_reserved_zero); fprintf(logfile , "   |-Dont Fragment Field   :
                // %d",(unsigned int)iphdr->ip_dont_fragment); fprintf(logfile , "   |-More Fragment Field :
                // %d",(unsigned int)iphdr->ip_more_fragment);
                log::info("   |-TTL                  : %d", (unsigned int) iph->ttl);
                log::info("   |-Protocol             : %d", (unsigned int) iph->protocol);
                log::info("   |-Checksum             : %d", ntohs(iph->check));
                log::info("   |-Source IP            : %s", inet_ntoa(source.sin_addr));
                log::info("   |-Destination IP       : %s", inet_ntoa(dest.sin_addr));
            }

            /**
             * Dump TCP packet
             * @param buffer: packet
             */
            static void dump_tcp_packet(const u_char* buffer)
            {
                unsigned short iphdrlen;
                struct iphdr* iph = (struct iphdr*) (buffer + sizeof(struct ethhdr));
                iphdrlen = iph->ihl * 4;
                struct tcphdr* tcph = (struct tcphdr*) (buffer + iphdrlen + sizeof(struct ethhdr));

                log::info("--- TCP ---");
                dump_ip_header(buffer);
                log::info("TCP Header");
                log::info("   |-Source Port          : %u", ntohs(tcph->source));
                log::info("   |-Destination Port     : %u", ntohs(tcph->dest));
                log::info("   |-Sequence Number      : %u", ntohl(tcph->seq));
                log::info("   |-Acknowledge Number   : %u", ntohl(tcph->ack_seq));
                log::info("   |-Header Length        : %d DWORDS or %d BYTES", (unsigned int) tcph->doff,
                          (unsigned int) tcph->doff * 4);
                // fprintf(logfile , "   |-CWR Flag : %d",(unsigned int)tcph->cwr);
                // fprintf(logfile , "   |-ECN Flag : %d",(unsigned int)tcph->ece);
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
            static void dump_udp_packet(const u_char* buffer /*, int size*/)
            {
                unsigned short iphdrlen;
                struct iphdr* iph = (struct iphdr*) (buffer + sizeof(struct ethhdr));
                iphdrlen = iph->ihl * 4;
                struct udphdr* udph = (struct udphdr*) (buffer + iphdrlen + sizeof(struct ethhdr));

                log::info("--- UDP ---");
                dump_ip_header(buffer);
                log::info("UDP Header");
                log::info("   |-Source Port          : %d", ntohs(udph->source));
                log::info("   |-Destination Port     : %d", ntohs(udph->dest));
                log::info("   |-UDP Length           : %d", ntohs(udph->len));
                log::info("   |-UDP Checksum         : %d", ntohs(udph->check));
                log::info("--- END UDP ---");
            }

            /**
             * Dump ICMP packet
             * @param buffer: packet
             */
            static void dump_icmp_packet(const u_char* buffer)
            {
                unsigned short iphdrlen;
                struct iphdr* iph = (struct iphdr*) (buffer + sizeof(struct ethhdr));
                iphdrlen = iph->ihl * 4;
                struct icmphdr* icmph = (struct icmphdr*) (buffer + iphdrlen + sizeof(struct ethhdr));

                log::info("--- ICMP ---");
                dump_ip_header(buffer);
                log::info("ICMP Header");
                log::info("   |-Type                 : %d", (unsigned int) (icmph->type));

                if ((unsigned int) (icmph->type) == 11) {
                    log::info("  (TTL Expired)");
                } else if ((unsigned int) (icmph->type) == ICMP_ECHOREPLY) {
                    log::info("  (ICMP Echo Reply)");
                }

                log::info("   |-Code                 : %d", (unsigned int) (icmph->code));
                log::info("   |-Checksum             : %d", ntohs(icmph->checksum));
                // fprintf(logfile , "   |-ID       : %d",ntohs(icmph->id));
                // fprintf(logfile , "   |-Sequence : %d",ntohs(icmph->sequence));
                log::info("--- END ICMP ---");
            }

          public:
            /// Enumerate available interfaces for packet capture
            int enumerate()
            {
                char err[100];

                if (pcap_findalldevs(&all_interfaces, err)) {
                    log::error("Unable to enumerate devices, terminating. > %s", err);
                    return -1;
                }

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
                if (_interfaces.size() == 0) {
                    enumerate();
                }

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
            static void sniff(const string& interface_descriptor)
            {
                char err[100];
                pcap_t* handle;

                // Open the device for sniffing
                log::info("--- START SNIFFING %s ---", interface_descriptor.c_str());
                handle = pcap_open_live(interface_descriptor.c_str(), 65536, 1, 0, err);

                if (handle == NULL) {
                    log::error("Couldn't open %s : %s", interface_descriptor.c_str(), err);
                    exit(1);
                }

                bool exit_thread = false;

                // TODO: Look at server code to create signal to kill thread.
                while (!exit_thread)
                    pcap_dispatch(handle, -1, process_packet, NULL);

                log::info("--- END SNIFFING %s ---", interface_descriptor.c_str());
            }

            /**
             * Start packet capture on interface names
             * @param interface_descriptors: interface names
             */
            void sniff(const vector<string>& interface_descriptors)
            {
                // TODO: Vector of threads/atomic bool
                if (interface_descriptors.size() > 1) {
                    log::error("TODO: Multiple threads unsupported");
                    exit(-1);
                }

                for (const string& interface_descriptor : interface_descriptors)
                    threads.push_back(thread([interface_descriptor] { sniff(interface_descriptor); }));
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
        };
    } // namespace collect
} // namespace recon
