#pragma once

#include <cstddef>
#include <cstdio>
#include <string>
#include <vector>

#include <log/log.h>

using std::ifstream;
using std::string;
using std::vector;

#define LINUX

#ifdef LINUX
#define xstr(s) str(s)
#define str(s)
#define ARP_LINE_FORMAT                                                                                      \
    "%" xstr(ARP_STRING_LEN) "s %*s %*s  %" xstr(ARP_STRING_LEN) "s %*s  %" xstr(ARP_STRING_LEN) "s"
#endif

namespace recon
{
    namespace collect
    {
#ifdef LINUX
        static const char* ARP_CACHE_LOCATION = "/proc/net/arp";
        static const size_t ARP_ENTRY_LENGTH = 1023;
        static const size_t ARP_BUFFER_LENGTH = ARP_ENTRY_LENGTH + 1;
#endif

        typedef struct {
            char* ip;
            char* device;
            char* mac;
        } arp_entry;

        /// ARP cache reader
        class arp
        {
          public:
            /**
             * Read ARP cache (Linux only) and store in passed vector
             * @param entries: vector of arp_entry to store results
             */
            static int read_cache(vector<arp_entry>& entries)
            {
                // TODO: C++ify and stop using FILE. Look up how to fscanf using ifstream
                FILE* arp_cache = fopen(ARP_CACHE_LOCATION, "r");

                if (!arp_cache) {
                    log::error("Failed to open ARP cache, not Linux?");
                    return -1;
                }

                // Ignore header
                char header[ARP_BUFFER_LENGTH];
                if (!fgets(header, sizeof(header), arp_cache))
                    return 1;
                char ip[ARP_BUFFER_LENGTH];
                char mac[ARP_BUFFER_LENGTH];
                char device[ARP_BUFFER_LENGTH];

                log::info("--- READ ARP CACHE ---");
                int count = 0;
                while (3 == fscanf(arp_cache, ARP_LINE_FORMAT, ip, mac, device)) {
                    arp_entry entry = {.ip = ip, .device = device, .mac = mac};
                    entries.push_back(entry);
                    log::info("%03d: Mac Address of [%s] on [%s] is \"%s\"", ++count, ip, device, mac);
                }
                log::info("--- END READ ARP CACHE ---");

                fclose(arp_cache);
                return 0;
            }
        };
    } // namespace collect
} // namespace recon
