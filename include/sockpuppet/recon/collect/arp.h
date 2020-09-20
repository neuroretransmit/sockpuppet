#pragma once

#include <cstddef>
#include <cstdio>
#include <string>
#include <vector>

#include <log/log.h>

using std::ifstream;
using std::string;
using std::vector;

// TODO: Remove and support other architectures.
#define LINUX

#ifdef LINUX
#define xstr(s) str(s)
#define str(s)
#define ARP_LINE_FORMAT "%" xstr(ARP_STRING_LEN) "s %*s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s"
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
        
        class arp
        {
        public:
            static int read_cache(vector<arp_entry>& entries)
            {
                FILE* arp_cache = fopen(ARP_CACHE_LOCATION, "r");
                
                if (!arp_cache) {
                    log::error("Failed to open ARP cache, not Linux?");
                    return -1;
                }

                /* Ignore the first line, which contains the header */
                char header[ARP_BUFFER_LENGTH];
                if (!fgets(header, sizeof(header), arp_cache))
                    return 1;

                char ip[ARP_BUFFER_LENGTH], mac[ARP_BUFFER_LENGTH], device[ARP_BUFFER_LENGTH];
                int count = 0;
                
                log::info("--- READ ARP CACHE ---");
                while (3 == fscanf(arp_cache, ARP_LINE_FORMAT, ip, mac, device)) {
                    arp_entry entry = {
                        .ip = ip,
                        .device = device,
                        .mac = mac
                    };
                    entries.push_back(entry);
                    log::info("%03d: Mac Address of [%s] on [%s] is \"%s\"\n",
                            ++count, ip, device, mac);
                    
                }
                log::info("--- END READ ARP CACHE ---");
                
                fclose(arp_cache);
                return 0;
            }
        };
    }
}
