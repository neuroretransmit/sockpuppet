#include <gtest/gtest.h>

#include "sockpuppet/recon/collect/arp.h"

using namespace ::testing;
using namespace recon::collect;

TEST(ARP, ReadCache)
{
    recon::collect::arp a;
    vector<arp_entry> cache;
    int rc = a.read_cache(cache);
    ASSERT_EQ(0, rc);
}
