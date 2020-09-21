#include <gtest/gtest.h>

#include "sockpuppet/recon/scan/syn.h"

using namespace recon::scan;

// TODO: Possibly fragile, need to see if CI has open ports
TEST(Scan, SYNQuickScan)
{
    syn syn_scanner;
    vector<bool> open = syn_scanner.quick_scan("127.0.0.1");
    bool is_one_open = false;
    for (bool port : open)
        is_one_open |= port;
    ASSERT_EQ(true, is_one_open);
}
