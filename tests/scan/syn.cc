#include <gtest/gtest.h>

#include "sockpuppet/scan/syn.h"

using namespace scanner::tcp;

// TODO: Less fragile test, just checking for DNS on router
TEST(SYNScan, TestPortIsOpen)
{
    scanner::tcp::syn s;
    ASSERT_TRUE(s.is_open("192.168.1.1", 53));
}
