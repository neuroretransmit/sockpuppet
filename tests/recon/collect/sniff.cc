#include <gtest/gtest.h>

#include "sockpuppet/recon/collect/sniff.h"

using namespace recon::collect;

TEST(Sniff, EnumerateInterfaces)
{
    packet_capture p;
    p.enumerate();
    vector<string> iface_descriptor_to_name = p.interfaces();
    p.dump_interfaces();
    ASSERT_GT(iface_descriptor_to_name.size(), 0);
}

// TODO: Make detachable killed threads
// CI should be running as root so permissions should not fail.
// thread will start detached so once sniffing, test should finish.
// TEST(Sniff, PacketCaptureInterface1)
// {
//     packet_capture p;
//     vector<string> interfaces = p.interfaces();
//     p.sniff(interfaces[0]);
// }
