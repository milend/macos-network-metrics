// MIT License
//
// Copyright (c) 2017 Milen Dzhumerov
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_mib.h>
#include <net/route.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

struct NetworkMetrics {
    uint64_t totalInputBytes, totalOutputBytes;
    uint64_t totalInputPackets, totalOutputPackets;
};

static struct NetworkMetrics GetNetworkMetrics(bool useIfmibData) {
    int mib[] = {
        CTL_NET,
        PF_ROUTE,
        0,
        0,
        NET_RT_IFLIST2,
        0
    };

    size_t length;
    if (sysctl(mib, 6, NULL, &length, NULL, 0) < 0) {
        fprintf(stderr, "sysctl: %s\n", strerror(errno));
        exit(1);
    }

    uint8_t *buffer = (uint8_t*)malloc(length);
    if (sysctl(mib, 6, buffer, &length, NULL, 0) < 0) {
        fprintf(stderr, "sysctl: %s\n", strerror(errno));
        exit(1);
    }

    struct NetworkMetrics metrics = (struct NetworkMetrics){};
    for (uint8_t *next = buffer, *end = buffer + length; next < end; ) {
        struct if_msghdr *message = (struct if_msghdr *)next;

        if (message->ifm_type == RTM_IFINFO2) {
            struct if_msghdr2 *message2 = (struct if_msghdr2 *)message;
            // To get the interface name, use `if_indextoname()`
            // and pass `message2->ifm_index` as the interface index.
            //
            // To detect the loopback interface, use `message2->ifm_flags`
            // and check for the `IFF_LOOPBACK` flag.
            if (useIfmibData) {
                int mib2[] = {
                    CTL_NET,
                    PF_LINK,
                    NETLINK_GENERIC,
                    IFMIB_IFDATA,
                    message->ifm_index,
                    IFDATA_GENERAL
                };

                struct ifmibdata mibdata = (struct ifmibdata){};
                size_t mibdata_len = sizeof(mibdata);
                if (sysctl(mib2, 6, &mibdata, &mibdata_len, NULL, 0) < 0) {
                    fprintf(stderr, "sysctl: %s\n", strerror(errno));
                    exit(1);
                }

                // The fields in `ifmd_data` do _not_ suffer from 4GiB truncation.
                // In addition, the 1KiB batching present in the `ifm_data` does
                // not apply to this API (though that seems like an security
                // issue that hasn't yet been fixed).
                metrics.totalInputPackets += mibdata.ifmd_data.ifi_ipackets;
                metrics.totalOutputPackets += mibdata.ifmd_data.ifi_opackets;
                metrics.totalInputBytes += mibdata.ifmd_data.ifi_ibytes;
                metrics.totalOutputBytes += mibdata.ifmd_data.ifi_obytes;
            } else {
                // The fields in `ifm_data` suffer from 4GiB truncation on macOS 13.2.1 (at the time of writing).
                metrics.totalInputPackets += message2->ifm_data.ifi_ipackets;
                metrics.totalOutputPackets += message2->ifm_data.ifi_opackets;
                metrics.totalInputBytes += message2->ifm_data.ifi_ibytes;
                metrics.totalOutputBytes += message2->ifm_data.ifi_obytes;
            }
        }

        next += message->ifm_msglen;
    }

    return metrics;
}

int main(int argc, const char *argv[]) {
    bool useIfmibData = true;
    struct NetworkMetrics lastMetrics = GetNetworkMetrics(useIfmibData);

    while (1) {
        sleep(1);
        struct NetworkMetrics currentMetrics = GetNetworkMetrics(useIfmibData);

        printf("--- PACKETS ---\n");
        uint64_t inputPacketsDelta = currentMetrics.totalInputPackets - lastMetrics.totalInputPackets;
        uint64_t outputPacketsDelta = currentMetrics.totalOutputPackets - lastMetrics.totalOutputPackets;
        printf("  Input (Download): %llu (total), %llu (delta)\n", currentMetrics.totalInputPackets, inputPacketsDelta);
        printf("  Output (Upload): %llu (total), %llu (delta)\n", currentMetrics.totalOutputPackets, outputPacketsDelta);

        // Byte metrics are rounded to the nearest 1KiB to avoid malicious programs to fingerprint the system.
        printf("--- BYTES ---\n");
        uint64_t inputBytesDelta = currentMetrics.totalInputBytes - lastMetrics.totalInputBytes;
        uint64_t outputBytesDelta = currentMetrics.totalOutputBytes - lastMetrics.totalOutputBytes;
        printf("  Input (Download): %llu (total), %llu (delta)\n", currentMetrics.totalInputBytes, inputBytesDelta);
        printf("  Output (Upload): %llu (total), %llu (delta)\n", currentMetrics.totalOutputBytes, outputBytesDelta);

        // As of macOS 13.2.1, there's a bug in the kernel which truncates values at the 4GiB mark, tracked as rdar://106029568.
        if (currentMetrics.totalInputBytes < lastMetrics.totalInputBytes) {
            printf("!! INPUT OVERFLOW !!\n");
            printf("Before: %llu, After: %llu, Difference: %llu\n", lastMetrics.totalInputBytes, currentMetrics.totalInputBytes, lastMetrics.totalInputBytes - currentMetrics.totalInputBytes);
        }

        if (currentMetrics.totalOutputBytes < lastMetrics.totalOutputBytes) {
            printf("!! OUTPUT OVERFLOW !!\n");
            printf("Before: %llu, After: %llu, Difference: %llu\n", lastMetrics.totalOutputBytes, currentMetrics.totalOutputBytes, lastMetrics.totalOutputBytes - currentMetrics.totalOutputBytes);
        }

        printf("\n\n");

        lastMetrics = currentMetrics;
    }

    return 0;
}
