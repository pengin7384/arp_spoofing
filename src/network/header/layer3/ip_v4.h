#pragma once
#include "src/network/header/header_base.h"

namespace spoof {

class IPv4 : public HeaderBase {
    libnet_ipv4_hdr *data;

public:

    IPv4(void);
    IPv4(const u_int8_t *ip_v4_packet);
    ~IPv4(void);

    virtual u_int8_t *toString(void);
    static size_t length(void)
    {
        return sizeof(libnet_ipv4_hdr);
    }

    u_int32_t getDstIp(void);

};



}
