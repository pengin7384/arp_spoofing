#include "ip_v4.h"

namespace spoof {


IPv4::IPv4(void)
{
    data = new libnet_ipv4_hdr();
}

IPv4::IPv4(const u_int8_t *ip_v4_packet)
{
    data = new libnet_ipv4_hdr();
    memcpy(data, ip_v4_packet, sizeof(libnet_ipv4_hdr));
}

IPv4::~IPv4(void)
{
    delete data;
}

u_int8_t *IPv4::toString(void)
{
    return reinterpret_cast<u_int8_t*>(data);
}


u_int32_t IPv4::getDstIp(void)
{
    return data->ip_dst.s_addr;
}


}
