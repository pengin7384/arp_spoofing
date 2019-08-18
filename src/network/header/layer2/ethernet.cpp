#include "ethernet.h"

namespace spoof {

Ethernet::Ethernet(void)
{
    data = new network_ethernet_header();
}

Ethernet::Ethernet(const u_int8_t *ethernet_packet)
{
    data = new network_ethernet_header();
    memcpy(data, ethernet_packet, sizeof(network_ethernet_header));
}

Ethernet::~Ethernet(void)
{
    delete data;
}

u_int8_t *Ethernet::toString(void)
{
    return reinterpret_cast<u_int8_t*>(data);
}

/* Getter */

void Ethernet::getDstMac(u_int8_t *dst_mac)
{
    memcpy(dst_mac, data->ether_dhost, ETHER_ADDR_LEN);
}

void Ethernet::getSrcMac(u_int8_t *src_mac)
{
    memcpy(src_mac, data->ether_shost, ETHER_ADDR_LEN);
}

u_int16_t Ethernet::getEtherType()
{
    return data->ether_type;
}


/* Setter */

void Ethernet::setDstMac(const u_int8_t *dst_mac)
{
    memcpy(data->ether_dhost, dst_mac, ETHER_ADDR_LEN);
}

void Ethernet::setSrcMac(const u_int8_t *src_mac)
{
    memcpy(data->ether_shost, src_mac, ETHER_ADDR_LEN);
}

void Ethernet::setEtherType(u_int16_t ether_type)
{
    data->ether_type = ether_type;
}
}
