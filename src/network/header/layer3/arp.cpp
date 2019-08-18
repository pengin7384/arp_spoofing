#include "arp.h"

namespace spoof  {

Arp::Arp(void)
{
    data = new network_arp_header();
}

Arp::Arp(const u_int8_t *arp_packet)
{
    data = new network_arp_header();
    memcpy(data, arp_packet, sizeof(network_arp_header));
}

Arp::~Arp(void)
{
    delete data;
    data = nullptr;
}

u_int8_t *Arp::toString(void)
{
    return reinterpret_cast<u_int8_t*>(data);
}


/* Getter */

u_int16_t Arp::getHardwareType(void)
{
    return data->arp_header.ar_hrd;
}

u_int16_t Arp::getProtocolType(void)
{
    return data->arp_header.ar_pro;
}

u_int8_t Arp::getHardwareSize(void)
{
    return data->arp_header.ar_hln;
}

u_int8_t Arp::getProtocolSize(void)
{
    return data->arp_header.ar_pln;
}

u_int16_t Arp::getOpCode(void)
{
    return data->arp_header.ar_op;
}

void Arp::getSenderMac(u_int8_t *sender_mac)
{
    memcpy(sender_mac, data->sender_mac, ETHER_ADDR_LEN);
}

u_int32_t Arp::getSenderIp(void)
{
    return data->sender_ip;
}

void Arp::getTargetMac(u_int8_t *target_mac)
{
    memcpy(target_mac, data->sender_mac, ETHER_ADDR_LEN);
}

u_int32_t Arp::getTargetIp(void)
{
    return data->target_ip;
}


/* Setter */

void Arp::setHardwareType(u_int16_t hdr_type)
{
    data->arp_header.ar_hrd = hdr_type;
}

void Arp::setProtocolType(u_int16_t pro_type)
{
    data->arp_header.ar_pro = pro_type;
}

void Arp::setHardwareSize(u_int8_t hdr_size)
{
    data->arp_header.ar_hln = hdr_size;
}

void Arp::setProtocolSize(u_int8_t pro_size)
{
    data->arp_header.ar_pln = pro_size;
}

void Arp::setOpCode(u_int16_t op_code)
{
    data->arp_header.ar_op = op_code;
}

void Arp::setSenderMac(u_int8_t *sender_mac)
{
    memcpy(data->sender_mac, sender_mac, ETHER_ADDR_LEN);
}

void Arp::setSenderIp(u_int32_t sender_ip)
{
    data->sender_ip = sender_ip;
}

void Arp::setTargetMac(u_int8_t *target_mac)
{
    memcpy(data->target_mac, target_mac, ETHER_ADDR_LEN);
}

void Arp::setTargetIp(u_int32_t target_ip)
{
    data->target_ip = target_ip;
}

}
