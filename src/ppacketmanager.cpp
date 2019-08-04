#include "ppacketmanager.h"

namespace pnetwork {

u_int8_t* PPacketManager::buildARP(
        u_int8_t* _dst_mac,
        u_int8_t* _src_mac,
        u_int16_t _op_code,
        u_int8_t* _sender_mac,
        u_int32_t _sender_ip,
        u_int8_t* _target_mac,
        u_int32_t _target_ip) {

    /* Build Ethernet(Layer2) */
    PEthernet ether;
    ether.setDstMac(_dst_mac);
    ether.setSrcMac(_src_mac);
    ether.setEtherType(htons(ETHERTYPE_ARP));

    /* BUild ARP(Layer3) */
    PArp arp;
    arp.setHardwareType(htons(ARPHRD_ETHER));
    arp.setProtocolType(htons(ETHERTYPE_IP));
    arp.setHardwareSize(0x06);
    arp.setProtocolSize(0x04);
    arp.setOpCode(htons(_op_code));
    arp.setSenderMac(_sender_mac);
    arp.setSenderIp(_sender_ip);
    arp.setTargetMac(_target_mac);
    arp.setTargetIp(_target_ip);

    u_int8_t* packet = reinterpret_cast<u_int8_t*>(malloc(PEthernet::length() + PArp::length()));
    memcpy(&packet[0], ether.toString(), PEthernet::length());
    memcpy(&packet[PEthernet::length()], arp.toString(), PArp::length());
    return packet;
}

u_int16_t PPacketManager::getEtherType(const u_int8_t* _packet) {
    libnet_ethernet_hdr* ether = reinterpret_cast<libnet_ethernet_hdr*>(const_cast<u_int8_t*>(_packet));
    u_int16_t h_type = ntohs(ether->ether_type);
    return h_type;
}

u_int32_t PPacketManager::getArpSenderIp(const u_int8_t* _packet) {
    PArp arp = PArp(_packet + PEthernet::length());
    return arp.getSenderIp();
}

void PPacketManager::getArpSenderMac(const u_int8_t* _packet,  u_int8_t* _sender_mac) {
    PArp arp = PArp(_packet + PEthernet::length());
    arp.getSenderMac(_sender_mac);
}


}
