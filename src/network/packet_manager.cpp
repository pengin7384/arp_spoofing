#include "packet_manager.h"

namespace spoof {


u_int8_t *PacketManager::buildARP(u_int8_t *dst_mac, u_int8_t *src_mac, u_int16_t op_code,
                                  u_int8_t *sender_mac, u_int32_t sender_ip, u_int8_t *target_mac,
                                  u_int32_t target_ip)
{

    /* Build Ethernet(Layer2) */
    Ethernet ether;
    ether.setDstMac(dst_mac);
    ether.setSrcMac(src_mac);
    ether.setEtherType(htons(ETHERTYPE_ARP));

    /* BUild ARP(Layer3) */
    Arp arp;
    arp.setHardwareType(htons(ARPHRD_ETHER));
    arp.setProtocolType(htons(ETHERTYPE_IP));
    arp.setHardwareSize(0x06);
    arp.setProtocolSize(0x04);
    arp.setOpCode(htons(op_code));
    arp.setSenderMac(sender_mac);
    arp.setSenderIp(sender_ip);
    arp.setTargetMac(target_mac);
    arp.setTargetIp(target_ip);

    u_int8_t* packet = reinterpret_cast<u_int8_t*>(malloc(Ethernet::length() + Arp::length()));
    memcpy(&packet[0], ether.toString(), Ethernet::length());
    memcpy(&packet[Ethernet::length()], arp.toString(), Arp::length());
    return packet;
}

u_int8_t *PacketManager::makeRelayPacket(const u_int8_t *packet, u_int32_t len, u_int8_t *my_mac, u_int8_t *tg_mac)
{
    u_int8_t *rl_packet = reinterpret_cast<u_int8_t*>(malloc(len));

    memcpy(rl_packet, packet, len);

    libnet_ethernet_hdr* ether = reinterpret_cast<libnet_ethernet_hdr*>(const_cast<u_int8_t*>(rl_packet));
    ether->ether_type = htons(ETHERTYPE_IP);
    memcpy(ether->ether_shost, my_mac, ETHER_ADDR_LEN);
    memcpy(ether->ether_dhost, tg_mac, ETHER_ADDR_LEN);

    return rl_packet;
}

bool PacketManager::isMacEqual(const u_int8_t *src_mac, const u_int8_t *dst_mac)
{
    for (u_int32_t i = 0; i < 6; i++) {
        if (src_mac[i] != dst_mac[i]) {
            return false;
        }
    }
    return true;
}

bool PacketManager::isArpRequest(const u_int8_t *packet, u_int32_t tg_ip)
{
    Arp arp = Arp(packet + Ethernet::length());
    if (arp.getTargetIp() == tg_ip) {
        return true;
    }
    return false;
}

u_int16_t PacketManager::getEtherType(const u_int8_t *packet)
{
    libnet_ethernet_hdr* ether = reinterpret_cast<libnet_ethernet_hdr*>(const_cast<u_int8_t*>(packet));
    u_int16_t h_type = ntohs(ether->ether_type);
    return h_type;
}

u_int32_t PacketManager::getArpSenderIp(const u_int8_t *packet)
{
    Arp arp = Arp(packet + Ethernet::length());
    return arp.getSenderIp();
}

void PacketManager::getArpSenderMac(const u_int8_t *packet,  u_int8_t *sender_mac)
{
    Arp arp = Arp(packet + Ethernet::length());
    arp.getSenderMac(sender_mac);
}

}
