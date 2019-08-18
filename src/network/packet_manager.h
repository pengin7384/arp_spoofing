#pragma once
#include <libnet.h>
#include "header/headers.h"


namespace spoof {

class PacketManager {

public:

    u_int8_t *buildARP(u_int8_t *dst_mac, u_int8_t *src_mac, u_int16_t op_code,
                       u_int8_t *sender_mac, u_int32_t sender_ip, u_int8_t *target_mac,
                       u_int32_t target_ip);
    u_int8_t *makeRelayPacket(const u_int8_t *packet, u_int32_t len, u_int8_t *my_mac, u_int8_t *tg_mac);
    bool isMacEqual(const u_int8_t *src_mac, const u_int8_t *dst_mac);
    bool isArpRequest(const u_int8_t *packet, u_int32_t tg_ip);
    u_int16_t getEtherType(const u_int8_t *packet);
    u_int32_t getArpSenderIp(const u_int8_t *packet);
    void getArpSenderMac(const u_int8_t *packet,  u_int8_t *sender_mac);

};

}
