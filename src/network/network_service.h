#pragma once
#include <pcap.h>
#include <libnet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "src/network/packet_manager.h"

namespace spoof {

class NetworkService {
    static NetworkService *instance;
    PacketManager packet_manager;
    u_int32_t cnt;
    u_int32_t *sd_ip;
    u_int32_t *tg_ip;
    u_int32_t my_ip;
    u_int8_t **sd_mac;
    u_int8_t **tg_mac;
    u_int8_t *my_mac;
    u_int8_t *bc_mac;
    u_int8_t *uk_mac;

public:
    static NetworkService *getInstance(void)
    {
        if (instance == nullptr) {
            instance = new NetworkService();
        }
        return instance;
    }

    static void destoryInstance(void)
    {
        delete instance;
        instance = nullptr;
    }

    NetworkService(void);
    ~NetworkService(void);
    void init(u_int32_t cnt);
    pcap_t *openPcap(const char* if_name);
    int32_t requestArp(pcap_t *pt, u_int32_t src_ip, u_int32_t dst_ip, u_int8_t *dst_mac);
    int32_t receiveArp(pcap_t *pt, u_int32_t sd_ip, u_int8_t *rv_mac);
    int32_t sendSpoofingArp(pcap_t *pt, u_int32_t sd_ip, u_int8_t *sd_mac, u_int32_t tg_ip);
    int32_t relayPacket(pcap_t *pt);
    int32_t spoofArp(const char *if_name, int ip_cnt, char **sd_ip, char **tg_ip);
    int32_t getMac(pcap_t *pt, u_int32_t src_ip, u_int8_t *dst_mac, u_int32_t dst_ip);
    int32_t getInterfaceMac(const char *if_name, u_int8_t *mac);
    u_int32_t getMyIp(const char *if_name);
};

}
