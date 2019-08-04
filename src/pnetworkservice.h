#pragma once
#include <iostream>
#include <libnet.h>
#include <pcap.h>
#include <sys/socket.h>
#include "ppacketmanager.h"

namespace pnetwork {

/**
* @brief The PNetworkService class
* @details Process networking like 'open', 'send', 'receive'
*/
class PNetworkService {
private:
    static PNetworkService* mInstance;
    PPacketManager mPacketManager;

    PNetworkService();
    ~PNetworkService();

public:
    static PNetworkService* getInstance() {
        if(mInstance == nullptr) {
            mInstance = new PNetworkService();
        }
        return mInstance;
    }

    static void destroy() {
        delete mInstance;
        mInstance = nullptr;
    }

    int receiveARP(pcap* _fp, const char* _target_ip, u_int8_t* _sender_mac);

    /* Return value (Success:0) */
    int requestARP(pcap_t* _fp, const char* _interface, const char* _ip);
    int spoofARP(const char* _interface, const char* _sender_ip, const char* _target_ip);
    int sendSpoofingARP(pcap_t* _fp,
                        const char* _interface,
                        const char* _sender_ip,
                        u_int8_t* _sender_mac,
                        const char* _target_ip);

    u_int8_t* getInterfaceMac(const char* _interface);

    u_int32_t getMyIp(const char* _interface);

    pcap_t* open(const char* _interface);

};



}
