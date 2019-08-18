TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += \
    -lpcap \
    -pthread

SOURCES += \
    src/network/header/header_base.cpp \
    src/network/header/layer2/ethernet.cpp \
    src/network/header/layer3/arp.cpp \
    src/main.cpp \
    src/network/header/layer3/ip_v4.cpp \
    src/network/network_service.cpp \
    src/network/packet_manager.cpp \
    src/util.cpp

HEADERS += \
    src/network/header/header_base.h \
    src/network/header/headers.h \
    src/network/header/layer2/ethernet.h \
    src/network/header/layer3/arp.h \
    src/network/header/layer3/ip_v4.h \
    src/network/network_service.h \
    src/network/packet_manager.h \
    src/util.h

