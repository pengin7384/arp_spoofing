TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += \
    -lpcap \
    -pthread

SOURCES += \
    src/header/layer2/pethernet.cpp \
    src/header/layer3/parp.cpp \
    src/header/pheaderbase.cpp \
    src/pmain.cpp \
    src/pnetworkservice.cpp \
    src/ppacketmanager.cpp

HEADERS += \
    src/header/layer3/parp.h \
    src/header/layer2/pethernet.h \
    src/header/pheader.h \
    src/header/pheaderbase.h \
    src/pnetworkservice.h \
    src/ppacketmanager.h \
    src/util/pstring.h

