QT += core
QT -= gui

CONFIG += c++11

TARGET = mal_site
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    thread.cpp \
    thread.cpp \
    thread.cpp

unix{
    LIBS += -L/path/libpcap
    LIBS += -lpcap

    INCLUDEPATH += /path/to/libpcap/headers
    DEPENDPATH += /path/to/libpcap/headers
}

win32{
    LIBS += -L'C://Program Files (x86)/Microsoft Visual Studio 14.0/VC/lib/x64/' -lwpcap
    LIBS += -lws2_32

    INCLUDEPATH +='C://Program Files (x86)/Microsoft Visual Studio 14.0/VC/include'
    DEPENDPATH += 'C://Program Files (x86)/Microsoft Visual Studio 14.0/VC/lib/x64'
}

HEADERS += \
    libnet\libnet-headers.h \
    libnet\libnet-macros.h \
    libnet\libnet-asn1.h \
    libnet\libnet-functions.h \
    libnet\libnet-structures.h \
    libnet\libnet-types.h \
    libnet/in_systm.h \
    libnet/libnet-asn1.h \
    libnet/libnet-functions.h \
    libnet/libnet-headers.h \
    libnet/libnet-macros.h \
    libnet/libnet-structures.h \
    libnet/libnet-types.h \
    packetmanager.h \
    thread.h \
    packetmanager.h \
    thread.h \
    packetmanager.h \
    thread.h \
    libnet/in_systm.h \
    libnet/libnet-asn1.h \
    libnet/libnet-functions.h \
    libnet/libnet-headers.h \
    libnet/libnet-macros.h \
    libnet/libnet-structures.h \
    libnet/libnet-types.h

