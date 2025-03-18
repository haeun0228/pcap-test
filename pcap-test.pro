TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += pcap-test.c
QT += core
INCLUDEPATH += /home/eileen/Qt6.8.2/6.8.2/gcc_64/include
LIBS += -L/home/eileen/Qt6.8.2/6.8.2/gcc_64/lib -lQt6Core

HEADERS += \
    ether.h \
    ip.h \
    mac.h \
    pch.h \
    tcp.h
