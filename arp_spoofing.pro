TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        custom.cpp \
        main.cpp

HEADERS += \
    custom.h
