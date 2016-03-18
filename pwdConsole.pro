QT += core
QT += concurrent
QT -= gui

TARGET = pwdConsole
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    pwdgenerator.cpp \
    signalhandler.cpp

HEADERS += \
    pwdgenerator.h \
    signalhandler.h

