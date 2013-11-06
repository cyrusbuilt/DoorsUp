#ifndef DOORSUP_H
#define DOORSUP_H
// Board = Arduino Uno
#define __AVR_ATmega328P__
#define ARDUINO 103
#define __AVR__
#define F_CPU 16000000L
#define __cplusplus
#define __attribute__(x)
#define __inline__
#define __asm__(x)
#define __extension__
#define __ATTR_PURE__
#define __ATTR_CONST__
#define __inline__
#define __asm__
#define __volatile__
#define __builtin_va_list
#define __builtin_va_start
#define __builtin_va_end
#define __DOXYGEN__
#define prog_void
#define PGM_VOID_P int
#define NOINLINE __attribute__((noinline))

#define WIN64
// #define WIN32
// #define DARWIN
// #define LINUX

typedef unsigned char byte;
extern "C" void __cxa_pure_virtual() {;}

void printSDErrorMessage(uint8_t e, bool eol = true);
void statusLedSDErrorFlash();
void statusLedNetworkWarnFlash();
void setNetworkDefaults();
void readConfig();
void webRequestHandler(WebServer &server, WebServer::ConnectionType type, char *url, bool isUrlComplete);
void initNetwork();
void output(WebServer &server, char* data, bool newLine);
void output(WebServer &server, int number, bool newLine);
bool isOpen(int pinNumber);
void notifyViaEmail(const String& to, const String& subject, const String& body);
void notifyViaEmail(const char* subject, const char* body);
void notifyViaSms(const char* subject, const char* body);
void doorOpenNotificationHandler();
void watchDogNotificationHandler();
void configureStatusPin(int pinNumber);
//
//

#if defined(WIN64)
#include "C:\Program Files (x86)\Arduino\hardware\arduino\variants\standard\pins_arduino.h"
#include "C:\Program Files (x86)\Arduino\hardware\arduino\cores\arduino\arduino.h"
#elif defined(WIN32)
#include "C:\Program Files\Arduino\hardware\arduino\variants\standard\pins_arduino.h"
#include "C:\Program Files\Arduino\hardware\arduino\cores\arduino\arduino.h"
#elif defined(DARWIN)
// TODO figure out mac paths (/Applications/Arduino.app/Contents/Resources/Java/hardware/arduino/ ..... ?
#elif defined(LINUX)
// TODO figure *NIX paths (?????)
#endif
#include "DoorsUp.ino"
#endif // DOORSUP_H
