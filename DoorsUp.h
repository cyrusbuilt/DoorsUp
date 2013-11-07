/*
 *DoorsUp
  v1.0a

  Author:
       Chris Brunner <cyrusbuilt at gmail dot com>

  Copyright (c) 2013 CyrusBuilt

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef DOORSUP_H
#define DOORSUP_H
// Board = Arduino Mega
#define __AVR_ATmega2560__
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
void configKeyReadFailure(IniFile &ini, char *key);
void readConfig();
void webRequestHandler(WebServer &server, WebServer::ConnectionType type, char *url, bool isUrlComplete);
void webRequestFailureHandler(WebServer &server, WebServer::ConnectionType type, char *url, bool isUrlComplete);
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
#include "/Applications/Arduino.app/Contents/Resources/Java/hardware/arduino/variants/standard/pins_arduino.h"
#include "/Applications/Arduino.app/Contents/Resources/Java/hardware/arduino/cores/arduino/arduino.h"
#elif defined(LINUX)
// TODO figure *NIX paths (?????)
#endif
#include "DoorsUp.ino"
#endif // DOORSUP_H
