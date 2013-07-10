/*
  DoorsUp
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

#include <aes256.h>
#include <Arduino.h>
#include <Ethernet.h>
#include <EthernetClient.h>
#include <IniFile.h>
#include <IPAddress.h>
#include <SD.h>
#include <SPI.h>
#include <Time.h>
#include <WebServer.h>

#define VERSION "DoorsUp v1.0a"
#define DEFAULT_SERVER_PORT 80
#define DEFAULT_SMTP_PORT 25

// Comment the following line to disable debug mode.
#define DEBUG 1

#ifdef DEBUG
#define DEBUG_BAUD_RATE 9600
#endif

// Pin definitions. NOTE: Ethernet shield w/SD card reader attaches to pins
// 10, 11, 12, and 13.
#define DOOR_CONTACT_PIN 3
#define SD_CS_PIN 4
#define STATUS_LED_PIN 6
#define DOOR_RELAY_PIN 9

// Analog boundary value (0-1023) used to distinguish between device/door status == opened and closed. Only applicable
// when STATUS_STRATEGY_3VCLOSED_5VOPENED or STATUS_STRATEGY_5VCLOSED_3VOPENED is being used.
#define STATUS_OPEN_TRESHOLD 1000

//*******************************************************************
// Notifications
//*******************************************************************

// if defined, will fire a notification when any door/device stays open more than the specified number of minutes
#define NOTIFICATIONS_WATCHDOG_MINUTES  5

// if defined, will fire a notification every time and as soon as any door/device gets opened
#define NOTIFICATIONS_OPEN

// number of milliseconds relay pin will be held high when triggered.
#define RELAY_DELAY 1000

// Size defines.
#define HTTP_PARAM_NAME_SIZE 16
#define HTTP_PARAM_VALUE_SIZE 64
#define PASSWORD_HEX_SIZE 32
#define PASSWORD_SIZE 16
#define AES256_CRYPTO_KEY_SIZE 32
#define CHALLENGE_TOKEN_SIZE 16

// Global constants.
const char *CONFIG_FILENAME = "/config.ini";
const byte MAC[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
const IPAddress DEFAULT_IP(192, 168, 1, 240);
const IPAddress DEFAULT_GW(192, 168, 1, 1);
const IPAddress DEFAULT_SN(255, 255, 255, 0);
const IPAddress DEFAULT_DNS = DEFAULT_GW;
const size_t BUFFERLEN = 80;

// Config file constants
const char *CONFIG_SECTION_MAIN = "Main";
const char *CONFIG_SECTION_NOTIFY = "Notifications";
const char *CONFIG_KEY_IP = "IP";
const char *CONFIG_KEY_GW = "Gateway";
const char *CONFIG_KEY_SN = "SubnetMask";
const char *CONFIG_KEY_DNS = "DNS";
const char *CONFIG_KEY_PORT = "Port";
const char *CONFIG_KEY_SMTPPORT = "SMTP_Port";
const char *CONFIG_KEY_SMTPSERVER = "SMTP_Server";
const char *CONFIG_KEY_SMTPEMAILADDRESS = "SMTP_EmailAddress";
const char *CONFIG_KEY_SMSEMAILADDRESS = "SMS_EmailAddress";
const char *CONFIG_KEY_NOTIFYEMAIL = "NotifyEmail";
const char *CONFIG_KEY_NOTIFYSMS = "NotifySMS";

//*******************************************************************
// Status reading strategy
//*******************************************************************
enum StatusStrategy
{
	CLOSED3V_OPENED5V = 0, // initial approach - uses analogRead combined with STATUS_OPEN_TRESHOLD (opened == +5v, closed == +3v)
	CLOSED5V_OPENED3V = 1, // alternate approach - uses analogRead combined with STATUS_OPEN_TRESHOLD (opened == +3v, closed == +5v)
	NORMALLY_CLOSED = 2,   // classic door sensor - uses digitalRead to interpret door/device status (opened == high-impedance, closed == GND)
	NORMALLY_OPENED = 3    // alternate approach - uses digitalRead to interpret door/device status (opened == GND, closed == high-impedance)
};

//*******************************************************************
// Configuration settings
//*******************************************************************
struct Configuration
{
	WebServer server;
	IPAddress ip;
	IPAddress gateway;
	IPAddress subnetmask;
	IPAddress client_dns;
	EthernetClient smtpClient;
	int serverPort;
	int smtpServerPort;
	bool notifySmtp;
	bool notifySms;
	char *smtpServerName;
	char *smtpDestEmail;
	char *smsDestEmail;
	StatusStrategy strategy_t;
	char *password;
};

// Global vars.
Configuration config;



/**
 * Prints the description of the associated error.
 * @param e The error to get the description of.
 * @param eol Set true if end of line.
 */
void printSDErrorMessage(uint8_t e, bool eol = true) {
#if defined(DEBUG)
	switch (e) {
	case IniFile::errorNoError:
		Serial.print("no error");
		break;
	case IniFile::errorFileNotFound:
		Serial.print("file not found.");
		break;
	case IniFile::errorFileNotOpen:
		Serial.print("file not open");
		break;
	case IniFile::errorBufferTooSmall:
		Serial.print("buffer too small");
		break;
	case IniFile::errorSeekError:
		Serial.print("seek error");
		break;
	case IniFile::errorSectionNotFound:
		Serial.print("section not found");
		break;
	case IniFile::errorKeyNotFound:
		Serial.print("key not found");
		break;
	case IniFile::errorEndOfFile:
		Serial.print("end of file");
		break;
	case IniFile::errorUnknownError:
		Serial.print("unknown error");
		break;
	default:
		Serial.print("unknown error value");
		break;
	}

	if (eol) {
		Serial.println();
	}
#endif
}

/**
 * Flashes the status LED once per second to indicate an SD card error occurred.
 * This method never returns as it runs in an endless loop.
 */
void statusLedSDErrorFlash() {
#if defined(DEBUG)
	Serial.println("ERROR: SD.begin() failed.");
#endif
	while (1) {
		digitalWrite(STATUS_LED_PIN, HIGH);
		delay(1000);
		digitalWrite(STATUS_LED_PIN, LOW);
		delay(1000);
	}
}

/**
 * Flash 5 times and then stop to indicate default network settings used do to
 * config read failure.
 */
void statusLedNetworkWarnFlash() {
	for (int i = 1; i <= 5; i++) {
		digitalWrite(STATUS_LED_PIN, HIGH);
		delay(200);
		digitalWrite(STATUS_LED_PIN, LOW);
		delay(200);
	}
}

/**
 * Sets the default network settings.
 */
void setNetworkDefaults() {
#if defined(DEBUG)
	Serial.println("Falling back to default network settings...");
#endif
	config.ip = DEFAULT_IP;
	config.gateway = DEFAULT_GW;
	config.subnetmask = DEFAULT_SN;
	config.client_dns = DEFAULT_DNS;
	config.notifySms = false;
	config.notifySmtp = false;
	config.serverPort = DEFAULT_SERVER_PORT;
	config.smtpServerPort = DEFAULT_SMTP_PORT;
	config.strategy_t = CLOSED3V_OPENED5V;

	statusLedNetworkWarnFlash();
}

/**
 * Reads the configuration file specified by the CONFIG_FILENAME
 * consstant and loads the values into memory.
 */
void readConfig() {
#if defined(DEBUG)
	Serial.print("Reading configuration...");
#endif

	// Init SD card.
	if (!SD.begin(SD_CS_PIN)) {
		statusLedSDErrorFlash();
	}

	// Open config file.
	char buffer[BUFFERLEN];
	IniFile ini(CONFIG_FILENAME);
	if (!ini.open()) {
		printSDErrorMessage(IniFile::errorFileNotOpen);
		setNetworkDefaults();
		return;
	}

	// Check to see if the file is valid. This can be used to warn if lines are
	// longer than the buffer.
	if (!ini.validate(buffer, BUFFERLEN)) {
#if defined(DEBUG)
		String fname = ini.getFilename();
		Serial.print("Config file '" + fname + "' not valid: ");
		printSDErrorMessage(ini.getError());
#endif
		setNetworkDefaults();
		ini.clearError();
		ini.close();
		return;
	}

	// Read in all the network settings.
	boolean fail = false;
	IPAddress temp;
	if (ini.getIPAddress(CONFIG_SECTION_MAIN, CONFIG_KEY_IP, buffer, BUFFERLEN, temp)) {
		config.ip = temp;
	}
	else {
#if defined(DEBUG)
		Serial.print("ERROR: Failed to read key: " + String(CONFIG_KEY_IP) + ". Message: ");
		printSDErrorMessage(ini.getError());
#endif
		fail = true;
	}

	if (ini.getIPAddress(CONFIG_SECTION_MAIN, CONFIG_KEY_SN, buffer, BUFFERLEN, temp)) {
		config.subnetmask = temp;
	}
	else {
#if defined(DEBUG)
		Serial.print("ERROR: Failed to read key: " + String(CONFIG_KEY_SN) + ". Message: ");
		printSDErrorMessage(ini.getError());
#endif
		fail = true;
	}

	if (ini.getIPAddress(CONFIG_SECTION_MAIN, CONFIG_KEY_GW, buffer, BUFFERLEN, temp)) {
		config.gateway = temp;
	}
	else {
#if defined(DEBUG)
		Serial.print("ERROR: Failed to ready key: " + String(CONFIG_KEY_GW) + ". Message: ");
		printSDErrorMessage(ini.getError());
#endif
		fail = true;
	}

	if (ini.getIPAddress(CONFIG_SECTION_MAIN, CONFIG_KEY_DNS, buffer, BUFFERLEN, temp)) {
		config.client_dns = temp;
	}
	else {
#if defined(DEBUG)
		Serial.print("ERROR: Failed to read key: " + String(CONFIG_KEY_DNS) + ". Message: ");
		printSDErrorMessage(ini.getError());
#endif
		fail = true;
	}

	int port;
	if (ini.getValue(CONFIG_SECTION_MAIN, CONFIG_KEY_PORT, buffer, BUFFERLEN, port)) {
		config.serverPort = port;
	}
	else {
#if defined(DEBUG)
		Serial.print("ERROR: Failed to read key: " + String(CONFIG_KEY_PORT) + ". Message: ");
		printSDErrorMessage(ini.getError());
#endif
		// On this one, we don't fail outright because the port is intially set to
		// its default anyway. If all the other settings were successful up to this
		// point, then we keep them and just use the default port. No sense in
		// defaulting *all* the settings over a bad port number.
	}

	// Revert to defaults if any network settings were wrong.
	if (fail) {
		setNetworkDefaults();
	}

	// Cleanup.
	if (ini.isOpen()) {
		ini.clearError();
		ini.close();
		ini.~IniFile();
	}
}

/**
 *
 * @param server
 * @param type
 * @param url
 * @param isUrlComplete
 */
void webRequestHandler(WebServer &server, WebServer::ConnectionType type, char *url, bool isUrlComplete) {
#if defined(DEBUG)
	Serial.println(F("**** Recieved HTTP request ****"));
#endif

	// Place holder for submitted password (as hex).
	char submittedPassword[PASSWORD_HEX_SIZE + 1];
	memset(&submittedPassword, 0, sizeof(submittedPassword));

	// Place holder for current challenge token value. The following must not be
	// initialized (memset) because it is static and must persist accross HTTP calls.
	static char currChallengeToken[CHALLENGE_TOKEN_SIZE + 1] = "";

	// Handle HTTP GET params (if provided).
	char name[HTTP_PARAM_NAME_SIZE + 1];
	char value[HTTP_PARAM_VALUE_SIZE + 1];

	// Process all HTTP GET params.
	if (type == WebServer::GET) {
#if defined(DEBUG)
		Serial.println(F("*** GET request ***"));
#endif
	}

	while ((url) && (strlen(url))) {
		// Process each HTTP GET param one at a time.
		memset(&name, 0, sizeof(name));
		memset(&value, 0, sizeof(value));
		config.server.nextURLparam(&url, name, HTTP_PARAM_NAME_SIZE, value, HTTP_PARAM_VALUE_SIZE);

#if defined(DEBUG)
		Serial.print(F("PARAM - Name: '"));
		Serial.print(name);
		Serial.print(F("' - Value: '"));
		Serial.print(value);
#endif

		// Keep hold of submitted encrypted hex password value.
		if (strcmp(name, "password") == 0) {
			strcpy(submittedPassword, value);
		}
	}

	// The presence of an HTTP GET password param results in a request
	// to trigger the relay (used to be triggered by an HTTP request of type POST).
	if (strlen(submittedPassword) > 0) {
#if defined(DEBUG)
		Serial.print(F("*** Submitted password: '"));
		Serial.print(submittedPassword);
		Serial.println(F("' ***"));
#endif

		// Decrypt password using latest challenge token as cypher key.
		uint8_t cryptoKey[AES256_CRYPTO_KEY_SIZE + 1];
		memset(&cryptoKey, 0, sizeof(cryptoKey));
		for (int i = 0; i < strlen(currChallengeToken); i++) {
			cryptoKey[i] = currChallengeToken[i];
		}

		uint8_t password[PASSWORD_SIZE + 1];
		memset(&password, 0, sizeof(password));

		// Convert password from hex string to ascii decimal.
		int i = 0;
		int j = 0;
		while (true) {
			if (!submittedPassword[j]) {
				break;
			}

			char hexValue[3] = { submittedPassword[j], submittedPassword[j + 1], '\0' };
			password[i] = (int)strtol(hexValue, NULL, 16);

			i++;
			j += 2;
		}

		// Proceed with AES256 password decryption.
		aes256_context ctx;
		aes256_init(&ctx, cryptoKey);
		aes256_decrypt_ecb(&ctx, password);
		aes256_done(&ctx);

		char passwordAsChar[PASSWORD_SIZE + 1];
		memset(&passwordAsChar, 0, sizeof(passwordAsChar));
		for (int i = 0; i < sizeof(password); i++) {
			passwordAsChar[i] = password[i];
		}

#if defined(DEBUG)
		Serial.print(F("*** Decrypted password: '"));
		Serial.print(passwordAsChar);
		Serial.println(F("' ***"));
#endif

		// If password matches, trigger relay.
		if (strcmp(passwordAsChar, config.password) == 0) {
#if defined(DEBUG)
			Serial.println(F("**** Auth Password MATCH! ****"));
			Serial.println(F("Relay triggered."));
#endif

			// Trigger door relay ping and hold it HIGH for the appropriate milliseconds.
			digitalWrite(DOOR_RELAY_PIN, HIGH);
			delay(RELAY_DELAY);
			digitalWrite(DOOR_RELAY_PIN, LOW);
		}
	}

	// Write response headers.
	config.server.httpSuccess("text/xml; charset=utf-8");
#if defined(DEBUG)
	Serial.println(F("*** XML output begin ***"));
#endif

	// Write opening element.
	output(config.server, "<?xml version=\"1.0\"?>", true);
	output(config.server, "<DoorsUp>", true);

	// Write door status.
	output(config.server, "<status statusPin=\"", false);
	output(config.server, DOOR_CONTACT_PIN, false);
	output(config.server, "\">", false);

	// Write current open/close state.
	output(config.server, (char*)(isOpen(DOOR_CONTACT_PIN) ? "Opened" : "Closed"), false);
	output(config.server, "</status>", false);

	// Re-gen new challenge token.
	sprintf(currChallengeToken, "Cyber%i%i%i", hour(), minute(), second());

	// Write challenge token.
	output(config.server, "<challengeToken>", false);
	output(config.server, currChallengeToken, false);
	output(config.server, "</challengeToken>", true);

	// Write closing element.
	output(config.server, "</DoorsUp>", true);
#if defined(DEBUG)
	Serial.println(F("**** XML output end ****"));
	Serial.println(F("**** END HTTP Request processing ****"));
#endif
}

/**
 * Initializes the network interface.
 */
void initNetwork() {
	byte m[sizeof(MAC)];
	memcpy(m, MAC, sizeof(MAC));
	Ethernet.begin(m, config.ip, config.client_dns, config.gateway, config.subnetmask);

	config.server = WebServer.WebServer("", config.serverPort);
	config.server.setDefaultCommand(&webRequestHandler);
	config.server.addCommand("", &webRequestHandler);
	config.server.begin();

#if defined(DEBUG)
	Serial.println();
	Serial.println("Network initialized as: ");
	Serial.println("IP: " + String(Ethernet.localIP()));
	Serial.println("Subnet: " + String(Ethernet.subnetMask()));
	Serial.println("Gateway: " + String(Ethernet.gatewayIP()));
	Serial.println("DNS: " + String(Ethernet.dnsServerIP()));
	Serial.println("Listening on port: " + String(config.serverPort));
#endif
}

/**
 * Prints a string to the specified webserver's output stream and (if enabled)
 * to the serial port for debug.
 * @param server The webserver to output to.
 * @param data The string data to output.
 * @param newLine Set true to termine the output with a new line.
 */
void output(WebServer &server, char* data, bool newLine) {
#if DEBUG
	if (newLine) {
		Serial.println(data);
	}
	else {
		Serial.print(data);
	}
#endif

	if (newLine) {
		server.println(data);
	}
	else {
		server.print(data);
	}
}

/**
 * Prints an integer to the specified webserver's output stream and (if enabled)
 * to the serial port for debug.
 * @param server The webserver to output to.
 * @param number The integer data to output.
 * @param newLine Set true to termine the output with a new line.
 */
void output(WebServer &server, int number, bool newLine) {
	char str[10] = "";
	itoa(number, str, 10);
	output(server, str, newLine);
}

/**
 * Checks the specified pin to determine whether or not the door is open.
 * @param pinNumber The pin to check for status.
 */
bool isOpen(int pinNumber) {
	int status = 0;
	if ((config.strategy_t == CLOSED3V_OPENED5V) || (config.strategy_t == CLOSED5V_OPENED3V)) {
		status = analogRead(pinNumber);
	}
	else if ((config.strategy_t == NORMALLY_CLOSED) || (config.strategy_t == NORMALLY_OPENED)) {
		status = digitalRead(pinNumber + 14); // addressing analog pins as digital pins (+14)
	}

	#if DEBUG
		Serial.print(F("*** isOpen - status value for pin: '"));
		Serial.print(pinNumber);
		Serial.print(F("' is '"));
		Serial.print(status);
	#endif

  bool is_open = false;
  switch (config.strategy_t) {
  case CLOSED3V_OPENED5V:
	  is_open = (status >= STATUS_OPEN_TRESHOLD);
	  break;
  case CLOSED5V_OPENED3V:
	  is_open = (status <= STATUS_OPEN_TRESHOLD);
	  break;
  case NORMALLY_CLOSED:
	  is_open = (status == LOW);
	  break;
  case NORMALLY_OPENED:
	  is_open = (status == HIGH);
	  break;
  }

  #if DEBUG
    Serial.print(F("' returing: '"));
    Serial.print(is_open ? F("Opened") : F("Closed"));
    Serial.println(F("' ***"));
  #endif

  return is_open;
}

/**
 * Sends a notification via e-mail.
 * @param to The address to send to.
 * @param subject The message subject.
 * @param body The body of the message (content).
 */
void notifyViaEmail(const String& to, const String& subject, const String& body) {
#if DEBUG
	Serial.print(F("*** SMTP - server name: '"));
    Serial.println(config.smtpServerName);
    Serial.print(F("to: "));
    Serial.println(to);
    Serial.print(F("subject: "));
    Serial.println(subject);
    Serial.print(F("body: "));
    Serial.println(body);
    Serial.println(F("***"));
#endif

	if (config.smtpClient.connect(config.smtpServerName, config.smtpServerPort)) {
#if DEBUG
		Serial.println(F("**** SMTP - connection established ****"));
#endif

		config.smtpClient.println(F("HELO "));
		config.smtpClient.print(F("relai.mydooropener.com"));
		
		config.smtpClient.print(F("MAIL FROM:"));
		config.smtpClient.println(F("noreply@mydooropener.com"));

		config.smtpClient.print(F("RCPT TO:"));
		config.smtpClient.println(to);

		config.smtpClient.println(F("DATA"));
		config.smtpClient.print(F("SUBJECT: "));
		config.smtpClient.println(subject);
		
		config.smtpClient.println();
		config.smtpClient.print(body);
		config.smtpClient.print(F(" "));
		config.smtpClient.println(F("doorsup://status"));

		config.smtpClient.println(F("."));
		config.smtpClient.println(F("."));

		config.smtpClient.println(F("QUIT"));
		config.smtpClient.stop();

#if DEBUG
		Serial.println(F("**** SMTP - disconnected ****"));
#endif
	}

#if DEBUG
	Serial.println(F("**** SMTP - completed ****"));
#endif
}

/**
 * Sends a notification via e-mail.
 * @param subject The message subject.
 * @param body The body of the message (content).
 */
void notifyViaEmail(const char* subject, const char* body) {
	notifyViaEmail(config.smtpDestEmail, subject, body);
}

/**
 * Sends a notification via SMS (text message).
 * @param subject The message subject.
 * @param body The body of the message (content).
 */
void notifyViaSms(const char* subject, const char* body) {
	notifyViaEmail(config.smsDestEmail, subject, body);
}

/**
 * Sends notifications of the door being open (if actually open).
 */
void doorOpenNotificationHandler() {
	if (isOpen(DOOR_CONTACT_PIN)) {
#if DEBUG
		Serial.print(F("**** Detected an open door on pin #"));
		Serial.print(String(DOOR_CONTACT_PIN));
		Serial.println(F(" ****"));
		Serial.println(F("**** sending notification ****"));
#endif
		char subject[] = "DoorsUp Notification";
		char body[] = "The door has just been opened.";
		if (config.notifySmtp) {
			notifyViaEmail(subject, body);
		}

		if (config.notifySms) {
			notifyViaSms(subject, body);
		}
	}
}

/**
 *
 */
void watchDogNotificationsHandler() {
	static time_t initialOpen = NULL;
	time_t latestOpen = NULL;
	static boolean notificationSent = false;
	boolean openDetected = false;

	if (isOpen(DOOR_CONTACT_PIN)) {
		if (!initialOpen) {
			initialOpen = now();
		}

		latestOpen = now();
		if ((latestOpen - initialOpen) > (NOTIFICATIONS_WATCHDOG_MINUTES * 60)) {
#ifdef DEBUG
			Serial.print(F("**** Watchdog Notification Handler - Detected opened device/door @ pin #"));
			Serial.print(DOOR_CONTACT_PIN);
			Serial.println(F(" ****"));
#endif
			if (!notificationSent) {
#ifdef DEBUG
				Serial.println(F("**** Watchdog Notification Handler - Sending notification ****"));
#endif
				char subject[] = "DoorsUp Notification";
				char body[100] = "";
				sprintf(body, "A door or device has been opened for more than %i minute(s).", NOTIFICATIONS_WATCHDOG_MINUTES);

				if (config.notifySms) {
					notifyViaSms(subject, body);
				}

				if (config.notifySmtp) {
					notifyViaEmail(subject, body);
				}

				notificationSent = true;
			}
			else {
#ifdef DEBUG
				Serial.println(F("**** Watchdog Notification Handler - NOT Sending Notification ****"));
#endif
			}
		}
		openDetected = true;
	}
}

/**
 * Configures the specified pin to poll for status (door contact) based on
 * poll status strategy.
 * @param pinNumber The pin to configure.
 */
void configureStatusPin(int pinNumber) {
	if ((config.strategy_t == CLOSED3V_OPENED5V) || (config.strategy_t == CLOSED5V_OPENED3V)) {
		pinMode(pinNumber, INPUT);
	}
	else if ((config.strategy_t == NORMALLY_CLOSED) || (config.strategy_t == NORMALLY_OPENED)) {
		pinMode((pinNumber + 14), INPUT_PULLUP);
	}
}

/**
 * Initialize host device and setup program.
 */
void setup() {
#ifdef DEBUG
	// Open serial port and wait for connection.
	Serial.begin(DEBUG_BAUD_RATE);
	while (!Serial) {
		delay(10);
	}
#endif
	// Configure SPI select pin for SD card as outputs and make device inactive
	// to gaurantee init success.
	pinMode(SD_CS_PIN, OUTPUT);
	digitalWrite(SD_CS_PIN, HIGH);

	// Indicate we are initializing.
	pinMode(STATUS_LED_PIN, OUTPUT);
	digitalWrite(STATUS_LED_PIN, HIGH);

	// Special handling for status pin (door contact).
	configureStatusPin(DOOR_CONTACT_PIN);

	// Set arbitrary time for always-changing challenge token generation.
	setTime(0, 0, 0, 1, 1, 2010);

	// This stuff has to happen in a specific order to work properly.
	SPI.begin();
	readConfig();
	initNetwork();
	digitalWrite(STATUS_LED_PIN, LOW);
}

/**
 * Main program loop.
 */
void loop() {
	char buffer[200];
	int len = sizeof(buffer);
	config.server.processConnection(buffer, &len);

	// TODO handle watchdog stuff here.

	if ((config.notifySms) || (config.notifySmtp)) {
		doorOpenNotificationHandler();
	}
}
