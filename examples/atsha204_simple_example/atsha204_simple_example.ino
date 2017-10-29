#include <sha204_i2c.h>

/* Attention: we need to set BUFFER_LENGTH to at least 64 in Wire.h */
atsha204Class sha204;

void setup() {
	Serial.begin(74800);
}
void loop() {
	Serial.println("wake up device.");
	sha204.simpleWakeup();
	Serial.print("get SN:");
	serialNumberExample();
	Serial.println("put device to sleep mode.");
	sha204.simpleSleep();
	delay(2000);

	Serial.println("wake up device.");
	sha204.simpleWakeup();
	Serial.println("call random:");
	randomExample();
	Serial.println("put device to sleep mode.");
	sha204.simpleSleep();
	Serial.println();

	delay(2000);

	Serial.println("wake up device.");
	sha204.simpleWakeup();
	Serial.println("Sending a MAC Challenge.");
	Serial.println("Response is:");
	macChallengeExample();
	Serial.println("put device to sleep mode.");
	sha204.simpleSleep();
	Serial.println();
	delay(3000);
}

byte wakeupExample() {
	uint8_t response[SHA204_RSP_SIZE_MIN];
	byte returnValue;

	returnValue = sha204.sha204c_wakeup(&response[0]);
	for (int i = 0; i < SHA204_RSP_SIZE_MIN; i++) {
		Serial.print(response[i], HEX);
		Serial.print(" ");
	}
	Serial.println();

	return returnValue;
}

byte randomExample() {
	uint8_t response[RANDOM_RSP_SIZE];
	byte returnValue;
	uint8_t tx_buffer[12] = { 0 };
	returnValue = sha204.sha204m_random(tx_buffer, response,
	RANDOM_NO_SEED_UPDATE);
	for (int i = 0; i < RANDOM_RSP_SIZE; i++) {
		Serial.print(response[i], HEX);
		Serial.print(" ");
	}
	Serial.println();

	return returnValue;
}

byte serialNumberExample() {
	uint8_t serialNumber[6];
	byte returnValue;

	returnValue = sha204.simpleGetSN(serialNumber);
	for (uint8_t i = 0; i < sizeof(serialNumber); i++) {
		Serial.print(serialNumber[i], HEX);
		Serial.print(" ");
	}
	Serial.println();

	return returnValue;
}

uint8_t getDevRev() {
	uint8_t rx_buffer[8] = { 0 };
	uint8_t tx_buffer[8] = { 0 };
	sha204.sha204m_dev_rev(tx_buffer, rx_buffer);
	for (int i = 0; i < 8; i++) {
		Serial.print(rx_buffer[i], HEX);
		Serial.print(" ");
	}
	Serial.println();
	return 0;
}

byte macChallengeExample() {

	uint8_t response[32];
	uint8_t challenge[MAC_CHALLENGE_SIZE] = { 0 };
	sprintf((char *)challenge,"Are you OK?");

	uint8_t ret_code = sha204.simpleMac(challenge, response);

	for (uint8_t i = 0; i < sizeof(response); i++) {
		Serial.print(response[i], HEX);
		Serial.print(' ');
	}
	Serial.println();

	return ret_code;
}


