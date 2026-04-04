#include <Arduino.h>

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println();
  Serial.println("=== 3V3 Enable Finder (SAFE) ===");

  // Safer GPIOs on ESP32-S3 (avoid flash pins 6-11, strap pins 0/45/46, USB 19/20, modem UART 43/44)
  const int pins[] = {4,5,7,16,17,18,21,26,27,33,34,35,36,37,38,39,40,41,42,47,48};
  const int count = sizeof(pins) / sizeof(pins[0]);

  for (int i = 0; i < count; i++) {
    int pin = pins[i];
    pinMode(pin, OUTPUT);

    Serial.printf("Testing GPIO %d -> HIGH for 3 seconds\r\n", pin);
    digitalWrite(pin, HIGH);
    delay(3000);

    Serial.printf("Testing GPIO %d -> LOW for 3 seconds\r\n", pin);
    digitalWrite(pin, LOW);
    delay(3000);
  }

  Serial.println("Done.");
}

void loop() {
  delay(1000);
}
