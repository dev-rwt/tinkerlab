#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <InfluxDbClient.h>
#include <InfluxDbCloud.h>
#include "./functions.h"



const char *ssid = "IITRPR";
const char *password = "V#6qF?pyM!bQ$%NX";


#define disable 0
#define enable  1


unsigned int channel = 1;


WiFiClient client;


 
#define INFLUXDB_URL "https://us-east-1-1.aws.cloud2.influxdata.com"
#define INFLUXDB_TOKEN "L8BJ54KRbha5JEIWgMdhqBwy3SiE3Pg51yTOkbiy0sqEKh_3HeD5Itj45NuF3Z5anROhgt0xHYBCv3LUxwfupA=="
#define INFLUXDB_ORG "f99506374b6a1f4a"
#define INFLUXDB_BUCKET "test"


#define TZ_INFO "UTC5.5"


InfluxDBClient dbclient(INFLUXDB_URL, INFLUXDB_ORG, INFLUXDB_BUCKET, INFLUXDB_TOKEN, InfluxDbCloud2CACert);


Point sensor("esp");



void enablesniffer() {
  wifi_set_opmode(STATION_MODE);           
  wifi_set_channel(channel);
  wifi_promiscuous_enable(disable);
  wifi_set_promiscuous_rx_cb(promisc_cb);   // When a packet is captured, a callback function is invoked
  wifi_promiscuous_enable(enable);
}


void connectToWiFi() {
   Serial.println();
   Serial.println();
   Serial.print("Connecting to WiFi");
   Serial.println("...");
   WiFi.begin(ssid, password);
   int retries = 0;
    while ((WiFi.status() != WL_CONNECTED) && (retries < 20)) {
      retries++;
      delay(500);
      Serial.print(".");
    }
    delay(1000);
    if (retries > 20) {
        Serial.println(F("WiFi connection FAILED"));
    }
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println(F("WiFi connected!"));
        Serial.println("IP address: ");
        Serial.println(WiFi.localIP());
        Serial.println(F("Setup ready"));
    }
    else{
      Serial.println(F("WiFi connection FAILED"));
    }
    
}








void setup() {
  Serial.begin(57600);
  connectToWiFi();

  timeSync(TZ_INFO, "pool.ntp.org", "time.nis.gov");
 

  // Check server connection
  if (dbclient.validateConnection()) {
    Serial.print("Connected to InfluxDB: ");
    Serial.println(dbclient.getServerUrl());
  } else {
    Serial.print("InfluxDB connection failed: ");
    Serial.println(dbclient.getLastErrorMessage());
  }


  for (int i=0;i<MAXlist;i++) {
    for (int i2=0;i2<12;i2++) {
      lastMACs[i][i2]=0x00; // clean the array (fill with 0's)
    }
  }

  enablesniffer();

  
}








void loop() {

  for (int i=0;i<MAXlist;i++) {
    for (int i2=0;i2<12;i2++) {
      lastMACs[i][i2]=0x00;           // clean the array (fill with 0's)
    }
  }
  sensor.clearFields();               // reset fields
  connectedMAC=0;                     // reset count
  packetcount=0;



  if (sniffing == true) {
    channel = 1;
    wifi_set_channel(channel);
    while (1) {
        delay(2500);
        channel++;
        if (channel == 15) break;             // only scan channels 1 to 14
        wifi_set_channel(channel);
    }
    Serial.println(connectedMAC);
 
    // Serial.print("Writing: ");
    // Serial.println(dbclient.pointToLineProtocol(sensor));




    // While in promiscuous mode, WiFi can't be connected

    wifi_promiscuous_enable(disable);


    WiFi.begin(ssid, password);
    int retries = 0;
    while ((WiFi.status() != WL_CONNECTED) && (retries < 20)) {
      retries++;
      delay(500);                                                       // Reconnect to WiFi
      Serial.print(".");
    }
    delay(1000);
    if (retries > 20) {
        Serial.println(F("WiFi connection FAILED"));
    }


    if (dbclient.validateConnection()) {
      Serial.println("Connected to InfluxDB");
    } else {
      Serial.println("InfluxDB connection failed: ");
    }

    
    sensor.addField("count",connectedMAC);
    sensor.addField("signal", WiFi.RSSI());                             // Adding count and signal strength fields
    sensor.addField("packets", packetcount);

    if (!dbclient.writePoint(sensor)) {
      Serial.print("InfluxDB write failed: ");
      Serial.println(dbclient.getLastErrorMessage());                   // Write the data point to database
    }
  }


  wifi_promiscuous_enable(enable);


  delay(10);
}
