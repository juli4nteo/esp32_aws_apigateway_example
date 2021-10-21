#include <WiFi.h>
#include "time.h"
#include <sha256.h>
#include <WiFiClientSecure.h>

const char* ssid     = "your-ssid";
const char* password = "your-password";
 
// AWS API gateway configuration
// Suppose your API gateway URI is:
//   https://ivsxai2qus.execute-api.us-east-1.amazonaws.com/application/devicedata
// Then:
//   host = "ivsxai2qus"
//   service = "execute-api"
//   region = "us-east-1"
//   TLD = "amazonaws.com"
//   path = "/application/devicedata"

const char *host = "your-AWS-host";
const char *service = "your-AWS-service";
const char *region = "your-AWS-region";
const char *TLD = "your-TLD";
const char *path = "your-path";

const char *customFQDN; //reserved for future use

// AWS IAM configuration
const char *awsKey = "your-AWSkey";
const char *awsSecret = "your-AWSSecretKey";
const char* apiKey = "your-APIKey";

const char* ntpServer = "pool.ntp.org";
const long  gmtOffset_sec = 0;
const int   daylightOffset_sec = 0;

WiFiClientSecure client;

const char* payload = "Hello World!";

void setup(){
  Serial.begin(115200);
  delay(10);

  // We start by connecting to a WiFi network

  Serial.println();
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
      delay(500);
      Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP()); 
}

void loop(){
  //send the payload with an interval of 10s
  sendData(payload);
  delay(10000);
}

/*-----Function to send payload to server---------------*/

void sendData(const char* payload) {
  if (WiFi.status() == WL_CONNECTED) {
  
    String url = String(host) + "." + String(service) + "." + String(region) + "." + String(TLD);
  
    String request = createRequest("POST", String(path), payload, String(apiKey), "application/json", "");
    
    Serial.println("\nStarting connection to server...");
    client.setInsecure();//skip verification
    client.setTimeout(5000);
    
    if (!client.connect(url.c_str(), 443)) {
      Serial.println("Connection failed!");
    }
    else {
      Serial.println("Connected to server!");
      // Make a HTTP request:
      client.print(request);
  
      // Check HTTP status
      char status[32] = {0};
      client.readBytesUntil('\r', status, sizeof(status));
      // It should be "HTTP/1.0 200 OK" or "HTTP/1.1 200 OK"
      if (strcmp(status + 9, "200 OK") != 0) {
        Serial.print(F("Unexpected response: "));
        Serial.println(status);
        // if there are incoming bytes available
      // from the server, read them and print them:
        while (client.available()) {
          char c = client.read();
          Serial.write(c);
        }
        client.stop();
      }
      // if there are incoming bytes available
      // from the server, read them and print them:
      while (client.available()) {
        char c = client.read();
        Serial.write(c);
      }
      client.stop();
    }
  }
}
/*----(END)-Functions to create payload and send to server---------------*/

/*-------AWS API signing requests functions----------*/
String createRequest(String method, String uri, String payload, String apiKey, String contentType, String queryString) {      

    char dateBuf[9], timeBuf[7];
  
    struct tm timeinfo;
    if(!getLocalTime(&timeinfo)){
      Serial.println("Failed to obtain time");
    }
    snprintf(dateBuf, sizeof(dateBuf), "%4d%02d%02d", (timeinfo.tm_year+1900), (timeinfo.tm_mon+1), (timeinfo.tm_mday));
    snprintf(timeBuf, sizeof(timeBuf), "%02d%02d%02d", (timeinfo.tm_hour), (timeinfo.tm_min), (timeinfo.tm_sec));
    String date(dateBuf);
    String time(timeBuf);

    Sha256.init();
    Sha256.print(payload);
    String payloadHash = hexHash(Sha256.result());
  
    String canonical_request = createCanonicalRequest(method, uri, date, time, payloadHash, apiKey, queryString, contentType);
    String string_to_sign = createStringToSign(canonical_request, date, time);
    String signature = createSignature(string_to_sign, date);
    String headers = createRequestHeaders(contentType, date, time, payload, payloadHash, apiKey, signature);
    
    String retval;
    retval += method + " " + "https://" + FQDN() + uri + " " + "HTTP/1.1\r\n";
    retval += headers + "\r\n";
    retval += payload + "\r\n\r\n";
    return retval;
}

String hexHash(uint8_t *hash) {
    char hashStr[(HASH_LENGTH * 2) + 1];
    for (int i = 0; i < HASH_LENGTH; ++i) {
        sprintf(hashStr+ 2 * i, "%02lx", 0xff & (unsigned long) hash[i]);
    }
    return String(hashStr);
}

String createCanonicalRequest(String method, String uri, String date, String time, String payloadHash, String apiKey, String queryString, String contentType) {
    String retval;
    String _signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
    retval += method + "\n";
    retval += uri + "\n";
    retval += queryString + "\n";
    String headers = createCanonicalHeaders(contentType, date, time, payloadHash, apiKey);
    retval += headers + _signedHeaders + "\n";
    retval += payloadHash;
    return retval;
}

String createCanonicalHeaders(String contentType, String date, String time, String payloadHash, String apiKey) {
    String retval;
    retval += "content-type:" + contentType + "\n";
    retval += "host:" + FQDN() + "\n";
    retval += "x-amz-content-sha256:" + payloadHash + "\n";
    retval += "x-amz-date:" + date + "T" + time + "Z\n\n";
    return retval;
}

String createRequestHeaders(String contentType, String date, String time, String payload, String payloadHash, String apiKey, String signature) {
    String retval;
    String _signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
    retval += "Content-Type: " + contentType + "\r\n";
    retval += "Connection: close\r\n";
    retval += "Content-Length: " + String(payload.length()) + "\r\n";
    retval += "x-api-key: " + apiKey + "\r\n"; 
    retval += "Host: " + FQDN() + "\r\n";
    retval += "x-amz-content-sha256: " + payloadHash + "\r\n";
    retval += "x-amz-date: " + date + "T" + time + "Z\r\n";
    retval += "Authorization: AWS4-HMAC-SHA256 Credential=" + String(awsKey) + "/" + \
               String(date) + "/" + String(region) + "/" + String(service) + "/aws4_request,SignedHeaders=" + \
               _signedHeaders + ",Signature=" + signature + "\r\n";
    return retval;
}

String FQDN() {
    String retval;
    if (((String)customFQDN).length() > 0) {
        retval = String(customFQDN);
    } else {
        retval = String(host) + "." + String(service) + "." + String(region) + "." + String(TLD);
    }
    return retval;
}

String createStringToSign(String canonical_request, String date, String time) {
    Sha256.init();
    Sha256.print(canonical_request);
    String hash = hexHash(Sha256.result());

    String retval;
    retval += "AWS4-HMAC-SHA256\n";
    retval += date + "T" + time + "Z\n";
    retval += date + "/" + String(region) + "/" + String(service) + "/aws4_request\n";
    retval += hash;
    return retval;
}

String createSignature(String toSign, String date) {
    String key = "AWS4" + String(awsSecret);

    Sha256.initHmac((uint8_t*)key.c_str(), key.length()); 
    Sha256.print(date);
    uint8_t* hash = Sha256.resultHmac();

    Sha256.initHmac(hash, HASH_LENGTH);
    Sha256.print(String(region));
    hash = Sha256.resultHmac();

    Sha256.initHmac(hash, HASH_LENGTH);
    Sha256.print(String(service));
    hash = Sha256.resultHmac();

    Sha256.initHmac(hash, HASH_LENGTH);
    Sha256.print("aws4_request");
    hash = Sha256.resultHmac();

    Sha256.initHmac(hash, HASH_LENGTH);
    Sha256.print(toSign);
    hash = Sha256.resultHmac();

    return hexHash(hash);
}
/*---(END)----AWS API signing requests functions----------*/
