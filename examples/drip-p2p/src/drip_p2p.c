
// drip_p2p.c


#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "app.h"

#include "FreeRTOS.h"
#include "task.h"

#include "radiolink.h"
#include "configblock.h"

#define DEBUG_MODULE "P2P"
#include "debug.h"

#include "keys.h"

#define MESSAGE "hello world"
#define MESSAGE_LENGTH 11


void p2pcallbackHandler(P2PPacket *p)
{
  // Parse the data from the other crazyflie and print it
  uint8_t other_id = p->data[0];
  static char msg[MESSAGE_LENGTH + 1];
  memcpy(&msg, &p->data[1], sizeof(char)*MESSAGE_LENGTH);
  msg[MESSAGE_LENGTH] = 0;
  uint8_t rssi = p->rssi;

  DEBUG_PRINT("[RSSI: -%d dBm] Message from CF nr. %d, %s\n", rssi, other_id, msg);
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    char buf[2 * 64 + 1];
    if (len > 64) len = 64;
    for (size_t i = 0; i < len; i++) {
        buf[2 * i]     = hex[data[i] >> 4];
        buf[2 * i + 1] = hex[data[i] & 0x0f];
    }
    buf[2 * len] = '\0';
    DEBUG_PRINT("%s: %s\n", label, buf);
}

uint8_t private_key[64];
uint8_t public_key[32];

void key_generation()
{

    uint8_t signature[64];

    generate_keys(private_key, public_key);

    print_hex("Public Key", public_key, sizeof(public_key));
    print_hex("Private Key", private_key, sizeof(private_key));

    char message[] = "Hello Test!";
    sign(signature, private_key, message, strlen(message));

    DEBUG_PRINT("\n");
    print_hex("Signature", signature, sizeof(signature));

    int success;
    success = verify(signature, public_key, message, strlen(message));
    DEBUG_PRINT("\n%d", success);
    if (success == 0) {
      DEBUG_PRINT("Verified.\n");
    }
    else {
      DEBUG_PRINT("NOT Verified.\n");
    }
}

void appMain()
{
  DEBUG_PRINT("Waiting for activation ...\n");

    // Initialize the p2p packet 
    static P2PPacket p_reply;
    p_reply.port=0x00;
    
    // Get the current address of the crazyflie and obtain
    //   the last two digits and send it as the first byte
    //   of the payload
    uint64_t address = configblockGetRadioAddress();
    uint8_t my_id =(uint8_t)((address) & 0x00000000ff);
    p_reply.data[0]=my_id;

    //Put a string in the payload
    char *str="Hello World";
    memcpy(&p_reply.data[1], str, sizeof(char)*MESSAGE_LENGTH);

    // Set the size, which is the amount of bytes the payload with ID and the string 
    p_reply.size=sizeof(char)*MESSAGE_LENGTH+1;

    // Register the callback function so that the CF can receive packets as well.
    p2pRegisterCB(p2pcallbackHandler);

    // generate keys
    key_generation();

  while(1) {
    // Send a message every 2 seconds
    //   Note: if they are sending at the exact same time, there will be message collisions, 
    //    however since they are sending every 2 seconds, and they are not started up at the same
    //    time and their internal clocks are different, there is not really something to worry about

    DEBUG_PRINT("IT WORKS\n");
    print_hex("Public Key", public_key, sizeof(public_key));
    print_hex("Private Key", private_key, sizeof(private_key));
    vTaskDelay(M2T(2000));
    radiolinkSendP2PPacketBroadcast(&p_reply);
  }
}

