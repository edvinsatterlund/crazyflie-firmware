
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
#define MAX_PAYLOAD 60
#define SIGN_FIRST_PACKET 14
#define SIGN_SECOND_PACKET 50
#define SEQ_NUM_LENGTH 2
#define PUBLIC_LENGTH 32

uint16_t seq_num = 0;

uint8_t* other_id;
uint16_t* other_seq_num;
char* other_body;
uint8_t* other_public;

char other_buffer[MAX_PAYLOAD-SIGN_FIRST_PACKET];

uint8_t other_sign[64]; // Cannot be pointer since fragmented

void p2pcallbackHandler(P2PPacket *p)
{
  // Save everything up to signature into buffer
  memcpy(&other_buffer, &p->data[0], sizeof(char)*MAX_PAYLOAD-SIGN_FIRST_PACKET);

  other_id = (uint8_t*)&other_buffer[0];
  other_seq_num = (uint16_t*)&other_buffer[1];
  other_public = (uint8_t*)&other_buffer[1+SEQ_NUM_LENGTH];
  other_body = &other_buffer[1+ SEQ_NUM_LENGTH+ PUBLIC_LENGTH];


  // Odd, first packet
  if (*other_seq_num % 2 != 0){




  }





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

    if (!generate_keys(private_key, public_key)) {
      DEBUG_PRINT("Failed to load or generate persistent keys.\n");
      return;
    }

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
    // First packet:
    // 1 byte: ID
    // 2 byte: seq number
    // 11 byte: Hello world
    // 32 byte: Public key
    // 14 bytes: 14 from signature
    
    // Second packet:
    // 50 bytes: signature
    // 1 byte: \0

    // Initialize the p2p packet 
    static P2PPacket p_reply_first;
    static P2PPacket p_reply_second;

    p_reply_first.port=0x00;
    p_reply_second.port=0x00;
    
    // Get the current address of the crazyflie and obtain
    //   the last two digits and send it as the first byte
    //   of the payload of the first packet
    uint64_t address = configblockGetRadioAddress();
    uint8_t my_id =(uint8_t)((address) & 0x00000000ff);

    uint8_t message[60];
    message[0] = my_id;

    // SEQ NUM SET IN LOOP

    // Put a string in the message
    char *str="Hello World";
    memcpy(&message[1+SEQ_NUM_LENGTH], str, sizeof(char)*MESSAGE_LENGTH);

    // generate keys
    key_generation();
    
    uint8_t signature[64];
    sign(signature, private_key, message, MESSAGE_LENGTH+1);

    // Continue building message with public key
    memcpy(&message[1+MESSAGE_LENGTH], public_key, sizeof(char)*32);

    // Put first 14 bytes of signature in message, (first packet)
    memcpy(&message[1+MESSAGE_LENGTH+32], signature, sizeof(char)*SIGN_FIRST_PACKET);

    // Copy message to first packet
    memcpy(&p_reply_first.data[0], message, sizeof(char)*MAX_PAYLOAD);

    // Build second packet, remaining 50 bytes of signature
    memcpy(&p_reply_second.data[0], &signature[SIGN_FIRST_PACKET], sizeof(char)*SIGN_SECOND_PACKET);

    char *nullterm = "\0";
    memcpy(&p_reply_second.data[SIGN_SECOND_PACKET], nullterm, sizeof(char));

    // Register the callback function so that the CF can receive packets as well.
    p2pRegisterCB(p2pcallbackHandler);
    
    // Set the size, which is the amount of bytes the payload with ID and the string 
    p_reply_first.size=sizeof(char)*60;
    p_reply_first.size=sizeof(char)*51;

  while(1) {
    // Send a message every 2 seconds
    //   Note: if they are sending at the exact same time, there will be message collisions, 
    //    however since they are sending every 2 seconds, and they are not started up at the same
    //    time and their internal clocks are different, there is not really something to worry about

    DEBUG_PRINT("IT WORKS\n");
    print_hex("Public Key", public_key, sizeof(public_key));
    print_hex("Private Key", private_key, sizeof(private_key));
    vTaskDelay(M2T(2000));

    seq_num++;
    // Copy message to first packet
    memcpy(&p_reply_first.data[1], &seq_num, sizeof(char)*SEQ_NUM_LENGTH);

    radiolinkSendP2PPacketBroadcast(&p_reply_first);
    radiolinkSendP2PPacketBroadcast(&p_reply_second);

  }
}

