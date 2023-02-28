/*
 *
 * Test app and integrity layer
 *
 */

#include "fsl_debug_console.h"
#include "fsl_crc.h"
#include "aes.h"
#include <math.h>

//This structure will receive the message to be tested and its size.
typedef struct messages_t{
	uint8_t* msg;
	size_t padded_len;
}messages_t;

//Functions
/*!
 * @brief Init for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 */

//base = CRC0  seed = 0xFFFFFFFFU
void InitCrc32(CRC_Type *base, uint32_t seed);
uint32_t CRC32(messages_t data);

/*!
 * @brief aes_crc function which test the AES and CRC functionality
 */

//Original function which validates the functionality of AES.
void aescrc_test_task();
void receive_cypher_messages(messages_t data);
messages_t encrypt_message_AES(uint8_t data[]);
messages_t decrypt_message_AES(uint8_t data[]);
void tcpecho_server(void *arg);
void tcpecho_client(void *arg);


