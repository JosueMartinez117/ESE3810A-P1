#include "aes_crc.h"

//Global variables

/* AES data */
//Key Size 16 bytes --> 128 bits
uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
//Initialization vector
uint8_t iv[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
struct AES_ctx ctx;
size_t test_string_len, padded_len;
uint8_t padded_msg[512] = {0};

void InitCrc32(CRC_Type *base, uint32_t seed)
{
	PRINTF("AES_DEBUG_INFO: InitCrc32 response\r\n");
    crc_config_t config;

    config.polynomial         = 0x04C11DB7U;
    config.seed               = seed;
    config.reflectIn          = true;
    config.reflectOut         = true;
    config.complementChecksum = true;
    config.crcBits            = kCrcBits32;
    config.crcResult          = kCrcFinalChecksum;

    CRC_Init(base, &config);
    PRINTF("AES_DEBUG_INFO: InitCrc32 completed\r\n");
}


void aescrc_test_task()
{
	PRINTF("AES_DEBUG_INFO: ----TESTING AES CRC32 APIs----\r\n");
	PRINTF("AES_DEBUG_INFO: aescrc_test_task response\r\n");
	uint8_t test_string[] = {"01234567890123456789"};
	messages_t test_encrypt_string, test_decrypt_string;
	uint32_t checksum32;

	PRINTF("AES_DEBUG_INFO: aescrc_test_task: testing AES and CRC with the test string 01234567890123456789\r\n\n");
	PRINTF("\nTesting AES128\r\n\n");

	PRINTF("AES_DEBUG_INFO: aescrc_test_task: encrypt_message_AES called function\r\n");
	test_encrypt_string = encrypt_message_AES(test_string);

	PRINTF("AES_DEBUG_INFO: aescrc_test_task: Encrypted Message: \r\n");
	for(int i=0; i<test_encrypt_string.padded_len; i++) {
		PRINTF("0x%02x,", test_encrypt_string.msg[i]);
	}

	PRINTF("\nTesting CRC32\r\n\n");

	PRINTF("AES_DEBUG_INFO: aescrc_test_task: CRC32 called function\r\n");
	checksum32 = CRC32(test_encrypt_string);
	PRINTF("CRC-32: 0x%08x\r\n", checksum32);

	PRINTF("AES_DEBUG_INFO: aescrc_test_task: decrypt_message_AES called function\r\n");
	test_decrypt_string = decrypt_message_AES(test_encrypt_string.msg);

	for(int i=0; i<test_decrypt_string.padded_len; i++) {
		PRINTF("0x%02x,", test_decrypt_string.msg[i]);
	}

    PRINTF("AES_DEBUG_INFO: aescrc_test_task completed\r\n");
    PRINTF("AES_DEBUG_INFO: TEST_SUCCESS\r\n");
    PRINTF("AES_DEBUG_INFO: Continue to real client - server connection...\r\n");
	PRINTF("\r\n");

}

messages_t encrypt_message_AES(uint8_t data[]){
	PRINTF("AES_DEBUG_INFO: encrypt_message_AES response\r\n");
	messages_t new_msg;
	/* Init the AES context structure */
	AES_init_ctx_iv(&ctx, key, iv);

	/* To encrypt an array its lenght must be a multiple of 16 so we add zeros */
	test_string_len = strlen(data);
	padded_len = test_string_len + (16 - (test_string_len%16) );
	memcpy(padded_msg, data, test_string_len);

	//Encrypt Buffer on CBC Mode

	PRINTF("AES_DEBUG_INFO: encrypt_message_AES: Encrypting buffer on CBC mode...\r\n");
	//Reference: void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
	AES_CBC_encrypt_buffer(&ctx, padded_msg, padded_len);

	new_msg.msg = padded_msg;
	new_msg.padded_len = padded_len;
	PRINTF("AES_DEBUG_INFO: encrypt_message_AES function completed \r\n");
	return new_msg;
}

messages_t decrypt_message_AES(uint8_t data[]){
	PRINTF("AES_DEBUG_INFO: decrypy_message_AES response\r\n");
	messages_t new_msg;
	uint8_t message_len = 0;
	/* Init the AES context structure */
	AES_init_ctx_iv(&ctx, key, iv);

	test_string_len = strlen(data);
	padded_len = test_string_len;
	memcpy(padded_msg, data, test_string_len);

	//Decrypt buffer on CBC mode
	//Reference:void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
	PRINTF("AES_DEBUG_INFO: dencrypt_message_AES: Decrypting buffer on CBC mode...\r\n");
	AES_CBC_decrypt_buffer(&ctx, padded_msg, padded_len);

	for(uint8_t i = 0; i < padded_len; i++ )
	{
		if(padded_msg[i] == 0)
		{
			message_len = i;
			break;
		}
	}

	new_msg.msg = padded_msg;
	new_msg.padded_len = message_len;
	PRINTF("AES_DEBUG_INFO: dencrypt_message_AES function completed \r\n");

	return new_msg;
}

uint32_t CRC32(messages_t data){

	PRINTF("AES_DEBUG_INFO: CRC32 response\r\n");
	/* CRC data */
	CRC_Type *base = CRC0;
	uint32_t checksum32;

	//base and seed
	InitCrc32(base, 0xFFFFFFFFU);
	CRC_WriteData(base, data.msg, data.padded_len);
	checksum32 = CRC_Get32bitResult(base);

	PRINTF("AES_DEBUG_INFO: CRC32 completed\r\n");
	return checksum32;

}

void receive_cypher_messages(messages_t data){

	PRINTF("AES_DEBUG_INFO: receive_cypher_messages response \r\n");
	uint8_t counter = 0;
	uint8_t body_bytes[128];
	uint8_t crcBytes[4];
	messages_t split_crc;
	messages_t split_aes;
	uint32_t original_checksum =  0;
	uint32_t calc_checksum =  0;

	PRINTF("AES_DEBUG_INFO: receive_cypher_messages: Getting body bytes \r\n");
	for(uint8_t i = 0; i < data.padded_len - 4; i++)
	{
		body_bytes[i] = data.msg[i];
	}

	PRINTF("AES_DEBUG_INFO: receive_cypher_messages: GET CRC bytes \r\n");
	for(uint8_t i = data.padded_len - 4; i < data.padded_len; i++)
	{
		crcBytes[counter] = data.msg[i];
		counter++;
	}

	PRINTF("AES_DEBUG_INFO: receive_cypher_messages: Convert CRC bytes from the message to int \r\n");
	for (uint8_t i = 0; i < 4; i++)
	{
		original_checksum = original_checksum + ( crcBytes[i] *  pow(256,i) );
	}

	split_crc.msg = body_bytes;
	split_crc.padded_len =  data.padded_len - 4;

	PRINTF("AES_DEBUG_INFO: CRC32 called function\r\n");
	calc_checksum = CRC32(split_crc);

	PRINTF("AES_DEBUG_INFO: receive_cypher_messages: Checksum comparison\r\n");
	if(original_checksum == calc_checksum)
	{
		PRINTF("AES_DEBUG_INFO: receive_cypher_messages: calculated checksum %u, Original checksum: %u \r\n\n",calc_checksum, original_checksum);
		PRINTF("AES_DEBUG_INFO: receive_cypher_messages: Checksum OK! Decrypting message...\r\n\n");

		PRINTF("AES_DEBUG_INFO: receive_cypher_messages: decrypt_message_AES called function\r\n");
		split_aes = decrypt_message_AES(body_bytes);

		PRINTF("AES_DEBUG_INFO: receive_cypher_messages: Decrypted Message: \r\n");
		for(int i=0; i<split_aes.padded_len; i++)
		{
			PRINTF("%c", split_aes.msg[i]);
		}
		PRINTF("\r\n");
	}
	else
	{
		PRINTF("AES_DEBUG_INFO: receive_cypher_messages: calculated Checksum: %u, Original checksum: %u \r\n\n",calc_checksum, original_checksum);
		PRINTF("AES_DEBUG_INFO: receive_cypher_messages: checksum NOT OK: Error in the message integrity \r\n\n");
	}

	PRINTF("AES_DEBUG_INFO: receive_cypher_messages completed \r\n");

}

