#include "aes_crc.h"
#include "lwip/sys.h"
#include "lwip/api.h"
#include "lwip/opt.h"

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
			PRINTF("Message HEX Format: 0x%02x, ", split_aes.msg[i]);
		}

		for(int i=0; i<split_aes.padded_len; i++)
		{
			PRINTF("Message ASCII Format: %c ", split_aes.msg[i]);
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

void tcpecho_server(void *arg){

	  struct netconn *conn, *newconn;
	  err_t err;
	  LWIP_UNUSED_ARG(arg);

	  /* Create a new connection identifier. */
	  /* Bind connection to well known port number 7. */

	  conn = netconn_new(NETCONN_TCP);
	  netconn_bind(conn, IP_ADDR_ANY, 10000);

	  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

	  /*TEST AES CRC FUNCTIONS BEFORE TO ESTABLISH THE CONNECTION*/
	  aescrc_test_task();
	  /* Tell connection to go into listening mode. */
	  netconn_listen(conn);

	  while (1) {

	    /* Grab new connection. */
	    err = netconn_accept(conn, &newconn);
	    /*printf("accepted new connection %p\n", newconn);*/
	    /* Process the new connection. */
	    if (err == ERR_OK) {
	      struct netbuf *buf;
	      void *data;
	      u16_t len;
	      messages_t new_message;

	      while ((err = netconn_recv(newconn, &buf)) == ERR_OK) {
	        /*printf("Recved\n");*/
	        do {
	    	  /*This function is used to obtain a pointer to and the length of a block of data in the netbuf buf.*/
	          netbuf_data(buf, &data, &len);
	          new_message.msg = data;
	          new_message.padded_len = len;

	          receive_cypher_messages(new_message);

	          //netbuf_data(buf, &data, &len);
	          err = netconn_write(newconn, data, len, NETCONN_COPY);


	        } while (netbuf_next(buf) >= 0);
	        netbuf_delete(buf);
	      }
	      /*printf("Got EOF, looping\n");*/
	      /* Close connection and discard connection identifier. */
	      netconn_close(newconn);
	      netconn_delete(newconn);
	    }
	  }
}

void tcpecho_client(void *arg){

	  struct netconn *conn, *newconn;
	  err_t err;
	  LWIP_UNUSED_ARG(arg);

	  //IP address
	  ip_addr_t server_addr;
	  server_addr.addr = IP4_ADDR(&server_addr, 192, 168, 0, 100);

	  /* Create a new connection identifier. */
	  /* Estbalish new connection */
	  //conn = netconn_new(NETCONN_TCP);


	  while (1){

	  //NETCONN CONNECT
	  /* Estbalish new connection */
	  conn = netconn_new(NETCONN_TCP);
	  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);
	  err = netconn_connect(conn, &server_addr, 10000);
	  if (err == ERR_OK) {

		  PRINTF("CONNECTION ESTABLISHED\n\r");

		  //aescrc_test_task();

		  struct netbuf *buf;
		  u32_t len;
		  void *data;
		  uint8_t crc_mask[4];
		  uint32_t checksum32;

		  messages_t new_message;
		  uint8_t data_info[] = {"Hello_World!"};

		  new_message = encrypt_message_AES(data_info);
		  PRINTF("AES_DEBUG_INFO: aescrc_test_task: Encrypted Message: \r\n");

		  for(int i=0; i<new_message.padded_len; i++) {
			  PRINTF("0x%02x,", new_message.msg[i]);
		  }
		  checksum32 = CRC32(new_message);

		  crc_mask[0] = checksum32 & 0xFF;
		  crc_mask[1] = checksum32 >> 8 & 0xFF;
		  crc_mask[2] = checksum32 >> 16 & 0xFF;
		  crc_mask[3] = checksum32 >> 24 & 0xFF;

		  PRINTF("CRC BYTES:  :");
		  for(int i = 0; i <4 ; i++){
			  PRINTF("0x%02x ",crc_mask[i] );
		    }

		  PRINTF("\n\r");

		  for (int i = 0; i < 4; i++) {
			  new_message.msg[new_message.padded_len + i] = crc_mask[i];
		   }

		  new_message.padded_len = strlen(new_message.msg);
		  PRINTF("Length of message: %d \n\r", new_message.padded_len);

		  PRINTF("Complete message: ");
		    for(int i=0; i < new_message.padded_len ; i++){
		    	PRINTF("0x%02x ",new_message.msg[i]);
		    }
		  PRINTF("\n\r");

		  data = new_message.msg;

		  PRINTF("WRITE FUNCTION - TRANSMIT DATA\n\r");
		  netconn_write(conn, data, new_message.padded_len, NETCONN_COPY);
		  err = netconn_recv(conn, &buf);

		  PRINTF("Transmission completed! \n\r");


	  netconn_close(conn);
	  netconn_delete(conn);
	  }
	 }
}
