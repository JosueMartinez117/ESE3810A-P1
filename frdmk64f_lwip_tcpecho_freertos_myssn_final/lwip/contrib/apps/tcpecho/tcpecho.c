/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#include "tcpecho.h"

#include "lwip/opt.h"

#if LWIP_NETCONN

#include "lwip/sys.h"
#include "lwip/api.h"
#include "aes_crc.h"
/*According to the define select which server / client instance you want to test */
#define SERVER_INSTANCE
//#define CLIENT_INSTANCE
/*-----------------------------------------------------------------------------------*/

/*APIs from main Application*/
#ifdef SERVER_INSTANCE
void tcpecho_server();
#endif
#ifdef CLIENT_INSTANCE
void tcpecho_client();
#endif
/*-----------------------------------------------------------------------------------*/
void
tcpecho_init(void)
{
#ifdef SERVER_INSTANCE
  sys_thread_new("tcpecho_server", tcpecho_server, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
#endif
#ifdef CLIENT_INSTANCE
  sys_thread_new("tcpecho_client", tcpecho_client, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
#endif
}
/*-----------------------------------------------------------------------------------*/

#endif /* LWIP_NETCONN */
