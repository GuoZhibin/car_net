/*
 * Author : Juicer
 * BALABALA
 */

#ifndef __llc_decap_debug_H__
#define __llc_decap_debug_H__

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>

unsigned int TEST_PORT_FUNC(struct sk_buff *skb);
void IP_int_to_str(uint32_t ip, unsigned int * addr);
void Show_SkBuff_Data(struct sk_buff * skb, bool MAC, bool NET, bool TSP, bool DAT, bool SHNIFO);
ssize_t WriteToFile(const char * FileName, unsigned char * DataToWrite, unsigned int DataLen);

#endif

