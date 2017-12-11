#ifndef DIRVE_H
#define DIRVE_H

#include<linux/module.h>
#include<linux/init.h>
#include<linux/netdevice.h>
#include<linux/errno.h>
#include<linux/skbuff.h>
#include<linux/etherdevice.h>
#include<linux/kernel.h>
#include<linux/types.h>//_be32
#include<linux/string.h>
#include<linux/inetdevice.h>
#include<net/net_namespace.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/kthread.h>
#include<linux/sched.h>
#include<asm/processor.h>
#include <linux/interrupt.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include"mmDebug.h"



#define UDP_CLI_PORT 4047
#define UDP_SERV_PORT 7003
#define UDP_CLI_TEST_PORT 4045
#define UDP_SERV_TEST_PORT 7006
#define UDP_PC_SEND_PORT 50003
#define UDP_PC_RECV_PORT 50004

#define RX_MTU 500

unsigned int preRoutHookDisp(void *priv, struct sk_buff *skb, 
				 const struct nf_hook_state *state);









#endif
