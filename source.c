#include"source.h"
unsigned int preRoutHookDisp(void *priv, struct sk_buff *skb, 
				 const struct nf_hook_state *state)
{
	struct udphdr *udph;
	unsigned short innerDstPort;
	static int seqNo = 0;
    udph =(struct udphdr *)(skb->data+sizeof(struct iphdr));
    innerDstPort=ntohs(udph->dest);

    if (innerDstPort == UDP_SERV_TEST_PORT)   //处理特定端口
    {
		printk("get udp packet for port UDP_SERV_TEST_PORT\n");
		kfree_skb(skb);
		return NF_STOLEN;
	}
    else
		return NF_ACCEPT;
}