
#include "source.h"

unsigned int preRoutHookDisp(		void *priv, 
									struct sk_buff *skb, 
									const struct nf_hook_state *state)
{
	struct iphdr * iph = (struct iphdr *)(skb->head + skb->network_header);
	struct udphdr *udph = (struct udphdr *)(skb->head + skb->transport_header);

	if(iph->protocol == IPPROTO_UDP)	// Judge package type
	{
		switch(ntohs(udph->dest))	// Judge destination port
		{
		case 8087:	
			vehicle_hook_term_process(skb);
			return NF_STOLEN;
		case 7006:
			return NF_ACCEPT;
		default:	
			break;
		}
	}
	return NF_ACCEPT;
}

void vehicle_hook_term_process(struct sk_buff *skb)	// Deal packages from terminal
{
	struct sk_buff *skb_decap = NULL;
	
	if(vehicle_udp_decap(skb))	
	{// LLC Ctrl
		process_term_ctl(skb);
	}
	else	
	{// LLC Data
//		skb_decap = vehicle_llc_decap_zerocpoy(skb);
		skb_decap = vehicle_llc_decap_datacopy(skb); 

		if(skb_decap) 
		{
			netif_receive_skb(skb_decap);
			skb_decap = NULL;
		}
	}
}

unsigned int process_term_ctl(struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}




