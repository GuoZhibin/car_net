#include "source.h"

unsigned int preRoutHookDisp(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct iphdr * iphd = (struct iphdr *)(skb->head + skb->network_header);
	struct udphdr *udph = (struct udphdr *)(skb->head + skb->transport_header);

	if(iphd->protocol == IPPROTO_UDP)	// Judge package type
	{
		switch(ntohs(udph->dest))	// Judge destination port
		{
		case 8087:	// TODO: Need to be modified.
			return vehicle_hook_term_process(skb);
			break;
	/*		
		case TERM_C2_VEHICLE_PORT:	// Terminal to car, command
	
			break;
		
		case TERM_D2_VEHICLE_PORT:	// Terminal to car, data

			break;
	*/		
		default:	
			return NF_ACCEPT;
			break;
		}

	}
	else
		return NF_ACCEPT;
}

unsigned int vehicle_hook_term_process(struct sk_buff *skb)	// Deal packages from terminal
{
	printk("----------------Before Decapsulation-----------------");
	Show_SkBuff_Data(skb);
	
	if(vehicle_udp_decap(skb))	// LLC Ctrl
	{
		printk("LLC Ctrl Head Received.\n");
		process_term_ctl(skb);
	}
	else	// LLC Data
	{
		vehicle_llc_decap(skb);
		
		printk("----------------After  Decapsulation-----------------");	
		Show_SkBuff_Data(skb);
		
//		netif_receive_skb(skb);
	}
	
	kfree_skb(skb);
	return NF_STOLEN;
}

int vehicle_udp_decap(struct sk_buff *skb)	// Decapsulate IP&UDP head.
{
	struct ctr_hdr * tmp;

	skb_pull(skb, sizeof(struct iphdr));
	skb_pull(skb, sizeof(struct udphdr));

	tmp = (struct ctr_hdr *)skb->data;
	if(tmp->d_or_c)	// LLC Ctrl
	{
		return 1;
	}
	else	// LLC Data
	{
		skb->network_header = skb->data - skb->head + sizeof(struct data_hdr);
		skb->transport_header = skb->network_header + sizeof(struct iphdr);
		return 0;
	}

}

bool vehicle_llc_decap(struct sk_buff *skb)	// Decapsulate LLC head
{
	skb_pull(skb, sizeof(struct data_hdr));
	return true;
//	netif_receive_skb();
}


unsigned int process_term_ctl(struct sk_buff *skb)	// Contorl Frame
{
// Skb will be empty after pulling.!!
//	skb_pull(skb, sizeof(struct ctr_hdr));
	return 0;
}


unsigned int TEST_PORT_FUNC(struct sk_buff *skb)
{
	Show_SkBuff_Data(skb);
	kfree_skb(skb);
	return NF_STOLEN;
}


void IP_int_to_str(uint32_t ip, unsigned int * addr)
{
	addr[0] = (unsigned int)((ip & 0xFF000000) >> 24);
	addr[1] = (unsigned int)((ip & 0x00FF0000) >> 16);
	addr[2] = (unsigned int)((ip & 0x0000FF00) >> 8);
	addr[3] = (unsigned int)(ip & 0x000000FF);	
}


void Show_SkBuff_Data(struct sk_buff * skb)
{
	unsigned int BuffData = 0;
	char devname[IFNAMSIZ];
	struct ethhdr * ethh = NULL;
	struct iphdr * iph = NULL;
	struct udphdr * udph = NULL;
	unsigned int IP_str[4];
	unsigned char * content = NULL;

/*******************************ETH INFO*****************************************/
	
	printk("+++++ETH INFO+++++\n");

	ethh = (struct ethhdr *)(skb->head + skb->mac_header); 
	
	// Dev Name
	if(unlikely(!skb->dev))
	{
		printk("ERROR : Dev name NULL.\n");
	}
	else
	{
		strcpy(devname, skb->dev->name);
		printk("Dev name : %s\n", devname);		
	}

	content = (unsigned char *)kmalloc(sizeof(unsigned char) * ETH_ALEN + 1, GFP_KERNEL);
	if(unlikely(!content))
	{
		printk("ERROR : kmalloc Failed.\n");
	}

	// Source Mac
	printk("Src Mac : %x.%x.%x.%x.%x.%x\n", \
				ethh->h_source[0], ethh->h_source[1], ethh->h_source[2], \
				ethh->h_source[3], ethh->h_source[4], ethh->h_source[5]);
	// Destination Mac
	printk("Dst Mac : %x.%x.%x.%x.%x.%x\n", \
				ethh->h_dest[0], ethh->h_dest[1], ethh->h_dest[2], \
				ethh->h_dest[3], ethh->h_dest[4], ethh->h_dest[5]);	
	
/********************************IP INFO****************************************/
	printk("+++++IP INFO+++++\n");

	iph = (struct iphdr *)(skb->head + skb->network_header);

	// Source IP
	BuffData = ntohl(iph->saddr);
	if(unlikely(!BuffData))
	{
		printk("ERROR : SrcIP NULL.\n");
	}
	else
	{
		IP_int_to_str(BuffData, IP_str);
		printk("Src IP : %u.%u.%u.%u\n", IP_str[0], IP_str[1], IP_str[2], IP_str[3]);
	}

	// Destination IP
	BuffData = ntohl(iph->daddr);
	if(unlikely(!BuffData))
	{
		printk("ERROR : DstIP NULL.\n");
	}
	else
	{
		IP_int_to_str(BuffData, IP_str);
		printk("Dst IP : %u.%u.%u.%u\n", IP_str[0], IP_str[1], IP_str[2], IP_str[3]);
	}

	// IP total length
	BuffData = ntohs(iph->tot_len);
	if(unlikely(!BuffData))
	{
		printk("ERROR : IP LEN NULL.\n");
	}
	else
	{
		printk("IP LEN : %d\n", BuffData);
	}

/*****************************UDP INFO*******************************************/
	
	printk("+++++UDP INFO+++++\n");

	udph = (struct udphdr *)(skb->head + skb->transport_header);

	// Src Port
	BuffData = ntohs(udph->source); 
	if(unlikely(!BuffData))
	{
		printk("ERROR : Src Port NULL.\n");
	}
	printk("Src Port : %d\n", BuffData);

	// Dst Port
	BuffData = ntohs(udph->dest);
	if(unlikely(!BuffData))
	{
		printk("ERROR : Dst Port NULL.\n");
	}
	printk("Dst Port : %d\n", BuffData);

	// UDP length
	BuffData = ntohs(udph->len); 
	if(unlikely(!BuffData))
	{
		printk("ERROR : UDP LEN NULL.\n");
	}
	printk("UDP LEN : %d\n", BuffData);

/**************************DATA INFO**********************************************/

	printk("+++++DATA INFO+++++\n");

	BuffData = ntohs(udph->len) - sizeof(struct udphdr); 

	// Data length
	if(unlikely(!BuffData))
	{
		printk("ERROR : Data LEN NULL.\n");
	}
	printk("Data LEN : %d\n", BuffData);

	content = (unsigned char *)kmalloc(sizeof(char) * BuffData + 1, GFP_KERNEL);
	if(unlikely(!content))
	{
		printk("ERROR : kmalloc Failed.\n");
	}
	memcpy(content, (char *)udph + sizeof(struct udphdr), BuffData);
	content[BuffData] = '\0';			// Print data

	printk("Data: %.*s", BuffData, content);

	kfree(content);

}


