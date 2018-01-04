
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
	struct sk_buff *skb_t = NULL;
	printk("----------------Receive-----------------");
	Show_SkBuff_Data(skb, true, true, true, false);
	
	if(vehicle_udp_decap(skb))	// LLC Ctrl
	{
		printk("***************Ctrl Frame***************\n");
		process_term_ctl(skb);
	}
	else	// LLC Data
	{
		if(skb_t) kfree_skb(skb_t);
		skb_t = vehicle_llc_decap(skb);
		printk("***************Data Frame***************\n");	
		if(skb_t) 
		{
			
//			if(WriteToFile("/home/juice/log/car_net/debug.txt", skb_t->data, skb_t->len) == 0)
//				printk("Write to file failed.\n");

			arraydata.data = (char *)skb_t->data;
			arraydata.size = skb_t->len;
			if(my_debugfs)
				debugfs_remove(my_debugfs);
			my_debugfs = debugfs_create_blob("car_net.txt", 0666, my_debugfs_root, &arraydata);
			if (!my_debugfs)
				printk("Debugfs create failed.\n");
			
			Show_SkBuff_Data(skb_t, false, true, true, true);

		}
//		netif_receive_skb(skb_t);
	}
	
//	if(skb_t) 	
//	{
//		kfree_skb(skb_t);
//		skb_t = NULL;
//	}

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

/*
 * Decapsulate LLC head
 * This function free the skb!! Don't free again outside!!
 */
struct sk_buff * vehicle_llc_decap(struct sk_buff *skb)	
{
	struct data_hdr * datah = (struct data_hdr *)skb->data;
	static struct sk_buff * skb_t = NULL;
	struct sk_buff * skb_return = NULL;
	static int pktlastsn = -1;
	unsigned int datalen = 0;
	char * ptr = NULL;

	const unsigned int headlen = sizeof(struct ethhdr) + sizeof(struct iphdr) + \
							sizeof(struct udphdr) + sizeof(struct data_hdr) + 16;
	
	if((pktlastsn < 0) || (datah->pkt_sn == pktlastsn + 1) || (pktlastsn == 4095 && datah->pkt_sn == 0))
	{
		pktlastsn = datah->pkt_sn;

		switch(datah->frag_flag)
		{
			case 3:	// 11 : No frag
				printk("No frag pkg get\n");
				skb_pull(skb, sizeof(struct data_hdr));
				skb_return = skb;
			break;
			case 2:	// 10 : First frag
			
				printk("First frag pkg get\n");
				
				if(unlikely(skb_t != NULL)) 
				{
					printk("ERROR : Recovery new pkg when old recoverying work unfinished.\n");
					break;
				}

				skb_t = create_new_skb(datah->len + headlen);	// TODO: 'headlen' can be deleted?
				
				datalen = skb->len - sizeof(struct data_hdr);
				if(unlikely(datalen < 0)) 
				{
					printk("ERROR : Datalen < 0.\n");
					break;
				}
				printk("First frag len : %d\n", datalen);
				
				ptr = skb_push(skb_t, datalen);
				memcpy(ptr, skb->data + sizeof(struct data_hdr), datalen);

				printk("skb_len : %d\n", skb_t->len);
				
				kfree_skb(skb);
				skb = NULL;
				
				break;
			case 1:	// 01 : Last frag
			
				printk("Last frag pkg get\n");
				
				if(unlikely(skb_t == NULL)) 
				{
					printk("ERROR : No skb was created for last frag.\n");
					break;
				}
				
				datalen = skb->len - sizeof(struct data_hdr);
				if(unlikely(datalen < 0)) 
				{
					printk("ERROR : Datalen < 0.\n");
					break;
				}
				printk("Last frag len : %d\n", datalen);
				
				ptr = skb_push(skb_t, datalen);
				memcpy(ptr, skb->data + sizeof(struct data_hdr), datalen);

				printk("skb_len : %d\n", skb_t->len);
				
				skb_t->network_header = skb_t->data - skb_t->head;
				skb_t->transport_header = skb_t->network_header + sizeof(struct iphdr);
				skb_t->ip_summed = CHECKSUM_NONE;
				skb_t->protocol = htons(ETH_P_IP);
	
				skb_return = skb_t;
				skb_t = NULL;

				kfree_skb(skb);
				skb = NULL;
				
				break;
			case 0:	// 00 : Middle frag
			
				printk("Middle frag pkg get\n");
				
				if(unlikely(skb_t == NULL)) 
				{
					printk("ERROR : No skb was created for middle frag.\n");
					break;
				}
				
				datalen = skb->len - sizeof(struct data_hdr);
				if(unlikely(datalen < 0)) 
				{
					printk("ERROR : Datalen < 0.\n");
					break;
				}
				printk("Middle frag len : %d\n", datalen);
				
				ptr = skb_push(skb_t, datalen);
				memcpy(ptr, skb->data + sizeof(struct data_hdr), datalen);

				printk("skb_len : %d\n", skb_t->len);
				
				kfree_skb(skb);
				skb = NULL;

				break;
			default:	break;
		}
	}
	else
	{
		printk("ERROR : sn error, pkg aborted.\n");
		kfree_skb(skb);
		skb = NULL;
	}
	
	return skb_return;
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
	Show_SkBuff_Data(skb, true, true, true, false);
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

struct sk_buff * create_new_skb(unsigned int len)
{
	struct sk_buff *skb = alloc_skb(len, GFP_KERNEL);
	if(unlikely(!skb)) 
	{
		printk("alloc failed\n"); 
		return NULL;
	} 
	
	skb_reserve(skb, len);
	skb->pkt_type  = PACKET_OTHERHOST;
	return skb;
}


void Show_SkBuff_Data(struct sk_buff * skb, bool MAC, bool NET, bool TSP, bool DAT)
{
	unsigned int BuffData = 0;
	char devname[IFNAMSIZ];
	struct ethhdr * ethh = NULL;
	struct iphdr * iph = NULL;
	struct udphdr * udph = NULL;
	unsigned int IP_str[4];
	unsigned char * content = NULL;

	if(MAC)
	{
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
	}

	if(NET)
	{
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
	}

	if(TSP)
	{
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

		printk("+++++DATA INFO+++++\n");

		BuffData = ntohs(udph->len) - sizeof(struct udphdr); 	// Data length
		if(unlikely(!BuffData))
		{
			printk("ERROR : Data LEN NULL.\n");
		}
		printk("Data LEN : %d\n", BuffData);
	}

/**************************DATA INFO**********************************************/
	if(DAT)
	{
		content = (unsigned char *)kmalloc(sizeof(char) * BuffData + 1, GFP_KERNEL);
		if(unlikely(!content))
		{
			printk("ERROR : kmalloc Failed.\n");
		}
		memcpy(content, (char *)udph + sizeof(struct udphdr), BuffData);
		content[BuffData] = '\0';			// Print data

		printk("Data: %s", content);

		kfree(content);
	}


}

ssize_t WriteToFile(const char * FileName, unsigned char * DataToWrite, unsigned int DataLen)
{
	struct file * MyFile = NULL;
	mm_segment_t old_fs;
	ssize_t rtn;

	MyFile = filp_open(FileName, O_RDWR|O_CREAT|O_APPEND, 0666);
	
	if(IS_ERR(MyFile))
	{
		printk("File open/create failed.\n");
		return 0;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	rtn = vfs_write(MyFile, DataToWrite, DataLen, &(MyFile->f_pos));

	set_fs(old_fs); 
	filp_close(MyFile, NULL); 

	return rtn;
}



