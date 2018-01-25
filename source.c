
#include "source.h"


#if defined LINUX_4_10
unsigned int preRoutHookDisp(		void *priv, 
									struct sk_buff *skb, 
									const struct nf_hook_state *state)
#elif defined LINUX_3_13
unsigned int preRoutHookDisp(		const struct nf_hook_ops *ops,
							       	struct sk_buff *skb,
							       	const struct net_device *in,
							       	const struct net_device *out,
							       	int (*okfn)(struct sk_buff *))
#endif
{
	struct iphdr * iphd = (struct iphdr *)(skb->head + skb->network_header);
	struct udphdr *udph = (struct udphdr *)(skb->head + skb->transport_header);
//	struct tcphdr *tcph = (struct tcphdr *)(skb->head + skb->transport_header);

	if(iphd->protocol == IPPROTO_UDP)	// Judge package type
	{
		switch(ntohs(udph->dest))	// Judge destination port
		{
		case 8087:	// TODO: Need to be modified.			
			vehicle_hook_term_process(skb);
			return NF_STOLEN;
			break;
	/*		
		case TERM_C2_VEHICLE_PORT:	// Terminal to car, command
	
			break;
		
		case TERM_D2_VEHICLE_PORT:	// Terminal to car, data

			break;
	*/		
		default:	
			break;
		}

	}
//	else if(iphd->protocol == IPPROTO_TCP)
//	{
//		if(ntohs(tcph->dest) == 7006)
//			Show_SkBuff_Data(skb, false, true, false, false);
//	}
	
	return NF_ACCEPT;
}

void vehicle_hook_term_process(struct sk_buff *skb)	// Deal packages from terminal
{
	struct sk_buff *skb_decap = NULL;
	
//	printk("----------------Receive-----------------");
//	Show_SkBuff_Data(skb, true, true, true, false, true);
	
	if(vehicle_udp_decap(skb))	// LLC Ctrl
	{
//		printk("***************Ctrl Frame***************\n");
		process_term_ctl(skb);
	}
	else	// LLC Data
	{
//		if(skb_t) 
//		{
//			printk("Old skb dropped.\n");
//			kfree_skb(skb_t);
//		}

//		printk("***************Data Frame***************\n");

//		IAmHere = 1;

		skb_decap = vehicle_llc_decap(skb);	

		if(skb_decap) 
		{	
//			printk("***************Package***************\n");
//			Show_SkBuff_Data(skb_decap, false, true, true, true, true);

			netif_receive_skb(skb_decap);
			
//			kfree_skb(skb_decap);
//			skb_decap = NULL;
		}
	}
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
	
	static struct sk_buff * skb_rec = NULL;
	static struct sk_buff * skb_last = NULL;
	struct sk_buff * skb_t = NULL;
	struct sk_buff * skb_return = NULL;
	static int pktlastsn = -1;
	static int fragsn = 0;
	struct skb_shared_info * shinfo = NULL;

	skb_pull(skb, sizeof(struct data_hdr));
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->network_header = skb->data - skb->head;
	skb->transport_header = skb->network_header + sizeof(struct iphdr);

	if((pktlastsn < 0) || (datah->pkt_sn == pktlastsn + 1) || 
		(pktlastsn == 4095 && datah->pkt_sn == 1) || (datah->pkt_sn == 0))
	{
		pktlastsn = datah->pkt_sn;

		switch(datah->frag_flag)
		{
			// 11 : No frag
			case 3:	
				skb_return = skb;
				skb_rec = NULL;
				skb_last = NULL;
			break;

			// 10 : First frag
			case 2:	
				if(unlikely(datah->frag_sn != 0))
				{
					printk(KERN_ERR"(Firs)ERROR : fragsn %d.", datah->frag_sn);
					break;
				}
#ifdef SAFE				
				if(unlikely(skb_rec != NULL)) 
				{
					printk(KERN_ERR"(First)ERROR : (sn%d)Last skb unfinished.\n", datah->pkt_sn);
					kfree_skb(skb_rec);
					skb_rec = NULL;
				}
#endif
				skb_rec = skb;
				skb_last = skb;
				fragsn = datah->frag_sn;
				skb_return = NULL;
				break;

			// 01 : Last frag
			case 1:	
				if(unlikely(datah->frag_sn != fragsn + 1))
				{
 					printk(KERN_ERR"(Last)ERROR : fragsn %d, Last fragsn %d\n", datah->frag_sn, fragsn);
					break;
				}								
#ifdef SAFE				
				if(unlikely(skb_rec == NULL)) 
				{
					printk(KERN_ERR"(Last)ERROR : Lacking in skb.\n");
					break;
				}
#endif				
				// Add frag_list
				shinfo = skb_shinfo(skb_last);
				shinfo->frag_list = skb;

				// Update len & data_len
				skb_t = skb_rec;
				do
				{
					skb_t->len += skb->len;
					skb_t->data_len += skb->len;
					shinfo = skb_shinfo(skb_t);
					skb_t = shinfo->frag_list;
				}
				while(skb_t != skb);
					
				skb_return = skb_rec;
				skb_rec = NULL;
				skb_last = NULL;
				break;

			// 00 : Middle frag
			case 0:	
				if(unlikely(datah->frag_sn != fragsn + 1))
				{
					printk(KERN_ERR"(Middle)ERROR : fragsn %d, Last fragsn %d\n", datah->frag_sn, fragsn);
					break;
				}
				fragsn = datah->frag_sn;

#ifdef SAFE
				if(unlikely(skb_rec == NULL)) 
				{
					printk(KERN_ERR"(Middle)ERROR : Lacking in skb.\n");
					break;
				}
#endif
				// Add frag_list
				shinfo = skb_shinfo(skb_last);
				shinfo->frag_list = skb;

				// Update len & data_len
				skb_t = skb_rec;
				do
				{
					skb_t->len += skb->len;
					skb_t->data_len += skb->len;
					shinfo = skb_shinfo(skb_t);
					skb_t = shinfo->frag_list;
				}
				while(skb_t != skb);
					
				skb_last = skb;
				skb_return = NULL;

				break;
				
			default:	break;
		}
	}
	else
	{
		printk(KERN_ERR"ERROR : sn error, Last sn:%d, this sn:%d\n", pktlastsn, datah->pkt_sn);
		kfree_skb(skb);
		skb = NULL;
		skb_return = NULL;
	}
	
	return skb_return;
	
}


unsigned int process_term_ctl(struct sk_buff *skb)	// Contorl Frame
{
// Skb will be empty after pulling.!!
//	skb_pull(skb, sizeof(struct ctr_hdr));
	kfree(skb);
	return 0;
}


unsigned int TEST_PORT_FUNC(struct sk_buff *skb)
{
	Show_SkBuff_Data(skb, true, true, true, false, true);
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
#ifdef SAFE	
	if(unlikely(!skb)) 
	{
		printk("alloc failed\n"); 
		return NULL;
	} 
#endif
	skb_reserve(skb, len);
	skb->pkt_type  = PACKET_OTHERHOST;
	return skb;
}


void Show_SkBuff_Data(struct sk_buff * skb, bool MAC, bool NET, bool TSP, bool DAT, bool SHINFO)
{
	unsigned int BuffData = 0;
	char devname[IFNAMSIZ];
	struct ethhdr * ethh = NULL;
	struct iphdr * iph = NULL;
	struct udphdr * udph = NULL;
	unsigned int IP_str[4];
	unsigned char * content = NULL;
	struct skb_shared_info * shinfo = NULL;

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

		printk("Data: %s\n", content);

		kfree(content);
	}

/**************************SHARED INFO**********************************************/
	if(SHINFO)
	{
		shinfo = (struct skb_shared_info *)(skb->head + skb->end);
		printk("+++++SHARED INFO+++++\n");
		if(unlikely(!shinfo))
		{	
			printk("ERROR : shinfo is null.\n");
		}
		printk("nr_frags = %d \ntx_flags = %d \ngso_size = %d \ngso_segs = %d \ngso_type = %d \nfrag_list exist = %d\n",
				shinfo->nr_frags, shinfo->tx_flags, shinfo->gso_size, shinfo->gso_segs,
				shinfo->gso_type, (shinfo->frag_list != NULL));
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



