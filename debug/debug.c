#include "debug.h"

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

		content = (unsigned char *)kmalloc(sizeof(unsigned char) * ETH_ALEN + 1, GFP_ATOMIC);
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

		BuffData = iph->protocol;
		printk("IP protocol : %d\n", BuffData);
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
		shinfo = skb_shinfo(skb);
		printk("+++++SHARED INFO+++++\n");
		if(unlikely(!shinfo))
		{	
			printk("ERROR : shinfo is null.\n");
		}
		printk("nr_frags = %d \ntx_flags = %d \ngso_size = %d \ngso_segs = %d \ngso_type = %d \nfrag_list exist = %d\n",
				shinfo->nr_frags, shinfo->tx_flags, shinfo->gso_size, shinfo->gso_segs,
				shinfo->gso_type, (shinfo->frag_list != NULL));
	}
	printk("---------------------------------------------\n\n");

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

