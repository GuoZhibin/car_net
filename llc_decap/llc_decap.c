#include "llc_decap.h"

/* Decapsulate IP&UDP head. Return packet type. */
int vehicle_udp_decap(struct sk_buff *skb)	
{
	struct ctr_hdr * tmp;

	skb_pull(skb, sizeof(struct iphdr));
	skb_pull(skb, sizeof(struct udphdr));

	tmp = (struct ctr_hdr *)skb->data;
	if(tmp->d_or_c)	
	{/* LLC Ctrl */
		return 1;
	}
	else	
	{/* LLC Data */
		return 0;
	}
}

/*
 * Decapsulate LLC head with datacopy
 * This function free the skb!! Don't free again outside!!
 */
struct sk_buff * vehicle_llc_decap_datacopy(struct sk_buff *skb)	
{
	struct data_hdr * datah = (struct data_hdr *)skb->data;
	static struct sk_buff * skb_rec = NULL;
	struct sk_buff * skb_return = NULL;
	static int fragsn = 0;
	char * ptr = NULL;

	const unsigned int headlen = sizeof(struct ethhdr) + sizeof(struct iphdr) + \
							sizeof(struct udphdr) + sizeof(struct data_hdr) + 16;	

	skb_pull(skb, sizeof(struct data_hdr));	
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = htons(ETH_P_IP);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	
	switch(datah->frag_flag)
	{
		// 11 : No frag
		case 3: 
			skb_return = skb;

			break;

		// 10 : First frag
		case 2: 	
			if(unlikely(skb_rec != NULL)) 
			{
				printk(KERN_ERR"(First)ERROR : (sn%d)Last skb unfinished.\n", datah->pkt_sn);
				kfree_skb(skb_rec);
				skb_rec = NULL;
			}
			if(unlikely(datah->frag_sn != 0))
			{
				printk(KERN_ERR"(First)ERROR : fragsn %d.", datah->frag_sn);
				kfree_skb(skb);
				break;
			}
			fragsn = datah->frag_sn;

			skb_rec = skb_copy_expand(skb, headlen, datah->len - skb->len + 16, GFP_ATOMIC);
			if(unlikely(skb_rec == NULL))
			{
				printk(KERN_ERR"(First)ERROR : skb_rec created failed.\n");
				break;
			}
			
			skb_return = NULL;

			kfree_skb(skb);
			skb = NULL;
			
			break;

		// 01 : Last frag
		case 1: 		
			if(unlikely(skb_rec == NULL)) 
			{
				printk(KERN_ERR"(Last)ERROR : Lacking in skb.\n");
				kfree_skb(skb);
				break;
			}
			if(unlikely(datah->frag_sn != fragsn + 1))
			{
				printk(KERN_ERR"(Last)ERROR : fragsn %d, Last fragsn %d\n", datah->frag_sn, fragsn);
				kfree_skb(skb_rec);
				skb_rec = NULL;
				kfree_skb(skb);
				break;
			}
			if(unlikely(skb_tailroom(skb_rec) < skb->len))
			{
				printk("skb_tailroom = %d, skb->len = %d\n", skb_tailroom(skb_rec), skb->len);
				kfree_skb(skb_rec);
				skb_rec = NULL;
				kfree_skb(skb);
				break;
			}
			
			ptr = skb_put(skb_rec, skb->len);
			memcpy(ptr, skb->data, skb->len);
										
			skb_return = skb_rec;
			skb_rec = NULL;

			kfree_skb(skb);
			skb = NULL;

			break;
		case 0: // 00 : Middle frag
			if(unlikely(skb_rec == NULL)) 
			{
				printk(KERN_ERR"(Middle)ERROR : Lacking in skb.\n");
				kfree_skb(skb);
				break;
			}	
			if(unlikely(datah->frag_sn != fragsn + 1))
			{
				printk(KERN_ERR"(Middle)ERROR : fragsn %d, Last fragsn %d\n", datah->frag_sn, fragsn);
				kfree_skb(skb_rec);
				skb_rec = NULL;
				kfree_skb(skb);
				break;
			}
			if(unlikely(skb_tailroom(skb_rec) < skb->len))
			{
				printk("(Middle)ERROR : tailroom not enough\n");
				kfree_skb(skb_rec);
				skb_rec = NULL;
				kfree_skb(skb);
				break;
			}
			
			fragsn = datah->frag_sn;

			ptr = skb_put(skb_rec, skb->len);
			memcpy(ptr, skb->data, skb->len);

			skb_return = NULL;

			kfree_skb(skb);
			skb = NULL;

			break;
		default:	break;
	}	
	
	return skb_return;
}

/*
 * Decapsulate LLC head with zerocopy
 * This function free the skb!! Don't free again outside!!
 */
struct sk_buff * vehicle_llc_decap_zerocpoy(struct sk_buff *skb)	
{
	struct data_hdr * datah = (struct data_hdr *)skb->data;
	
	static struct sk_buff * skb_rec = NULL;
	static struct sk_buff * skb_last = NULL;
	struct sk_buff * skb_return = NULL;
	static int fragsn = 0;
	struct skb_shared_info * shinfo = NULL;
	struct iphdr * iph = NULL;

	skb_pull(skb, sizeof(struct data_hdr));
	
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = htons(ETH_P_IP);
	skb->network_header = skb->data - skb->head;
	skb->transport_header = skb->network_header + sizeof(struct iphdr);

	switch(datah->frag_flag)
	{
		// 11 : No frag
		case 3:	
			skb_return = skb;
		break;

		// 10 : First frag
		case 2:	
			if(unlikely(skb_rec != NULL)) 
			{
				printk(KERN_ERR"(First)ERROR : (sn%d)Last skb unfinished.\n", datah->pkt_sn);
				kfree_skb(skb_rec);
				skb_rec = NULL;
			}
			if(unlikely(datah->frag_sn != 0))
			{
				printk(KERN_ERR"(First)ERROR : fragsn %d.", datah->frag_sn);
				kfree_skb(skb);
				break;
			}		
			fragsn = datah->frag_sn;
			
			skb_rec = skb;
			skb_last = skb;

			skb_rec->next = NULL;

			iph = ip_hdr(skb_rec);
			iph->check = 0;
			iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
			
			skb_return = NULL;
			break;

		// 01 : Last frag
		case 1:	
			if(unlikely(skb_rec == NULL)) 
			{
				printk(KERN_ERR"(Last)ERROR : Lacking in skb.\n");
				kfree_skb(skb);
				break;
			}	
			if(unlikely(datah->frag_sn != fragsn + 1))
			{
				printk(KERN_ERR"(Last)ERROR : fragsn %d, Last fragsn %d\n", datah->frag_sn, fragsn);
				kfree_skb(skb_rec);
				skb_rec = NULL;
				kfree_skb(skb);
				break;
			}
			
			// Add fragment
			if(skb_last == skb_rec)
			{
				shinfo = skb_shinfo(skb_last);
				shinfo->frag_list = skb;
			}
			else
			{
				skb_last->next = skb;
				skb->next = NULL;
			}
			skb_rec->len += skb->len;
			skb_rec->data_len += skb->len;
			skb_rec->truesize += skb->truesize;
			
			skb_return = skb_rec;
			skb_rec = NULL;
			skb_last = NULL;
			break;

		// 00 : Middle frag
		case 0:	
			if(unlikely(skb_rec == NULL)) 
			{
				printk(KERN_ERR"(Middle)ERROR : Lacking in skb.\n");
				kfree_skb(skb);
				break;
			}	
			if(unlikely(datah->frag_sn != fragsn + 1))
			{
				printk(KERN_ERR"(Middle)ERROR : fragsn %d, Last fragsn %d\n", datah->frag_sn, fragsn);
				kfree_skb(skb_rec);
				skb_rec = NULL;
				kfree_skb(skb);
				break;
			}
			fragsn = datah->frag_sn;

			// Add fragment
			if(skb_last == skb_rec)
			{
				shinfo = skb_shinfo(skb_last);
				shinfo->frag_list = skb;
				skb->next = NULL;
			}
			else
			{
				skb_last->next = skb;
				skb->next = NULL;
			}
			skb_rec->len += skb->len;
			skb_rec->data_len += skb->len;
			skb_rec->truesize += skb->truesize;
			
			skb_last = skb;
			skb_return = NULL;

			break;
			
		default:	break;
	}
	
	return skb_return;
	
}


struct sk_buff * copy_new_skb(struct sk_buff *skb, int len)
{
	struct sk_buff * nskb = NULL;
	
	nskb = alloc_skb(skb->len + 18 + len, GFP_ATOMIC);
	if(unlikely(nskb == NULL)) 
	{
		printk(KERN_ERR"nskb allc failed\n");
		return NULL;
	}
	skb_reserve(nskb, 2);
	skb_put(nskb, skb->len + ETH_HLEN);
	skb_reset_mac_header(nskb);
	skb_set_network_header(nskb, ETH_HLEN);
	skb_set_transport_header(nskb, ETH_HLEN + sizeof(struct iphdr));
	memcpy(skb_mac_header(nskb), skb_mac_header(skb), ETH_HLEN);
	memcpy(skb_network_header(nskb), skb_network_header(skb), skb_headlen(skb));
	skb_pull(nskb, ETH_HLEN);
	nskb->dev = skb->dev;
	nskb->pkt_type = skb->pkt_type;
	nskb->protocol = skb->protocol;
	nskb->ip_summed = CHECKSUM_NONE;
	nskb->tstamp = skb->tstamp;
	
	return nskb;
}




