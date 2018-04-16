#include "source.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NIC test");
MODULE_AUTHOR("MAC");

static struct nf_hook_ops preRoutHook;

//struct dentry * my_debugfs_root = NULL;

//u32 IAmHere = 0;

//struct debugfs_blob_wrapper arraydata;
//struct dentry * my_debugfs = NULL;

//struct dentry * my_debugfs_file = NULL;
//
//struct seq_operations car_net_seq_ops = {
//	.start = car_net_seq_start,
//   	.stop = car_net_seq_stop,
//   	.next = car_net_seq_next,
//   	.show = car_net_seq_show
//};
//
//static int car_net_seq_open(struct inode *inode, struct file *file)
//{
//        return seq_open(file, &car_net_seq_ops);
//};
//
//static const struct file_operations car_net_fops
//{
//	.owner = THIS_MODULE,
//	.open = car_net_seq_open,
//	.read = seq_read,
//	.write = seq_write,
//	.llseek = seq_lseek,
//	.release = single_release
//};

int mmHookInit(void)
{
	preRoutHook.hook = preRoutHookDisp;
	preRoutHook.hooknum = NF_INET_PRE_ROUTING;
	preRoutHook.pf = NFPROTO_IPV4;
	preRoutHook.priority = NF_IP_PRI_LAST;
	nf_register_hook(&preRoutHook);
	return 0;
}


void mmHookExit(void)
{
	nf_unregister_hook(&preRoutHook);
}

//void FindMySkb(void * pa, struct sk_buff *skb)
//{
//	struct iphdr * iph = (struct iphdr *)(skb->data);
//	struct udphdr *udph = (struct udphdr *)(skb->data + sizeof(struct iphdr));
//	struct tcphdr *tcph = (struct udphdr *)(skb->data + sizeof(struct iphdr));
//
//	if(iph->protocol == IPPROTO_UDP)
//	{
//		
//		switch(ntohs(udph->dest))
//		{
//		case 8087:
//			printk("Unpacked skb!\n");
//			break;
//		case 7006:
//			printk("Packed skb!\n");
//			break;	
//		default:	
//			break;
//		}
//	}
//	else if(iph->protocol == IPPROTO_TCP)
//	{
//		switch(ntohs(tcph->dest))
//		{
//		case 8087:
//			printk("Unpacked skb!\n");
//			break;
//		case 7006:
//			printk("Packed skb!\n");
//			break;	
//		default:	
//			break;
//		}
//	}
//}


static int mm_init(void)
{	
//	my_debugfs_root = debugfs_create_dir("car_net_dir", NULL);
//	if (!my_debugfs_root)
//		printk("Debugfs dir create failed.\n");
//
//	my_debugfs = debugfs_create_u32("IAmHere", 0666, my_debugfs_root, &IAmHere);

//	my_debugfs_file = debugfs_create_file("user_net_file", 0666, my_debugfs_root, NULL, car_net_fops);
//	if (!my_debugfs_file)
//		printk("Debugfs file create failed.\n");
	
//	int rtn = register_trace_netif_receive_skb(FindMySkb, NULL);
//	if(rtn) printk("rtn %d\n", rtn);

	mmHookInit();
	
	printk("car start work!\n");
	return 0;
}


static void mm_exit(void)
{
	msleep(1000);

//	debugfs_remove_recursive(my_debugfs_root);
//	my_debugfs_root = NULL;

//	unregister_trace_netif_receive_skb(FindMySkb, NULL);
//	tracepoint_synchronize_unregister();


	mmHookExit();	
	mmDebug(MM_INFO,"xmit_Exit run..\n");
}

module_init(mm_init);
module_exit(mm_exit);
