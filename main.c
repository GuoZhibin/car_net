#include"source.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NIC test");
MODULE_AUTHOR("MAC");

static struct nf_hook_ops preRoutHook;

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


static int mm_init(void)
{	
	mmHookInit();
	printk("car start work!\n");
	return 0;
}


static void mm_exit(void)
{
	msleep(1000);
	mmHookExit();
	mmDebug(MM_INFO,"xmit_Exit run..\n");
}

module_init(mm_init);
module_exit(mm_exit);
