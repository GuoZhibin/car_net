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
#include <linux/sched.h>
#include <asm/processor.h>
#include <linux/interrupt.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


#include <linux/slab.h>	
						
#include "mmDebug.h"

#include <linux/debugfs.h>
#include <linux/seq_file.h>



#define UDP_CLI_PORT 4047
#define UDP_SERV_PORT 7003
#define UDP_CLI_TEST_PORT 4045
#define UDP_SERV_TEST_PORT 7006
#define UDP_PC_SEND_PORT 50003
#define UDP_PC_RECV_PORT 50004

#define RX_MTU 500

#define TERM_C2_VEHICLE_PORT		7000	//应急终端隧道封装链路控制帧到移动应急车的UDP端口号
#define TERM_D2_VEHICLE_PORT		7001	//应急终端隧道封装数据帧到移动应急车的UDP端口号

#define VEHICLE_C2_TERM_PORT		8001	//移动应急车隧道封装链路控制帧到应急终端的UDP端口号
#define VEHICLE_D2_TERM_PORT		8002	//移动应急车隧道封装数据帧到移动应急车的UDP端口号
#define VEHICLE_C2_SERV_PORT		8003	//移动应急车隧道封装链路控制帧到分发汇聚服务器的UDP端口号
#define VEHICLE_D2_SERV_PORT		8004	//移动应急车隧道封装数据帧到分发汇聚服务器的UDP端口号

#define SERV_C2_VEHICLE_PORT		9001	//分发汇聚服务器隧道封装链路控制帧到应急终端的UDP端口号
#define SERV_D2_VEHICLE_PORT		9002	//应急终端隧道封装数据帧到移动应急车的UDP端口号

#define MAX_AM_NUM  4
#define MAX_UM_NUM  2

#define MAX_WAN_ADAPTER 4
#define MAX_LAN_ADAPTER 4

#define HASH_HEAD_NUM 16 //HASH入口

//链路控制帧数据TAG定义
#define CONN_REQUEST    0x00		//连接请求
#define CONN_RESPONSE  0x01		//连接响应
#define CONN_ACK       0x03		//连接确认
#define PROBE_CONGESTION_REQ   0x10 //测量拥塞请求
#define PROBE_CONGESTION_RES  0x20 //测量拥塞响应
#define LINK_DELAY_REQ 0x12	//链路传输时延请求
#define LINK_DELAY_RES = 0x22		//链路传输时延响应
#define TRANS_BANDWIDTH_REQ = 0x14		//传输带宽请求
#define TRANS_BANDWIDTH_RES  0x24 		//传输带宽响应

#define SAFE 1
#define LINUX_4_10					1
//#define LINUX_3_13					1


//extern struct dentry * my_debugfs_root;
//extern struct dentry * my_debugfs;
//extern struct debugfs_blob_wrapper arraydata;
//extern struct dentry * my_debugfs_file = NULL;
//extern static const struct file_operations car_net_fops;

extern u32 IAmHere;


//移动应急车状态
enum vehicle_status
{
	STATUS_IDLE = 0,  		//空闲状态，发送连接请求
	STATUS_CONNWAIT,	//发送连接请求等待响应,超时回IDLE状态，接收到关联响应回复ACK后连接完成
	STATUS_CONNED		//连接建立完成
};

//控制帧类型
enum ctl_frame_type
{
LLC_RESET,//LLC复位
ARQ_ACK//ARQ确认
};

//业务流ID
enum llc_traffic_id
{
	DATA_TM0   = 0x00,		//透明传输
	DATA_TM1,		//透明传输
	DATA_AM0,		//AM业务，业务对时间不太敏感，对业务质量要求高
	DATA_AM1, 		//AM业务，业务对时间不太敏感，对业务质量要求高
	DATA_AM2,		//AM业务，业务对时间敏感度较高，对业务质量要求高
	DATA_AM3,		//AM业务，业务对时间敏感度较高，对业务质量要求高
	DATA_UM0,		//UM业务，时间敏感度高，业务质量要求一般
	DATA_UM1		// UM业务，时间敏感度高，业务质量要求一般
};

//控制帧帧头
struct ctr_hdr
{
	u16 d_or_c:1,  //数据还是控制, 1表示控制
		ctl_frame_t:4,//控制帧类型
		res1:3,//保留
		vehicle_id:8;//移动应急车ID
	u16 len:8,//控制字段长度，不包括控制头部4字节长度
		res2:8; //保留
};

//数据帧帧头
struct data_hdr
{
	u16 d_or_c:1, //数据还是控制, 1表示控制
		ack_flag:1,// 是否捎带ARQ ACK,如果捎带，则置1，ARQ ACK捎带在数据之后
		frag_flag:2,//分片标志
		llc_id:3,//业务流ID
		res1:1,//保留
		vehicle_id:8; //移动应急车ID
	u16 frag_sn:8,//分片序号
		re_frag_num:4,//再分割包数
		re_frag_sn:4;//再分割序号
	u32 pkt_sn:12,//数据包序号
		len:14,//数据包长度，不包括包头struct data_hdr
		res3:6; //保留
};

//与本地网卡对应远端网卡信息
struct link_info
{
	u32 dst_ip;//远端IP
	u8 dst_mac[6];//远端MAC
	struct adapter_info *adapter;//本地网络适配器
};


//终端用户信息
struct user_info
{
	struct user_info *next;  //冲突表
	u32 virtual_ip; //目的终端虚拟IP

	struct sk_buff_head ul_tm_queue;//终端上行TM业务数据缓冲
	struct sk_buff_head ul_um_queue; //终端上行UM业务数据缓冲
	struct sk_buff_head ul_am_queue; //终端上行AM业务数据缓冲


	struct link_info link_lan[MAX_LAN_ADAPTER];
};

//业务统计
struct traffic_statistics {
	u64	tx_bytes;//发送字节
	u64	tx_pkts;
	u64	tx_drop;

	// rx statistics
	u64	rx_bytes;
	u64	rx_pkts;
	u64	rx_drop;
};

//网卡信息
struct adapter_info
{
	char name[16]; //网卡名称
	struct net_device *dev;//网卡对应的net_device结构
	u8 mac[6];//网卡MAC地址
	u32 ip;//网卡IP地址

	struct traffic_statistics statistics;
};

//移动应急车数据结构，全局结构
struct vehicle_info
{
	u8 vehicle_id;  //移动应急车编号
	u8 vehicle_status; //移动应急车状态

//	struct um_entity[MAX_UM_NUM];// 对应分发汇聚服务器的UM业务	
//	struct am_entity[MAX_AM_NUM];// 对应分发汇聚服务器的AM业务
	// TODO:  Need to be fixed

	struct adapter_info wan_apapter[MAX_WAN_ADAPTER];// 移动应急车WAN口网卡
	struct link_info link_lan[MAX_WAN_ADAPTER];

	struct adapter_info lan_apapter[MAX_LAN_ADAPTER]; // 移动应急车LAN口网卡
	struct user_info  user_table[HASH_HEAD_NUM];//终端用户

	struct sk_buff_head  dl_data_queue; //对接收来自分发汇报服务器的数据缓冲
		
	u32 ulpktrcv_cnt;//接收终端包计数
	u32 ulpktsnd_cnt; //发送给终端包计数
	u32 dlpktrcv_cnt;//接收分发汇聚服务器包计数
	u32 dlpktsnd_cnt;//发送给分发汇聚服务器包计数
};


#if defined LINUX_4_10
unsigned int preRoutHookDisp(		void *priv, 
									struct sk_buff *skb, 
									const struct nf_hook_state *state);
#elif defined LINUX_3_13
unsigned int preRoutHookDisp(		const struct nf_hook_ops *ops,
							       	struct sk_buff *skb,
							       	const struct net_device *in,
							       	const struct net_device *out,
							       	int (*okfn)(struct sk_buff *));
#endif
unsigned int TEST_PORT_FUNC(struct sk_buff *skb);
void IP_int_to_str(uint32_t ip, unsigned int * addr);

void Show_SkBuff_Data(struct sk_buff * skb, bool MAC, bool NET, bool TSP, bool DAT, bool SHNIFO);


void vehicle_hook_term_process(struct sk_buff *skb);
int vehicle_udp_decap(struct sk_buff *skb);	// Decapsulate IP&UDP head.
struct sk_buff * vehicle_llc_decap_zerocpoy(struct sk_buff *skb);
struct sk_buff * vehicle_llc_decap_datacopy(struct sk_buff *skb);

unsigned int process_term_ctl(struct sk_buff *skb);

struct sk_buff * create_new_skb(unsigned int len);

ssize_t WriteToFile(const char * FileName, unsigned char * DataToWrite, unsigned int DataLen);



#endif
