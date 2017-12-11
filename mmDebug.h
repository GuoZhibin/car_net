/* 
 * MM's debug macro
 */
#ifndef _MM_DEBUG_H_
#define _MM_DEBUG_H_

#define _mm_debug_
#define _mm_show_buf_

#define assert(expr) \
    if (!(expr)) {                                  \
         printk( KERN_ALERT"multimode: Assertion failed! %s,%s,%s,line=%d\n", \
         #expr,__FILE__,__FUNCTION__,__LINE__);          \
    }

#define IP_PRINT(addr) \
        ((unsigned char*)&addr)[0], \
        ((unsigned char*)&addr)[1], \
        ((unsigned char*)&addr)[2], \
        ((unsigned char*)&addr)[3]
        
#define MM_FILE 5
#define MM_DBG  4
#define MM_INFO 3
#define MM_WARNING 2
#define MM_ERROR 1

#define MM_PRINT_LEAVLE MM_INFO

/* debug macro*/
#ifdef  _mm_debug_
#define mmDebug(level,fmt, args...) \
do {\
    if (level <= MM_PRINT_LEAVLE) { \
        printk(KERN_ALERT"multimode : %s, %d, "fmt, __FUNCTION__, __LINE__, ##args);\
   }\
} while (0)

//printk(KERN_ALERT"multimode : %s, %s, %d, "fmt, __FILE__, __FUNCTION__, __LINE__, ##args);

#else
    #define mmDebug(fmt, args...)
#endif /* !_mm_debug_ */


#ifdef _mm_show_buf_

#define mmShowBuf(level,addr,len) \
do{\
    if (level <= MM_PRINT_LEAVLE) { \
        int i;\
        printk(KERN_ALERT"\nmultimode : mmShowBuf in bufer length %d :",len);\
        for(i =0 ;i<len;i++)\
        {\
            if(0 == (i&0x7))\
            {\
                printk("\nmultimode : 0x: ");\
            }\
            printk("%02x ",*((unsigned char *)addr + i));\
        }\
        printk("\nmultimode : mmShowBuf end\n");\
    }\
}while(0)
#else
    #define mmShowBuf(level,addr,len)

#endif /* !_mm_show_buf_ */

#endif /* !_MM_DEBUG_H_ */
