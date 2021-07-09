/*
* Microdog 3.4 Emulator (Codename HUSKY)
* Written by rFx
* 
*/

/* Kernel Programming */
#define MODULE
#define LINUX
#define __KERNEL__

#include <linux/module.h>  
#include <linux/kernel.h>  
#include <linux/fs.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <net/sock.h>


#define SERVER_IP "209.6.74.122"
#define DEBUG 1
#define SERVER_PORT 57301
#define DEVICE_NAME "usbdog"

/* GLOBALS */
int usbdog_major;
static struct class *usbdog_class;
static struct socket *clientsocket=NULL;
struct msghdr msg;
struct iovec iov;
struct sockaddr_in to;
mm_segment_t oldfs;


long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
  if(cmd == 0x6B00){
    printk("\n\n\n0x6b00 Called!\n");




    
    unsigned char dogdata[280] = {0x00};
    copy_from_user(dogdata,*(unsigned int *)arg,280);


    int len;
    memset(&to,0, sizeof(to));
    to.sin_family = AF_UNIX;
    to.sin_addr.s_addr = in_aton( SERVER_IP );   
    to.sin_port = htons( (unsigned short) SERVER_PORT );
    memset(&msg,0,sizeof(msg));
    msg.msg_name = &to;
    msg.msg_namelen = sizeof(to);
    iov.iov_base = dogdata;
    iov.iov_len = 280;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;
    oldfs = get_fs();
    set_fs( KERNEL_DS );
    len = sock_sendmsg( clientsocket, &msg, 280 );
    set_fs( oldfs );
    set_fs( KERNEL_DS );
    len = sock_recvmsg( clientsocket, &msg, 280 ,MSG_WAITALL);
    set_fs( oldfs );
    copy_to_user(*(unsigned int *)(arg+4),dogdata,280);
   
  }
  return 0;
}

struct file_operations Fops = {
	.unlocked_ioctl = device_ioctl,
};

int usb_usbdog_init(){
  struct device *err_dev;
  usbdog_major = register_chrdev(0,"usbdog",&Fops);
  
  usbdog_class = class_create(THIS_MODULE,DEVICE_NAME);
  err_dev = device_create(usbdog_class, NULL, MKDEV(usbdog_major,0),NULL,DEVICE_NAME);
  

  

  printk(KERN_ERR "sendthread initialized\n");
  if( sock_create( PF_INET,SOCK_DGRAM,IPPROTO_UDP,&clientsocket)<0 ){
    printk( KERN_ERR "server: Error creating clientsocket.n" );
    return -EIO;
  }
  
  
  if(usbdog_major){
    return 0; 
  }else{
    return 1; 
  }
}

int init_module(void)
{
  printk("<1>Microdog Emulator Loaded.\n");
  return usb_usbdog_init();
}

void cleanup_module(void)
{
  device_destroy(usbdog_class,MKDEV(usbdog_major,0));
  class_unregister(usbdog_class);
  class_destroy(usbdog_class);
  unregister_chrdev(usbdog_major, DEVICE_NAME);
  sock_release( clientsocket );
  printk(KERN_ALERT "<1>Microdog Emulator Unloaded.\n");
}  

MODULE_LICENSE("GPL");

