/*
 * Kernel module to log connections per-PID
 * Various snippets borrowed from Linux chardev.c and kprobe_example.c
 *
 * Copyright (C) 2014 Mitchell Perilstein
 * Licensed under GNU GPL Version 2. See LICENSING file for details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/cdev.h>
#include <asm/byteorder.h>

#define DEVICE_NAME 	"connwatch"
#define FILENAME    	"/dev/connwatch"
#define SUCCESS		0
#define BUF_LEN		1024

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);

static struct file_operations fops = {
    .read = device_read,
    .open = device_open,
    .release = device_release
};

const char *dgram  = "inet_dgram_connect";
const char *stream = "inet_stream_connect";

static dev_t dev;
static struct cdev *my_cdev;

static int Device_Open = 0;	/* Is device open? Used to prevent multiple access to device */
static char msg[BUF_LEN];	/* The msg the device will give when asked */
static char *msg_Ptr;

static char *my_inet_ntoa(struct sockaddr_in *addr)
{
    unsigned char *bytes = (unsigned char *)&(addr->sin_addr.s_addr);
    static char buffer[18];
    snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d",
             bytes[0], bytes[1], bytes[2], bytes[3]);
    return buffer;
}

static void report(char *type, struct sockaddr_in *uaddr)
{
    /* filter local - see /include/linux/in.h */
    if (! ipv4_is_private_10(uaddr->sin_addr.s_addr)  &&
        ! ipv4_is_private_172(uaddr->sin_addr.s_addr) &&
        ! ipv4_is_private_192(uaddr->sin_addr.s_addr) &&
        ! ipv4_is_zeronet(uaddr->sin_addr.s_addr)     &&
        ! ipv4_is_loopback(uaddr->sin_addr.s_addr)) {

        /* TODO - make this a ring buffer to avoid overwriting messages
           that haven't been read by consumer yet. */

        sprintf(msg, "%s port:%d addr:%s from %s pid %d\n",
               type, ntohs(uaddr->sin_port), my_inet_ntoa(uaddr), current->comm, current->pid);
        msg_Ptr = msg;
    }
}

static int my_stream_connect(void *sock, struct sockaddr_in *uaddr, size_t addrlen, int flags)
{
    report("stream", uaddr);
    jprobe_return();

    /*NOTREACHED*/
    return 0;
}

static int my_dgram_connect(void *sock, struct sockaddr_in *uaddr, size_t addrlen, int flags)
{
    report("dgram", uaddr);
    jprobe_return();

    /*NOTREACHED*/
    return 0;
}

static struct jprobe my_stream_jprobe = {
    .entry = (kprobe_opcode_t *) my_stream_connect
};

static struct jprobe my_dgram_jprobe = {
    .entry = (kprobe_opcode_t *) my_dgram_connect
};

static int plant(struct jprobe *probe, const char *thing)
{
    int ret;

    probe->kp.addr = (kprobe_opcode_t *) kallsyms_lookup_name(thing);
    if (!probe->kp.addr) {
        printk("%s Couldn't find %s to plant jprobe\n", DEVICE_NAME, thing);
        return -1;
    }

    if ((ret = register_jprobe(probe)) < 0) {
        printk("%s register_jprobe %s failed, returned %d\n", DEVICE_NAME, thing, ret);
        return -1;
    }

    printk("%s planted %s jprobe at %p, handler addr %p\n", DEVICE_NAME, thing,
           probe->kp.addr, probe->entry);

    return SUCCESS;
}

static int device_open(struct inode *sip, struct file *sfp)
{
    if (Device_Open)
        return -EBUSY;

    Device_Open++;
    //    sprintf(msg, "ready\n");
    // msg_Ptr = msg;
    try_module_get(THIS_MODULE);
    
    return SUCCESS;
}

static ssize_t device_read(struct file *ignore, char *buffer, size_t length, loff_t *ignore2)
{
    int copied = 0;

    if (*msg_Ptr == 0)
        return 0;

    while (length && *msg_Ptr) {
        put_user(*(msg_Ptr++), buffer++);
        length--;
        copied++;
    }

    return copied;
}

static int device_release(struct inode *sip, struct file *sfp)
{
    Device_Open--;		/* We're now ready for our next caller */
    module_put(THIS_MODULE);

    return SUCCESS;
}

static int __init connwatch_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (ret < 0) return ret;

    my_cdev = cdev_alloc();
    my_cdev->owner = THIS_MODULE;
    my_cdev->ops = &fops;
    ret = cdev_add(my_cdev, dev, 1);
    if (ret < 0) return ret;

    printk("%s allocated %d, %d\n", DEVICE_NAME, MAJOR(dev), MINOR(dev));

    ret = plant(&my_stream_jprobe, stream);
    if (ret < 0) return ret;

    ret = plant(&my_dgram_jprobe, dgram);
    if (ret < 0) return ret;

    return SUCCESS;
}

static void __exit_call connwatch_cleanup(void)
{
    cdev_del(my_cdev);
    unregister_chrdev_region(dev, 1);
    unregister_jprobe(&my_stream_jprobe);
    unregister_jprobe(&my_dgram_jprobe);
    printk("%s unregistered\n", DEVICE_NAME);
}

module_init(connwatch_init)
module_exit(connwatch_cleanup)

MODULE_AUTHOR("Mitchell Perilstein");
MODULE_DESCRIPTION("connwatch - Report new network connections by PID as they occur");
MODULE_LICENSE("GPL v2");
