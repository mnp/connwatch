/*
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <asm/byteorder.h>

#define MYNAME   "connwatch"
#define FILENAME "/dev/connwatch"

struct event {
    
};

const char *dgram  = "inet_dgram_connect";
const char *stream = "inet_stream_connect";

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
        printk("%s %s port:%d addr:%s from %s pid %d\n", 
               MYNAME, type, ntohs(uaddr->sin_port), 
               my_inet_ntoa(uaddr), current->comm, current->pid);
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

int plant(struct jprobe *probe, const char *thing)
{
    int ret;

    probe->kp.addr = (kprobe_opcode_t *) kallsyms_lookup_name(thing);
    if (!probe->kp.addr) {
        printk("%s Couldn't find %s to plant jprobe\n", MYNAME, thing);
        return -1;
    }

    if ((ret = register_jprobe(probe)) < 0) {
        printk("%s register_jprobe %s failed, returned %d\n", MYNAME, thing, ret);
        return -1;
    }

    printk("%s planted %s jprobe at %p, handler addr %p\n", MYNAME, thing,
           probe->kp.addr, probe->entry);

    return 0;
}

int init_module(void)
{
        int ret;
        dev_t dev;
        
        ret = alloc_chrdev_region(&dev, 0, 1, MYNAME);
        if (ret < 0) return ret;

        printk("%s allocated %d, %d\n", MYNAME, MAJOR(dev), MINOR(dev));

        ret = plant(&my_stream_jprobe, stream);
        if (ret < 0) return ret;

        ret = plant(&my_dgram_jprobe, dgram);
        if (ret < 0) return ret;

        return 0;
}

void cleanup_module(void)
{
    unregister_chrdev_region(dev, 1);
    unregister_jprobe(&my_stream_jprobe);
    unregister_jprobe(&my_dgram_jprobe);
    printk("%s unregistered\n", MYNAME);
}

MODULE_AUTHOR("Mitchell Perilstein");
MODULE_DESCRIPTION("connwatch - Report new network connections");
MODULE_LICENSE("GPL v2");
