#define _GNU_SOURCE /* for F_SETSIG */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "handler.h"

#include "util.h"
#include "net2.h"
#include "ether.h"

#include "ethertap.h"

#define ETHER_PCAP_IRQ (SIGRTMIN+3)

struct ether_pcap {
    char name[IFNAMSIZ];
    int fd;
    unsigned int irq;
};

#define PRIV(x) ((struct ether_pcap *)x->priv)

static int ether_pcap_addr(struct network_device *dev) {
    int soc;
    struct ifreq ifr = {};

    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        errorf("socket: %s, device=%s", strerror(errno), dev->name);
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name)-1);
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) {
        errorf("ioctl(SIOCGIFHWADDR): %s, device=%s", strerror(errno), dev->name);
        close(soc);
        return -1;
    }
    memcpy(dev->address, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(soc);
    return 0;
}

static int ether_pcap_open(struct network_device *dev)
{
    struct ether_pcap *pcap;
    struct sockaddr_ll addr = {};
    struct ifreq ifr = {};

    pcap = PRIV(dev);

    pcap->fd = socket(PF_PACKET, SOCK_RAW, hton16(ETH_P_ALL));
    if (pcap->fd == -1) {
        errorf("socket: %s, device=%s", strerror(errno), dev->name);
        return -1;
    }
    strncpy(ifr.ifr_name, pcap->name, sizeof(ifr.ifr_name)-1);
    if (ioctl(pcap->fd, SIOCGIFINDEX, &ifr) == -1) {
        errorf("ioctl(SIOCGIFINDEX): %s, device=%s", strerror(errno), dev->name);
        close(pcap->fd);
        return -1;
    }
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = hton16(ETH_P_ALL);
    addr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(pcap->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        errorf("binding failed: %s, device=%s", strerror(errno), dev->name);
        close(pcap->fd);
        return -1;
    }
    if (ioctl(pcap->fd, SIOCGIFFLAGS, &ifr) == -1) {
        errorf("ioctl(SIOCGIFFLAGS): %s, device=%s", strerror(errno), dev->name);
        close(pcap->fd);
        return -1;
    }
    ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
    if (ioctl(pcap->fd, SIOCSIFFLAGS, &ifr) == -1) {
        errorf("ioctl(SIOCSIFFLAGS): %s, device=%s", strerror(errno), dev->name);
        close(pcap->fd);
        return -1;
    }

    if (fcntl(pcap->fd, F_SETOWN, getpid()) == -1) {
        errorf("fcntl(F_SETOWN): %s, device=%s", strerror(errno), dev->name);
        close(pcap->fd);
        return -1;
    }

    if (fcntl(pcap->fd, F_SETFL, O_ASYNC) == -1) {
        errorf("fcntl(F_SETFL): %s, device=%s", strerror(errno), dev->name);
        close(pcap->fd);
        return -1;
    }

    if (fcntl(pcap->fd, F_SETSIG, pcap->irq) == -1) {
        errorf("fcntl(F_SETSIG): %s, device=%s", strerror(errno), dev->name);
        close(pcap->fd);
        return -1;
    }
    if (memcmp(dev->address, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0) {
        if (ether_pcap_addr(dev) == -1) {
            errorf("ether_pcap_addr() failure, device=%s", dev->name);
            close(pcap->fd);
            return -1;
        }
    }
    return 0;
};

static int ether_pcap_close(struct network_device *dev)
{
    close(PRIV(dev)->fd);
    return 0;
}

static ssize_t ether_pcap_write(struct network_device *dev, const uint8_t *frame, size_t flen)
{
    return write(PRIV(dev)->fd, frame, flen);
}

int ether_pcap_transmit(struct network_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst)
{
    return ether_transmit_helper(dev, type, buf, len, dst, ether_pcap_write);
}

static ssize_t ether_pcap_read(struct network_device *dev, uint8_t *buf, size_t size)
{
    ssize_t len;

    len = read(PRIV(dev)->fd, buf, size);
    if (len <= 0) {
        if (len == -1 && errno != EINTR) {
            errorf("read: %s, device=%s", strerror(errno), dev->name);
        }
        return -1;
    }
    return len;
}

static int ether_pcap_isr(unsigned int irq, void *id)
{
    struct network_device *dev = (struct network_device *)id;
    struct pollfd pfd;
    int ret;

    pfd.fd = PRIV(dev)->fd;
    pfd.events = POLLIN;
    while (1) {
        ret = poll(&pfd, 1, 0);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            errorf("poll: %s, device=%s", strerror(errno), dev->name);
            return -1;
        }
        if (ret == 0) {
            break;
        }
        ether_poll_helper(dev, ether_pcap_read);
    }
    return 0;
}

static struct network_device_operations ether_pcap_ops = {
    .open = ether_pcap_open,
    .close = ether_pcap_close,
    .transmit = ether_pcap_transmit,
};

struct network_device * ether_pcap_init(const char *name, const char *addr)
{
    struct network_device *dev;
    struct ether_pcap *pcap;

    dev = network_device_allocate(ether_setup_helper);
    if (!dev) {
        errorf("network_device_alloc() failure");
        return NULL;
    }
    if (addr) {
        if (ether_addr_pton(addr, dev->address) == -1) {
            errorf("invalid address, address=%s", addr);
            return NULL;
        }
    }
    dev->ops = &ether_pcap_ops;
    pcap = memory_alloc(sizeof(*pcap));
    if (!pcap) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    strncpy(pcap->name, name, sizeof(pcap->name)-1);
    pcap->fd = -1;
    pcap->irq = ETHER_PCAP_IRQ;
    dev->priv = pcap;
    if (network_device_register(dev) == -1) {
        errorf("network_device_register() failure");
        memory_free(pcap);
        return NULL;
    }
    intr_request_irq(pcap->irq, ether_pcap_isr, NETWORK_IRQ_SHARED, dev->name, dev);
    debugf("ethernet device initialized, device=%s", dev->name);
    return dev;
}