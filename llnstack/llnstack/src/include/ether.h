#ifndef ETHER_H
#define ETHER_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#include "net2.h"
#include "ip2.h"

#define ARP_RESOLVE_ERROR      -1
#define ARP_RESOLVE_INCOMPLETE  0
#define ARP_RESOLVE_FOUND       1

/**
 * @brief Resolves the hardware address (MAC address) corresponding to the given IP address.
 *
 * This function is used to resolve the hardware address (MAC address) corresponding to the given IP address.
 *
 * @param iface Pointer to the network interface structure.
 * @param pa The IP address to resolve.
 * @param ha Pointer to the buffer where the resolved hardware address will be stored.
 * @return Returns ARP_RESOLVE_ERROR if an error occurred during resolution, ARP_RESOLVE_INCOMPLETE if the resolution is still in progress, or ARP_RESOLVE_FOUND if the resolution was successful.
 */
extern int arp_resolve(struct network_interface *iface, IPAddress pa, uint8_t *ha);

/**
 * @brief Initializes the ARP module.
 *
 * This function initializes the ARP module and performs any necessary setup.
 *
 * @return Returns 0 on success, or a negative value if an error occurred.
 */
extern int initialize_arp_protocol(void);

/**
 * Initializes an Ethernet tap device.
 *
 * This function creates and initializes an Ethernet tap device with the specified name and address.
 *
 * @param name The name of the Ethernet tap device.
 * @param addr The address of the Ethernet tap device.
 * @return A pointer to the initialized network device structure.
 */
extern struct network_device * ether_tap_init(const char *name, const char *addr);

// Length of an Ethernet address
#define ETHER_ADDR_LEN 6

// Maximum length of a string representation of an Ethernet address
#define ETHER_ADDR_STR_LEN 18 

// Size of the Ethernet header
#define ETHER_HDR_SIZE 14

// Minimum size of an Ethernet frame
#define ETHER_FRAME_SIZE_MIN   60

// Maximum size of an Ethernet frame
#define ETHER_FRAME_SIZE_MAX 1514

// Minimum size of the payload in an Ethernet frame
#define ETHER_PAYLOAD_SIZE_MIN (ETHER_FRAME_SIZE_MIN - ETHER_HDR_SIZE)

// Maximum size of the payload in an Ethernet frame
#define ETHER_PAYLOAD_SIZE_MAX (ETHER_FRAME_SIZE_MAX - ETHER_HDR_SIZE)

// Ethernet frame types
#define ETHER_TYPE_IP   0x0800
#define ETHER_TYPE_ARP  0x0806
#define ETHER_TYPE_IPV6 0x86dd

// Special Ethernet addresses
extern const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN];
extern const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN];

// Function to convert a string representation of an Ethernet address to binary
extern int ether_addr_pton(const char *p, uint8_t *n);

// Function to convert a binary Ethernet address to a string representation
extern char *ether_addr_ntop(const uint8_t *n, char *p, size_t size);

// Helper function for transmitting an Ethernet frame
extern int ether_transmit_helper(struct network_device *dev, uint16_t type, const uint8_t *payload, size_t plen, const void *dst, ssize_t (*callback)(struct network_device *dev, const uint8_t *buf, size_t len));

// Helper function for polling an Ethernet device for received frames
extern int ether_poll_helper(struct network_device *dev, ssize_t (*callback)(struct network_device *dev, uint8_t *buf, size_t size));

// Helper function for setting up an Ethernet device
extern void ether_setup_helper(struct network_device *network_device);

// Function to initialize an Ethernet device
extern struct network_device * ether_init(const char *name);

#endif