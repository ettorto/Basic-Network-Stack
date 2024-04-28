#ifndef PARAMS_H
#define PARAMS_H

#include <stdint.h>

/**
 * @brief The name of the Ethernet tap interface.
 */
#define ETHER_TAP_NAME "tap0"

/**
 * @brief The hardware address of the Ethernet tap interface.
 */
#define ETHER_TAP_HW_ADDR "2e:60:e8:2a:d9:e5"

/**
 * @brief The IP address of the Ethernet tap interface.
 */
#define ETHER_TAP_IP_ADDR "192.0.2.7"

/**
 * @brief The netmask of the Ethernet tap interface (CLASS b).
 */
#define ETHER_TAP_NETMASK "255.255.0.0"

/**
 * @brief The default gateway IP address.
 */
#define DEFAULT_GATEWAY "192.0.2.1"

// the server IP address
extern char SERVER_IP_ADDR[];

#endif
