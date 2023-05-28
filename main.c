/*
 * Copyright (C) 2015 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Example application for demonstrating the RIOT network stack
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>

#include "shell.h"
#include "msg.h"
#include "net/gnrc/rpl.h"
#include "net/gnrc/rpl/dodag.h"
#include "net/gnrc/rpl/structs.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/hdr.h"
#include "net/ipv6/addr.h"

#include "net/sock/udp.h"
#include "thread.h"
#include "xtimer.h"

#ifndef ADDR_IPV6
#define ADDR_IPV6 "fec0:affe::1"
#endif

#ifndef DADOG_ID
#define DADOG_ID (1)
#endif

#define MAIN_QUEUE_SIZE (8)
#define UDP_BUFFER_SIZE (128U)
#define SERVER_MSG_QUEUE_SIZE (8)
#define SERVER_STACKSIZE (THREAD_STACKSIZE_DEFAULT)
#define SERVER_PORT (1234)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

char server_stack[SERVER_STACKSIZE];

// Assume que este é o endereço do gateway
ipv6_addr_t gateway_addr = IPV6_ADDR_UNSPECIFIED; // Set your gateway IP here.

#define _IPV6_DEFAULT_PREFIX_LEN (64U)

#ifdef MODULE_GNRC_IPV6
static uint8_t _get_prefix_len(char *addr)
{
    int prefix_len = ipv6_addr_split_int(addr, '/', _IPV6_DEFAULT_PREFIX_LEN);

    if (prefix_len < 1)
    {
        prefix_len = _IPV6_DEFAULT_PREFIX_LEN;
    }

    return prefix_len;
}
#endif

static void *_udp_server(void *args)
{
    (void)args; 
    
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    local.port = SERVER_PORT;
    sock_udp_t sock;

    if (sock_udp_create(&sock, &local, NULL, 0) < 0)
    {
        puts("Error creating UDP server socket");
        return NULL;
    }

    while (1)
    {
        char buffer[UDP_BUFFER_SIZE];
        sock_udp_ep_t remote;
        ssize_t res;

        if ((res = sock_udp_recv(&sock, buffer, sizeof(buffer), SOCK_NO_TIMEOUT, &remote)) >= 0)
        {
            puts("Received a packet");
            /* handle received packet */

            // Responda com o endereço do gateway
            char addr_str[IPV6_ADDR_MAX_STR_LEN];
            ipv6_addr_to_str(addr_str, &gateway_addr, IPV6_ADDR_MAX_STR_LEN);
            sock_udp_send(&sock, addr_str, strlen(addr_str), &remote);
        }
    }

    return NULL;
}

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("RIOT border router example application");

    puts("Initializing the rpl root node");
    netif_t *iface = netif_get_by_name("6");
    ipv6_addr_t addr;
    uint8_t prefix_len;
    uint16_t flags = GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_VALID;
    prefix_len = _get_prefix_len(ADDR_IPV6);
    if (ipv6_addr_from_str(&addr, ADDR_IPV6) == NULL)
    {
        printf("error: unable to parse IPv6 address.\n");
        return 1;
    }
    flags |= (prefix_len << 8U);
    if (netif_set_opt(iface, NETOPT_IPV6_ADDR, flags, &addr, sizeof(addr)) < 0)
    {
        printf("error: unable to add IPv6 address\n");
        return 1;
    }
    gnrc_rpl_init(6);
    ipv6_addr_t dodag_id;

    if (ipv6_addr_from_str(&dodag_id, ADDR_IPV6) == NULL)
    {
        printf("error: <dodag_id> must be a valid IPv6 address\n");
        return 1;
    }

    gnrc_rpl_instance_t *inst = gnrc_rpl_root_init(DADOG_ID, &dodag_id, false, false);
    (void)inst;

    /* start UDP server thread */
    thread_create(server_stack, sizeof(server_stack),
                  THREAD_PRIORITY_MAIN - 1,
                  THREAD_CREATE_STACKTEST,
                  _udp_server, NULL, "udp server");

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
