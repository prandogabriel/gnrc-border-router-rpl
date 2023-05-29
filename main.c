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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net/netif.h" /* for resolving ipv6 scope */

#include "thread.h"

#define MAIN_QUEUE_SIZE (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#define _IPV6_DEFAULT_PREFIX_LEN (64U)
#ifndef GATEWAY_IPV6_ADDR
#define GATEWAY_IPV6_ADDR "2001:660:3207:400::64"
#endif

#define SERVER_MSG_QUEUE_SIZE (8)
#define SERVER_BUFFER_SIZE (64)

static int server_socket = -1;
static char server_buffer[SERVER_BUFFER_SIZE];
static char server_stack[THREAD_STACKSIZE_DEFAULT];
static msg_t server_msg_queue[SERVER_MSG_QUEUE_SIZE];

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

static void process_request(int sock, struct sockaddr_in6 *src, socklen_t src_len, char *request)
{
    /* Check if the message is "gateway_ipv6_request" */
    if (strncmp(request, "gateway_ipv6_request", 20) == 0)
    {
        char reply[] = GATEWAY_IPV6_ADDR;

        printf("Sending gateway IPv6 address: %s\n", reply);

         char addr_str[IPV6_ADDR_MAX_STR_LEN];
        inet_ntop(AF_INET6, &(src->sin6_addr), addr_str, INET6_ADDRSTRLEN);

        printf("Received from address: %s, port: %d\n", addr_str, ntohs(src->sin6_port));

        if (sendto(sock, reply, strlen(reply), 0, (struct sockaddr *)src, src_len) < 0)
        {
            puts("Error sending response");
        }
        else
        {
            printf("Sending gateway IPv6 address: %s\n", reply);
        }
    }
}

static void *_server_thread(void *args)
{
    struct sockaddr_in6 server_addr;
    uint16_t port;
    msg_init_queue(server_msg_queue, SERVER_MSG_QUEUE_SIZE);
    server_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    (void)args;
    port = 8000;
    server_addr.sin6_family = AF_INET6;
    memset(&server_addr.sin6_addr, 0, sizeof(server_addr.sin6_addr));
    server_addr.sin6_port = htons(port);
    if (server_socket < 0)
    {
        puts("error initializing socket");
        server_socket = 0;
        return NULL;
    }
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        server_socket = -1;
        puts("error binding socket");
        return NULL;
    }
    printf("Success: started UDP server on port %" PRIu16 "\n", port);
    while (1)
    {
        int res;
        struct sockaddr_in6 src;
        socklen_t src_len = sizeof(struct sockaddr_in6);

        /* Clear the buffer */
        memset(server_buffer, 0, sizeof(server_buffer));

        if ((res = recvfrom(server_socket, server_buffer, sizeof(server_buffer), 0,
                            (struct sockaddr *)&src, &src_len)) < 0)
        {
            puts("Error on receive");
        }
        else if (res == 0)
        {
            puts("Peer did shut down");
        }
        else
        {
            printf("Received data: ");
            puts(server_buffer);

            /* Process the request */
            process_request(server_socket, &src, src_len, server_buffer);
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
    prefix_len = _get_prefix_len("2001:db8::1");
    if (ipv6_addr_from_str(&addr, "2001:db8::1") == NULL)
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

    if (ipv6_addr_from_str(&dodag_id, "2001:db8::1") == NULL)
    {
        printf("error: <dodag_id> must be a valid IPv6 address\n");
        return 1;
    }
    gnrc_rpl_instance_t *inst = gnrc_rpl_root_init(1, &dodag_id, false, false);
    (void)inst;

    /* start server (which means registering pktdump for the chosen port) */
    if (thread_create(server_stack, sizeof(server_stack), THREAD_PRIORITY_MAIN - 1,
                      THREAD_CREATE_STACKTEST,
                      _server_thread, NULL, "UDP server") <= KERNEL_PID_UNDEF)
    {
        puts("error initializing thread");
    }

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
