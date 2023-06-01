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
#include "net/sock/udp.h"
#include "thread.h"

#define MAIN_QUEUE_SIZE (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#define _IPV6_DEFAULT_PREFIX_LEN (64U)

static char server_stack[THREAD_STACKSIZE_DEFAULT];

#ifndef GATEWAY_IPV6_ADDR
#define GATEWAY_IPV6_ADDR ("2001:660:3207:400::64")
#endif

#ifndef ROOT_IPV6_ADDR
#define ROOT_IPV6_ADDR ("2001:db8::1")
#endif

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

static void *_server_thread(void *args)
{
    (void)args;
    uint8_t buf[128];

    kernel_pid_t iface_pid = 6;
    if (gnrc_netif_get_by_pid(iface_pid) == NULL)
    {
        printf("unknown interface specified\n");
        return NULL;
    }

    gnrc_rpl_init(iface_pid);
    printf("successfully initialized RPL on interface %d\n", iface_pid);

    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    sock_udp_t sock;

    local.port = 8000;

    if (sock_udp_create(&sock, &local, NULL, 0) < 0)
    {
        puts("Error creating UDP sock");
        return NULL;
    }

    while (1)
    {
        sock_udp_ep_t remote;
        ssize_t res;

        if ((res = sock_udp_recv(&sock, buf, sizeof(buf), SOCK_NO_TIMEOUT,
                                 &remote)) >= 0)
        {
            puts("Received a message");
            /* Check if the message is "gateway_ipv6_request" */
            if (strncmp((char *)buf, "gateway_ipv6_request", 20) == 0)
            {

                if (sock_udp_send(&sock, GATEWAY_IPV6_ADDR, strlen(GATEWAY_IPV6_ADDR), &remote) < 0)
                {
                    puts("Error sending reply");
                }
            }
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
    prefix_len = _get_prefix_len(ROOT_IPV6_ADDR);
    if (ipv6_addr_from_str(&addr, ROOT_IPV6_ADDR) == NULL)
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

    if (ipv6_addr_from_str(&dodag_id, ROOT_IPV6_ADDR) == NULL)
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
