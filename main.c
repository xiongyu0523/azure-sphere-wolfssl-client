/* client.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

 /* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/ssl.h>

/* Azure Sphere */
#include <applibs/log.h>
#include <applibs/networking.h>
#include <applibs/storage.h>

#define SERVER_URL  "example.com"
#define SERVER_PORT "443"
static const char msg[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

int main(int argc, char** argv)
{
    bool    isNetworkingReady = false;
    int     sockfd = 0;
    char    buff[1024];
    size_t  len;
    int     ret;

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char* ca_path = NULL;

    /* Check if the Azure Sphere Dev Board has network connectivity. */
    if ((Networking_IsNetworkingReady(&isNetworkingReady) < 0) || !isNetworkingReady) {
        Log_Debug("ERROR: network is not up.\n");
        return -1;
    }

    /* connect to server */
    struct sockaddr_storage addr;
    socklen_t sockaddr_len = sizeof(struct sockaddr_in);

    struct addrinfo hints;
    struct addrinfo* answer = NULL;

    memset(&addr, 0, sizeof(addr));
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(SERVER_URL, SERVER_PORT, &hints, &answer) < 0 || answer == NULL) {
        Log_Debug("no addr info for responder\n");
        return -1;
    }

    sockaddr_len = answer->ai_addrlen;
    memcpy(&addr, answer->ai_addr, sockaddr_len);
    freeaddrinfo(answer);

    sockfd = socket(addr.ss_family, SOCK_STREAM, 0);
    if (sockfd < 0) {
        Log_Debug("bad socket fd, out of fds?\n");
        return -1;
    }

    if (connect(sockfd, (const struct sockaddr *)&addr, sockaddr_len) != 0) {
        Log_Debug("Responder tcp connect failed\n");
        close(sockfd);
        return -1;
    }

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create and initialize WOLFSSL_CTX */
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (ctx == NULL) {
        Log_Debug("ERROR: failed to create WOLFSSL_CTX\n");
        goto cleanupLabel;
    }

    /* Load root CA certificates into WOLFSSL_CTX */
    ca_path = Storage_GetAbsolutePathInImagePackage("certs/DigiCertGlobalRootCA.pem");
    if (ca_path == NULL) {
        Log_Debug("ERROR: the certificate path could not be resolved\n");
        goto cleanupLabel;
    }

    ret = wolfSSL_CTX_load_verify_locations(ctx, ca_path, NULL);
    if (ret != WOLFSSL_SUCCESS) {
        Log_Debug("ERROR: failed to load root certificate\n");
        goto cleanupLabel;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        Log_Debug("ERROR: failed to create WOLFSSL object\n");
        goto cleanupLabel;
    }

    /* Attach wolfSSL to the socket */
    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS) {
        Log_Debug("Error attaching socket fd to wolfSSL.\n");
        goto cleanupLabel;
    }

    /* Connect to wolfSSL on the server side */
    int err = wolfSSL_connect(ssl);
    if (err != WOLFSSL_SUCCESS) {
        Log_Debug("ERROR: failed to connect to server, error code is %d\n", wolfSSL_get_error(ssl, err));
        goto cleanupLabel;
    }

    /* Get length of message for server. */
    Log_Debug("\n%s\n", msg);
    len = strnlen(msg, sizeof(msg));

    /* Send the message to the server */
    if (wolfSSL_write(ssl, msg, (int)len) != len) {
        Log_Debug("ERROR: failed to write\n");
        goto cleanupLabel;
    }

    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if (wolfSSL_read(ssl, buff, sizeof(buff) - 1) == -1) {
        Log_Debug("ERROR: failed to read\n");
        goto cleanupLabel;
    }

    ///* Print to stdout any data the server sends */
    Log_Debug("Server Reply: %s\n", buff);

    return 0;

cleanupLabel:
    free(ca_path);
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
    close(sockfd);          /* Close the connection to the server       */
    return -1;              /* Return reporting a success               */
}
