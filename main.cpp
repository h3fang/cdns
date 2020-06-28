#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <map>

#include <unistd.h>
#include <uv.h>

static const char *DNS_V4 = "114.114.114.114";
static const char *DNS_V6 = "2001:4860:4860::8844";
static const int DNS_PORT = 53;

uv_loop_t *loop;
uv_udp_t relay_socket, query_v4, query_v6;
sockaddr_in server_v4, any_v4, local_v4;
sockaddr_in6 server_v6, any_v6;

std::map<uint16_t, sockaddr> query_map;

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_query_send(uv_udp_send_t *req, int status) {
    free(req);
    if (status) {
        fprintf(stderr, "on_query_send, %s\n", uv_strerror(status));
        return;
    }
}

void on_relay_send(uv_udp_send_t *req, int status) {
    free(req);
    if (status) {
        fprintf(stderr, "on_relay_send, %s\n", uv_strerror(status));
        return;
    }
}

void on_query_recv(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread == 0) {
        if (buf) { free(buf->base); }
        return;
    }
    else if (nread < 12) {
        fprintf(stderr, "on_query_recv, invalid datagram size: %d\n", nread);
        free(buf->base);
        return;
    }

    uint16_t id = ntohs(*(uint16_t*)(buf->base));

    uv_udp_send_t *send_req = (uv_udp_send_t *) malloc(sizeof(uv_udp_send_t));
    uv_buf_t buf_send = uv_buf_init(buf->base, nread);
    uv_udp_send(send_req, &relay_socket, &buf_send, 1, &query_map[id], on_relay_send);
    query_map.erase(id);
    free(buf->base);
}

void on_relay_recv(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread == 0) {
        if (buf) { free(buf->base); }
        return;
    }
    else if (nread < 12) {
        fprintf(stderr, "on_relay_recv, invalid datagram size: %d\n", nread);
        free(buf->base);
        return;
    }

    int hostname_size = strlen(buf->base+12);
    if (hostname_size+1 + 12 + 4 > nread) {
        fprintf(stderr, "on_relay_recv, invalid hostname size: %d\n", hostname_size);
        free(buf->base);
        return;
    }

    uint16_t query_type = ntohs(*(uint16_t*)(buf->base+12+hostname_size+1));
    uv_udp_send_t *send_req = (uv_udp_send_t *) malloc(sizeof(uv_udp_send_t));
    uv_buf_t buf_send = uv_buf_init(buf->base, nread);

    if (query_type == 28) { // AAAA
        uv_udp_send(send_req, &query_v6, &buf_send, 1, (struct sockaddr *)&server_v6, on_query_send);
    }
    else {
        uv_udp_send(send_req, &query_v4, &buf_send, 1, (struct sockaddr *)&server_v4, on_query_send);
    }

    query_map[ntohs(*(uint16_t*)(buf->base))] = *addr;
    free(buf->base);
}

void init_socket(uv_udp_t *s, const struct sockaddr *addr, uv_udp_recv_cb cb) {
    int r = uv_udp_init(loop, s);
    if (r < 0) { fprintf(stderr, "uv_udp_init: %s\n", uv_strerror(r)); }
    r = uv_udp_bind(s, addr, 0);
    if (r < 0) { fprintf(stderr, "uv_udp_bind: %s\n", uv_strerror(r)); }
    uv_udp_recv_start(s, alloc_buffer, cb);
    if (r < 0) { fprintf(stderr, "uv_udp_recv_start: %s\n", uv_strerror(r)); }
}

int main(int argc, char **argv) {
    int c = 0, local_port = DNS_PORT;

    while ((c = getopt(argc, argv, "4:6:p:")) != -1) {
        switch (c) {
        case '4':
            DNS_V4 = optarg;
            break;
        case '6':
            DNS_V6 = optarg;
            break;
        case 'p':
            local_port = strtol(optarg, nullptr, 10);
            break;
        default:
            return 1;
        }
    }

    loop = uv_default_loop();

    uv_ip4_addr(DNS_V4, DNS_PORT, &server_v4);
    uv_ip6_addr(DNS_V6, DNS_PORT, &server_v6);

    uv_ip4_addr("127.0.0.1", local_port, &local_v4);
    init_socket(&relay_socket, (const struct sockaddr *)&local_v4, on_relay_recv);

    uv_ip4_addr("0.0.0.0", 0, &any_v4);
    init_socket(&query_v4, (const struct sockaddr *)&any_v4, on_query_recv);

    uv_ip6_addr("::", 0, &any_v6);
    init_socket(&query_v6, (const struct sockaddr *)&any_v6, on_query_recv);

    return uv_run(loop, UV_RUN_DEFAULT);
}
