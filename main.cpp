#include <memory>
#include <string>
#include <iostream>
#include <thread>
#include <mutex>
#include <cstring>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static const char *DNS_V4 = "114.114.114.114";
static const char *DNS_V6 = "2001:4860:4860::8844";
static const int DNS_PORT = 53;
static int relay_socket = -1;
static const int relay_buffer_size = 2048;
static std::mutex relay_socket_mtx;

int uv_ip4_addr(const char* ip, int port, struct sockaddr_in* addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sin_family = AF_INET;
  addr->sin_port = htons(port);
  return inet_pton(AF_INET, ip, &(addr->sin_addr.s_addr));
}

int uv_ip6_addr(const char* ip, int port, struct sockaddr_in6* addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sin6_family = AF_INET6;
  addr->sin6_port = htons(port);
  return inet_pton(AF_INET6, ip, &(addr->sin6_addr.s6_addr));
}

int create_udp_socket(int type) {
    int s = socket(type, SOCK_DGRAM, 0);
    if (s < 0) {
        std::cerr << "Failed to create socket\n";
        return -1;
    }

    struct sockaddr * addr = 0;
    socklen_t addr_size = 0;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;

    if (type == AF_INET) {
        uv_ip4_addr("0.0.0.0", 0, &addr4);
        addr = (struct sockaddr *)&addr4;
        addr_size = sizeof(addr4);
    }
    else if (type == AF_INET6) {
        uv_ip6_addr("::", 0, &addr6);
        addr = (struct sockaddr *)&addr6;
        addr_size = sizeof(addr6);
    }
    else {
        close(s);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));

    if(bind(s, addr, addr_size) < 0) {
        close(s);
        std::cerr << "Failed to bind\n";
        return -1;
    }

    return s;
}

std::string get_hostname_from_sequence(const char *s) {
    std::string r;
    r.reserve(128);

    while (*s != 0) {
        for (int i=*s; i>0; i--) {
            s++;

            if (*s == 0) {
                r.clear();
                return r;
            }

            r.push_back(*s);
        }
        s++;
        r.push_back('.');
    }

    return r;
}

bool resolve(char *data_ptr, int data_size, const sockaddr * client_addr, socklen_t addr_length) {
    std::unique_ptr<char[]> ptr(data_ptr);

    if (data_size < 12) {
        std::cerr << "Invalid datagram size: " << data_size << std::endl;
        return false;
    }

    // check number of questions, should be 1+
    uint16_t num_of_questions = ntohs(*(uint16_t*)(data_ptr+4));
    if (num_of_questions < 1) {
        std::cerr << "Invalid num_of_questions: " << num_of_questions << std::endl;
        return false;
    }

    if (num_of_questions > 1) {
        std::cerr << num_of_questions << " questions in header section\n";
    }

    auto hostname = get_hostname_from_sequence(data_ptr+12);

    if (int(hostname.size()+1 + 12 + 4) > data_size) {
        std::cerr << "Invalid hostname size: " << hostname << std::endl;
        return false;
    }

    uint16_t query_type = ntohs(*(uint16_t*)(data_ptr+12+hostname.size()+1));

    int s = -1;

    if (query_type == 28) { // AAAA
        s = create_udp_socket(AF_INET6);
        if (s < 0) {
            return false;
        }

        struct sockaddr_in6 addr;
        uv_ip6_addr(DNS_V6, DNS_PORT, &addr);

        if (sendto(s, data_ptr, data_size, 0, (struct sockaddr *)&addr, sizeof(addr)) != data_size) {
            close(s);
            std::cerr << "Failed to send query data\n";
            return false;
        }
    }
    else {
        s = create_udp_socket(AF_INET);
        if (s < 0) {
            return false;
        }

        struct sockaddr_in addr;
        uv_ip4_addr(DNS_V4, DNS_PORT, &addr);

        if (sendto(s, data_ptr, data_size, 0, (struct sockaddr *)&addr, sizeof(addr)) != data_size) {
            close(s);
            std::cerr << "Failed to send query data\n";
            return false;
        }
    }

    data_size = recvfrom(s, data_ptr, relay_buffer_size, 0, NULL, 0);

    close(s);

    if (data_size <= 0) {
        std::cerr << "Failed to receive response package\n";
        return false;
    }

    relay_socket_mtx.lock();
    int sent = sendto(relay_socket, data_ptr, data_size, 0, client_addr, addr_length);
    relay_socket_mtx.unlock();

    if (sent != data_size) {
        fprintf(stderr, "Failed to send response\n");
        return false;
    }

    return true;
}

int main(int argc, char **argv)
{
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

    relay_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(relay_socket < 0) {
        fprintf(stderr, "Failed to create socket\n");
        return 1;
    }

    sockaddr_in addr;
    uv_ip4_addr("127.0.0.1", local_port, &addr);

    if(bind(relay_socket, (sockaddr *)&addr, sizeof(addr))<0) {
        std::cerr << "Failed to bind\n";
        return 2;
    }

    while (true) {
        char *relay_buffer = new char[relay_buffer_size];
        sockaddr_in *client_addr = new sockaddr_in;
        socklen_t addr_length = sizeof(client_addr);

        int data_size = recvfrom(relay_socket, relay_buffer, relay_buffer_size, 0, (sockaddr *)client_addr, &addr_length);

        std::thread(resolve, relay_buffer, data_size, (sockaddr *)client_addr, addr_length).detach();
    }

    return 0;
}
