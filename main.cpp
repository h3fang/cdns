#include <memory>
#include <string>
#include <iostream>
#include <thread>
#include <cstring>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

const char *DNS_V4 = "119.29.29.29";
const char *DNS_V6 = "2001:4860:4860::8888";

int sfd = -1;

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

std::string get_hostname_form_sequence(const char *s) {
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

bool resolve(char* data_ptr, int data_size, const sockaddr_in6 client_addr, socklen_t addr_length) {
    std::unique_ptr<char[]> data(data_ptr);

    if (data_size < 12) {
        std::cerr << "Invalid datagram size: " << data_size << std::endl;
        return false;
    }

    // check for QR bit, should be 0 (query)
    if ((*(data_ptr+2) & 0b10000000) != 0) {
        std::cerr << "Invalid QR bit: " << *(data_ptr+2) << "\n";
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

    auto hostname = get_hostname_form_sequence(data_ptr+12);
//    std::cout << hostname << std::endl;

    if (int(hostname.size()+1 + 12 + 4) > data_size) {
        std::cerr << "Invalid hostname size: " << hostname << std::endl;
        return false;
    }

    uint16_t query_class = ntohs(*(uint16_t*)(data_ptr+12+hostname.size()+1+2));

    if (query_class != 1) {
        std::cerr << "Invalid query class: " << query_class << std::endl;
        return false;
    }

    uint16_t query_type = ntohs(*(uint16_t*)(data_ptr+12+hostname.size()+1));

    int s = -1;

    if (query_type == 28) { // AAAA
        s = create_udp_socket(AF_INET6);
        if (s < 0) {
            std::cerr << "Failed to create and bind socket on ::1\n";
            return false;
        }

        struct sockaddr_in6 addr;
        uv_ip6_addr(DNS_V6, 53, &addr);

        if (sendto(s, data_ptr, data_size, 0, (struct sockaddr *)&addr, sizeof(addr)) != data_size) {
            close(s);
            std::cerr << "Failed to send query data\n";
            return false;
        }
    }
    else {
        s = create_udp_socket(AF_INET);
        if (s < 0) {
            std::cerr << "Failed to create and bind socket on 127.0.0.1\n";
            return false;
        }

        struct sockaddr_in addr;
        uv_ip4_addr(DNS_V4, 53, &addr);

        if (sendto(s, data_ptr, data_size, 0, (struct sockaddr *)&addr, sizeof(addr)) != data_size) {
            close(s);
            std::cerr << "Failed to send query data\n";
            return false;
        }
    }

    data_size = recvfrom(s, data_ptr, 2048, 0, NULL, 0);

    close(s);

    if (data_size <= 0) {
        std::cerr << "Failed to receive response package\n";
        return false;
    }

    sendto(sfd, data_ptr, data_size, 0, (struct sockaddr *)&client_addr, addr_length);

    return true;
}

int main()
{
    sfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if(sfd < 0) {
        std::cerr << "Failed to create socket\n";
        return 1;
    }

    struct sockaddr_in6 addr;
    uv_ip6_addr("::1", 53, &addr);

    if(bind(sfd, (struct sockaddr *)&addr, sizeof(addr))<0) {
        std::cerr << "Failed to bind\n";
        return 2;
    }

    while (true) {
        char* data_ptr = new char[2048];
        int data_size = 0;
        sockaddr_in6 client_addr;
        socklen_t addr_length = sizeof(client_addr);

        bzero(&client_addr, addr_length);

        data_size = recvfrom(sfd, data_ptr, 2048, 0, (struct sockaddr *)&client_addr, &addr_length);

        std::thread(resolve, data_ptr, data_size, client_addr, addr_length).detach();
    }

    return 0;
}
