#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 2048

int create_tun_interface(const char *dev) {
  char command[256];
  snprintf(command, sizeof(command), "ip tuntap add mode tun dev %s", dev);
  if (system(command) == -1) {
    perror("Failed to create TUN interface up");
  } else {
    printf("TUN interface %s created.\n", dev);
  }

  struct ifreq ifr;
  int tun_fd = open("/dev/net/tun", O_RDWR);
  if (tun_fd < 0) {
    perror("Opening /dev/net/tun");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN; // TUN device
  if (dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
  }

  if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
    perror("Creating TUN interface");
    close(tun_fd);
    return -1;
  }

  return tun_fd;
}

class TunWrapper {
private:
  int epollfd;
  struct epoll_event events[10];
  int tun_fd;

public:
  TunWrapper(int tun_fd) : tun_fd(tun_fd) {
    epollfd = epoll_create1(0);
    if (epollfd == -1) {
      printf("Failed to create epoll\n");
      return;
    }

    struct epoll_event read_data_ev;

    read_data_ev.events = EPOLLIN;
    read_data_ev.data.fd = tun_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, tun_fd, &read_data_ev) == -1) {
      printf("Failed to create tun listen event\n");
      return;
    }
  }

  void tun_step() {
    int nfds = epoll_wait(epollfd, events, 10, -1);
    if (nfds == -1) {
      printf("Failed to listen for events\n");
      return;
    }

    for (int n = 0; n < nfds; ++n) {
      if (events[n].data.fd == tun_fd) {
        char buffer[BUFFER_SIZE];
        int num_bytes = read(tun_fd, buffer, sizeof(buffer));
        if (num_bytes < 0) {
          printf("Reading from TUN interface");
          break;
        }
        // Process the data from the buffer (e.g., route it, encrypt it, etc.)
        printf("Read %d bytes from TUN interface\n", num_bytes);
      }
    }
  }
};

void add_route(const char *destination, const char *gateway) {
  char command[256];
  snprintf(command, sizeof(command), "ip route add %s via %s", destination,
           gateway);
  if (system(command) == -1) {
    perror("Failed to add route");
  } else {
    printf("Route added: %s via %s\n", destination, gateway);
  }
}

void bring_tun_up(const char *dev) {
  char command[256];
  snprintf(command, sizeof(command), "ip link set %s up", dev);
  if (system(command) == -1) {
    perror("Failed to bring TUN interface up");
  } else {
    printf("TUN interface %s is up.\n", dev);
  }
}

void init_tun(char *target_ip) {
  const char *tun_device = "tun0";
  int tun_fd = create_tun_interface(tun_device);

  if (tun_fd < 0) {
    fprintf(stderr, "Failed to create TUN interface\n");
    return;
  }

  add_route("1.1.1.1", "192.168.0.1");
  add_route(target_ip, "192.168.0.1");
}
