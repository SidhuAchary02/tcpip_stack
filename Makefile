CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -Iinclude -g
SRCS    = utils.c \
          stack.c \
          layer1_physical.c \
          layer2_ethernet.c \
          layer3_ip.c \
          layer4_udp.c \
          layer4_tcp.c \
          layer5_application.c \
          main.c
TARGET  = tcpip

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: all clean
