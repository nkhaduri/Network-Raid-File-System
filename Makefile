CC=gcc 
CFLAGS=-g
FUSE = `pkg-config fuse --cflags --libs`
CLIENT = net_raid_client.c 
SERVER = net_raid_server.c
OBJECTS = net_raid_client net_raid_server
OPENSSL = -lssl -lcrypto

build:
	$(CC) $(CFLAGS) -o net_raid_client $(CLIENT) $(FUSE)
	$(CC) $(CFLAGS) -o net_raid_server $(SERVER) $(OPENSSL) 

clean: 
	-rm -f *.o
	-rm -f $(OBJECTS)