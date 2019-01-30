# Network-Raid-File-System
Network raid (RAID 1) file system, final project for Operating Systems Engineering class

Need to install following packages (commands for linux):

$ sudo apt install pkg-config libfuse-dev
$ sudo apt-get install libpcap-dev libssl-dev

Compile:
$ make

Run servers: 
$ ./net_raid_server 127.0.0.1 port_number /path/to/storage_dir1
$ ./net_raid_server 127.0.0.1 port_number /path/to/storage_dir2
…

Run client
$ ./net_raid_client /path/to/config_file
