#!/bin/sh


/bin/rm -f  /etc/network/interfaces

/bin/cat << EOF > /etc/network/interfaces
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet static
    address 10.7.15.100
    netmask 255.255.0.0
    gateway 10.7.1.1
    dns-nameservers 8.8.8.8

auto eth1
iface eth1 inet dhcp

auto eth2
iface eth2 inet manual
    up ip link set eth2 up
    up ip link set eth2 promisc on
    down ip link set eth2 promisc off
    down ip link set eth2 down

auto eth3
iface eth3 inet manual
    up ip link set eth3 up
    up ip link set eth3 promisc on
    down ip link set eth3 promisc off
    down ip link set eth3 down
EOF



SSH_DIR=/root/.ssh
if [ ! -d $SSH_DIR ]; then
    mkdir $SSH_DIR
    chmod 700 $SSH_DIR
fi

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJC++rntDXh1pn+W15RPr205/DGDdNbL4HIHWDINin9KPIvR9RT6/jPh2UWomjVlLAz32qv7KT0CbVprNBsOxoFOWxh/topMdOS5dMP8fh1nUqsvDgQnJjjBa7EVjnPdeXjo64aJgONh/1gK1rT9yRsdW06o7GFsjrkLMQJyxYPz7vOMYPnymafgJZV98shJ/z4VqVZR8dctB6Sf/yDYHeIIFR7liKln/D7OmW7zTubsEhYCEJYu4kgZ1yvaio/bcyRL9xN4pstPxINvZ/vbbZE1GF+bleNn5fqJhDbERBU5gtsyvtjdJybjq2H0IWrCM+sD5TGnhrkf2e5HjjlD7f v-magine controller
" >> $SSH_DIR/authorized_keys