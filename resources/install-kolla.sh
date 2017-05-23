#!/bin/bash

set -e

config_network_adapter () {
    local IFACE=$1
    local IPADDR=$2
    local NETMASK=$3
    local ZONE=$4

    cat << EOF > /etc/sysconfig/network-scripts/ifcfg-$IFACE
DEVICE="$IFACE"
NM_CONTROLLED="no"
BOOTPROTO="none"
MTU="1500"
ONBOOT="yes"
IPADDR="$IPADDR"
NETMASK="$NETMASK"
ZONE="$ZONE"
EOF
}

get_interface_ipv4 () {
    local IFACE=$1
    /usr/sbin/ip addr show $IFACE | /usr/bin/sed -n 's/^\s*inet \([0-9.]*\)\/\([0-9]*\)\s* brd \([0-9.]*\).*$/\1 \2 \3/p'
}

set_interface_static_ipv4_from_dhcp () {
    local IFACE=$1
    local ZONE=$2
    local IPADDR
    local PREFIX
    local NETMASK
    local BCAST

    read IPADDR PREFIX BCAST <<< `get_interface_ipv4 $IFACE`
    NETMASK=`/usr/bin/ipcalc -4 --netmask $IPADDR/$PREFIX | /usr/bin/sed -n  's/^\NETMASK=\(.*\).*$/\1/p'`

    config_network_adapter $IFACE $IPADDR $NETMASK $ZONE
}

config_ovs_network_adapter () {
    local ADAPTER=$1

    cat << EOF > /etc/sysconfig/network-scripts/ifcfg-$ADAPTER
DEVICE="$ADAPTER"
NM_CONTROLLED="no"
BOOTPROTO="none"
MTU="1500"
ONBOOT="yes"
EOF
}

function generate_ssh_key() {
    local SSH_KEY_PATH=$1
    local SSH_KEY_PATH_PUB="$SSH_KEY_PATH.pub"

    if [ ! -d ~/.ssh ]; then
        /bin/mkdir ~/.ssh
        /bin/chmod 700 ~/.ssh
    fi
    if [ -f "$SSH_KEY_PATH" ]; then
        /bin/rm -f $SSH_KEY_PATH
    fi
    if [ -f "$SSH_KEY_PATH_PUB" ]; then
        /bin/rm -f $SSH_KEY_PATH_PUB
    fi
    /bin/ssh-keygen -t rsa -b 2048 -N '' -f $SSH_KEY_PATH
    /bin/cat $SSH_KEY_PATH_PUB >> ~/.ssh/authorized_keys
}

exec_with_retry () {
    local MAX_RETRIES=$1
    local INTERVAL=$2

    local COUNTER=0
    while [ $COUNTER -lt $MAX_RETRIES ]; do
        local EXIT=0
        eval '${@:3}' || EXIT=$?
        if [ $EXIT -eq 0 ]; then
            return 0
        fi
        let COUNTER=COUNTER+1

        if [ -n "$INTERVAL" ]; then
            sleep $INTERVAL
        fi
    done
    return $EXIT
}

function add_hostname_to_hosts() {
    local HOST_IP=$1
    local HOSTNAME=$2

    local HOSTS_LINE="$HOST_IP $HOSTNAME"
    grep -q "^$HOSTS_LINE\$" /etc/hosts || echo $HOSTS_LINE >> /etc/hosts
    HOSTS_LINE="$HOST_IP ${HOSTNAME%.*}"
    grep -q "^$HOSTS_LINE\$" /etc/hosts || echo $HOSTS_LINE >> /etc/hosts
}

function download_cirros_image() {
    local CIRROS_URL=$1
    local CIRROS_TMP_FILE=$2

    echo "Downloading Cirros image: $CIRROS_URL"
    exec_with_retry 5 0 wget -q "$CIRROS_URL" -O "$CIRROS_TMP_FILE"
    if [ "$(file $CIRROS_TMP_FILE | grep gzip)" ]
    then
        mv "$CIRROS_TMP_FILE" "$CIRROS_TMP_FILE.gz"
        gunzip "$CIRROS_TMP_FILE.gz"
    fi

    openstack image create --public --property hypervisor_type=hyperv \
    --disk-format vhd --container-format bare --file "$CIRROS_TMP_FILE" cirros-gen1-vhdx
    rm "$CIRROS_TMP_FILE"
}

function disable_network_manager() {
    /bin/systemctl stop NetworkManager.service
    /bin/systemctl disable NetworkManager.service
    /sbin/service network start
    /sbin/chkconfig network on
}

function configure_firewall() {
    # Disable firewalld
    systemctl disable firewalld
    systemctl stop firewalld
    yum install -y iptables-services
    systemctl enable iptables.service
    systemctl start iptables.service

    # TODO: limit access to: -i $MGMT_IFACE
    /usr/sbin/iptables -I INPUT -p tcp --dport 3260 -j ACCEPT
    /usr/sbin/iptables -I INPUT -p tcp --dport 5672 -j ACCEPT
    /usr/sbin/iptables -I INPUT -p tcp --dport 9696 -j ACCEPT
    /usr/sbin/iptables -I INPUT -p tcp --dport 9292 -j ACCEPT
    /usr/sbin/iptables -I INPUT -p tcp --dport 8776 -j ACCEPT
    /usr/sbin/iptables -I INPUT -p tcp --dport 8780 -j ACCEPT
    /usr/sbin/iptables -I INPUT -p tcp --dport 35357 -j ACCEPT
    /usr/sbin/iptables -I INPUT -p tcp --dport 8774 -j ACCEPT
    /usr/sbin/iptables -I INPUT -p tcp --dport 5000 -j ACCEPT
    /usr/sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
    /usr/sbin/service iptables save
}

function configure_ovs_bridge() {
    docker exec -ti -u root neutron_server pip install --upgrade pip
    docker exec -ti -u root neutron_server pip install wheel
    docker exec -ti -u root neutron_server pip install "networking-hyperv<=4.0.0"
    docker restart neutron_server

    # create OVS data bridge
    docker exec -ti -u root openvswitch_vswitchd ovs-vsctl add-br br-data
    docker exec -ti -u root openvswitch_vswitchd ovs-vsctl add-port br-data $DATA_IFACE
    docker exec -ti -u root openvswitch_vswitchd ovs-vsctl add-port br-data phy-br-data || true
    docker exec -ti -u root openvswitch_vswitchd ovs-vsctl set interface phy-br-data type=patch
    docker exec -ti -u root openvswitch_vswitchd ovs-vsctl add-port br-int int-br-data || true
    docker exec -ti -u root openvswitch_vswitchd ovs-vsctl set interface int-br-data type=patch
    docker exec -ti -u root openvswitch_vswitchd ovs-vsctl set interface phy-br-data options:peer=int-br-data
    docker exec -ti -u root openvswitch_vswitchd ovs-vsctl set interface int-br-data options:peer=phy-br-data

    # configure ML2 plugin for neutron 
    for conf_file in /etc/kolla/neutron-server/ml2_conf.ini /etc/kolla/neutron-openvswitch-agent/ml2_conf.ini
    do
        sed -i '/bridge_mappings/c\bridge_mappings = physnet1:br-ex,physnet2:br-data' $conf_file
        sed -i '/flat_networks/c\flat_networks = physnet1,physnet2' $conf_file
        sed -i '/network_vlan_ranges/c\network_vlan_ranges = physnet2:500:2000' $conf_file
    done

    exec_with_retry 5 0 docker restart neutron_server neutron_openvswitch_agent
}

function remove_kvm_containers() {
    # Remove unneeded Nova containers
    for name in nova_compute nova_ssh nova_libvirt
    do
        for id in $(sudo docker ps -q -a -f name=$name)
        do
            docker stop $id 2>/dev/null || :
            docker rm $id 2>/dev/null || :
        done
    done
}

function configure_private_net_subnet() {
    PRIVATE_NET=private_net
    PRIVATE_SUBNET=private_subnet

    if [ "${FIP_RANGE_NAME_SERVERS[@]}" ]; then
        exec_with_retry 5 0 /usr/bin/neutron net-create $PRIVATE_NET \
        --provider:segmentation_id 500 --provider:physical_network physnet2 \
        --provider:network_type vlan --shared

        exec_with_retry 5 0 /usr/bin/neutron subnet-create $PRIVATE_NET \
        10.10.10.0/24 --name $PRIVATE_SUBNET --allocation-pool \
        start=10.10.10.50,end=10.10.10.150 --gateway 10.10.10.1 \
        --dns_nameservers list=true ${FIP_RANGE_NAME_SERVERS[@]}
    fi
}

function configure_public_net_subnet() {
    PUBLIC_NET=public_net
    PUBLIC_SUBNET=public_subnet

    exec_with_retry 5 0 /usr/bin/neutron net-create $PUBLIC_NET \
    --router:external --provider:physical_network physnet1 --provider:network_type flat

    exec_with_retry 5 0 /usr/bin/neutron subnet-create $PUBLIC_NET \
    --name $PUBLIC_SUBNET --allocation-pool start=$FIP_RANGE_START,end=$FIP_RANGE_END \
    --disable-dhcp --gateway $FIP_RANGE_GATEWAY $FIP_RANGE
}

function configure_router() {
    PUBLIC_ROUTER=router1

    exec_with_retry 5 0 /usr/bin/neutron router-create $PUBLIC_ROUTER
    exec_with_retry 5 0 /usr/bin/neutron router-interface-add $PUBLIC_ROUTER $PRIVATE_SUBNET
    exec_with_retry 5 0 /usr/bin/neutron router-gateway-set $PUBLIC_ROUTER $PUBLIC_NET
}

function create_nova_flavors() {
    exec_with_retry 5 0 nova flavor-create m1.nano 11 96 1 1
    exec_with_retry 5 0 nova flavor-create m1.tiny 1 512 1 1
    exec_with_retry 5 0 nova flavor-create m1.small 2 2048 20 1
    exec_with_retry 5 0 nova flavor-create m1.medium 3 4096 40 2
    exec_with_retry 5 0 nova flavor-create m1.large 5 8192 80 4
    exec_with_retry 5 0 nova flavor-create m1.xlarge 6 16384 160 8
}

function create_demo_user() {
    openstack project create --domain default --description "Demo Project" demo
    openstack user create --domain default --password $ADMIN_PASSWORD demo
    openstack role add --project demo --user demo _member_
}

function apply_cloudbase_theme() {
    #sed -i '13s/.*/COMPRESS_OFFLINE = False/' /etc/kolla/horizon/local_settings
    cat << EOF >> /etc/kolla/horizon/local_settings
AVAILABLE_THEMES = [
        ('cloudbase','Cloudbase','themes/cloudbase'),
        ('default', 'Default', 'themes/default'),
]
EOF
    docker restart horizon
}

function add_hyperv_to_inventory() {
    sed -i '18 i\[hyperv] \
"'$WINDOWS_HOST_IP'" \
\
[hyperv:vars] \
ansible_user="'$HYPERV_USERNAME'" \
ansible_password="'$HYPERV_PASSWORD'" \
ansible_port=5986 \
ansible_connection=winrm \
ansible_winrm_server_cert_validation=ignore' /usr/share/kolla-ansible/ansible/inventory/all-in-one

    sed -i '/hyperv]/a\
"'$WINDOWS_HOST_IP'"' /usr/share/kolla-ansible/ansible/inventory/all-in-one

    sed -i '/hyperv:vars/a\
ansible_user="'$HYPERV_USERNAME'" \
ansible_password="'$HYPERV_PASSWORD'" \
ansible_port=5986 \
ansible_connection=winrm \
ansible_winrm_server_cert_validation=ignore' /usr/share/kolla-ansible/ansible/inventory/all-in-one

}

ADMIN_PASSWORD=$1
FIP_RANGE=$2
FIP_RANGE_START=$3
FIP_RANGE_END=$4
FIP_RANGE_GATEWAY=$5
HYPERV_USERNAME=$6
HYPERV_PASSWORD=$7
KOLLA_INTERNAL_VIP_ADDRESS=$8
WINDOWS_HOST_IP=$9
FIP_RANGE_NAME_SERVERS=${@:10}

DATA_IFACE=data
EXT_IFACE=ext
OVS_DATA_BRIDGE=br-data
OVS_EXT_BRIDGE=br-ex
SSH_KEY_PATH=~/.ssh/id_rsa
MGMT_ZONE=management
MGMT_EXT_IFACE=mgmt_ext
MGMT_INT_IFACE=mgmt_int
CIRROS_URL=https://www.cloudbase.it/downloads/cirros-0.3.4-x86_64.vhdx.gz
KOLLA_OPENSTACK_VERSION=4.0.0
DOCKER_NAMESPACE=dardelean
GIT_KOLLA_REPO=https://github.com/dardelean/kolla.git
GIT_KOLLA_ANSIBLE_REPO=https://github.com/dardelean/kolla-ansible.git


if [ $(grep 'BOOTPROTO="none"' /etc/sysconfig/network-scripts/ifcfg-$MGMT_EXT_IFACE) ]
then
    MGMT_IFACE=$MGMT_EXT_IFACE
    disable_network_manager
else
    MGMT_IFACE=$MGMT_INT_IFACE
fi

set_interface_static_ipv4_from_dhcp $MGMT_INT_IFACE $MGMT_ZONE
/usr/sbin/ifup $MGMT_IFACE
config_ovs_network_adapter $DATA_IFACE
/usr/sbin/ifup $DATA_IFACE
config_ovs_network_adapter $EXT_IFACE
/usr/sbin/ifup $EXT_IFACE

read HOST_IP NETMASK_BITS BCAST  <<< `get_interface_ipv4 $MGMT_IFACE`
add_hostname_to_hosts $HOST_IP $(hostname)

exec_with_retry 5 0 /usr/bin/yum install -y ntpdate

if [ $http_proxy ]
then
    # packstack fails when accessing Keystone otherwise
    /usr/bin/sed -i '/^no_proxy=.*$/s/$/,'$HOST_IP'/' /etc/environment
    export no_proxy=$no_proxy,$HOST_IP
fi

SKIP_NTP_CONFIG=""
exec_with_retry 5 0 /sbin/ntpdate pool.ntp.org || SKIP_NTP_CONFIG=1 && >&2 echo "ntpdate failed, make sure the NTP server is available"


generate_ssh_key $SSH_KEY_PATH

configure_firewall

# Install dependencies
exec_with_retry 5 0 yum install -y epel-release
exec_with_retry 5 0 yum update -y
exec_with_retry 5 0 yum install -y wget git python-pip python-docker-py python-devel libffi-devel gcc openssl-devel
exec_with_retry 5 0 pip install -U pip 2> /dev/null
exec_with_retry 5 0 pip install "pywinrm>=0.2.2" 2> /dev/null
exec_with_retry 5 0 pip install -U python-openstackclient python-neutronclient 2> /dev/null


# Install Docker and Ansible
curl -sSL https://get.docker.io | bash
yum install -y ansible


# Configure Docker
exec_with_retry 5 0 mkdir -p /etc/systemd/system/docker.service.d
exec_with_retry 5 0 tee /etc/systemd/system/docker.service.d/kolla.conf <<-'EOF'
[Service]
MountFlags=shared
EOF

exec_with_retry 5 0 systemctl daemon-reload
exec_with_retry 5 0 systemctl restart docker


# Set up cinder-volumes
if ! vgs cinder-volumes 2>/dev/null
then
    exec_with_retry 5 0 mkdir -p /var/cinder
    exec_with_retry 5 0 fallocate -l 10G /var/cinder/cinder-volumes.img
    exec_with_retry 5 0 losetup /dev/loop2 /var/cinder/cinder-volumes.img

    exec_with_retry 5 0 pvcreate /dev/loop2
    exec_with_retry 5 0 vgcreate cinder-volumes /dev/loop2

    # make this reboot persistent
    echo "losetup /dev/loop2 /var/cinder/cinder-volumes.img" >> /etc/rc.d/rc.local
    chmod +x /etc/rc.d/rc.local
fi

# Install Kolla and Kolla-ansible
if [ ! -d /root/kolla ]
then
    exec_with_retry 5 0 git clone $GIT_KOLLA_REPO -b stable/ocata /root/kolla/
fi

if [ ! -d /root/kolla-ansible ]
then
    exec_with_retry 5 0 git clone $GIT_KOLLA_ANSIBLE_REPO -b stable/ocata /root/kolla-ansible/
fi

exec_with_retry 5 0 pip install /root/kolla 2> /dev/null
exec_with_retry 5 0 pip install /root/kolla-ansible 2> /dev/null

cp -r /root/kolla-ansible/etc/kolla /etc/


# Configure globals.yml for Kolla
#sed -i '/docker_namespace/c\docker_namespace: "'$DOCKER_NAMESPACE'"' /etc/kolla/globals.yml
sed -i '/kolla_base_distro/c\kolla_base_distro: "centos"' /etc/kolla/globals.yml
sed -i '/kolla_install_type/c\kolla_install_type: "source"' /etc/kolla/globals.yml
sed -i '/openstack_release/c\openstack_release: "'$KOLLA_OPENSTACK_VERSION'"' /etc/kolla/globals.yml
sed -i 's/^kolla_internal_vip_address:\s.*$/kolla_internal_vip_address: "'$KOLLA_INTERNAL_VIP_ADDRESS'"/g' /etc/kolla/globals.yml
sed -i '/#network_interface:/c\network_interface: "'$MGMT_IFACE'"' /etc/kolla/globals.yml
sed -i '/#neutron_external_interface:/c\neutron_external_interface: "'$EXT_IFACE'"' /etc/kolla/globals.yml

# set admin password
sed -i '/keystone_admin_password/c\keystone_admin_password: "'$ADMIN_PASSWORD'"' /etc/kolla/passwords.yml

# enable cinder
sed -i '/#enable_cinder:/c\enable_cinder: "yes"' /etc/kolla/globals.yml
sed -i '/#enable_cinder_backend_lvm:/c\enable_cinder_backend_lvm: "yes"' /etc/kolla/globals.yml
sed -i '/#cinder_volume_group:/c\cinder_volume_group: "cinder-volumes"' /etc/kolla/globals.yml

#sed -i '/enable_magnum:/c\enable_magnum: "yes"' /etc/kolla/globals.yml

# hyperv setup
sed -i '/enable_hyperv/c\enable_hyperv: "yes"' /etc/kolla/globals.yml
sed -i '/hyperv_username/c\hyperv_username: "'$HYPERV_USERNAME'"' /etc/kolla/globals.yml
sed -i '/hyperv_password/c\hyperv_password: "'$HYPERV_PASSWORD'"' /etc/kolla/globals.yml
sed -i '/vswitch_name/c\vswitch_name: "v-magine-data"' /etc/kolla/globals.yml
sed -i '/nova_msi_url/c\nova_msi_url: "https://cloudbase.it/downloads/HyperVNovaCompute_Ocata_15_0_0.msi"' /etc/kolla/globals.yml

exec_with_retry 5 0 systemctl restart docker
exec_with_retry 5 0 systemctl enable docker


# kolla-ansible prechecks fails if the hostname in the hosts file is set to 127.0.1.1
MGMT_IP=$(sudo ip addr show $MGMT_IFACE | sed -n 's/^\s*inet \([0-9.]*\).*$/\1/p')
sudo bash -c "echo $MGMT_IP $(hostname) >> /etc/hosts"


if [ `docker images | wc -l` -lt 10 ]
then
    exec_with_retry 5 0 kolla-ansible pull
fi

exec_with_retry 5 0 kolla-genpwd

#kolla-ansible prechecks -i /usr/share/kolla-ansible/ansible/inventory/all-in-one -vvv

add_hyperv_to_inventory

exec_with_retry 5 0 kolla-ansible deploy -i /usr/share/kolla-ansible/ansible/inventory/all-in-one
exec_with_retry 5 0 kolla-ansible post-deploy -i /usr/share/kolla-ansible/ansible/inventory/all-in-one

source /etc/kolla/admin-openrc.sh

exec_with_retry 5 0 nova service-disable --reason "hyperv" kolla.cloudbase nova-compute

CIRROS_TMP_FILE=$(/usr/bin/mktemp)
download_cirros_image "$CIRROS_URL" "$CIRROS_TMP_FILE"

configure_ovs_bridge
configure_public_net_subnet
configure_private_net_subnet
configure_router
create_nova_flavors
create_demo_user
#apply_cloudbase_theme
remove_kvm_containers

exec_with_retry 5 0 docker restart neutron_server neutron_openvswitch_agent neutron_dhcp_agent openvswitch_vswitchd openvswitch_db

exec_with_retry 5 0 docker restart horizon

echo "Done!"