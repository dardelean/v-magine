#!/bin/bash

set -e

get_interface_ipv4 () {
    local IFACE=$1
    /sbin/ip addr show $IFACE | /bin/sed -n 's/^\s*inet \([0-9.]*\)\/\([0-9]*\)\s* brd \([0-9.]*\).*$/\1 \2 \3/p'
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
    /usr/bin/ssh-keygen -t rsa -b 2048 -N '' -f $SSH_KEY_PATH
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

    exec_with_retry 5 0 openstack image create --public --property \
    hypervisor_type=hyperv --disk-format vhdx --container-format bare \
    --file "$CIRROS_TMP_FILE" cirros-gen1-vhdx
    rm "$CIRROS_TMP_FILE"
}

function disable_network_manager() {
    /bin/systemctl stop NetworkManager.service
    /bin/systemctl disable NetworkManager.service
    /sbin/service network start
    /sbin/chkconfig network on
}

function configure_firewall() {
    # TODO: limit access to: -i $MGMT_IFACE
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
    apt install -y iptables-persistent

    /sbin/iptables -I INPUT -p tcp --dport 3260 -j ACCEPT
    /sbin/iptables -I INPUT -p tcp --dport 5672 -j ACCEPT
    /sbin/iptables -I INPUT -p tcp --dport 9696 -j ACCEPT
    /sbin/iptables -I INPUT -p tcp --dport 9292 -j ACCEPT
    /sbin/iptables -I INPUT -p tcp --dport 8776 -j ACCEPT
    /sbin/iptables -I INPUT -p tcp --dport 8780 -j ACCEPT
    /sbin/iptables -I INPUT -p tcp --dport 35357 -j ACCEPT
    /sbin/iptables -I INPUT -p tcp --dport 8774 -j ACCEPT
    /sbin/iptables -I INPUT -p tcp --dport 5000 -j ACCEPT
    /sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
    /usr/sbin/netfilter-persistent save
}

function configure_ovs_bridge() {

    # create OVS data bridge
    docker exec -u root openvswitch_vswitchd ovs-vsctl add-br br-data
    docker exec -u root openvswitch_vswitchd ovs-vsctl add-port br-data $DATA_IFACE
    docker exec -u root openvswitch_vswitchd ovs-vsctl add-port br-data phy-br-data || true
    docker exec -u root openvswitch_vswitchd ovs-vsctl set interface phy-br-data type=patch
    docker exec -u root openvswitch_vswitchd ovs-vsctl add-port br-int int-br-data || true
    docker exec -u root openvswitch_vswitchd ovs-vsctl set interface int-br-data type=patch
    docker exec -u root openvswitch_vswitchd ovs-vsctl set interface phy-br-data options:peer=int-br-data
    docker exec -u root openvswitch_vswitchd ovs-vsctl set interface int-br-data options:peer=phy-br-data

    # configure ML2 plugin for neutron
    for conf_file in /etc/kolla/neutron-server/ml2_conf.ini /etc/kolla/neutron-openvswitch-agent/ml2_conf.ini
    do
        cat << EOF > $conf_file
[ml2]
type_drivers = flat,vlan
tenant_network_types = flat,vlan
mechanism_drivers = openvswitch,hyperv
extension_drivers = port_security

[ml2_type_vlan]
network_vlan_ranges = physnet2:500:2000

[ml2_type_flat]
flat_networks = physnet1, physnet2

[securitygroup]
firewall_driver = neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver

[ovs]
bridge_mappings = physnet1:br-ex,physnet2:br-data
ovsdb_connection = tcp:$HOST_IP:6640
local_ip = $HOST_IP
EOF
    done

    exec_with_retry 5 0 docker restart neutron_server neutron_openvswitch_agent
}

function install_networking_hyperv() {
    echo "installing networking-hyperv..."
    docker exec -u root neutron_server pip install "networking-hyperv>=5.0.0,<6.0.0"
    echo "networking-hyperv installed succsessfully..."
}

function remove_kvm_containers() {
    # Remove unneeded Nova containers
    for name in nova_compute nova_ssh nova_libvirt
    do
        for id in $(sudo docker ps -q -a -f name=$name)
        do
            exec_with_retry 5 0 docker stop $id 2>/dev/null || :
            exec_with_retry 5 0 docker rm $id 2>/dev/null || :
        done
    done
}

function configure_private_net_subnet() {
    PRIVATE_NET=private_net
    PRIVATE_SUBNET=private_subnet

    if [ "${FIP_RANGE_NAME_SERVERS[@]}" ]; then
        exec_with_retry 5 0 neutron net-create $PRIVATE_NET \
        --provider:segmentation_id 500 --provider:physical_network physnet2 \
        --provider:network_type vlan --shared

        exec_with_retry 5 0 neutron subnet-create $PRIVATE_NET \
        10.10.10.0/24 --name $PRIVATE_SUBNET --allocation-pool \
        start=10.10.10.50,end=10.10.10.150 --gateway 10.10.10.1 \
        --dns_nameservers list=true ${FIP_RANGE_NAME_SERVERS[@]}
    fi
}

function configure_public_net_subnet() {
    PUBLIC_NET=public_net
    PUBLIC_SUBNET=public_subnet

    exec_with_retry 5 0 neutron net-create $PUBLIC_NET \
    --router:external --provider:physical_network physnet1 --provider:network_type flat

    exec_with_retry 5 0 neutron subnet-create $PUBLIC_NET \
    --name $PUBLIC_SUBNET --allocation-pool start=$FIP_RANGE_START,end=$FIP_RANGE_END \
    --disable-dhcp --gateway $FIP_RANGE_GATEWAY $FIP_RANGE
}

function configure_router() {
    PUBLIC_ROUTER=router1

    exec_with_retry 5 0 neutron router-create $PUBLIC_ROUTER
    exec_with_retry 5 0 neutron router-interface-add $PUBLIC_ROUTER $PRIVATE_SUBNET
    exec_with_retry 5 0 neutron router-gateway-set $PUBLIC_ROUTER $PUBLIC_NET
}

function create_nova_flavors() {
    exec_with_retry 5 0 nova flavor-create m1.nano 1 96 1 1
    exec_with_retry 5 0 nova flavor-create m1.micro 2 128 2 1
    exec_with_retry 5 0 nova flavor-create m1.tiny 3 512 1 1
    exec_with_retry 5 0 nova flavor-create m1.small 4 2048 20 1
    exec_with_retry 5 0 nova flavor-create m1.medium 5 4096 40 2
    exec_with_retry 5 0 nova flavor-create m1.large 6 8192 80 4
    exec_with_retry 5 0 nova flavor-create m1.xlarge 7 16384 160 8
}

function create_demo_user() {
    openstack project create --domain default --description "Demo Project" demo
    openstack user create --domain default --password $ADMIN_PASSWORD demo
    openstack role add --project demo --user demo _member_
}

function apply_cloudbase_theme() {
    docker exec -u root horizon apt install -y software-properties-common
    docker exec -u root horizon add-apt-repository -y ppa:cloudbaseit/cbsl-theme-pike
    docker exec -u root horizon apt update -y
    docker exec -u root horizon apt install -y openstack-dashboard-cloudbase-theme

    cat << EOF >> /etc/kolla/horizon/local_settings
AVAILABLE_THEMES = [
        (
                'cloudbase','Cloudbase','themes/cloudbase'
        ),
]
EOF

    docker restart horizon
}

function add_hyperv_to_inventory() {
    sed -i '/#hyperv_host/c\"'$WINDOWS_HOST_IP'"' $INVENTORY_FILE
    sed -i '/#ansible_user/c\ansible_user="'$HYPERV_USERNAME'"' $INVENTORY_FILE
    sed -i '/#ansible_password/c\ansible_password="'$HYPERV_PASSWORD'"' $INVENTORY_FILE
    sed -i '/#ansible_port/c\ansible_port="5986"' $INVENTORY_FILE
    sed -i '/#ansible_connection/c\ansible_connection="winrm"' $INVENTORY_FILE
    sed -i '/#ansible_winrm_server_cert_validation/c\ansible_winrm_server_cert_validation="ignore"' $INVENTORY_FILE
}

ADMIN_PASSWORD=$1
FIP_RANGE=$2
FIP_RANGE_START=$3
FIP_RANGE_END=$4
FIP_RANGE_GATEWAY=$5
HYPERV_USERNAME=$6
HYPERV_PASSWORD=$7
WINDOWS_HOST_IP=$8
EXT_VSWITCH=$9
FIP_RANGE_NAME_SERVERS=${@:10}

DATA_IFACE=data
EXT_IFACE=ext
OVS_DATA_BRIDGE=br-data
OVS_EXT_BRIDGE=br-ex
DATA_VSWITCH=v-magine-data
SSH_KEY_PATH=~/.ssh/id_rsa
MGMT_ZONE=management
MGMT_EXT_IFACE=mgmt_ext
MGMT_INT_IFACE=mgmt_int
CIRROS_URL=https://www.cloudbase.it/downloads/cirros-0.3.4-x86_64.vhdx.gz
KOLLA_OPENSTACK_VERSION=5.0.0
DOCKER_NAMESPACE=dardelean
INSTALL_TYPE=binary
GIT_KOLLA_REPO=https://github.com/openstack/kolla.git
GIT_KOLLA_ANSIBLE_REPO=https://github.com/openstack/kolla-ansible.git
INVENTORY_FILE=/usr/local/share/kolla-ansible/ansible/inventory/all-in-one
PASSWORDS_FILE=/etc/kolla/passwords.yml
GLOBALS_FILE=/etc/kolla/globals.yml
GIT_BRANCH=stable/pike
MGMT_IFACE=$MGMT_EXT_IFACE


read HOST_IP NETMASK_BITS BCAST  <<< `get_interface_ipv4 $MGMT_IFACE`
add_hostname_to_hosts $HOST_IP $(hostname)

# NTP client
exec_with_retry 5 0 apt-get install -y ntpdate

if [ $http_proxy ]
then
    # packstack fails when accessing Keystone otherwise
    /usr/bin/sed -i '/^no_proxy=.*$/s/$/,'$HOST_IP'/' /etc/environment
    export no_proxy=$no_proxy,$HOST_IP
fi

SKIP_NTP_CONFIG=""
exec_with_retry 5 0 /usr/sbin/ntpdate pool.ntp.org || SKIP_NTP_CONFIG=1 && >&2 \
echo "ntpdate failed, make sure the NTP server is available"


generate_ssh_key $SSH_KEY_PATH

configure_firewall

# Without this LIS won't work
exec_with_retry 5 0 apt-get install -y linux-cloud-tools-common \
linux-tools-`uname -r` linux-cloud-tools-`uname -r`

# Install dependencies
exec_with_retry 5 0 apt-get install software-properties-common vim -y
exec_with_retry 5 0 apt-add-repository ppa:ansible/ansible -y
exec_with_retry 5 0 apt-get update
exec_with_retry 5 0 apt-get install -y docker.io ansible

# Remove lxd or lxc so it won't bother Docker
exec_with_retry 5 0 apt-get remove -y lxd lxc

exec_with_retry 5 0 apt-get install -y python-pip
exec_with_retry 5 0 apt-get --auto-remove --yes remove python-openssl
exec_with_retry 5 0 pip install pyOpenSSL 2> /dev/null
exec_with_retry 5 0 apt-get install -y python-openstackclient
exec_with_retry 5 0 pip install "pywinrm>=0.2.2" 2> /dev/null


# Configure Docker
mkdir -p /etc/systemd/system/docker.service.d
tee /etc/systemd/system/docker.service.d/kolla.conf <<-'EOF'
[Service]
MountFlags=shared
EOF

exec_with_retry 5 0 systemctl daemon-reload
exec_with_retry 5 0 systemctl restart docker


# Set up cinder-volumes
if ! vgs cinder-volumes 2>/dev/null
then
    exec_with_retry 5 0 mkdir -p /var/cinder
    exec_with_retry 5 0 fallocate -l 30G /var/cinder/cinder-volumes.img
    exec_with_retry 5 0 losetup /dev/loop2 /var/cinder/cinder-volumes.img

    exec_with_retry 5 0 pvcreate /dev/loop2
    exec_with_retry 5 0 vgcreate cinder-volumes /dev/loop2

    # make this reboot persistent
    cat << EOF > /etc/rc.local
#!/bin/bash

losetup /dev/loop2 /var/cinder/cinder-volumes.img
EOF
    chmod +x /etc/rc.local

    # needed for Ubuntu distro
    echo "configfs" >> /etc/modules
    exec_with_retry 5 0 update-initramfs -u

    modprobe configfs
    systemctl start sys-kernel-config.mount
fi

# Install Kolla and Kolla-ansible
if [ ! -d /root/kolla ]
then
    exec_with_retry 5 0 git clone $GIT_KOLLA_REPO -b $GIT_BRANCH /root/kolla/
fi

if [ ! -d /root/kolla-ansible ]
then
    exec_with_retry 5 0 git clone $GIT_KOLLA_ANSIBLE_REPO -b $GIT_BRANCH /root/kolla-ansible/
fi

exec_with_retry 5 0 pip install /root/kolla 2> /dev/null
exec_with_retry 5 0 pip install /root/kolla-ansible 2> /dev/null

cp -r /root/kolla-ansible/etc/kolla /etc/

# kolla-ansible prechecks fails if the hostname in the hosts file is set to 127.0.1.1
MGMT_IP=$(sudo ip addr show $MGMT_IFACE | sed -n 's/^\s*inet \([0-9.]*\).*$/\1/p')
if [ $(ip addr | grep $MGMT_IP) -ne 0 ]
then
    sudo bash -c "echo $MGMT_IP $(hostname) >> /etc/hosts"
fi

# Configure globals.yml for Kolla
sed -i '/#docker_namespace/c\docker_namespace: "'$DOCKER_NAMESPACE'"' $GLOBALS_FILE
sed -i '/#openstack_release/c\openstack_release: "'$KOLLA_OPENSTACK_VERSION'"' $GLOBALS_FILE
sed -i '/#kolla_base_distro:/c\kolla_base_distro: "ubuntu"' $GLOBALS_FILE
sed -i '/#kolla_install_type:/c\kolla_install_type: "'$INSTALL_TYPE'"' $GLOBALS_FILE
sed -i '/#enable_haproxy:/c\enable_haproxy: "no"' $GLOBALS_FILE
#sed -i '/#enable_magnum:/c\enable_magnum: "yes"' $GLOBALS_FILE
sed -i 's/^kolla_internal_vip_address:\s.*$/kolla_internal_vip_address: "'$MGMT_IP'"/g' $GLOBALS_FILE
sed -i '/#network_interface/c\network_interface: "'$MGMT_IFACE'"' $GLOBALS_FILE
sed -i '/#neutron_external_interface/c\neutron_external_interface: "'$EXT_IFACE'"' $GLOBALS_FILE

# set admin password
sed -i '/keystone_admin_password/c\keystone_admin_password: "'$ADMIN_PASSWORD'"' $PASSWORDS_FILE

# enable cinder
sed -i '/#enable_cinder:/c\enable_cinder: "yes"' $GLOBALS_FILE
sed -i '/#enable_cinder_backend_lvm/c\enable_cinder_backend_lvm: "yes"' $GLOBALS_FILE
sed -i '/#cinder_volume_group/c\cinder_volume_group: "cinder-volumes"' $GLOBALS_FILE

# enable magnum but not the dashboard if install type is binary
sed -i '/#enable_magnum/c\enable_magnum: "yes"' $GLOBALS_FILE
if [ $INSTALL_TYPE = "binary" ]; then
    sed -i '/#enable_horizon_magnum/c\enable_horizon_magnum: "no"' $GLOBALS_FILE
fi

# hyperv setup
#sed -i '/#nova_console/c\nova_console: "rdp"' $GLOBALS_FILE
sed -i '/#enable_hyperv/c\enable_hyperv: "yes"' $GLOBALS_FILE
sed -i '/#hyperv_username/c\hyperv_username: "'$HYPERV_USERNAME'"' $GLOBALS_FILE
sed -i '/#hyperv_password/c\hyperv_password: "'$HYPERV_PASSWORD'"' $GLOBALS_FILE
sed -i '/#vswitch_name/c\vswitch_name: "'$DATA_VSWITCH'"' $GLOBALS_FILE
sed -i '/#nova_msi_url/c\nova_msi_url: "https://cloudbase.it/downloads/HyperVNovaCompute_Pike_16_0_0.msi"' $GLOBALS_FILE

exec_with_retry 5 0 systemctl restart docker
exec_with_retry 5 0 systemctl enable docker


if [ `docker images | wc -l` -lt 10 ]
then
    exec_with_retry 5 0 kolla-ansible pull
fi


exec_with_retry 5 0 kolla-genpwd

#kolla-ansible prechecks -i $INVENTORY_FILE

add_hyperv_to_inventory

exec_with_retry 5 0 kolla-ansible deploy -i $INVENTORY_FILE
exec_with_retry 5 0 kolla-ansible post-deploy -i $INVENTORY_FILE

# networking-hyperv is present in ml2_conf by default but the package
# is not installed in the binary neutron_server image, so the container
# will not start correctly
if [ $INSTALL_TYPE = "binary" ]; then
    sed -i '/mechanism_drivers/c\mechanism_drivers = openvswitch' \
    /etc/kolla/neutron-server/ml2_conf.ini
fi

source /etc/kolla/admin-openrc.sh

exec_with_retry 5 0 nova service-disable --reason "hyperv" kolla.cloudbase \
nova-compute

CIRROS_TMP_FILE=$(/bin/mktemp)
download_cirros_image "$CIRROS_URL" "$CIRROS_TMP_FILE"

# install networking-hyperv and enable hyperv as mechanism_driver
if [ $INSTALL_TYPE = "binary" ]; then
    install_networking_hyperv
    sed -i '/mechanism_drivers/c\mechanism_drivers = openvswitch,hyperv' \
    /etc/kolla/neutron-server/ml2_conf.ini
fi

configure_ovs_bridge
sleep 15
configure_public_net_subnet
configure_private_net_subnet
configure_router
create_nova_flavors
create_demo_user
apply_cloudbase_theme
remove_kvm_containers

echo "Restarting KVP daemon"
exec_with_retry 5 0 systemctl restart hv-kvp-daemon.service
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo "KVP daemon restarted"
else
    echo "KVP daemon failed to restart"
fi

exec_with_retry 5 0 docker restart neutron_server neutron_openvswitch_agent \
neutron_dhcp_agent openvswitch_vswitchd openvswitch_db

echo "Done!"
