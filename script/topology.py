from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Node
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

import time

def addRouter(net, name):
    r = net.addHost(name, cls=Node)
    r.cmd('sysctl -w net.ipv4.ip_forward=1')
    return r

def create_network():
    net = Mininet(controller=Controller, link=TCLink, switch=OVSSwitch)

    print("Adding controller")
    net.addController('c0')

    print("Adding hosts")

    h1 = net.addHost('h1', ip='10.0.1.2/24')

    h2 = net.addHost('h2', ip='10.0.1.3/24')

    h3 = net.addHost('h3', ip='10.0.2.2/24')

    h5 = net.addHost('h5', ip='10.0.2.3/24')

    h4 = net.addHost('h4', ip='10.0.3.2/24')


    print("Adding switches")
    switch_field = net.addSwitch('s1')
    switch_control = net.addSwitch('s2')
    switch_it = net.addSwitch('s3')
    core_switch = net.addSwitch('s4')

    print("Adding router")
    r0 = addRouter(net, 'r0')

    print("Creating links")

    net.addLink(h1, switch_field, bw=5)

    net.addLink(h2, switch_field, bw=5)


    net.addLink(h3, switch_control, bw=5)

    net.addLink(h5, switch_control, bw=5)


    net.addLink(h4, switch_it, bw=5)

    # Attacker: eth0, dari loop control, lalu lateral ke Field (eth1).
    net.addLink(h5, switch_field, bw=5)

    net.addLink(switch_field, core_switch, bw=5)
    net.addLink(switch_control, core_switch, bw=5)
    net.addLink(switch_it, core_switch, bw=5)
    
    net.addLink(r0, switch_field, bw=5)
    net.addLink(r0, switch_control, bw=5)
    net.addLink(r0, switch_it, bw=5)

    return net

def post_start_setup(net):
    r0 = net.get('r0')
    print("\nConfiguring router interfaces")
    r0.cmd('ifconfig r0-eth0 10.0.1.1/24 up')  # Field Zone
    r0.cmd('ifconfig r0-eth1 10.0.2.1/24 up')  # Control Zone
    r0.cmd('ifconfig r0-eth2 10.0.3.1/24 up')  # IT Zone

    print("Applying inter-zone segmentation on r0")
    # Default-deny forwarding with explicit allows:
    # - Field <-> Control allowed
    # - IT <-> Control allowed
    # - Field <-> IT blocked
    r0.cmd('iptables -F FORWARD')
    r0.cmd('iptables -P FORWARD DROP')
    r0.cmd('iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
    r0.cmd('iptables -A FORWARD -i r0-eth0 -o r0-eth1 -j ACCEPT')  # Field -> Control
    r0.cmd('iptables -A FORWARD -i r0-eth1 -o r0-eth0 -j ACCEPT')  # Control -> Field
    r0.cmd('iptables -A FORWARD -i r0-eth2 -o r0-eth1 -j ACCEPT')  # IT -> Control
    r0.cmd('iptables -A FORWARD -i r0-eth1 -o r0-eth2 -j ACCEPT')  # Control -> IT
    r0.cmd('iptables -A FORWARD -i r0-eth0 -o r0-eth2 -j DROP')    # Field -> IT
    r0.cmd('iptables -A FORWARD -i r0-eth2 -o r0-eth0 -j DROP')    # IT -> Field

    print("Setting default routes on hosts")

    net.get('h1').cmd('ip route add default via 10.0.1.1')

    net.get('h2').cmd('ip route add default via 10.0.1.1')



    net.get('h3').cmd('ip route add default via 10.0.2.1')





    net.get('h4').cmd('ip route add default via 10.0.3.1')


    print("Attacker: foothold Control saja; Field (eth1) down sampai eskalasi")
    # eth0 = switch_control (IP dari addHost). eth1 = switch_field (lateral movement).
    net.get('h5').cmd('ip link set h5-eth1 down')
    net.get('h5').cmd('ip route replace default via 10.0.2.1 dev h5-eth0')
    print("  (manual CLI: panggil escalate_attacker_to_field(net) untuk lateral ke Field)")

    time.sleep(5)
    print("Network ready")


def escalate_attacker_to_field(net):
    """
    Eskalasi lateral: aktifkan antarmuka Field pada attacker (setelah foothold di Control).
    Dipanggil dari orchestrator saat skenario MITM (atau manual dari CLI).
    """
    h = net.get('h5')
    h.cmd('ip link set h5-eth1 up')
    h.cmd('ip addr add 10.0.1.100/24 dev h5-eth1')
    h.cmd('ip route replace default via 10.0.2.1 dev h5-eth0')
    print("[topology] Attacker eskalasi ke Field: h5-eth1 = 10.0.1.100/24")


def CPS_topology():
    net = create_network()
    print("Starting network")
    net.start()
    post_start_setup(net)
    CLI(net)

    print("Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    CPS_topology()
