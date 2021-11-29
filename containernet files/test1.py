#!/usr/bin/python
"""
This is the most simple example to showcase Containernet.
"""
from mininet.net import Containernet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
setLogLevel('info')

net = Containernet(controller=Controller)
info('*** Adding docker containers\n')
d1 = net.addDocker("mongodb-svc", ip='192.187.3.100', dimage="laboraufg/mongodb-free5gc")
d2 = net.addDocker("amf", ip='192.187.3.2', dimage="laboraufg/free5gc-st1")
d3 = net.addDocker("upf", ip='192.187.3.6', devices=["/dev/net/tun:/dev/net/tun"], dimage="laboraufg/free5gc-st1")
d4 = net.addDocker("smf", ip='192.187.3.3', dimage="laboraufg/free5gc-st1")
d5 = net.addDocker("hss", ip='192.187.3.4', dimage="laboraufg/free5gc-st1")
d6 = net.addDocker("pcrf", ip='192.187.3.5', dimage="laboraufg/free5gc-st1")
d7 = net.addDocker("webui", ip='192.187.3.101', dimage="laboraufg/webui-free5gc", ports=[3000], port_bindings={3000:3000})
d8 = net.addDocker("enb", ip='192.187.3.253', dimage="laboraufg/enb-openairsim")
d9 = net.addDocker("ue", ip='192.187.3.254', dimage="laboraufg/ue-openairsim")
#d10 = net.addDocker('bmv2', ip='10.0.0.252', dimage="opennetworking/p4mn")
#d11 = net.addDocker('p4r', ip='12.0.0.254', build_params={"dockerfile":"Dockerfile", "path":"../../p4runtime-shell/"})

info('*** Creating links\n')


info('*** Starting network\n')
net.start()

info('*** Testing connectivity\n')
#net.ping([d1, d4])
#net.ping([d2], manualdestip="11.0.0.253")
#net.ping([d3], manualdestip="11.0.0.252")
#net.ping([d2], manualdestip="12.0.0.254")
#net.ping([d4], manualdestip="12.0.0.252")
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()