#!/usr/bin/python

"""
Example network of Quagga routers
(QuaggaTopo + QuaggaService)
"""

import sys
import atexit

# patch isShellBuiltin
import mininet.util
import mininext.util
mininet.util.isShellBuiltin = mininext.util.isShellBuiltin
sys.modules['mininet.util'] = mininet.util

from mininet.util import dumpNodeConnections
from mininet.node import OVSController
from mininet.log import setLogLevel, info

from mininext.cli import CLI
from mininext.net import MiniNExT

from topo import QuaggaTopo
import time

net = None


def Script():
    global net
    for host in net.hosts:
        host.cmdPrint('echo 1 > /proc/sys/net/ipv4/ip_forward');

    H1 = net.getNodeByName("H1")
    R1 = net.getNodeByName("R1")
    R2 = net.getNodeByName("R2")
    R3 = net.getNodeByName("R3")
    R4 = net.getNodeByName("R4")
    H2 = net.getNodeByName("H2")

    R1.cmdPrint('ip addr add 173.0.1.1/16 dev R1-eth1')
    R1.cmdPrint('ip addr add 174.0.1.1/16 dev R1-eth2')
    R2.cmdPrint('ip addr add 175.0.1.1/16 dev R2-eth1')
    R3.cmdPrint('ip addr add 176.0.1.1/16 dev R3-eth1')
    R4.cmdPrint('ip addr add 175.0.1.2/16 dev R4-eth1')
    R4.cmdPrint('ip addr add 176.0.1.2/16 dev R4-eth2')

#Check for 5 attemts if ping converges 
def QuestionB2():
    global net
    H1 = net.getNodeByName("H1")
    H2 = net.getNodeByName("H2")
    for i in xrange(1,10):
        print H1.cmd('ping -c1 %s' % H2.IP())
        print "TimeNow : " + str(time.time())
        time.sleep(1)

def QuestionB3():
    global net
    H1 = net.getNodeByName("H1")
    H2 = net.getNodeByName("H2")

    print "----------------------Taking Link Down----------------------------------"
    print "TimeNow : " + str(time.time())
    #Take the R1 - R2 link
    net.configLinkStatus('R1', 'R2', 'down')
    for i in xrange(1,10):
        print H1.cmd('ping -c1 %s' % H2.IP())
        print "TimeNow : " + str(time.time())
        time.sleep(5)    


def startNetwork():
    "instantiates a topo, then starts the network and prints debug information"

    info('** Creating Quagga network topology\n')
    topo = QuaggaTopo()

    info('** Starting the network\n')
    global net
    net = MiniNExT(topo, controller=OVSController)
    net.start()

    Script()
    QuestionB2()

    QuestionB3()
    # info('** Dumping host connections\n')
    # dumpNodeConnections(net.hosts)

    # info('** Testing network connectivity\n')
    # net.ping(net.hosts)

    # info('** Dumping host processes\n')
    # for host in net.hosts:
    #     host.cmdPrint("ps aux")

    info('** Running CLI\n')
    CLI(net)


def stopNetwork():
    "stops a network (only called on a forced cleanup)"

    if net is not None:
        info('** Tearing down Quagga network\n')
        net.stop()

if __name__ == '__main__':
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()
