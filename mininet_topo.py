#!/usr/bin/python

#Copyright (c) 2016 Enrique Saurez


#The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info, warn
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections
from time import sleep
class customTopo(Topo):
    """create topology with numCore core switches
    numEdge edge switches, hostsPerEdge, bw bandwidth, delay"""

    def build(self, numCores = 3, numEdges=4, hostsPerEdge=2, bw = 5, delay = None):
        
        switch_counter = 1
        added =False
        for i in range(numCores):
            c_name = "s" + str(switch_counter)
            switch_counter += 1
            controller  = self.addSwitch(c_name, protocols='OpenFlow13')
            configuration = dict(bw=bw, delay=delay,max_queue_size=10, loss=0, use_htb=True)                
            host_counter = 1
            for i in range(numEdges):
                switch_name = "s" + str(switch_counter)
                switch_counter += 1
                switch = self.addSwitch(switch_name, protocols='OpenFlow13')
                self.addLink(controller, switch, **configuration)
                if added:
                    continue
                for j in range(hostsPerEdge):
                    host_name = "h" + str(host_counter)
                    host = self.addHost(host_name)
                    self.addLink(host, switch, **configuration)
                    host_counter += 1
            added = True

def test():
    topo = customTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)


    print("Start RYU controller and continue. (Press Enter)")
    input()

    net.addController('rmController', controller=RemoteController,
            ip='127.0.0.1', port=6633)
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    test()
