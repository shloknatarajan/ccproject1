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
        
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")

        ## Add switches
        s1 = self.addSwitch("s1", protocols='OpenFlow13')
        s2 = self.addSwitch("s2", protocols='OpenFlow13')
        s3 = self.addSwitch("s3", protocols='OpenFlow13')
        s4 = self.addSwitch("s4", protocols='OpenFlow13')


        # Add links (Use the switches in then node1 space)
        self.addLink(s1, h1, 1)
        self.addLink(s1, s2, port1=2, port2=1)
        self.addLink(s1, s3, 3, 1)
        self.addLink(s3, s4, 2, 2)
        self.addLink(s2, s4, 2, 1)
        self.addLink(s4, h2, 3)
        self.addLink(s4, h3, 4)

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
