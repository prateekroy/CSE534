import socket
import sys
import os
from threading import Thread
import json
from pprint import pprint
import time
import threading

routingTable = {}
hostname = ""
hostip = ""
hostport = ""
neighbor_dict = {}
allHosts = {}
lock = threading.Lock()

def startServer(host, listenPort):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, listenPort))
        s.listen(1)

        while 1:
                print "Waiting for connection"
                conn, addr = s.accept()
                print 'Connected by', addr
                data = conn.recv(4096).decode('utf8')
                if not data: break
                OnRecieve(data)
                # conn.send("Recieved"+data)
                conn.close()

def SendData(host, port, data):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.sendall(data.encode('utf8'))
        # data = s.recv(1024);
        # print data
        s.close()

def SendAllNeighbors(data):
        for neighbor in neighbor_dict:
                ip = allHosts[neighbor][0]["ip"]
                port = allHosts[neighbor][1]["port"]
                print ip, port, data
                SendData(ip, int(port), data)


#https://stackoverflow.com/questions/2835559/parsing-values-from-a-json-file
def populate_dvt(dvt_path):
        dist_vector = json.load(open(dvt_path))
        hosts = ['H1','R1','R2','R3','R4','H2']
        neighbors = populate_neighbors('neighbor.txt')

        for router in dist_vector:
                for host in hosts:
                        #add me
                        if host == router:
                                dist_vector[router].append({"dest": host, "cost": 0, "nexthop": host})
                        elif host not in neighbors[router]:
                                dist_vector[router].append({"dest": host, "cost": sys.maxsize, "nexthop": ''})



        apnajson = dist_vector[hostname]
        apnaroute = {}
        for item in apnajson:
                apnaroute[item["dest"]] = (item["cost"], item["nexthop"])

        # print apnaroute

        # pprint(dist_vector)
        return apnaroute


def populate_neighbors(neighbor_path):
        jsondata = json.load(open(neighbor_path))
        # pprint(neighbor_list)
        dic = {}
        for host in jsondata:
                l = []
                for index in range(len(jsondata[host])):
                        l.append(jsondata[host][index]["neighbor"])   
                dic[host] = l 

        return dic

def populate_ips(ip_path):
        # "om_points": "value"
        jsondata = json.load(open(ip_path))
        
        return jsondata

def myfunc(ip, port):
        # print ip, port
        startServer(ip, int(port));


def StartServerThread():
        global hostname, hostip, hostport, routingTable, neighbor_dict
        t = Thread(target=myfunc, args=(hostip,hostport))
        t.start()        

def printRoutingTable():
        global hostname, routingTable, neighbor_dict
        for entry in routingTable:
                print entry["dest"] , "|" , entry["nexthop"], "|" , entry["cost"]


def readConfig():
        global hostname, hostip, hostport, routingTable, neighbor_dict, allHosts

        dist_vector = populate_dvt('table.txt')
        neighbour_dict = populate_neighbors('neighbor.txt')
        hostdict = populate_ips('ip_config.txt')

        allHosts = hostdict;
        hostip = hostdict[hostname][0]["ip"]
        hostport = hostdict[hostname][1]["port"]

        routingTable = dist_vector
        neighbor_dict = neighbour_dict[hostname]        





def OnRecieve(data):
        global lock
        lock.acquire()

        #ectractNeighbor Routing table
        datab = json.loads(data)
 

        neighborRoutingTable = datab[0]
        sender = datab[1]
        print "################## " + sender
        print neighborRoutingTable


        updated = False
        #Run Bellman Ford 
        for x in neighborRoutingTable.keys():
                distance = routingTable[sender][0] + neighborRoutingTable[x][0]
                if routingTable[x][0] > distance:
                        routingTable[x] = (distance, sender)
                        updated = True;


        print "Bellman Ford Done!!!!!!!!"
        #if update send to all neighbors
        if updated:
                payload = json.dumps([routingTable, hostname])
                print "%%%%%%%%%%%%%%%%%%%%JJ%%%%%%%%%%%%%%%%%%%%%%"
                print routingTable
                print "%%%%%%%%%%%%%%%%%%%%JJ%%%%%%%%%%%%%%%%%%%%%%"
                SendAllNeighbors(payload)

        lock.release()


def test_populate_dvt():
        dvt_path = sys.argv[1]
        dist_vector = populate_dvt('table.txt')
        # print dist_vector["H1"]
        return dist_vector

def test_populate_neighbors():
        neighbour_dict = populate_neighbors('neighbor.txt')
        print neighbour_dict




if __name__ == '__main__':

        hostname = sys.argv[1]
        readConfig();
        StartServerThread();
        


        # print hostip, hostport

        time.sleep(10)
        payload = json.dumps([routingTable, hostname])
        SendAllNeighbors(payload)

        while 1:
                x = 2