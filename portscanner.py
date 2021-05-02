import socket
import time
import threading
from queue import Queue
import logging
from scapy.layers.inet import TCP, IP, ICMP

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

def simple_port_scanner(target_host):
    startTime = time.time()
    target = target_host
    t_IP = socket.gethostbyname(target)
    print ('Starting scan on host: ', t_IP)
    for i in range(79,81):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = s.connect_ex((t_IP, i))
        if(conn == 0) :
            print ('Port {}: OPEN'.format(i))
        s.close()
    print('Time taken:', time.time() - startTime)

def tcp_port_scanner(n1,s1,e1):
    net = n1
    net1 = net.split('.')
    a = '.'
    net2 = net1[0] + a + net1[1] + a + net1[2] + a
    st1 = s1
    en1 = e1
    en1 = en1 + 1
    t1 = time.time()
    def scan(addr):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((addr, 135))
        if result == 0:
            return 1
        else:
            return 0
    def run1():
        for ip in range(st1, en1):
            addr = net2 + str(ip)
            if (scan(addr)):
                print(addr, "is live")
    run1()
    total = time.time() - t1
    print("Scanning completed in: ", total)

def threaded_port_scanner(target1):
    socket.setdefaulttimeout(0.25)
    print_lock = threading.Lock()
    target = target1
    t_IP = socket.gethostbyname(target)
    print('Starting scan on host: ', t_IP)
    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((t_IP, port))
            with print_lock:
                print(port, 'is open')
            s.close()
        except:
            pass
    def threader():
        while True:
            worker = q.get()
            portscan(worker)
            q.task_done()
    q = Queue()
    startTime = time.time()
    for x in range(100):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
    for worker in range(1, 500):
        q.put(worker)
    q.join()
    print('Time taken:', time.time() - startTime)

def tcp_port_scanner_scapy():
    dst_ip = '192.168.10.3'
    src_port = RandShort()
    dst_port = 80
    tcp_connect_scan_resp = sr1(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S'), timeout=10)
    if (str(type(tcp_connect_scan_resp)) == "<class 'NoneType'>"):
        print("Closed")
    elif (tcp_connect_scan_resp.haslayer(TCP)):
        if (tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='AR'), timeout=10)
            print("Open")
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
            print("Closed")

def null_port_scanner():
    dst_ip = '127.0.0.1'
    src_port = RandShort()
    dst_port = 80
    null_scan_resp = sr1(IP(dst=dst_ip) / TCP(dport=dst_port, flags=""), timeout=10)
    if (str(type(null_scan_resp)) == "<class 'NoneType'>"):
        print("Open|Filtered")
    elif (null_scan_resp.haslayer(TCP)):
        if (null_scan_resp.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif (null_scan_resp.haslayer(ICMP)):
        if (int(null_scan_resp.getlayer(ICMP).type) == 3 and int(null_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,13]):
            print("Filtered")

def main():
    print("*********************************************************")
    print("\t\t\t\t\tPORT SCANNER")
    print("*********************************************************")
    choice = int(input("Enter the choice.. \n 1.SIMPLE PORT SCANNER \n 2.TCP PORT SCANNER "
                       "\n 3.THREADED PORT SCAN \n 4.TCP PORT SCANNER USING SCAPY\n 5.NULL PORT SCANNER USING SCAPY\n 6.EXIT\n"))
    while (choice != 6):
        if (choice == 1):
            target = input('Enter the host to be scanned: ')
            simple_port_scanner(target)
        elif (choice == 2):
            net = input("Enter the IP address: ")
            st1 = int(input("Enter the Starting Port Number: "))
            en1 = int(input("Enter the Last Port Number: "))
            tcp_port_scanner(net,st1,en1)
        elif (choice == 3):
            target1 = input('Enter the host to be scanned: ')
            threaded_port_scanner(target1)
        elif (choice == 4):
            tcp_port_scanner_scapy()
        elif (choice==5):
            null_port_scanner()
        choice = int(input("\nDo you want to enter any other choice.. \n "
                           "1.SIMPLE PORT SCANNER \n 2.TCP PORT SCANNER \n 3.THREADED PORT SCAN \n 4.TCP PORT SCANNER USING SCAPY\n "
                           "5.NULL PORT SCANNER USING SCAPY\n 6.EXIT\n"))

main()
