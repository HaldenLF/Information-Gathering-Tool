from argparse import ArgumentParser
from scapy.all import ARP, Ether, srp
import socket
from queue import Queue
from threading import Thread, Lock

#Change to increase or decrease speed
N_THREADS = 200
q = Queue ()
print_lock = Lock()


def open_port (port):
    # This will determine if the host has the port open or closed
    try:
        s = socket.socket()
        #tries to connect to the host using that port.
        s.connect((host, port))
    except:
        with print_lock:
        #cant connect to port means its closed
            return False
    else:
        #connection established so port is open
        with print_lock:
            print (f"{host:15}: {port:5} is open ")
    finally:
        s.close()


def scan_thread():
    global q
    while True:
        #get the port number from the queue
        worker = q.get()
        #scan port number
        open_port (worker)
        #tells it when finished
        q.task_done ()


def main (host, ports):
    global q
    for t in range (N_THREADS):
        t = Thread (target=scan_thread)
        #when daemon set to true the thread will end when main thread ends
        t.daemon = True
        t.start()
    for worker in ports:
        #puts port in queue
        q.put(worker)
    
    q.join()

parser = ArgumentParser(
    prog='Network Scanner',
    description='This is a network scanner that uses arp requests.',
    epilog='Make sure to check out Stuffy24 on YOUTUBE!'
)

#set up help menu
parser.add_argument ('-t', "--target", help="Use the syntax -t to specify your target. Must be in CIDR Notation", required=True)

#parsing command line arguments, needed according to argparse python page
args = parser.parse_args()

#Change target to whatever IP space your wanting to scan
target_ip = args.target

#Create arp packet
arp = ARP(pdst=target_ip)

#Create the Ether broadcast packet
ether = Ether (dst='ff:ff:ff:ff:ff:ff')
packet = ether/arp

#This stacks them together
result = srp(packet, timeout=3, verbose=0) [0]

#list of clients
clients = []
for sent, recieved in result:
    # for each response, append ip and mac address to clients list
    clients.append({'ip': recieved.psrc, 'mac' : recieved.hwsrc})

#print clients
print ("Available devices in the network: ")
print ("IP" + " "*18+"MAC")
for client in clients:
    print("{:16} {}".format(client['ip'], client['mac']))

print ("What would you like to do next?")
print ("1.Port Scan")

answer = input ("Enter number\n")

if answer == "1":
    host = input ("Enter the host: ")
    print ("what ports would you like to scan?")
    ports = input ("Enter the ports/range: ")
    host, port_range = host, ports

    start_port, end_port = port_range.split("-")
    start_port, end_port = int(start_port), int (end_port)

    ports = [p for p in range (start_port, end_port)]
    main (host, ports)

    print("Scan Complete")
else:

    print("Thank you have a good day")