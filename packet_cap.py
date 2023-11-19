import socket

HOST = socket.gethostbyname(socket.gethostname())
PORT = 0
TIMEOUT = 10.0

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST,0))
s.settimeout(TIMEOUT)

s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
for i in range(100):
    raw_packet = s.recvfrom(2048)
    bytes = [i for i in raw_packet[0]]
    cap_hexdump = ([f'{i:0>2X}' for i in bytes])
    ints = ' '.join([str(i) for i in bytes])
    # string = ' '.join([str(i) for i in utf_8_decode(packet[0], 'ignore')])
    
    binary = [f'{i:0>8b}' for i in bytes]
    
    packet = {}
    packet['version'] = binary[0][:4]
    packet['ihl'] = binary[0][4:8]
    packet['type of service'] = binary[1]
    packet['total length'] = binary[2:4]
    packet['identification'] = binary[4:6]
    packet['flags'] = binary[6:8]
    packet['time to live'] = binary[8]
    packet['protocol'] = binary[9]
    packet['header checksum'] = binary[10:12]
    packet['source address'] = binary[12:16]
    packet['destination address'] = binary[16:20]
    packet['source port'] = binary[20:22]
    packet['destination port'] = binary [22:24]
    packet['sequence number'] = binary [24:28]
    packet['acknowledgement number'] = binary[28:32]
    packet['tcp segment length'] = binary[32]
    packet['tcp flags'] = binary[33]
    packet['window'] = binary[34:36]
    packet['checksum'] = binary[36:38]
    packet['urgent pointer'] = binary[38:40]
    packet['max segment size'] = binary[40:42]

    sorcPort = int(''.join([i for i in packet['source port']]),base=2)
    destPort = int(''.join([i for i in packet['destination port']]),base=2)

    source, dest = '', ''
    for sorc,des in zip(packet['source address'], packet['destination address']):
        source += str(int(sorc, base =2)) + '.'
        dest += str(int(des, base=2)) + '.'
    
    print('from: ' + source + ':' ,sorcPort, 'to: ' + dest + ':', destPort)

    print(' '.join(cap_hexdump[0:20]))
    print(' '.join(cap_hexdump[20:]))

    print(''.join([chr(i) for i in bytes]), '\n'*2)

    
    
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)