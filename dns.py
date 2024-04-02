#!/usr/bin/env python3

import argparse
import binascii
import random
import re
import select
import socket
from collections import OrderedDict

# See https://web.archive.org/web/20180919041301/https://routley.io/tech/2017/12/28/hand-writing-dns-messages.html
# See https://tools.ietf.org/html/rfc1035

# Constants
QTYPES: list[tuple[str, int]] = [
    # see https://en.wikipedia.org/wiki/List_of_DNS_record_types
    ('A', 1),  # Address record
    ('NS', 2),  # Name server record
    ('CNAME', 5),  # Canonical name record
    ('SOA', 6),  # Start of authority record
    ('PTR', 12),  # PTR Resource Record 
    ('HINFO', 13),  # Host Information
    ('MX', 15),  # Mail exchange record
    ('TXT', 16),  # Text record
    ('RP', 17),  # Responsible Person
    ('AFSDB', 18),  # AFS database record
    ('SIG', 24),  # Signature
    ('KEY', 25),  # Key record
    ('AAAA', 28),  # IPv6 address record
    ('LOC', 29),  # Location record
    ('SRV', 33),  # Service locator
    ('NAPTR', 35),  # Naming Authority Pointer
    ('KX', 36),  # Key Exchanger record
    ('CERT', 37),  # Certificate record
    ('DNAME', 39),  # Delegation name record
    ('APL', 42),  # Address Prefix List
    ('DS', 43),  # Delegation signer
    ('SSHFP', 44),  # SSH Public Key Fingerprint
    ('IPSECKEY', 45),  # IPsec Key
    ('RRSIG', 46),  # DNSSEC signature
    ('NSEC', 47),  # Next Secure record
    ('DNSKEY', 48),  # DNS Key record
    ('DHCID', 49),  # DHCP identifier
    ('NSEC3', 50),  # Next Secure record version 3
    ('NSEC3PARAM', 51),  # NSEC3 parameters
    ('TLSA', 52),  # TLSA certificate association
    ('SMIMEA', 53),  # S/MIME cert association
    ('HIP', 55),  # Host Identity Protocol
    ('CDS', 59),  # Child DS
    ('CDNSKEY', 60),  # 
    ('OPENPGPKEY', 61),  # OpenPGP public key record
    ('CSYNC', 62),  # Child-to-Parent Synchronization
    ('ZONEMD', 63),  # Message Digests for DNS Zones
    ('SVCB', 64),  # Service Binding
    ('HTTPS', 65),  # HTTPS Binding
    ('EUI48', 108),  # MAC address (EUI-48)
    ('EUI64', 109),  # MAC address (EUI-64)
    ('TKEY', 249),  # Transaction Key record
    ('TSIG', 250),  # Transaction Signature
    ('URI', 256),  # Uniform Resource Identifier
    ('CAA', 257),  # Certification Authority Authorization
    ('TA', 32768),  # DNSSEC Trust Authorities
    ('DLV', 32769),  # DNSSEC Lookaside Validation record
]

RCODES: dict[int,tuple[str,str]] = {
    0:  ('NOERROR',    'No Error'),
    1:  ('FORMERR',    'Format Error'),
    2:  ('SERVFAIL',   'Server Failure'),
    3:  ('NXDOMAIN',   'Non-Existent Domain'),
    4:  ('NOTIMP',     'Not Implemented'),
    5:  ('REFUSED',    'Query Refused'),
    6:  ('YXDOMAIN',   'Name Exists when it should not'),
    7:  ('YXRRSET',    'RR Set Exists when it should not'),
    8:  ('NXRRSET',    'RR Set that should exist does not'),
    9:  ('NOTAUTH',    'Server Not Authoritative for zone'),
    9:  ('NOTAUTH',    'Not Authorized'),
    10: ('NOTZONE',    'Name not contained in zone'),
    11: ('DSOTYPENI',  'DSO-TYPE Not Implemented'),
    12: ('UNASSIGNED', 'Unassigned'),
    13: ('UNASSIGNED', 'Unassigned'),
    14: ('UNASSIGNED', 'Unassigned'),
    15: ('UNASSIGNED', 'Unassigned'),
    16: ('BADVERS',    'Bad OPT Version'),
    16: ('BADSIG',     'TSIG Signature Failure'),
    17: ('BADKEY',     'Key not recognized'),
    18: ('BADTIME',    'Signature out of time window'),
    19: ('BADMODE',    'Bad TKEY Mode'),
    20: ('BADNAME',    'Duplicate key name'),
    21: ('BADALG',     'Algorithm not supported'),
    22: ('BADTRUNC',   'Bad Truncation'),
    23: ('BADCOOKIE',  'Bad/missing Server Cookie'),
    24: ('TIMEOUT', 'Query timed out'),
}

class DNSRecord:
    type: str
    value: str
    rcode: str
    status: str
    status_desc: str
    domain: str
    def __init__(self, type: str, domain: str, value: str, rcode: str) -> None:
        self.type = type
        self.domain = domain
        self.value = value
        self.rcode = int(rcode)
        (status, desc) = RCODES.get(self.rcode, ("UNKNOWN", "Unknown DNS Error"))
        self.status = status
        self.status_desc = desc
    
    def __repr__(self) -> str:
        return f"DNSRecord<{self.type}, {self.domain}, {self.value}, {self.rcode}, {self.status}>"

# helper functions

def _get_type_from_string(type: str) -> str:
    for (qtype, id) in QTYPES:
        if type.upper() == qtype:
            return "{:04x}".format(id)
    raise KeyError("Invalid DNS QTYPE", type)

def _get_type_by_id(type: str) -> str:
    itype = int(type, 16)
    for (qtype, id) in QTYPES:
        if id == itype:
            return qtype

def __send_udp_message(message: str, address: str, port: int) -> str:
    # send_udp_message sends a message to UDP server
    # message should be a hexadecimal encoded string, with no spaces or newlines
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)
    # create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        # wait 2 seconds for a reply
        ready = select.select([sock], [], [], 2)
        if ready:
            data, _ = sock.recvfrom(4096)
        else:
            data = bytes('')
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")

def __build_message(type="A", address=""):
    ID = random.getrandbits(16)  # 16-bit identifier (0-65535)

    QR = 0      # Query: 0, Response: 1     1bit
    OPCODE = 0  # Standard query = 0        4bit
    AA = 0      # Answer is Authoritative   1bit
    TC = 0      # Message is truncated      1bit
    RD = 1      # Recursion Desired         1bit
    RA = 0      # Recursion Allowed         1bit
    Z = 0       # Legacy, not parsed        3bit
    RCODE = 0   # Server Response Code      4bit

    query_params = str(QR)
    query_params += str(OPCODE).zfill(4)
    query_params += str(AA) + str(TC) + str(RD) + str(RA)
    query_params += str(Z).zfill(3)
    query_params += str(RCODE).zfill(4)
    query_params = "{:04x}".format(int(query_params, 2))

    QDCOUNT = 1 # Number of questions           4bit
    ANCOUNT = 0 # Number of answers             4bit
    NSCOUNT = 0 # Number of authority records   4bit
    ARCOUNT = 0 # Number of additional records  4bit

    message = ""
    message += "{:04x}".format(ID)
    message += query_params
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    # QNAME is url split up by '.', preceded by int indicating length of part
    addr_parts = address.split(".")
    for part in addr_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = binascii.hexlify(part.encode())
        message += addr_len
        message += addr_part.decode()

    message += "00" # Terminating bit for QNAME

    # Type of request
    QTYPE = _get_type_from_string(type)
    message += QTYPE

    # Class for lookup. 1 is Internet
    QCLASS = 1
    message += "{:04x}".format(QCLASS)

    return message

def __decode_message(message, hostname: str) -> list[DNSRecord]:    
    response: list[DNSRecord] = []
    
    query_params  = message[4:8]
    ANCOUNT       = message[12:16]
    NSCOUNT       = message[16:20]
    ARCOUNT       = message[20:24]

    params = "{:b}".format(int(query_params, 16)).zfill(16)
    QPARAMS = OrderedDict([
        ("QR",     params[0:1]),
        ("OPCODE", params[1:5]),
        ("AA",     params[5:6]),
        ("TC",     params[6:7]),
        ("RD",     params[7:8]),
        ("RA",     params[8:9]),
        ("Z",      params[9:12]),
        ("RCODE",  params[12:16])
    ])

    rcode = int(QPARAMS['RCODE'], 2)

    # Question section
    QUESTION_SECTION_STARTS = 24
    question_parts = __parse_parts(message, QUESTION_SECTION_STARTS, [])   

    QTYPE_STARTS = QUESTION_SECTION_STARTS + (len("".join(question_parts))) + (len(question_parts) * 2) + 2
    QCLASS_STARTS = QTYPE_STARTS + 4

    # Answer section
    ANSWER_SECTION_STARTS = QCLASS_STARTS + 4
    
    NUM_ANSWERS = max([int(ANCOUNT, 16), int(NSCOUNT, 16), int(ARCOUNT, 16)])
    if NUM_ANSWERS > 0:        
        for _ in range(NUM_ANSWERS):
            if (ANSWER_SECTION_STARTS < len(message)):
                ATYPE = message[ANSWER_SECTION_STARTS + 4:ANSWER_SECTION_STARTS + 8]
                RDLENGTH = int(message[ANSWER_SECTION_STARTS + 20:ANSWER_SECTION_STARTS + 24], 16)
                RDDATA = message[ANSWER_SECTION_STARTS + 24:ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)]

                if ATYPE == _get_type_from_string("A"):
                    octets = [RDDATA[i:i+2] for i in range(0, len(RDDATA), 2)]
                    RDDATA_decoded = ".".join(list(map(lambda x: str(int(x, 16)), octets)))
                elif ATYPE == _get_type_from_string("AAAA"):
                    octets = [str(RDDATA[i:i+4]).lstrip('0') for i in range(0, len(RDDATA), 4)]
                    RDDATA_decoded = ":".join(octets)
                    RDDATA_decoded = re.sub(r'(:)\1+', r'\1\1', RDDATA_decoded)
                else:
                    RDDATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), __parse_parts(RDDATA, 0, [])))
                    
                ANSWER_SECTION_STARTS = ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)

            type = _get_type_by_id(ATYPE)
            response.append(DNSRecord(type, hostname ,RDDATA_decoded, rcode)) 

    return response

def __parse_parts(message, start, parts):
    part_start = start + 2
    part_len = message[start:part_start]
    
    if len(part_len) == 0:
        return parts
    
    part_end = part_start + (int(part_len, 16) * 2)
    parts.append(message[part_start:part_end])

    if message[part_end:part_end + 2] == "00" or part_end > len(message):
        return parts
    else:
        return __parse_parts(message, part_end, parts)

def _resolve(hostname: str, server: str, port: int, type: str) -> list[DNSRecord]:
    '''the small resolve, returns all records for a given hostname of one type'''
    message = __build_message(type , hostname)
    response = ""
    tries = 0
    while response == "":
        response = __send_udp_message(message, server, port)
        if response == "":
            tries+=1
        if tries > 3:
            # we tried 3 times without answer, return special 3841 timeout
            # this is listed as "Unassigned" by 
            return [DNSRecord(type, hostname, "", 3841)]
    return __decode_message(response, hostname)

def _Resolve(hostname: str, server: str, port: int, type: str) -> list[DNSRecord]:
    '''the big Resolve, returns recursice records for a given hostname of one type'''
    results: list[DNSRecord] = []
    queue = _resolve(hostname, server, port, type)
    while True:
        # loop until add records in the queue have been resolved
        try:
            record = queue.pop()
        except IndexError:
            break

        if record.type == type:
            results.append(record)
        elif record.type == "CNAME":
            temp = _resolve(record.value, server, port, type)
            queue.extend(temp)
    return results

def Resolve(hostname: str, server: str, port: int = 53) -> list[DNSRecord]:
    '''Resolves a DNS hostname to A and AAAA records using the specified server'''
    a_records = _Resolve(hostname, server, port, "A")
    aaaa_records = _Resolve(hostname, server, port, "AAAA") 
    return a_records + aaaa_records
    
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("hostname", help="the hostname to query")
    p.add_argument("server", help="DNS Sever to query")
    args = p.parse_args()
    records = Resolve(args.hostname, args.server)
    for record in records:
        print(record)