#!/usr/bin/env python
# -*- coding: utf-8 -*-

from core.plugin import BaseHostPlugin

from ctypes import *
import os
import sys
import socket
import binascii
import struct


class SMB_HEADER(Structure):
  """SMB Header decoder.
  """

  _pack_ = 1  # Alignment

  _fields_ = [
    ("server_component", c_uint32),
    ("smb_command", c_uint8),
    ("error_class", c_uint8),
    ("reserved1", c_uint8),
    ("error_code", c_uint16),
    ("flags", c_uint8),
    ("flags2", c_uint16),
    ("process_id_high", c_uint16),
    ("signature", c_uint64),
    ("reserved2", c_uint16),
    ("tree_id", c_uint16),
    ("process_id", c_uint16),
    ("user_id", c_uint16),
    ("multiplex_id", c_uint16)
  ]

  def __new__(self, buffer=None):
    return self.from_buffer_copy(buffer)

  def __init__(self,buffer=None):
    pass

def generate_smb_proto_payload(*protos):
    """Generate SMB Protocol. Pakcet protos in order.
    """
    hexdata = []
    for proto in protos:
      hexdata.extend(proto)
    return b"".join(hexdata)

def calculate_doublepulsar_xor_key(s):
    """Calaculate Doublepulsar Xor Key
    """
    x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
    x = x & 0xffffffff  # this line was added just to truncate to 32 bits
    return x

def negotiate_proto_request():
    """Generate a negotiate_proto_request packet.
    """
    netbios = [
      b'\x00',              # 'Message_Type'
      b'\x00\x00\x54'       # 'Length'
    ]

    smb_header = [
      b'\xFF\x53\x4D\x42',  # 'server_component': .SMB
      b'\x72',              # 'smb_command': Negotiate Protocol
      b'\x00\x00\x00\x00',  # 'nt_status'
      b'\x18',              # 'flags'
      b'\x01\x28',          # 'flags2'
      b'\x00\x00',          # 'process_id_high'
      b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      b'\x00\x00',          # 'reserved'
      b'\x00\x00',          # 'tree_id'
      b'\x2F\x4B',          # 'process_id'
      b'\x00\x00',          # 'user_id'
      b'\xC5\x5E'           # 'multiplex_id'
    ]

    negotiate_proto_request = [
      b'\x00',              # 'word_count'
      b'\x31\x00',          # 'byte_count'
      # Requested Dialects
      b'\x02',              # 'dialet_buffer_format'
      b'\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00',   # 'dialet_name': LANMAN1.0
      b'\x02',              # 'dialet_buffer_format'
      b'\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00',   # 'dialet_name': LM1.2X002
      b'\x02',              # 'dialet_buffer_format'
      b'\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00',  # 'dialet_name3': NT LANMAN 1.0
      b'\x02',              # 'dialet_buffer_format'
      b'\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00'   # 'dialet_name4': NT LM 0.12
    ]

    return generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request)


def session_setup_andx_request():
    """Generate session setuo andx request.
    """
    netbios = [
      b'\x00',              # 'Message_Type'
      b'\x00\x00\x63'       # 'Length'
    ]

    smb_header = [
      b'\xFF\x53\x4D\x42',  # 'server_component': .SMB
      b'\x73',              # 'smb_command': Session Setup AndX
      b'\x00\x00\x00\x00',  # 'nt_status'
      b'\x18',              # 'flags'
      b'\x01\x20',          # 'flags2'
      b'\x00\x00',          # 'process_id_high'
      b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      b'\x00\x00',          # 'reserved'
      b'\x00\x00',          # 'tree_id'
      b'\x2F\x4B',          # 'process_id'
      b'\x00\x00',          # 'user_id'
      b'\xC5\x5E'           # 'multiplex_id'
    ]

    session_setup_andx_request = [
      b'\x0D',              # Word Count
      b'\xFF',              # AndXCommand: No further command
      b'\x00',              # Reserved
      b'\x00\x00',          # AndXOffset
      b'\xDF\xFF',          # Max Buffer
      b'\x02\x00',          # Max Mpx Count
      b'\x01\x00',          # VC Number
      b'\x00\x00\x00\x00',  # Session Key
      b'\x00\x00',          # ANSI Password Length
      b'\x00\x00',          # Unicode Password Length
      b'\x00\x00\x00\x00',  # Reserved
      b'\x40\x00\x00\x00',  # Capabilities
      b'\x26\x00',          # Byte Count
      b'\x00',              # Account
      b'\x2e\x00',          # Primary Domain
      b'\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00',    # Native OS: Windows 2000 2195
      b'\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00',        # Native OS: Windows 2000 5.0
    ]

    return generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request)


def tree_connect_andx_request(ip, userid):
    """Generate tree connect andx request.
    """
    netbios = [
      b'\x00',              # 'Message_Type'
      b'\x00\x00\x47'       # 'Length'
    ]

    smb_header = [
      b'\xFF\x53\x4D\x42',  # 'server_component': .SMB
      b'\x75',              # 'smb_command': Tree Connect AndX
      b'\x00\x00\x00\x00',  # 'nt_status'
      b'\x18',              # 'flags'
      b'\x01\x20',          # 'flags2'
      b'\x00\x00',          # 'process_id_high'
      b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      b'\x00\x00',          # 'reserved'
      b'\x00\x00',          # 'tree_id'
      b'\x2F\x4B',          # 'process_id'
      userid,              # 'user_id'
      b'\xC5\x5E'           # 'multiplex_id'
    ]

    ipc = b"\\\\%s\IPC$\x00"%(ip.encode())

    tree_connect_andx_request = [
      b'\x04',              # Word Count
      b'\xFF',              # AndXCommand: No further commands
      b'\x00',              # Reserved
      b'\x00\x00',          # AndXOffset
      b'\x00\x00',          # Flags
      b'\x01\x00',          # Password Length
      b'\x1C\x00',          # Byte Count
      b'\x00',              # Password
      ipc,        # \\xxx.xxx.xxx.xxx\IPC$
      b'\x3f\x3f\x3f\x3f\x3f\x00'   # Service
    ]

    length = len(b"".join(smb_header)) + len(b"".join(tree_connect_andx_request))
    # netbios[1] = '\x00' + struct.pack('>H', length)
    netbios[1] = struct.pack(">L", length)[-3:]

    return generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request)


def peeknamedpipe_request(treeid, processid, userid, multiplex_id):
    """Generate tran2 request
    """
    netbios = [
      b'\x00',              # 'Message_Type'
      b'\x00\x00\x4a'       # 'Length'
    ]

    smb_header = [
      b'\xFF\x53\x4D\x42',  # 'server_component': .SMB
      b'\x25',              # 'smb_command': Trans2
      b'\x00\x00\x00\x00',  # 'nt_status'
      b'\x18',              # 'flags'
      b'\x01\x28',          # 'flags2'
      b'\x00\x00',          # 'process_id_high'
      b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      b'\x00\x00',          # 'reserved'
      treeid,
      processid,
      userid,
      multiplex_id
    ]

    tran_request = [
      b'\x10',              # Word Count
      b'\x00\x00',          # Total Parameter Count
      b'\x00\x00',          # Total Data Count
      b'\xff\xff',          # Max Parameter Count
      b'\xff\xff',          # Max Data Count
      b'\x00',              # Max Setup Count
      b'\x00',              # Reserved
      b'\x00\x00',          # Flags
      b'\x00\x00\x00\x00',  # Timeout: Return immediately
      b'\x00\x00',          # Reversed
      b'\x00\x00',          # Parameter Count
      b'\x4a\x00',          # Parameter Offset
      b'\x00\x00',          # Data Count
      b'\x4a\x00',          # Data Offset
      b'\x02',              # Setup Count
      b'\x00',              # Reversed
      b'\x23\x00',          # SMB Pipe Protocol: Function: PeekNamedPipe (0x0023)
      b'\x00\x00',          # SMB Pipe Protocol: FID
      b'\x07\x00',
      b'\x5c\x50\x49\x50\x45\x5c\x00'  # \PIPE\
    ]

    return generate_smb_proto_payload(netbios, smb_header, tran_request)


def trans2_request(treeid, processid, userid, multiplex_id):
    """Generate trans2 request.
    """
    netbios = [
      b'\x00',              # 'Message_Type'
      b'\x00\x00\x4f'       # 'Length'
    ]

    smb_header = [
      b'\xFF\x53\x4D\x42',  # 'server_component': .SMB
      b'\x32',              # 'smb_command': Trans2
      b'\x00\x00\x00\x00',  # 'nt_status'
      b'\x18',              # 'flags'
      b'\x07\xc0',          # 'flags2'
      b'\x00\x00',          # 'process_id_high'
      b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      b'\x00\x00',          # 'reserved'
      treeid,
      processid,
      userid,
      multiplex_id
    ]

    trans2_request = [
      b'\x0f',              # Word Count
      b'\x0c\x00',          # Total Parameter Count
      b'\x00\x00',          # Total Data Count
      b'\x01\x00',          # Max Parameter Count
      b'\x00\x00',          # Max Data Count
      b'\x00',              # Max Setup Count
      b'\x00',              # Reserved
      b'\x00\x00',          # Flags
      b'\xa6\xd9\xa4\x00',  # Timeout: 3 hours, 3.622 seconds
      b'\x00\x00',          # Reversed
      b'\x0c\x00',          # Parameter Count
      b'\x42\x00',          # Parameter Offset
      b'\x00\x00',          # Data Count
      b'\x4e\x00',          # Data Offset
      b'\x01',              # Setup Count
      b'\x00',              # Reserved
      b'\x0e\x00',          # subcommand: SESSION_SETUP
      b'\x00\x00',          # Byte Count
      b'\x0c\x00' + b'\x00' * 12
    ]

    return generate_smb_proto_payload(netbios, smb_header, trans2_request)



class SMBDoublePulsar(BaseHostPlugin):
    bugname = "DoublePulsar后门"
    bugrank = "紧急"

    def filter(self,host):
        return host.port == 445 or host.service == 'smb'

    def verify(self,host, user='',pwd='',timeout=10):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        try:
            buffersize = 1024
            ip = host.host
            # Send smb request based on socket.
            client.connect((ip, host.port))
            # SMB - Negotiate Protocol Request
            raw_proto = negotiate_proto_request()
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)
            # SMB - Session Setup AndX Request
            raw_proto = session_setup_andx_request()
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)
            netbios = tcp_response[:4]
            smb_header = tcp_response[4:36]   # SMB Header: 32 bytes
            smb = SMB_HEADER(smb_header)
            user_id = struct.pack('<H', smb.user_id)
            # parse native_os from Session Setup Andx Response
            session_setup_andx_response = tcp_response[36:]
            native_os = session_setup_andx_response[9:].split(b'\x00')[0]
            # SMB - Tree Connect AndX Request
            raw_proto = tree_connect_andx_request(ip, user_id)
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)
            netbios = tcp_response[:4]
            smb_header = tcp_response[4:36]   # SMB Header: 32 bytes
            smb = SMB_HEADER(smb_header)
            tree_id = struct.pack('<H', smb.tree_id)
            process_id = struct.pack('<H', smb.process_id)
            user_id = struct.pack('<H', smb.user_id)
            multiplex_id = struct.pack('<H', smb.multiplex_id)
            # SMB - PeekNamedPipe Request
            raw_proto = peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id)
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)
            netbios = tcp_response[:4]
            smb_header = tcp_response[4:36]
            smb = SMB_HEADER(smb_header)
            # nt_status = smb_header[5:9]
            nt_status = struct.pack('BBH', smb.error_class, smb.reserved1, smb.error_code)
            # 0xC0000205 - STATUS_INSUFF_SERVER_RESOURCES - vulnerable
            # 0xC0000008 - STATUS_INVALID_HANDLE
            # 0xC0000022 - STATUS_ACCESS_DENIED
            if nt_status == b'\x05\x02\x00\xc0':
                self.bugreq = "[+] [{}] is likely VULNERABLE to MS17-010! ({})".format(ip, native_os)
                # vulnerable to MS17-010, check for DoublePulsar infection
                raw_proto = trans2_request(tree_id, process_id, user_id, multiplex_id)
                client.send(raw_proto)
                tcp_response = client.recv(buffersize)
                netbios = tcp_response[:4]
                smb_header = tcp_response[4:36]
                smb = SMB_HEADER(smb_header)
                if smb.multiplex_id == 0x0051:
                  key = calculate_doublepulsar_xor_key(smb.signature)
                  self.bugreq = "Host is likely INFECTED with DoublePulsar! - XOR Key: {}".format(key)
                self.bugaddr = "%s:%s"%(ip,host.port)
                return True
            elif nt_status in (b'\x08\x00\x00\xc0', b'\x22\x00\x00\xc0'):
                print("[-] [{}] does NOT appear vulnerable".format(ip))
            else:
                print("[-] [{}] Unable to detect if this host is vulnerable".format(ip))
        except Exception as err:
            print("[-] [{}] Exception: {}".format(ip, err))
        finally:
            client.close()


class Ms17010(BaseHostPlugin):
    bugname = "MS17010 命令执行"
    bugrank = "紧急"

    def filter(self,host):
        return host.port == 445 or host.service == 'smb'

    def verify(self,host,user='',pwd='',timeout=10):
        negotiate_protocol_request = binascii.a2b_hex(
            "00000054ff534d42720000000018012800000000000000000000000000002f4b"
            "0000c55e003100024c414e4d414e312e3000024c4d312e325830303200024e54"
            "204c414e4d414e20312e3000024e54204c4d20302e313200")
        session_setup_request = binascii.a2b_hex(
            "00000063ff534d42730000000018012000000000000000000000000000002f4b"
            "0000c55e0dff000000dfff020001000000000000000000000000004000000026"
            "00002e0057696e646f7773203230303020323139350057696e646f7773203230"
            "303020352e3000")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host.host,int(host.port)))
            s.send(negotiate_protocol_request)
            s.recv(1024)
            s.send(session_setup_request)
            data = s.recv(1024)
            user_id = data[32:34]
            ip = host.host
            tree_connect_andx_request = "000000%xff534d42750000000018012000000000000000000000000000002f4b%sc55e04ff000000000001001a00005c5c%s5c49504324003f3f3f3f3f00" % ((58 + len(ip)), binascii.b2a_hex(user_id).decode(), binascii.b2a_hex(ip.encode()).decode())
            s.send(binascii.a2b_hex(tree_connect_andx_request))
            data = s.recv(1024)
            allid = data[28:36]
            payload = "0000004aff534d422500000000180128000000000000000000000000%s1000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00" % binascii.b2a_hex(allid).decode()
            s.send(binascii.a2b_hex(payload))
            data = s.recv(1024)
            if b"\x05\x02\x00\xc0" in data:
                self.bugaddr = "%s:%s"%(host.host,host.port)
                self.bugres = str(data)
                return True
        except Exception as e:
            print(e)
        finally:
            s.close()



