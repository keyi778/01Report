#!/usr/bin/env python3
import time
import warnings
import argparse
import os
import sys
from time import sleep
from time import strftime
import grpc
from scapy.all import Ether, Packet, BitField, raw
import ipaddress
from randomForest import predict_single_record
from LinearRegression import make_prediction

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [
        BitField('src_ip', 0, 32),
        BitField('dst_ip', 0, 32),
        BitField('tcp_fin', 0, 1),
        BitField('tcp_syn', 0, 1),
        BitField('tcp_rst', 0, 1),
        BitField('tcp_psh', 0, 1),
        BitField('tcp_ack', 0, 1),
        BitField('tcp_urg', 0, 1),
        BitField('tcp_cwe', 0, 1),
        BitField('tcp_ece', 0, 1),
        BitField('dst_port', 0, 16),
        BitField('additional_protocol', 0, 8),
        BitField('fwd_pkt_len_max', 0, 16),
        BitField('fwd_pkt_len_min', 0, 16),
        BitField('fwd_pkt_len_mean', 0, 16),
        BitField('fwd_pkt_len_std', 0, 16),
        BitField('bwd_pkt_len_max', 0, 16),
        BitField('bwd_pkt_len_min', 0, 16),
        BitField('bwd_pkt_len_mean', 0, 16),
        BitField('bwd_pkt_len_std', 0, 16),
        BitField('pad', 0, 8)
    ]

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print("%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            ))
def writeCloneSessionEntry(p4info_helper, sw, clone_session_id, cpu_port = 10):
    """
    Installs a clone session entry to a switch

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    :param clone_session_id: the session identifier
    :param cpu_port: the CPU port of the switch, default to 10
    """
    clone_entry = p4info_helper.buildCloneSessionEntry(clone_session_id,
                                                       [{"egress_port": cpu_port, "instance": 0}], 0)
    sw.WritePREEntry(clone_entry)

def writeTableRule(p4info_helper, sw, table_name, match_fields, action_name, action_params = None):
    """
    Installs a table rule to a switch

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    :param table_name: the match table name
    :param match_fields: match fields dictionary
    :param action_name: action name
    :param action_params: the parameters of the action, default to None
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        action_name=action_name,
        action_params=action_params)
    sw.WriteTableEntry(table_entry)
def writeIpv4ForwardRule(p4info_helper, sw, dst_ip_addr, forward_mac_addr, forward_port, dst_ip_length=32):
    writeTableRule(p4info_helper, sw,
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, dst_ip_length)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": forward_mac_addr,
            "port": forward_port
        }
    )
def writeIpv4ForwardRulea(p4info_helper, sw, dst_ip_addr, forward_mac_addr, forward_port, dst_ip_length=32):
    writeTableRule(p4info_helper, sw,
        table_name="MyIngress.ipv4_lpma",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, dst_ip_length)
        },
        action_name="MyIngress.ipv4_forwarda",
        action_params={
            "dstAddr": forward_mac_addr,
            "port": forward_port
        }
    )
def writeIpv4ForwardRuleb(p4info_helper, sw, dst_ip_addr, forward_mac_addr, forward_port, dst_ip_length=32):
    writeTableRule(p4info_helper, sw,
        table_name="MyIngress.ipv4_lpmb",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, dst_ip_length)
        },
        action_name="MyIngress.ipv4_forwardb",
        action_params={
            "dstAddr": forward_mac_addr,
            "port": forward_port
        }
    )
def writeIpv4ForwardRulec(p4info_helper, sw, dst_ip_addr, forward_mac_addr, forward_port, dst_ip_length=32):
    writeTableRule(p4info_helper, sw,
        table_name="MyIngress.ipv4_lpmc",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, dst_ip_length)
        },
        action_name="MyIngress.ipv4_forwardc",
        action_params={
            "dstAddr": forward_mac_addr,
            "port": forward_port
        }
    )
def writeIpv4ForwardRuled(p4info_helper, sw, dst_ip_addr, forward_mac_addr, forward_port, dst_ip_length=32):
    writeTableRule(p4info_helper, sw,
        table_name="MyIngress.ipv4_lpmd",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, dst_ip_length)
        },
        action_name="MyIngress.ipv4_forwardd",
        action_params={
            "dstAddr": forward_mac_addr,
            "port": forward_port
        }
    )


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('%s: ' % table_name, end=' ')
            for m in entry.match:
                print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print('->', action_name, end=' ')
            for p in action.params:
                print(p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                print('%r' % p.value, end=' ')
            print()

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        #print("please input the length of ecn: ", end="")
        #ecn_length = int(input())

        # Create a switch connection object for s1, s2 and s3;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.9:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.9:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program on s2")


        # Install necessary ipv4 forward rules
         # s1 rules
        writeIpv4ForwardRulea(p4info_helper, s1,
            dst_ip_addr="127.0.0.5",
            forward_mac_addr="08:00:00:00:01:05",
            forward_port=5)
        writeIpv4ForwardRuleb(p4info_helper, s1,
            dst_ip_addr="127.0.0.6",
            forward_mac_addr="08:00:00:00:01:16",
            forward_port=5)
        writeIpv4ForwardRulec(p4info_helper, s1,
            dst_ip_addr="127.0.0.7",
            forward_mac_addr="08:00:00:00:02:07",
            forward_port=5)
        writeIpv4ForwardRuled(p4info_helper, s1,
            dst_ip_addr="127.0.0.8",
            forward_mac_addr="08:00:00:00:03:08",
            forward_port=5)
        #writeIpv4ForwardRule(p4info_helper, s1,
        #    dst_ip_addr="127.0.0.1",
        #    forward_mac_addr="08:00:00:00:01:01",
        #    forward_port=1)
        #writeIpv4ForwardRule(p4info_helper, s1,
        #    dst_ip_addr="127.0.0.2",
        #    forward_mac_addr="08:00:00:00:01:12",
        #    forward_port=2)
        #writeIpv4ForwardRule(p4info_helper, s1,
        #    dst_ip_addr="127.0.0.3",
        #    forward_mac_addr="08:00:00:00:02:03",
        #    forward_port=3)
        #writeIpv4ForwardRule(p4info_helper, s1,
        #    dst_ip_addr="127.0.0.4",
        #    forward_mac_addr="08:00:00:00:03:04",
        #    forward_port=4)
        # s2 rules
        writeIpv4ForwardRule(p4info_helper, s2,
            dst_ip_addr="127.0.0.5",
            forward_mac_addr="08:00:00:00:01:05",
            forward_port=1)
        writeIpv4ForwardRule(p4info_helper, s2,
            dst_ip_addr="127.0.0.6",
            forward_mac_addr="08:00:00:00:01:16",
            forward_port=2)
        writeIpv4ForwardRule(p4info_helper, s2,
            dst_ip_addr="127.0.0.7",
            forward_mac_addr="08:00:00:00:02:07",
            forward_port=3)
        writeIpv4ForwardRule(p4info_helper, s2,
            dst_ip_addr="127.0.0.8",
            forward_mac_addr="08:00:00:00:03:08",
            forward_port=4)
        #writeIpv4ForwardRule(p4info_helper, s2,
        #    dst_ip_addr="127.0.0.1",
        #    forward_mac_addr="08:00:00:00:01:01",
        #    forward_port=5)
        #writeIpv4ForwardRule(p4info_helper, s2,
        #    dst_ip_addr="127.0.0.2",
        #    forward_mac_addr="08:00:00:00:01:12",
        #    forward_port=5)
        #writeIpv4ForwardRule(p4info_helper, s2,
        #    dst_ip_addr="127.0.0.3",
        #    forward_mac_addr="08:00:00:00:02:03",
        #    forward_port=5)
        #writeIpv4ForwardRule(p4info_helper, s2,
        #    dst_ip_addr="127.0.0.4",
        #    forward_mac_addr="08:00:00:00:03:04",
        #    forward_port=5)




        # Install clone session entry
        writeCloneSessionEntry(p4info_helper, s1, 100)
        writeCloneSessionEntry(p4info_helper, s2, 100)
        print("Installed clone session entries")

        print("Start lessoning")
        last_time = time.time()
        counter = 0
        warnings.filterwarnings("ignore")
        while True:

            for msg in s2.stream_msg_resp:
                # Only process PacketIn
                if (msg.WhichOneof('update') == 'packet'):
                    packet = Ether(raw(msg.packet.payload))
                    # Parse CPU header, notify user about the congestion
                    if packet.type == 0x2333:
                        #predict_single_record()
                        cpu_header = CpuHeader(bytes(packet.load))
                        result = predict_single_record(cpu_header.dst_port, cpu_header.additional_protocol, cpu_header.fwd_pkt_len_max, cpu_header.fwd_pkt_len_min, cpu_header.fwd_pkt_len_mean, cpu_header.fwd_pkt_len_std, cpu_header.bwd_pkt_len_max, cpu_header.bwd_pkt_len_min, cpu_header.bwd_pkt_len_mean, cpu_header.bwd_pkt_len_std, cpu_header.tcp_fin, cpu_header.tcp_syn, cpu_header.tcp_rst, cpu_header.tcp_psh, cpu_header.tcp_ack, cpu_header.tcp_urg, cpu_header.tcp_cwe, cpu_header.tcp_ece)
                        counter = counter + 1
                        current_time = time.time()
                        if current_time - last_time >= 10:
                            future_10s_packets = make_prediction(counter)
                            print("Counter value before reset:", counter)
                            print("The next 10s packets will be:", future_10s_packets)
                            counter = 0
                            last_time = current_time
                        print(f"packet num:{counter}within 10s")
                        print(f"Source IP Address:{str(ipaddress.IPv4Address(cpu_header.src_ip))}")
                        print(f"Destination IP address:{str(ipaddress.IPv4Address(cpu_header.dst_ip))}")
                        print(f"dst_port:{cpu_header.dst_port}")
                        print(f"protocol:{cpu_header.additional_protocol}")
                        print(f"fwd_pkt_len_max:{cpu_header.fwd_pkt_len_max}")
                        print(f"fwd_pkt_len_min:{cpu_header.fwd_pkt_len_min}")
                        print(f"fwd_pkt_len_mean:{cpu_header.fwd_pkt_len_mean}")
                        print(f"fwd_pkt_len_std:{cpu_header.fwd_pkt_len_std}")
                        print(f"bwd_pkt_len_max:{cpu_header.bwd_pkt_len_max}")
                        print(f"bwd_pkt_len_min:{cpu_header.bwd_pkt_len_min}")
                        print(f"bwd_pkt_len_mean:{cpu_header.bwd_pkt_len_mean}")
                        print(f"bwd_pkt_len_std:{cpu_header.bwd_pkt_len_std}")
                        print(f"tcp_fin:{cpu_header.tcp_fin}")
                        print(f"tcp_syn:{cpu_header.tcp_syn}")
                        print(f"tcp_rst:{cpu_header.tcp_rst}")
                        print(f"tcp_psh:{cpu_header.tcp_psh}")
                        print(f"tcp_ack:{cpu_header.tcp_ack}")
                        print(f"tcp_urg:{cpu_header.tcp_urg}")
                        print(f"tcp_cwe:{cpu_header.tcp_cwe}")
                        print(f"tcp_ece:{cpu_header.tcp_ece}")
                        print("predict package type is:" + result)
            #for msg in s2.stream_msg_resp:
            #    # Only process PacketIn
            #    if (msg.WhichOneof('update') == 'packet'):
            #        packet = Ether(raw(msg.packet.payload))
            #        # Parse CPU header, notify user about the congestion
            #        if packet.type == 0x2333:
            #            cpu_header = CpuHeader(bytes(packet.load))
            #            print("S2���淢������·ӵ���������Ƿ���ӵ��ʱS2ת�������ݰ��������Ϣ")
            #            print(f"ԴIP��ַ��{str(ipaddress.IPv4Address(cpu_header.src_ip))}")
            #            print(f"Ŀ��IP��ַ��{str(ipaddress.IPv4Address(cpu_header.dst_ip))}")
            #            print(f"���˿ڣ�{cpu_header.tcp_fin}")
            #            print(f"���˿ڣ�{cpu_header.tcp_syn}")

            sleep(1)

        # Read table entries from s1, s2 and s3
        # readTableRules(p4info_helper, s1)
        # readTableRules(p4info_helper, s2)
        # readTableRules(p4info_helper, s3)
    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/ecn.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/ecn.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
