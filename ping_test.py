#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
ping_test.py <ip_to_ping>

Script Python2:
  - Chạy ping -c 10 <ip_to_ping> với timeout 1 giây mỗi gói
  - Song song chạy tcpdump -i h1-eth0 icmp and host <ip_to_ping>
  - Ghi logs vào file /tmp/tcpdump_<pid>.txt
  - Phân tích request/reply, tính RTT, in kết quả giống ping
  - Hiển thị request_time và reply_time để dễ tính toán
"""

import sys
import subprocess
import os
import signal
import time
import re

def main():
    if len(sys.argv) < 2:
        print("Usage: python ping_test.py <destination_ip>")
        sys.exit(1)

    dest_ip = sys.argv[1]
    count = 10  # Số gói ping

    # Đặt tên file tạm
    pid = os.getpid()
    dump_file = "/tmp/tcpdump_%d.txt" % pid

    # 1) Chạy tcpdump
    iface = sorted(i for i in os.listdir('/sys/class/net') if i != 'lo')[0]
    tcpdump_cmd = [
        "tcpdump", "-i", iface,
        "icmp and host %s" % dest_ip,
        "-n", "-tt",
        "-l"
    ]

    dump_fh = open(dump_file, "w")
    tcpdump_proc = subprocess.Popen(tcpdump_cmd, stdout=dump_fh, stderr=subprocess.PIPE)

    # Cho tcpdump khởi động
    time.sleep(1)

    # 2) Chạy ping -c 10 với timeout 1 giây mỗi gói
    ping_cmd = ["ping", dest_ip, "-c", str(count), "-W", "1"]
    ping_proc = subprocess.Popen(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Đợi ping xong
    out, err = ping_proc.communicate()
    ping_ret = ping_proc.returncode

    # 3) Dừng tcpdump
    time.sleep(1)
    tcpdump_proc.terminate()
    tcpdump_proc.wait()
    dump_fh.close()

    # 4) Đọc file /tmp/tcpdump_<pid>.txt, parse request/reply
    request_time = {}
    reply_time = {}
    seqs = set()

    with open(dump_file, "r") as fh:
        for line in fh:
            line = line.strip()
            m_ts = re.match(r"^(\d+\.\d+)\s+IP\s+(\S+)\s+>\s+(\S+):\s+(ICMP\s+echo\s+\w+),.*seq\s+(\d+)", line)
            if m_ts:
                tstamp = float(m_ts.group(1))
                src = m_ts.group(2)
                dst = m_ts.group(3)
                icmptype = m_ts.group(4)
                seq_str = m_ts.group(5)
                seq_num = int(seq_str)
                seqs.add(seq_num)

                if "request" in icmptype:
                    request_time[seq_num] = tstamp
                elif "reply" in icmptype:
                    reply_time[seq_num] = tstamp

    # 5) Hiển thị request_time và reply_time để phân tích
    print("\n--- Request Times ---")
    for seq, t in request_time.items():
        print("seq=%d: %.6f" % (seq, t))
    print("\n--- Reply Times ---")
    for seq, t in reply_time.items():
        print("seq=%d: %.6f" % (seq, t))

    # 6) Tính toán & In kết quả mô phỏng lệnh ping
    transmitted = count
    received = 0
    rtt_list = []

    print("\nPING %s (%s) 56(84) bytes of data." % (dest_ip, dest_ip))

    for i in range(1, count+1):
        if i in request_time and i in reply_time:
            received += 1
            rtt_ms = (reply_time[i] - request_time[i]) * 1000.0
            rtt_list.append(rtt_ms)
            print("64 bytes from %s: icmp_seq=%d ttl=64 time=%.3f ms" % (dest_ip, i, rtt_ms))
        else:
            reason = "No reply" if i in request_time else "No request"
            print("Request timeout for icmp_seq=%d (%s)" % (i, reason))

    print("\n--- %s ping statistics ---" % dest_ip)
    loss = (transmitted - received) * 100.0 / transmitted
    print("%d packets transmitted, %d received, %.0f%% packet loss" % (transmitted, received, loss))

    if rtt_list:
        rtt_min = min(rtt_list)
        rtt_max = max(rtt_list)
        rtt_avg = sum(rtt_list)/len(rtt_list)
        import math
        variance = sum((x - rtt_avg)**2 for x in rtt_list)/len(rtt_list)
        rtt_std = math.sqrt(variance)
        print("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms" % (rtt_min, rtt_avg, rtt_max, rtt_std))
    else:
        print("rtt min/avg/max/mdev = 0/0/0/0 ms")

if __name__=="__main__":
    main()
