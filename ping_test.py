#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
ping_test.py <ip_to_ping>

Script Python2:
  - Chạy ping -c 5 <ip_to_ping>
  - Song song chạy tcpdump -i h1-eth0 icmp and host <ip_to_ping>
  - Ghi logs vào file /tmp/tcpdump_<pid>.txt
  - Phân tích request/reply, tính RTT, in kết quả giống ping
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
    count = 5  # Số gói ping

    # Đặt tên file tạm
    pid = os.getpid()
    dump_file = "/tmp/tcpdump_%d.txt" % pid

    # 1) Chạy tcpdump
    # -n: không resolve name
    # -t: bỏ timestamp tcpdump (hoặc -tt -l cũng được)
    # -l: line-buffered
    # Giới hạn filter: icmp and host dest_ip
    tcpdump_cmd = [
        "tcpdump", "-i", "h1-eth0",
        "icmp and host %s" % dest_ip,
        "-n", "-tt",
        "-l"
    ]

    dump_fh = open(dump_file, "w")
    tcpdump_proc = subprocess.Popen(tcpdump_cmd, stdout=dump_fh, stderr=subprocess.PIPE)

    # Cho tcpdump khởi động 1 chút
    time.sleep(1)

    # 2) Chạy ping -c 5
    ping_cmd = ["ping", dest_ip, "-c", str(count)]
    ping_proc = subprocess.Popen(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Đợi ping xong
    out, err = ping_proc.communicate()
    ping_ret = ping_proc.returncode

    # 3) Dừng tcpdump
    # Cách đơn giản: gửi signal TERM
    tcpdump_proc.terminate()
    tcpdump_proc.wait()
    dump_fh.close()

    # 4) Đọc file /tmp/tcpdump_<pid>.txt, parse request/reply
    #    Mẫu line: "1684003278.123456 IP 10.0.0.1 > 10.0.1.1: ICMP echo request, id 12345, seq 1, length 64"
    #    Hoặc     "1684003278.125678 IP 10.0.1.1 > 10.0.0.1: ICMP echo reply, id 12345, seq 1, length 64"

    request_time = {}
    reply_time = {}
    seqs = set()

    with open(dump_file, "r") as fh:
        for line in fh:
            line=line.strip()
            # Tách timestamp
            m_ts = re.match(r"^(\d+\.\d+)\s+IP\s+(\S+)\s+>\s+(\S+):\s+(ICMP\s+echo\s+\w+),.*seq\s+(\d+)", line)
            if m_ts:
                tstamp = float(m_ts.group(1))
                src = m_ts.group(2)
                dst = m_ts.group(3)
                icmptype = m_ts.group(4)  # "ICMP echo request" or "ICMP echo reply"
                seq_str = m_ts.group(5)
                seq_num = int(seq_str)
                seqs.add(seq_num)

                if "request" in icmptype:
                    request_time[seq_num] = tstamp
                elif "reply" in icmptype:
                    reply_time[seq_num] = tstamp

    # 5) Tính toán & In kết quả mô phỏng lệnh ping
    transmitted = count
    received = 0
    rtt_list = []

    print("PING %s (%s) 56(84) bytes of data." % (dest_ip, dest_ip))

    for i in range(1, count+1):
        if i in request_time and i in reply_time:
            received += 1
            # Tính RTT (ms)
            rtt_ms = (reply_time[i] - request_time[i]) * 1000.0
            rtt_list.append(rtt_ms)
            print("64 bytes from %s: icmp_seq=%d ttl=64 time=%.3f ms" % (dest_ip, i, rtt_ms))
        else:
            print("Request timeout for icmp_seq=%d" % i)

    print("")
    print("--- %s ping statistics ---" % dest_ip)
    loss = (transmitted - received) * 100.0 / transmitted
    print("%d packets transmitted, %d received, %.0f%% packet loss" % (transmitted, received, loss))

    if rtt_list:
        rtt_min = min(rtt_list)
        rtt_max = max(rtt_list)
        rtt_avg = sum(rtt_list)/len(rtt_list)
        # Tạm tính mdev = std dev
        import math
        variance = sum((x - rtt_avg)**2 for x in rtt_list)/len(rtt_list)
        rtt_std = math.sqrt(variance)
        print("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms" % (rtt_min, rtt_avg, rtt_max, rtt_std))
    else:
        print("rtt min/avg/max/mdev = 0/0/0/0 ms")

if __name__=="__main__":
    main()
