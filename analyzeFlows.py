#Author: Zonglin Peng

import pyshark
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.externals import joblib
import sys

print("=============Start Sniffing================")
rcvd_counter = 0
sent_counter = 0
rcvd_bytes = 0
sent_bytes = 0
prev_time = 0
burst_cnter = 0
src_port = 0
dst_port = 0
print_dict = {}
addr_dict = {}
addr_counter = {}
ports = []
my_addr = "192.168.12.100"
clf = joblib.load('svm.pkl')

print("<timestamp><src addr><dst addr><src port><dst port><protocol><#packets sent><#packets rcvd><#bytes send><#bytes rcvd><label>")

cap = pyshark.LiveCapture('eth1', bpf_filter='(tcp or udp) and ip')
cap.sniff(packet_count = 100)

def print_conversation_header(pkt):
# for pkt in cap:	
	try:
		global prev_time
		global addr_dict
		global addr_counter
		global src_port
		global dst_port
		global ports
		global burst_cnter
		timestam = pkt.sniff_timestamp
		protocol = pkt.transport_layer
		src_addr = pkt.ip.src
		dst_addr = pkt.ip.dst
		pkg_leng = pkt.length
				
		# if pkt[pkt.transport_layer].srcport != src_port:
		# 	src_port = pkt[pkt.transport_layer].srcport
		# 	ports.append(src_port)
		# if pkt[pkt.transport_layer].dstport != dst_port:
		# 	dst_port = pkt[pkt.transport_layer].dstport
		# 	ports.append(dst_port)

		# packet info
		if(dst_addr == my_addr):
			global rcvd_counter
			global rcvd_bytes
			for _ in pkt:
				rcvd_counter = rcvd_counter + 1
			rcvd_bytes += int(pkg_leng)
		elif(src_addr == my_addr):
			global sent_counter
			global sent_bytes
			for _ in pkt:
				sent_counter = sent_counter + 1
			sent_bytes += int(pkg_leng)

		# smv info
		other_addr = dst_addr if src_addr == my_addr else src_addr
		index_addr = other_addr + protocol
		addr_counter[index_addr] = addr_counter.get(index_addr, 0) + 1


		if(addr_counter[index_addr] < 10):
			data_list = addr_dict.get(index_addr, list()) # get
			if(len(data_list) == 6):
				data_list[0] = data_list[0] + rcvd_counter
				data_list[1] = data_list[1] + sent_counter
				data_list[2] = data_list[2] + rcvd_bytes
				data_list[3] = data_list[3] + sent_bytes
				data_list[4] = src_port
				data_list[5] = dst_port
			elif(len(data_list) == 0):
				data_list.append(rcvd_counter)
				data_list.append(sent_counter)
				data_list.append(rcvd_bytes)
				data_list.append(sent_bytes)
				data_list.append(src_port)
				data_list.append(dst_port)
			addr_dict[index_addr] = data_list # put


		#================== BURST =======================
		if(int(float(timestam)) - prev_time > 1):
			burst_cnter=burst_cnter+1
			print("____________________ Burst: ", burst_cnter, "________________________")

			for lis in addr_dict:
				data = np.zeros(7)
				# the_list = np.asarray(addr_dict[lis])
				the_list = addr_dict[lis]

				data[0] = the_list[0]
				data[1] = the_list[1]
				data[2] = the_list[2]
				data[3] = the_list[3]
				data[4] = the_list[4]
				data[5] = the_list[5]
				protoc = lis[len(lis) - 3: len(lis)]
				data[6] = 0 if protoc == "TCP" else 1
				addr = lis[: len(lis) - 3]
				label = ""
				
				data = np.expand_dims(data, axis=0)
				result = clf.predict(data)
				print(result, data[0, 0],data[0, 1],data[0, 2],data[0, 3],data[0, 4],data[0, 5],data[0, 6],sep="\t")

				if result ==  0:	
					label = "Youtube App"
				elif result == 1:
					label = "Wikipedia Web"
				elif result == 2: 
					label = "Fruit Ninjia"
				elif result == 3: 
					label = "Weather Channel"
				elif result == 4: 
					label = "Google News"
				else: 
					label = "Uknown Source"

				# Info of a flow
				print(float(timestam), my_addr, addr, the_list[4], the_list[5], the_list[0], the_list[1], the_list[2], the_list[3], label, sep='\t')
				# print(float(timestam), addr, my_addr, dst_port, src_port, protoc, abs(rcvd_counter-len(the_list)), abs(rcvd_bytes-sum(the_list)), abs(sent_counter-len(the_list)), abs(sent_bytes-sum(the_list)), label, sep='\t')
			
			prev_time = int(float(timestam))
			rcvd_counter = 0
			sent_counter = 0
			rcvd_bytes = 0
			sent_bytes = 0
			addr_dict = {}
			addr_counter = {}
			ports = []

	except AttributeError as e:
		pass
	except Exception as e:
		print(e)

cap.apply_on_packets(print_conversation_header, timeout = 1000)
