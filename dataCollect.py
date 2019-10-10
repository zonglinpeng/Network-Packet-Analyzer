#Author: Zonglin Peng

import pyshark
import numpy as np

print("=============Start Sniffing================")
rcvd_counter = 0
sent_counter = 0
rcvd_bytes = 0
sent_bytes = 0
prev_time = 0
addr_dict = {}
addr_counter = {}
first_ten_packet = []

print("<timestamp>\t<src addr>\t<dst addr>\t<src port>\t<dst port>\t<protocol>")

cap = pyshark.LiveCapture('eth1', bpf_filter='(tcp or udp) and ip')
cap.sniff(packet_count = 100)
my_addr = "192.168.12.100"

def print_conversation_header(pkt):
#for pkt in cap:	
	try:
		global prev_time
		global addr_dict
		global addr_counter
		timestam = pkt.sniff_timestamp
		protocol = pkt.transport_layer
		src_addr = pkt.ip.src
		src_port = pkt[pkt.transport_layer].srcport
		dst_addr = pkt.ip.dst
		dst_port = pkt[pkt.transport_layer].dstport
		pkg_leng = pkt.length
		
		if(dst_addr == my_addr):
			global rcvd_counter
			global rcvd_bytes
			for _ in pkt:
				rcvd_counter = rcvd_counter + 1
			rcvd_bytes += int(pkg_leng)
			port = dst_addr
			dst_addr = src_port
			src_port = port
		elif(src_addr == my_addr):
			global sent_counter
			global sent_bytes
			for _ in pkt:
				sent_counter = sent_counter + 1
			sent_bytes += int(pkg_leng)

		other_addr = dst_addr if src_addr == my_addr else src_addr
		index_addr = other_addr + protocol
		addr_counter[index_addr] = addr_counter.get(index_addr, 0) + 1
				
		if(addr_counter[index_addr] <= 10):
			data_list = addr_dict.get(index_addr, list()) # get
			# data_list.append(int(pkg_leng)) # set
			if(len(data_list) == 7):
				data_list[0] = data_list[0] + rcvd_counter
				data_list[1] = data_list[1] + sent_counter
				data_list[2] = data_list[2] + rcvd_bytes
				data_list[3] = data_list[3] + sent_bytes
				data_list[4] = src_port
				data_list[5] = dst_port
				data_list.append(pkg_leng)
			elif(len(data_list) == 0):
				data_list.append(rcvd_counter)
				data_list.append(sent_counter)
				data_list.append(rcvd_bytes)
				data_list.append(sent_bytes)
				data_list.append(src_port)
				data_list.append(dst_port)
				data_list.append(pkg_leng)
			addr_dict[index_addr] = data_list # put

		rcvd_counter = 0
		sent_counter = 0
		rcvd_bytes = 0
		sent_bytes = 0

		if(int(float(timestam)) - prev_time > 1):
			#print("<#packets sent>\t<#packets rcvd>\t<#bytes send>\t<#bytes rcvd>")
			#print(sent_counter, rcvd_counter, sent_bytes, rcvd_bytes, sep='\t|\t')
			print("___________________________________________________________________________")
			
			prev_time = int(float(timestam))
			X = np.load('dataset.npy')
			for lis in addr_dict:
				data = np.zeros(8)
				# the_list = np.asarray(addr_dict[lis])
				the_list = addr_dict[lis]
				data[0] = 0 # <=====

				data[1] = the_list[0]
				data[2] = the_list[1]
				data[3] = the_list[2]
				data[4] = the_list[3]
				data[5] = the_list[4]
				data[6] = the_list[5]
				protoc = lis[len(lis) - 3: len(lis)]
				data[7] = 0 if protoc == "TCP" else 1
				print("HERE")
				
				print(data)
				leng_list = the_list[6:len(leng_list)]
				print(leng_list)

				if( (len(leng_list) < 10)):
					np.pad(leng_list, (0, 10 - len(leng_list)), 'constant')
					print(leng_list)
				data = np.concatenate((data, np.asarray(leng_list)), axis=0)

				# print(data)

				X = np.vstack((X, data))
			np.save("dataset", X)
			addr_dict = {}
			addr_counter = {}
			
		#print (timestam, src_addr, dst_addr, src_port, dst_port, protocol, sep='\t')

	except AttributeError as e:
		pass
	except Exception as e:
		print(e)

#print("end")
#np.save("youtube", np.zeros(6))
cap.apply_on_packets(print_conversation_header, timeout = 1000)
