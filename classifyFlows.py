#Author: Zonglin Peng

import pyshark
import numpy as np
from sklearn.externals import joblib

print("=============Start Sniffing================")
rcvd_counter = 0
sent_counter = 0
rcvd_bytes = 0
sent_bytes = 0
prev_time = 0
burst_cnter = 0
print_dict = {}
addr_dict = {}
addr_counter = {}
ports = []
my_addr = "192.168.12.100"
clf = joblib.load('svm1.pkl')

print("<timestamp><src addr><dst addr><src port><dst port><protocol><#packets sent><#packets rcvd><#bytes send><#bytes rcvd><label>")

# cap = pyshark.LiveCapture('eth1', bpf_filter='(tcp or udp) and ip')
# cap.sniff(packet_count = 100)
cap = pyshark.FileCapture('mytrace.pcap', display_filter='(tcp or udp) and ip')


# def print_conversation_header(pkt):
for pkt in cap:	
	try:
		# global prev_time
		# global addr_dict
		# global addr_counter
		timestam = pkt.sniff_timestamp
		protocol = pkt.transport_layer
		src_addr = pkt.ip.src
		src_port = pkt[pkt.transport_layer].srcport
		dst_addr = pkt.ip.dst
		dst_port = pkt[pkt.transport_layer].dstport
		pkg_leng = pkt.length
		
		# smv info
		other_addr = dst_addr if src_addr == my_addr else src_addr
		index_addr = other_addr + protocol
		addr_counter[index_addr] = addr_counter.get(index_addr, 0) + 1
		ports.append(src_port)
		ports.append(dst_port)

		if(addr_counter[index_addr] < 10):
			data_list = addr_dict.get(index_addr, list()) # get
			data_list.append(int(pkg_leng)) # set
			addr_dict[index_addr] = data_list # put
		
		# packet info
		if(dst_addr == my_addr):
			# global rcvd_counter
			# global rcvd_bytes
			for _ in pkt:
				rcvd_counter = rcvd_counter + 1
			rcvd_bytes += int(pkg_leng)
		elif(src_addr == my_addr):
			# global sent_counter
			# global sent_bytes
			for _ in pkt:
				sent_counter = sent_counter + 1
			sent_bytes += int(pkg_leng)
		
		# store print info
		# index_addr = src_addr + dst_addr + src_port + dst_port + protocol
		# info_list = print_dict.get(index_addr, [0,0,0,0,0]) # get
		# info_list[0] = timestam
		# info_list[1] += sent_counter
		# info_list[2] += sent_bytes
		# info_list[3] += rcvd_counter
		# info_list[4] += sent_bytes
		# print_dict[index_addr] = info_list # put

#================== BURST =======================
		if(int(float(timestam)) - prev_time > 1):
			print("____________________ Burst: ", burst_cnter+1, "________________________")

			for lis in addr_dict:
				data = np.zeros(5)
				the_list = np.asarray(addr_dict[lis])
				data[0] = len(the_list)
				data[1] = sum(the_list)
				data[2] = np.var(the_list)
				data[3] = np.mean(the_list)
				protoc = lis[len(lis) - 3: len(lis)]
				addr = lis[: len(lis) - 3]
				data[4] = 0 if protoc == "TCP" else 1
				# print(data[0],data[1],data[2],data[3],data[4],data[5],sep="\t")
				highest_score = 0
				total_score = 1
				result = 10
				label = ""
				for i in range(4):
					score = clf.score(data, np.array(i))
					total_score -= score
					if highest_score < score:
						highest_score = score
						result = i
				if highest_score < total_score: # unknown
					result = 10

				if result ==  0:	
					label = "Youtube App"
				elif result == 1:
					label = "Wikipedia Web"
				elif result == 2: 
					label = "Fruit Ninjia"
				elif result == 3: 
					label = "Weather Chanel"
				elif result == 4: 
					label = "Google News"
				elif result == 10: 
					label = "Uknown Source"
				
				# for info in info_list:
				# 	if 

				print(int(timestam), my_addr, addr, protoc, len(the_list), sum(the_list), label, sep='\t')

			# print("<#packets sent>\t<#packets rcvd>\t<#bytes send>\t<#bytes rcvd>")
			# print(sent_counter, rcvd_counter, sent_bytes, rcvd_bytes, sep='\t|\t')
			
			prev_time = int(float(timestam))
			rcvd_counter = 0
			sent_counter = 0
			rcvd_bytes = 0
			sent_bytes = 0
			addr_dict = {}
			addr_counter = {}
			
		#print (timestam, src_addr, dst_addr, src_port, dst_port, protocol, sep='\t')

	except AttributeError as e:
		pass
	except Exception as e:
		print(e)

#print("end")
#np.save("youtube", np.zeros(6))
# cap.apply_on_packets(print_conversation_header, timeout = 1000)
