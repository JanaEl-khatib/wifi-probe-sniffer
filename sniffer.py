from scapy.all import *

# Empty list to remeber the Wi-Fi names
probeReqs = {}

# sniffProves Function
def sniffProves(p):
	# Asking for Wi-Fi
	if p.haslayer(Dot11ProbeReq):
		# Open it up and find the Wi-Fi name that is being requested
		netName = p.getlayer(Dot11ProbeReq).info.decode(errors='ignore')
		# Has the Wi-Fi been seen before?
		if netName in probeReqs:
			probeReqs[netName] += 1
		else:
			probeReqs[netName] = 1
			# Print it out
			print('[+] Detected New Probe Request: ' + netName)
			# Save detected networks to a .txt file
			with open("probe_requests.txt", "a") as file:
				file.write(netName + "\n")
packets = rdpcap("dot11-sample.pcap")

# Goes through each note and runs the function
for pkt in packets:
	sniffProves(pkt)

# Print Summary
print("\n Summary of the Probe Requests:")
for net, count in probeReqs.items():
	print(f"  - {net}: seen {count} time(s)")
