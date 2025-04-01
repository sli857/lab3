package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.nio.ByteBuffer;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;

public class Router extends Device
{	
	private RouteTable forwardingTable;
	private ArpCache addressTable;

	private boolean ripEnabled = false;
	private RIPv2 ripDatabase;
	private long ripLastUpdateTimestamp;
	private IPv4 cachedIpPacket;
	private Ethernet cachedEthernetFrame;
	private Iface cachedInterface;
	
	public Router(String hostname, DumpFile packetLog)
	{
		super(hostname, packetLog);
		this.forwardingTable = new RouteTable();
		this.addressTable = new ArpCache();
	}
	
	public RouteTable getRouteTable()
	{ 
		return this.forwardingTable; 
	}
	
	public void loadRouteTable(String configFile)
	{
		if (!forwardingTable.load(configFile, this))
		{
			System.err.println("Failed to initialize routing table from " + configFile);
			System.exit(1);
		}
		
		System.out.println("Static route table loaded successfully");
		System.out.println("-------------------------------------------------");
		System.out.print(this.forwardingTable.toString());
		System.out.println("-------------------------------------------------");
	}

	public void startRIPTable()
	{
		System.out.println("Initializing RIP protocol...");

		this.ripEnabled = true;
		this.ripDatabase = new RIPv2();

		// Add directly connected networks
		for (Iface networkInterface : this.interfaces.values()) {
			int network = networkInterface.getIpAddress() & networkInterface.getSubnetMask();
			RIPv2Entry directEntry = new RIPv2Entry(network, networkInterface.getSubnetMask(), 0, System.currentTimeMillis());
			this.ripDatabase.addEntry(directEntry);
		}

		// Broadcast RIP request
		broadcastRipMessage(RIPv2.COMMAND_REQUEST);

		// Initialize timer
		this.ripLastUpdateTimestamp = System.currentTimeMillis();
		
		System.out.println("RIP protocol initialized");
		System.out.println("-------------------------------------------------");
		System.out.print(this.ripDatabase.toString());
		System.out.println("-------------------------------------------------");
	}
	
	public void loadArpCache(String cacheFile)
	{
		if (!addressTable.load(cacheFile))
		{
			System.err.println("Failed to initialize ARP cache from " + cacheFile);
			System.exit(1);
		}
		
		System.out.println("Static ARP cache loaded successfully");
		System.out.println("----------------------------------");
		System.out.print(this.addressTable.toString());
		System.out.println("----------------------------------");
	}

	public void handlePacket(Ethernet etherPacket, Iface incomingIface)
	{
		System.out.println("→ Received: " + etherPacket.toString().replace("\n", "\n\t"));
		
		// Only handle IPv4 packets
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			System.out.println("Dropped: Not an IPv4 packet");
			return;
		}

		// Process IPv4 packet
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();

		// Validate checksum
		if (!validateChecksum(ipPacket)) {
			System.out.println("Dropped: Invalid checksum");
			return;
		}

		// Update TTL
		ipPacket.setTtl((byte)(ipPacket.getTtl() - 1));
		if (ipPacket.getTtl() == 0) {
			System.out.println("Dropped: TTL expired");
			return;
		}

		// Process RIP packet if enabled
		if (ripEnabled) {
			cachedEthernetFrame = etherPacket;
			cachedIpPacket = ipPacket;
			cachedInterface = incomingIface;

			if (processRipPacket()) {
				System.out.println("RIP packet processed");
				clearCachedPackets();
				return;
			}
			clearCachedPackets();
		}

		// Recalculate checksum
		ipPacket.resetChecksum();
		ipPacket.serialize();

		// Don't forward packets destined for router interfaces
		for (Iface routerIface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == routerIface.getIpAddress()) {
				System.out.println("Dropped: Packet addressed to router");
				return;
			}
		}

		// Find outgoing interface
		Iface outgoingIface;
		if (ripEnabled) {
			outgoingIface = findRouteInRipTable(ipPacket.getDestinationAddress());
		} else {
			RouteEntry route = this.forwardingTable.lookup(ipPacket.getDestinationAddress());
			outgoingIface = (route != null) ? route.getInterface() : null;
		}

		if (outgoingIface == null) {
			System.out.println("Dropped: No route to destination");
			return;
		}

		// Find next hop MAC address
		ArpEntry nextHop = this.addressTable.lookup(ipPacket.getDestinationAddress());
		if (nextHop == null) {
			System.out.println("Dropped: Destination MAC not found in ARP cache");
			return;
		}

		// Update Ethernet header
		etherPacket.setDestinationMACAddress(nextHop.getMac().toBytes());
		etherPacket.setSourceMACAddress(outgoingIface.getMacAddress().toBytes());
		etherPacket.setPayload(ipPacket);

		// Forward packet
		System.out.println("Forwarding packet to next hop");
		boolean success = sendPacket(etherPacket, outgoingIface);
		System.out.println(success ? "Packet forwarded successfully" : "Failed to forward packet");
	}

	private boolean validateChecksum(IPv4 ipPacket)
	{
		short originalChecksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		ipPacket.serialize();
		return ipPacket.getChecksum() == originalChecksum;
	}

	private void clearCachedPackets() {
		this.cachedEthernetFrame = null;
		this.cachedIpPacket = null;
		this.cachedInterface = null;
	}

	public Iface findRouteInRipTable(int destinationIp)
	{
		if (this.ripDatabase.getEntries().isEmpty() || destinationIp == 0) {
			return null;
		}
			
		int longestMatch = 0;
		RIPv2Entry bestEntry = null;
		
		for (RIPv2Entry entry : this.ripDatabase.getEntries()) {
			int tableNetworkAddr = entry.getAddress() & entry.getSubnetMask();
			int destNetworkAddr = destinationIp & entry.getSubnetMask();
			
			int[] tableBytes = extractIpBytes(tableNetworkAddr);
			int[] destBytes = extractIpBytes(destNetworkAddr);
			
			int matchDepth = compareNetworkBytes(tableBytes, destBytes);
			if (matchDepth > longestMatch) {
				longestMatch = matchDepth;
				bestEntry = entry;
			}
		}

		if (bestEntry == null || bestEntry.getMetric() == 16) {
			return null;
		}
		
		if (bestEntry.getNextHopAddress() == 0) {
			// Direct connection
			for (Iface iface : this.interfaces.values()) {
				if ((iface.getIpAddress() & iface.getSubnetMask()) == bestEntry.getAddress()) {
					return iface;
				}
			}
		} else {
			// Route via next hop
			for (Iface iface : this.interfaces.values()) {
				if (iface.getIpAddress() == bestEntry.getNextHopAddress()) {
					return iface;
				}
			}
		}
		
		return null;
	}
	
	private int[] extractIpBytes(int ipAddress) {
		int[] bytes = new int[4];
		bytes[0] = (ipAddress >> 24) & 0xFF;
		bytes[1] = (ipAddress >> 16) & 0xFF;
		bytes[2] = (ipAddress >> 8) & 0xFF;
		bytes[3] = ipAddress & 0xFF;
		return bytes;
	}
	
	private int compareNetworkBytes(int[] addr1, int[] addr2) {
		for (int i = 0; i < 4; i++) {
			if (addr1[i] != addr2[i]) {
				return i;
			}
		}
		return 4;
	}

	public boolean processRipPacket()
	{
		System.out.println("Checking if packet is RIP message");

		if (!(cachedIpPacket.getPayload() instanceof UDP)) {
			return false;
		}

		UDP udpPacket = (UDP) cachedIpPacket.getPayload();
		if (udpPacket.getDestinationPort() != UDP.RIP_PORT) {
			return false;
		}
		
		if (!(udpPacket.getPayload() instanceof RIPv2)) {
			return false;
		}

		RIPv2 ripPacket = (RIPv2) udpPacket.getPayload();
		
		if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {
			System.out.println("Processing RIP request");
			processRipUpdate(true);
		} else if (ripPacket.getCommand() == RIPv2.COMMAND_RESPONSE) {
			System.out.println("Processing RIP response");
			processRipUpdate(false);
		} else {
			System.out.println("Invalid RIP command");
		}
		
		return true;
	}

	private void processRipUpdate(boolean needsResponse)
	{
		UDP udpData = (UDP) cachedIpPacket.getPayload();  
		RIPv2 receivedRipData = (RIPv2) udpData.getPayload();
		boolean tableModified = false;

		for (RIPv2Entry entry : receivedRipData.getEntries()) {
			if (updateRipRoutingTable(entry)) {
				tableModified = true;
			}
    	}

		if (tableModified) {
			broadcastRipMessage(RIPv2.COMMAND_RESPONSE); 
		} else if (needsResponse) {
			sendTargetedRipResponse(); 
		}
	}

	public void checkLastRIPTime()
	{	
		boolean tableUpdated = pruneExpiredEntries();

		if ((System.currentTimeMillis() - ripLastUpdateTimestamp) > 10000) {
			broadcastRipMessage(RIPv2.COMMAND_RESPONSE);
			ripLastUpdateTimestamp = System.currentTimeMillis();
			return;
		}

		if (tableUpdated) {
			broadcastRipMessage(RIPv2.COMMAND_RESPONSE);
		}
	}

	private boolean pruneExpiredEntries()
	{
		boolean foundExpired = false;

		for (RIPv2Entry entry : this.ripDatabase.getEntries()) {
			if (entry.getNextHopAddress() == 0) {
				// Local entry, refresh timestamp
				entry.setTime(System.currentTimeMillis());
			} else if (entry.getMetric() == 16) {
				// Already marked unreachable
				entry.setTime(System.currentTimeMillis());
			} else if (entry.isExpired(System.currentTimeMillis())) {
				// Mark as expired
				foundExpired = true;
			}
		}

		return foundExpired;
	}

	private boolean updateRipRoutingTable(RIPv2Entry newEntry) {
		int targetNetwork = newEntry.getAddress();
		int subnetMask = newEntry.getSubnetMask();
		int newMetric = newEntry.getMetric() + 1;

		// Check if this is a directly connected network
		for (Iface iface : this.interfaces.values()) {
			int localNetwork = iface.getIpAddress() & iface.getSubnetMask();
			if (localNetwork == targetNetwork) {
				return false;
			}					
		}

		// Check for existing entries
		for (int i = 0; i < this.ripDatabase.getEntries().size(); i++) {
			RIPv2Entry existingEntry = this.ripDatabase.getEntries().get(i);
			
			if (existingEntry.getAddress() == targetNetwork) {
				// Same next hop
				if (existingEntry.getNextHopAddress() == this.cachedInterface.getIpAddress()) {
					if (existingEntry.getMetric() == newMetric) {
						// Refresh timestamp only
						existingEntry.setTime(System.currentTimeMillis());
						return false;
					} else {
						// Update metric
						existingEntry.setMetric(newMetric);
						existingEntry.setTime(System.currentTimeMillis());
						return true;
					}
				} else {
					// Different next hop - compare metrics
					if (existingEntry.getMetric() <= newMetric) {
						return false;
					} else {
						// Update to better path
						existingEntry.setMetric(newMetric);
						existingEntry.setTime(System.currentTimeMillis());
						existingEntry.setNextHopAddress(this.cachedInterface.getIpAddress());
						return true;
					}
				}
			} 
		}

		// New entry
		if (newEntry.getMetric() < 16) {
			RIPv2Entry addedEntry = new RIPv2Entry(
				targetNetwork, 
				subnetMask, 
				newMetric, 
				System.currentTimeMillis()
			);
			
			addedEntry.setNextHopAddress(this.cachedInterface.getIpAddress());
			this.ripDatabase.addEntry(addedEntry);
			return true;
		}

		return false;
	}

	private void broadcastRipMessage(byte commandType)
	{
		if (!ripEnabled) {
			return;
		}

		if (commandType != RIPv2.COMMAND_REQUEST && commandType != RIPv2.COMMAND_RESPONSE) {
			return;
		}

		this.ripDatabase.setCommand(commandType);
		pruneExpiredEntries();

		// RIP multicast address and broadcast MAC
		int multicastIp = IPv4.toIPv4Address("224.0.0.9");
		MACAddress broadcastMac = MACAddress.valueOf("FF:FF:FF:FF:FF:FF");
		
		for (Iface iface : this.interfaces.values()) {
			sendRipPacket(iface, multicastIp, broadcastMac);
		}
		
		// Reset command
		this.ripDatabase.setCommand((byte) 0);
	}

	private void sendTargetedRipResponse() {
		if (!ripEnabled || this.ripDatabase.getCommand() != RIPv2.COMMAND_RESPONSE) {
			return;
		}

		Iface targetIface = findRouteInRipTable(this.cachedInterface.getIpAddress());
		if (targetIface == null) {
			return;
		}
		
		sendRipPacket(
			targetIface, 
			cachedIpPacket.getSourceAddress(), 
			cachedEthernetFrame.getSourceMAC()
		);
	}

	private void sendRipPacket(Iface outIface, int destIp, MACAddress destMac)
	{
		if (outIface == null) {
			return;
		}

		// Create IP packet
		IPv4 ipPacket = new IPv4();
		ipPacket.setSourceAddress(outIface.getIpAddress());
		ipPacket.setDestinationAddress(destIp);
		ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
		ipPacket.setTtl((byte) 255);
		ipPacket.setPayload(createRipUdpPacket());

		// Create Ethernet frame
		Ethernet ethFrame = new Ethernet();
		ethFrame.setEtherType(Ethernet.TYPE_IPv4);
		ethFrame.setDestinationMACAddress(destMac.toBytes());
		ethFrame.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ethFrame.setPayload(ipPacket);

		// Send packet
		System.out.println("Sending RIP update");
		boolean success = sendPacket(ethFrame, outIface);
		System.out.println(success ? "RIP update sent" : "Failed to send RIP update");
	}

	private UDP createRipUdpPacket()
	{
		UDP udpPacket = new UDP();
		udpPacket.setSourcePort(UDP.RIP_PORT);
		udpPacket.setDestinationPort(UDP.RIP_PORT);
		udpPacket.setChecksum((short) 0);
		udpPacket.setPayload(this.ripDatabase);
		return udpPacket;
	}
}
