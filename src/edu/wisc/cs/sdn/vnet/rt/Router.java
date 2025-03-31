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
	private ArpCache addressCache;

	private boolean ripEnabled = false;
	private RIPv2 ripDatabase;
	private long lastRipUpdateTimestamp;
	private IPv4 currentIpPacket;
	private Ethernet currentEtherFrame;
	
	public Router(String host, DumpFile logfile)
	{
		super(host, logfile);
		this.forwardingTable = new RouteTable();
		this.addressCache = new ArpCache();
	}
	
	public RouteTable getRouteTable()
	{ 
		return this.forwardingTable; 
	}
	
	public void loadRouteTable(String routeTableFile)
	{
		if (!forwardingTable.load(routeTableFile, this))
		{
			System.err.println("Failed to initialize routing table from file " + routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.forwardingTable.toString());
		System.out.println("-------------------------------------------------");
	}

	public void startRIPTable()
	{
		System.out.println("Initializing RIP table...");

		this.ripEnabled = true;
		this.ripDatabase = new RIPv2();

		for (Iface networkInterface : this.interfaces.values()) {
			int networkPrefix = networkInterface.getIpAddress() & networkInterface.getSubnetMask();
			RIPv2Entry entry = new RIPv2Entry(networkPrefix, networkInterface.getSubnetMask(), 0, System.currentTimeMillis());
			this.ripDatabase.addEntry(entry);
		}

		broadcastRipMessage(RIPv2.COMMAND_REQUEST);
		this.lastRipUpdateTimestamp = System.currentTimeMillis();
		
		System.out.println("RIP table initialized");
		System.out.println("-------------------------------------------------");
		System.out.print(this.ripDatabase.toString());
		System.out.println("-------------------------------------------------");
	}
	
	public void loadArpCache(String arpCacheFile)
	{
		if (!addressCache.load(arpCacheFile))
		{
			System.err.println("Failed to initialize ARP cache from file " + arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.addressCache.toString());
		System.out.println("----------------------------------");
	}

	public void handlePacket(Ethernet etherFrame, Iface incomingInterface)
	{
		System.out.println("*** -> Received packet: " +
				etherFrame.toString().replace("\n", "\n\t"));
		
		if (etherFrame.getEtherType() != Ethernet.TYPE_IPv4) {
			System.out.println("Non-IPv4 packet detected. Dropping.");
			return;
		}

		IPv4 ipPacket = (IPv4)etherFrame.getPayload();

		if (!validateChecksum(ipPacket)) {
			System.out.println("Checksum validation failed. Dropping packet.");
			return;
		}

		ipPacket.setTtl((byte)(ipPacket.getTtl() - 1));

		if (ipPacket.getTtl() == 0) {
			System.out.println("TTL expired. Dropping packet.");
			return;
		}

		if (ripEnabled) {
			this.currentEtherFrame = etherFrame;
			this.currentIpPacket = ipPacket;

			if (processRipPacket()) {
				System.out.println("RIP packet processed. No further handling needed.");
				this.currentEtherFrame = null;
				this.currentIpPacket = null;
				return;
			}
			
			this.currentEtherFrame = null;
			this.currentIpPacket = null;
		}

		ipPacket.resetChecksum();
		ipPacket.serialize();

		for (Iface networkInterface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == networkInterface.getIpAddress()) {
				System.out.println("Packet destined for router interface. Dropping.");
				return;
			}
		}

		Iface outgoingInterface;

		if (ripEnabled) {
			outgoingInterface = findRipRoute(ipPacket.getDestinationAddress());
			if (outgoingInterface == null) {
				System.out.println("No route found in RIP table. Dropping packet.");
				return;
			}
		}
		else {
			RouteEntry routeMatch = this.forwardingTable.lookup(ipPacket.getDestinationAddress());
			if (routeMatch == null) {
				System.out.println("No matching route found. Dropping packet.");
				return;
			}
			outgoingInterface = routeMatch.getInterface();
		}

		ArpEntry arpEntry = this.addressCache.lookup(ipPacket.getDestinationAddress());
		if (arpEntry == null) {
			System.out.println("ARP resolution failed. Dropping packet.");
			return;
		} else {
			System.out.println("Route and ARP resolution successful. Forwarding packet.");
		}

		etherFrame.setDestinationMACAddress(arpEntry.getMac().toBytes());
		etherFrame.setSourceMACAddress(outgoingInterface.getMacAddress().toBytes());
		etherFrame.setPayload(ipPacket);

		System.out.println("Sending packet to next hop.");
		if (sendPacket(etherFrame, outgoingInterface)) {
			System.out.println("Packet forwarded successfully.");
		}
		else {
			System.out.println("Packet forwarding failed.");
		}
	}

	public boolean validateChecksum(IPv4 ipPacket)
	{
		short originalChecksum = (short)(ipPacket.getChecksum());
		ipPacket.resetChecksum();
		ipPacket.serialize();

		return ipPacket.getChecksum() == originalChecksum;
	}

	public Iface findRipRoute(int destAddress)
	{
		if (this.ripDatabase.getEntries().isEmpty()) { 
			return null; 
		}

		if (destAddress == 0) { 
			return null; 
		}
		
		int longestMatch = 0;
		RIPv2Entry matchingEntry = null;
		int tableNetworkAddr = 0;
		int destNetworkAddr = 0;
		int[] destAddrBytes = new int[4];
		int[] tableAddrBytes = new int[4];	

		for (RIPv2Entry entry : this.ripDatabase.getEntries())
		{
			tableNetworkAddr = entry.getAddress() & entry.getSubnetMask();
			destNetworkAddr = destAddress & entry.getSubnetMask();

			tableAddrBytes[0] = (int)((tableNetworkAddr >> 24) & 0xFF);
			tableAddrBytes[1] = (int)((tableNetworkAddr >> 16) & 0xFF);
			tableAddrBytes[2] = (int)((tableNetworkAddr >> 8) & 0xFF);
			tableAddrBytes[3] = (int)(tableNetworkAddr & 0xFF);

			destAddrBytes[0] = (int)((destNetworkAddr >> 24) & 0xFF);
			destAddrBytes[1] = (int)((destNetworkAddr >> 16) & 0xFF);
			destAddrBytes[2] = (int)((destNetworkAddr >> 8) & 0xFF);
			destAddrBytes[3] = (int)(destNetworkAddr & 0xFF);

			System.out.println("Comparing network addresses for route lookup:");
			System.out.println("Destination network: " + destAddrBytes);
			
			for (int i = 0; i < 4; i++)
			{
				System.out.println(String.format("Comparing bytes: table[%d]=%d, dest[%d]=%d", 
					i, tableAddrBytes[i], i, destAddrBytes[i]));
				
				if (tableAddrBytes[i] == destAddrBytes[i])
				{
					if (i >= longestMatch)
					{
						longestMatch = i+1;
						matchingEntry = entry;
					}
				}
				else
				{
					break;
				}
			}
		}

		System.out.println("Found matching entry in RIP table:");
		System.out.println(matchingEntry.toString());

		if (matchingEntry == null) {
			return null;
		}
		else if (matchingEntry.getMetric() == 16) {
			return null;
		}
		else if (matchingEntry.getNextHopAddress() == 0) {
			for (Iface networkInterface : this.interfaces.values()) {
				if ((networkInterface.getIpAddress() & networkInterface.getSubnetMask()) == matchingEntry.getAddress()) {
					return networkInterface;
				}
			}
			return null;
		}
		else {
			for (Iface networkInterface : this.interfaces.values()) {
				if ((networkInterface.getIpAddress() & networkInterface.getSubnetMask()) == matchingEntry.getNextHopAddress()) {
					return networkInterface;
				}
			}
		}
		return null;
	}

	public boolean processRipPacket()
	{
		System.out.println("Checking if packet contains RIP data.");

		if (!(currentIpPacket.getPayload() instanceof UDP)) {
			System.out.println("Not a UDP packet. Skipping RIP processing.");
			return false;
		}

    	UDP udpSegment = (UDP) currentIpPacket.getPayload();

		if (udpSegment.getDestinationPort() != UDP.RIP_PORT) {
			System.out.println("UDP packet not destined for RIP port 520. Ignoring.");
			return false;
		}
		
		System.out.println("UDP packet on port 520 detected.");

		if (!(udpSegment.getPayload() instanceof RIPv2)) {
			System.out.println("UDP packet does not contain RIP data. Ignoring.");
			return false;
		}

    	RIPv2 ripMessage = (RIPv2) udpSegment.getPayload();

		if (ripMessage.getCommand() == RIPv2.COMMAND_REQUEST) {
			System.out.println("Processing RIP REQUEST...");
			processRipData(true);
		}
		else if (ripMessage.getCommand() == RIPv2.COMMAND_RESPONSE) {
			System.out.println("Processing RIP RESPONSE...");
			processRipData(false);
		}
		else {
			System.out.println("Invalid RIP command. Ignoring packet.");
			return true;
		}
		
		System.out.println("RIP message processing completed.");
		return true;
	}

	public void processRipData(boolean responseRequired)
	{
		System.out.println("Processing RIP message content.");

		UDP udpSegment = (UDP) currentIpPacket.getPayload();  
		RIPv2 receivedRipData = (RIPv2) udpSegment.getPayload();

		boolean tableUpdated = false;

		for (RIPv2Entry entry : receivedRipData.getEntries()) {
			if (updateRipTable(entry)) {
				tableUpdated = true;
			}
    	}

		if (tableUpdated) {
			broadcastRipMessage(RIPv2.COMMAND_RESPONSE); 
		} else if (responseRequired) {
			System.out.println("No table updates, but response required. Sending response.");
			sendDirectRipResponse(); 
		}

		System.out.println("RIP data processing completed.");
	}

	public void checkRipTimers()
	{	
    	boolean tableUpdated = checkForExpiredEntries();

		if ((System.currentTimeMillis() - lastRipUpdateTimestamp) > 10000) {
			broadcastRipMessage(RIPv2.COMMAND_REQUEST);
			lastRipUpdateTimestamp = System.currentTimeMillis();
			return;
		}

		if (tableUpdated) {
			broadcastRipMessage(RIPv2.COMMAND_RESPONSE);
		}
	}

	public boolean checkForExpiredEntries()
	{
		boolean foundExpired = false;

		for (RIPv2Entry entry : this.ripDatabase.getEntries()) 
		{
			if (entry.isExpired(System.currentTimeMillis())) 
			{
				foundExpired = true;
			}
		}

		return foundExpired;
	}

	private boolean updateRipTable(RIPv2Entry entry) {
		System.out.println("Evaluating RIP entry for table update.");
		entry.toString();

		int targetNetwork = entry.getAddress();
		int netmask = entry.getSubnetMask();
		int hopCount = entry.getMetric() + 1;

		int localNetwork = 0;
		for (Iface networkInterface : this.interfaces.values()) {
			localNetwork = networkInterface.getIpAddress() & networkInterface.getSubnetMask();
			if (localNetwork == targetNetwork) {
				return false;
			}					
		}

		for (int i = 0; i < this.ripDatabase.getEntries().size(); i++) {
			if (this.ripDatabase.getEntries().get(i).getAddress() == targetNetwork) {
				if (this.ripDatabase.getEntries().get(i).getNextHopAddress() == currentIpPacket.getSourceAddress()) {
					this.ripDatabase.getEntries().get(i).setMetric(hopCount);
					this.ripDatabase.getEntries().get(i).setTime(System.currentTimeMillis());
					return true;
				} 
				else {
					if (this.ripDatabase.getEntries().get(i).getMetric() <= hopCount) {
						return false;
					} else {
						this.ripDatabase.getEntries().get(i).setMetric(hopCount);
						this.ripDatabase.getEntries().get(i).setTime(System.currentTimeMillis());
						this.ripDatabase.getEntries().get(i).setNextHopAddress(currentIpPacket.getSourceAddress());
						return true;
					}
				}
			} 
		}

		System.out.println("New network discovered.");

		if (entry.getMetric() < 16) {
			RIPv2Entry newEntry = new RIPv2Entry(targetNetwork, netmask, hopCount, System.currentTimeMillis());
			newEntry.setTime(System.currentTimeMillis());
			this.ripDatabase.addEntry(newEntry);
			return true;
		}

		System.out.println("Entry not added to table.");
		return false;
	}

	public void broadcastRipMessage(byte commandType)
	{
		if (!ripEnabled) {
			System.out.println("RIP not enabled. Cannot send RIP messages.");
			return;
		}

		if (commandType != 1 && commandType != 2) {
			System.out.println("Invalid RIP command type. Aborting.");
			return;
		}

		System.out.println("Preparing RIP broadcast message.");

		this.ripDatabase.setCommand(commandType);
		checkForExpiredEntries();

		int multicastAddr = IPv4.toIPv4Address("224.0.0.9");
		MACAddress broadcastMac = MACAddress.valueOf("FF:FF:FF:FF:FF:FF");
		
		for (Iface networkInterface : this.interfaces.values()) {
			sendRipPacket(networkInterface, multicastAddr, broadcastMac);
		}

		this.ripDatabase.setCommand((byte) 0);
	}

	public void sendDirectRipResponse()
	{
		if (this.ripDatabase.getCommand() == 2) {
			Iface targetInterface = this.forwardingTable.lookup(currentIpPacket.getDestinationAddress()).getInterface();
			sendRipPacket(targetInterface, currentIpPacket.getSourceAddress(), currentEtherFrame.getSourceMAC()); 
		} 
		else {
			System.out.println("Invalid command for direct response.");
		}
	}

	public void sendRipPacket(Iface outInterface, int destinationIp, MACAddress destinationMac)
	{
		if (outInterface == null) {
			System.out.println("Invalid interface for RIP message.");
			return;
		}

		IPv4 ipv4Packet = new IPv4();
		ipv4Packet.setSourceAddress(outInterface.getIpAddress());
		ipv4Packet.setDestinationAddress(outInterface.getSubnetMask());
		ipv4Packet.setProtocol(IPv4.PROTOCOL_UDP);
		ipv4Packet.setTtl((byte) 255);
		ipv4Packet.setPayload(createRipUdpPacket());

		Ethernet etherFrame = new Ethernet();
		etherFrame.setDestinationMACAddress(destinationMac.toBytes());
		etherFrame.setSourceMACAddress(outInterface.getMacAddress().toBytes());
		etherFrame.setPayload(ipv4Packet);

		System.out.println("Sending RIP message...");
		if (sendPacket(etherFrame, outInterface)) {
			System.out.println("RIP message sent successfully.");
		}
		else {
			System.out.println("Failed to send RIP message.");
		}
	}

	public UDP createRipUdpPacket()
	{
		UDP udpSegment = new UDP();
		udpSegment.setSourcePort(UDP.RIP_PORT);
		udpSegment.setDestinationPort(UDP.RIP_PORT);
		udpSegment.setChecksum((short) 0);
		udpSegment.setPayload(this.ripDatabase);
		return udpSegment;
	}
}