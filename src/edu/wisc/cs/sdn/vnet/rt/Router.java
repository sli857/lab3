package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.nio.ByteBuffer;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	/** BTD - Default value for RIP is false */
	private boolean RIPActive = false;
	private RIPv2 RIPtable;
	private long LastRIPCheckTime;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * BTD - Generate a new RIP routing table.
	 */
	public void startRIPTable()
	{
		
		// Initialize key values in Router
		this.RIPActive = true;
		this.RIPtable = new RIPv2();

		// Load in attached interfaces and add subnets reachable directly by router's interfaces
		for (Iface iface : this.interfaces.values()) {
			// Reachable subnet calculation
			int targetSubnet = iface.getIpAddress() & iface.getSubnetMask();
			RIPv2Entry new_entry = new RIPv2Entry(targetSubnet, iface.getSubnetMask(), 0);
			this.RIPtable.addEntry(new_entry);
		}

		// Send Request for RIP 
		requestRIP();

		// Set RIP timer
		this.LastRIPCheckTime = System.currentTimeMillis();
		
		// Update user
		System.out.println("Started RIP table.");
		System.out.println("-------------------------------------------------");
		System.out.print(this.RIPtable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
		
		
		/*************************** Perform validation of the Packet  ******************************************/

		// Check if IPv4 packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			System.out.println("Not an IPv4 packet. Dropping packet.");
			return;
		}

		// Cast the IP packet to an IPv4 packet
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();

		// Subroutine to verify checksum 
		if (!verifyChecksum(ipPacket)) {
			System.out.println("Invalid checksum. Dropping packet.");
			return;
		}

		// Decrement TTL by 1
		ipPacket.setTtl((byte)(ipPacket.getTtl() - 1));

		// Check if TTL is 0
		if (ipPacket.getTtl() == 0) {
			System.out.println("TTL is 0. Dropping packet.");
			return;
		}

		// BTD - Check if UDP message containing RIP
		 if (checkForRIP(ipPacket)) {
			return; // Perform no further processing if this is a UDP packet for RIP
		 }

		// Recalculate checksum of the IP packet
		ipPacket.resetChecksum();
		ipPacket.serialize();

		// Check if destination IP is one of the router's interfaces
		for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				System.out.println("Destination IP is one of the router's interfaces. Dropping packet.");
				return;
			}
		}

		// BTD - need alternative handling for when RIP is active to replace using routeTable.lookup, can borrow code though

		// Check if destination IP is in routing table
		RouteEntry bestMatch = this.routeTable.lookup(ipPacket.getDestinationAddress()); // BTD - only instance of use of routeTable
		if (bestMatch == null) {
			System.out.println("No matching route in routing table. Dropping packet.");
			return;
		}

		// Check ARP cache for MAC address
		ArpEntry arpEntry = this.arpCache.lookup(ipPacket.getDestinationAddress());
		if (arpEntry == null) {
			System.out.println("No matching ARP entry in ARP cache. Aborting.");
			return;
		} else {
			System.out.println("Passed all verification and matching ARP entry in ARP cache. Forwarding packet.");
		}

		/*************************** Update the header of the Ethernet Packet ***********************************/

		// Make updates to the Ethernet packet
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
		etherPacket.setSourceMACAddress(bestMatch.getInterface().getMacAddress().toBytes());
		etherPacket.setPayload(ipPacket);

		/***************************** Call sendPacket() with the appropriate arguments *************************/
		System.out.println("Attempting to send packet to next hop.");
		if (sendPacket(etherPacket, bestMatch.getInterface()))
		{
			System.out.println("Packet sent successfully.");
		}
		else
		{
			System.out.println("Failed to send packet.");
		}
		
		return;
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param I4packet the Ethernet packet that was received
	 * @return Boolean true if checksum is valid, false otherwise
	 */
	public boolean verifyChecksum(IPv4 I4packet)
	{
		// Get the checksum from the IP header
		short checksumTemp = (short) (I4packet.getChecksum());

		// Reset the checksum of the packet
		I4packet.resetChecksum();

		// Serialize and recalculate the checksum
		I4packet.serialize();

		// Compare the calculated checksum with the checksum in the header
		if (I4packet.getChecksum() == checksumTemp) {
			return true;
		} else {
			return false;
		}
		
	}

	/*********************************** Handling for RIP ***********************************/

	/**
	 * BTD - UDP Packet checking and handling
	 */
	public boolean checkForRIP(IPv4 ipPacket)
	{
		// All inner packet layers are already deserialized

		// Is this a UDP packet
		if (! UDP.equals(ipPacket.getPayload())){
			return false;
		}

		// Expected target port
		short tPort = 520;

		// Is this a UDP packet hitting expected port 520
		if (ipPacket.getPayload().getDestinationPort != tPort){
			return false;
		}
		
		// If this is a response, update existing data (also handle if it is a request)
		reviewRIPdata(false, ipPacket); // Sending UDP layer

		return true;
	}

	/**
	 * BTD - Check if Another RIP Request needs sent
	 */
	public void checkLastRIPTime()
	{	
		// Save current time and set update flag to false
		long currentTime = System.currentTimeMillis();
    	boolean sendUpdate = false;

		// Iterate through the routing table to check for expired entries
		sendUpdate = checkExpiredEntries();

		// Check if the last RIP check was more than 10 seconds ago
		if ((currentTime - LastRIPCheckTime) > 10000) {
			// Send a RIP request to all neighbors
			sendRIP(true); // Assume this method sends a RIP request to all neighbors
			LastRIPCheckTime = currentTime; // Update the last RIP check time
			return;
		}

		// Send a RIP response update if any entries were marked expired 
		if (sendUpdate) {
			sendRIP(false); // Assume this method sends a RIP response to all neighbors
		}
		
		return;

	}

	/**
	 * BTD - Check for expired entries in RIP table, return true if any updates
	 */
	public boolean checkExpiredEntries()
	{
		boolean foundExpired = false;
		// Check if any entries have expired
		for (RIPv2Entry entry : this.RIPtable.getEntries()) {
			if (entry.isExpired(System.currentTimeMillis())) {
				
				foundExpired = true; // Found an expired entry
			}
		}
		// Remove all expired entries from the RIP table
		this.RIPtable.removeEntries();
		return foundExpired;
	}

	/**
	 * BTD - Check if new data provided from RIP message
	 * @param boolean document whether or not response is required
	 */
	public void reviewRIPdata(boolean needsResponse, IPv4 ipPacket)
	{
		// Extract the UDP Packet
		UDP udpData = ipPacket.getPayload();  
		// Extract the RIP data
		RIPv2 receivedRIPdata = udpData.getPayload();

		// Initialize to no updates
		boolean foundUpdates = false;

		// Loop over entries sent, if any updates to table then will change flag to send update
		for (RIPv2Entry entry : receivedRIPdata.getEntries()) {
			// Assume updateRoutingTable returns true if the table was changed
			if (updateRoutingTable(entry)) {
				foundUpdates = true;
			}
    	}

		// OR statement handling, if table was updated or a request was sent then send response
		if (foundUpdates || needsResponse) {
			sendRIP();
		}
	}

	/**
	 * Updates the routing table with a new RIP entry.
	 * Returns true if the table was changed due to the new entry.
	 */
	private boolean updateRoutingTable(RIPv2Entry entry) {
	    // Extract information from the new entry
	    int targetSubnet = entry.getAddress();
	    int subnetMask = entry.getSubnetMask();
	    int metric = entry.getMetric() + 1; // Increment metric for the next hop
		long entryAge = System.currentTimeMillis() - entry.getTime();

	    // Check if the metric is invalid (RIP metric 16 means unreachable or older than 30 seconds)
	    if (metric >= 16 || entryAge > 30000) {
	        return false;
	    }


	    // Loop over the routing table to find an existing entry
		for (RIPv2Entry existingEntry : this.RIPtable.getEntries()) {
			if (existingEntry.getAddress() == targetSubnet) {
				// If the entry already exists, compare metrics and take best
				if (metric < existingEntry.getMetric()) {
					existingEntry.setMetric(metric);
					existingEntry.setTime(System.currentTimeMillis());
					return true;
				} else {
					return false; // No update needed, found a match but it was better already
				}
			}
		}

	    // If no existing route or the new route has a better metric, update the table
	    if (existingEntry == null || metric < existingEntry.getMetric()) {
			// New an entry for the routing table
			RIPv2Entry newEntry = new RIPv2Entry(targetSubnet, subnetMask, metric);
			this.RIPtable.addEntry(newEntry);
			// Update the last update time
			newEntry.setTime(System.currentTimeMillis());
			// Return true to indicate the table was changed
	        return true;
	    }

	    // If the existing route is better or equal, do nothing
	    return false;
		}

	//------------------------------------- RIP -> UDP packet -> IP packet for order of encapsulation

	/**
	 * BTD - Send a RIP request
	 * @param byte command type of RIP message
	 * @param Iface interface to send the packet on (if this is broadcast, should pass null)
	 */
	public void sendRIP(byte command_type, IPv4 ipPacket)
	{
		// Check if RIP is active
		if (!RIPActive) {
			System.out.println("RIP is not active. Cannot send RIP request.");
			return;
		}

		// Check if the command type is valid
		if  (command_type != 1 && command_type != 2) {
			System.out.println("Invalid command type. Cannot send RIP request.");
			return;
		}

		// Set the command type
		this.RIPtable.setCommand(command_type, iface);

		// Check for expired entries
		checkExpiredEntries();

		// Check if interface is in list of interfaces
		if (ipPacket.getDestinationAddress() == null) {
			// Rotate through interfaces on router
			for (Iface iface : this.interfaces.values()) {
				// Send the packet
				sendIPv4rip(iface);
			}
		}
		else (ipPacket.getDestinationAddress() != null){
			if(!this.interfaces.containsKey(ipPacket.getDestinationAddress())) {
				System.out.println("Invalid interface. Cannot send RIP request.");
			} 
			else if (this.RIPtable.getCommand() == 2) {
					// Send the packet
					sendIPv4rip(ipPacket.getDestinationAddress());
			} else {
				System.out.println("Invalid command type. Must be type 2 if sending out targetted interface.");
			}
		} 

		// Reset the command type
		this.RIPtable.setCommand((byte) 0);
		return;

	}

	/**
	 * Generate IPv4 for RIP
	 * @param Iface interface to send the packet on (if this is broadcast, should pass null)
	 */
	public IPv4 sendIPv4rip(Iface iface)
	{
		// Make sure a valid interface was sent
		if (iface == null) {
			System.out.println("Invalid interface in sendIPv4rip. Cannot send RIP request.");
			return null;
		}

		// Create a new IPv4 packet
		IPv4 ipv4Packet = new IPv4();

		// Set the source and destination IP addresses
		ipv4Packet.setSourceAddress(iface.getIpAddress());
		ipv4Packet.setDestinationAddress(iface.getSubnetMask());

		// Set the protocol to UDP
		ipv4Packet.setProtocol(IPv4.PROTOCOL_UDP);

		// Set the TTL to 255
		ipv4Packet.setTtl((byte) 255);

		// Set the payload to the UDP packet
		ipv4Packet.setPayload(generateUDPrip());

		// Set the checksum
		ipv4Packet.resetChecksum();

		// Serialize

		// Send the packet
		System.out.println("Attempting to send RIP message.");
		if (sendPacket(etherPacket, iface))
		{
			System.out.println("Packet sent successfully.");
		}
		else
		{
			System.out.println("Failed to send packet.");
		}
		
		return;
		
	}

	/**
	 * Generate RIP UDP packet
	 */
	public UDP generateUDPrip()
	{
		// Encapulate the RIP packet in a UDP packet
		UDP udpPacket = new UDP();

		// Set the source and destination ports
		udpPacket.setSourcePort((short) 520);
		udpPacket.setDestinationPort((short) 520);

		// Set the length and checksum to 0, calculated in serialization
		udpPacket.setLength((short) 0);
		udpPacket.setChecksum((short) 0);

		// Set the payload to the RIP packet
		udpPacket.setPayload(this.RIPtable);

		// return the UDP packet
		return udpPacket;

	}



}
