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
	private IPv4 tempStoreIPv4;
	private Ethernet tempStoreEthernet;
	
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
		// Initialize RIP table
		System.out.println("Attempting to start RIP table.");

		// Initialize key values in Router
		this.RIPActive = true;
		this.RIPtable = new RIPv2();

		// Load in attached interfaces and add subnets reachable directly by router's interfaces
		for (Iface iface : this.interfaces.values()) {
			// Reachable subnet calculation
			int targetSubnet = iface.getIpAddress() & iface.getSubnetMask();
			RIPv2Entry new_entry = new RIPv2Entry(targetSubnet, iface.getSubnetMask(), 0, System.currentTimeMillis());
			this.RIPtable.addEntry(new_entry);
		}

		// Send Request for RIP 
		sendRIP(true, RIPv2.COMMAND_REQUEST); // BTD - send request to all interfaces

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
		if (RIPActive) {
			// Temporarily store ethernet and ip packet details
			this.tempStoreEthernet = etherPacket;
			this.tempStoreIPv4 = ipPacket;

			if (checkForRIP()) {
				System.out.println("Received RIP packet. No further processing required in Router.handlePacket.");
				// Reset the tempStoreEthernet and tempStoreIPv4
				this.tempStoreEthernet = null;
				this.tempStoreIPv4 = null;
				return; // Perform no further processing if this is a UDP packet for RIP
			}
			// Reset the tempStoreEthernet and tempStoreIPv4
			this.tempStoreEthernet = null;
			this.tempStoreIPv4 = null;
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
		Iface bestMatch;

		// Check if destination IP is in routing table
		if (RIPActive) {
			bestMatch = RIPlookup(ipPacket.getDestinationAddress());

		}
		else {
			RouteEntry bestRouteMatch = this.routeTable.lookup(ipPacket.getDestinationAddress()); // BTD - only instance of use of routeTable
			if (bestRouteMatch == null) {
				System.out.println("No matching route in routing table. Dropping packet.");
				return;
			}
			bestMatch = bestRouteMatch.getInterface();
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
		etherPacket.setSourceMACAddress(bestMatch.getMacAddress().toBytes());
		etherPacket.setPayload(ipPacket);

		/***************************** Call sendPacket() with the appropriate arguments *************************/
		System.out.println("Attempting to send packet to next hop.");
		if (sendPacket(etherPacket, bestMatch))
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
	 * BTD - Find if their is a matching route in the RIP table for a given IP address
	 * @param int ipAddress the IP address to check
	 * @return  the matching route entry, or null if not found
	 */

	public Iface RIPlookup(int ip)
	{
			// Check if the RIP table is empty
			if (this.RIPtable.getEntries().isEmpty())
			{ return null; }

			// Check if the IP address is 0
			if (ip == 0)
			{ return null; }
			
			// Initialize
			int max_match = 0;
			RIPv2Entry matching_entry = null;
			int table_ip = 0;
			int dst_ip = 0;
			int[] dst_ip_bytes = new int[4];
			int[] table_ip_bytes = new int[4];	

			// Iterate through the RIP table
			for (RIPv2Entry entry : this.RIPtable.getEntries())
			{
				
				// Get the destination IP
				table_ip = entry.getAddress() & entry.getSubnetMask();
				dst_ip = ip & entry.getSubnetMask();

				// Break up the IP address into 4 bytes
				table_ip_bytes[0] = (int) ((table_ip >> 24) & 0xFF);
				table_ip_bytes[1] = (int) ((table_ip >> 16) & 0xFF);
				table_ip_bytes[2] = (int) ((table_ip >> 8) & 0xFF);
				table_ip_bytes[3] = (int) (table_ip & 0xFF);

				// Break up the destination IP address into 4 bytes
				dst_ip_bytes[0] = (int) ((dst_ip >> 24) & 0xFF);
				dst_ip_bytes[1] = (int) ((dst_ip >> 16) & 0xFF);
				dst_ip_bytes[2] = (int) ((dst_ip >> 8)  & 0xFF);
				dst_ip_bytes[3] = (int) ( dst_ip        & 0xFF);

				// Print out the pair
				System.out.println("Comparing table IP with destination IP:");
				System.out.println("With destination IP: " + dst_ip_bytes);
				
				// Loop over bytes and compare to determine if they match
				for (int i = 0; i < 4; i++)
				{
					System.out.println(String.format("Comparing table byte: %d, with destination byte: %d", table_ip_bytes[i] , dst_ip_bytes[i]));
					if (table_ip_bytes[i] == dst_ip_bytes[i])
					{
						// Check if the prefix match is longer than the current max
						if (i >= max_match)
						{
							max_match = i+1;
							matching_entry = entry;
						}
					}
					else
					{break;}
				}
			}

			// Print out matching entry
			System.out.println("Matching entry in RIP table:");
			System.out.println(matching_entry.toString());

			// Determine the interface based on the matching entry
			if (matching_entry == null) {
				return null; // No matching entry found
			}
			else if (matching_entry.getMetric() == 16) {
				return null; // Entry is unreachable
			}
			else if (matching_entry.getNextHopAddress() == 0) {
				// This router is the source of the information
				// Return the interface associated with the entry
				for (Iface iface : this.interfaces.values()) {
					if (iface.getIpAddress() == matching_entry.getAddress()) {
						return iface; // Return the matching interface
					}
				}
				return null; // Entry is unreachable
			}
			else {
			// Based on the entry, find the best interface
			for (Iface iface : this.interfaces.values()) {
				if (iface.getIpAddress() == matching_entry.getNextHopAddress()) {
					return iface; // Return the matching interface
					}
				}
			}
			return null; // Entry is unreachable
	}

	/**
	 * BTD - UDP Packet checking and handling
	 */
	public boolean checkForRIP()
	{
		// temporarily set IPv
		// All inner packet layers are already deserialized
		System.out.println("Examining pack for RIP in Router.checkForRIP.");

		// Is this a UDP packet
		if (!(tempStoreIPv4.getPayload() instanceof UDP)) {
			System.out.println("Not a UDP packet. Cannot process RIP request in Router.checkForRIP.");
			return false;
		}

		// Cast the payload to a UDP packet
    	UDP udpPacket = (UDP) tempStoreIPv4.getPayload();

		// Is this a UDP packet hitting expected port 520
		if (udpPacket.getDestinationPort() != UDP.RIP_PORT) {
			System.out.println("UDP packet is not destined for RIP port 520. Ignoring.");
			return false;
		}
		
		// Have received a UDPpacket, check if it is a RIP packet
		System.out.println("Have confirmed is UDP at port 520, Router.checkForRIP.");

		// Check if the payload of the UDP packet is a RIP packet
		if (!(udpPacket.getPayload() instanceof RIPv2)) {
			System.out.println("UDP packet does not contain a RIP payload. Ignoring.");
			return false;
		}

		// Cast the payload to a RIP packet
    	RIPv2 ripPacket = (RIPv2) udpPacket.getPayload();

		// If this is a request, update existing data (also handle if it is a request) and respond
		if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {
			System.out.println("Received RIP REQUEST. Processing...");
			reviewRIPdata(true); // Sending UDP layer
		} // If this is a response, update existing data
		else if (ripPacket.getCommand() == RIPv2.COMMAND_RESPONSE) {
			System.out.println("Received RIP RESPONSE. Processing...");
			reviewRIPdata(false); // Sending UDP layer
		} // If this is neither, raise an error
		else {
			System.out.println("Invalid RIP command type. Cannot process RIP request in Router.checkForRIP.");
			return true; // Invalid command type
		}
		
		// Return true to indicate that the packet was processed
		System.out.println("Have successfully processed UDP message, Router.checkForRIP.");
		return true;
	}

	/**
	 * BTD - Check if new data provided from RIP message
	 * @param boolean document whether or not response is required
	 */
	public void reviewRIPdata(boolean needsResponse)
	{
		// Reviewing received RIP data
		System.out.println("Reviewing received RIP data in Router.reviewRIPdata.");

		// Extract the UDP Packet
		UDP udpData = (UDP) tempStoreIPv4.getPayload();  
		// Extract the RIP data
		RIPv2 receivedRIPdata = (RIPv2) udpData.getPayload();

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
		if (foundUpdates) {
			sendRIP(true, RIPv2.COMMAND_RESPONSE); 
		} else if (needsResponse) {
			System.out.println("No updates to table, but a response is required. Sending empty response.");
			sendRIP(false, RIPv2.COMMAND_RESPONSE); 
		}

		// Have reviewed the received RIP data
		System.out.println("Completed review of RIP data in Router.reviewRIPdata.");

	}

	/**
	 * BTD - Check if Another RIP Request needs sent
	 */
	public void checkLastRIPTime()
	{	
		// Set update flag to false
    	boolean sendUpdate = false;

		// Iterate through the routing table to check for expired entries
		sendUpdate = checkExpiredEntries();

		// Check if the last RIP check was more than 10 seconds ago
		if ((System.currentTimeMillis() - LastRIPCheckTime) > 10000) {
			// Send a RIP request to all neighbors
			sendRIP(true, RIPv2.COMMAND_REQUEST); // Assume this method sends a RIP request to all neighbors
			LastRIPCheckTime = System.currentTimeMillis(); // Update the last RIP check time
			return;
		}

		// Send a RIP response update if any entries were marked expired 
		if (sendUpdate) {
			sendRIP(true, RIPv2.COMMAND_RESPONSE); // Assume this method sends a RIP response to all neighbors
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
		for (RIPv2Entry entry : this.RIPtable.getEntries()) 
		{
			if (entry.isExpired(System.currentTimeMillis())) 
				{
				foundExpired = true; // Found an expired entry
				}
		}

		return foundExpired;
	}

	

	/**
	 * Updates the routing table with a new RIP entry.
	 * Returns true if the table was changed due to the new entry.
	 */
	private boolean updateRoutingTable(RIPv2Entry entry) {
	    
		// Starting review of table
		System.out.println("Reviewing routing table for a single entry in Router.updateRoutingTable.");
		entry.toString();

		// Extract information from the new entry
	    int targetSubnet = entry.getAddress();
	    int subnetMask = entry.getSubnetMask();
	    int metric = entry.getMetric() + 1; // Increment metric for the next hop

		// Chech if this router is the source
		int calculatedSubnet = 0;
		for (Iface iface : this.interfaces.values()) {
			// Reachable subnet calculation
			calculatedSubnet = iface.getIpAddress() & iface.getSubnetMask();
			if (calculatedSubnet == targetSubnet) { // This router is the source
				return false; // No updates, this router is the source of the information
			}					
		}

	    // Loop over the routing table to find an existing entry
		for (int count = 0; count < this.RIPtable.getEntries().size(); count++) {
			
			// Check if the entry already exists
			if (this.RIPtable.getEntries().get(count).getAddress() == targetSubnet) {

				// Check if the gateway is a match
				if (this.RIPtable.getEntries().get(count).getNextHopAddress() == tempStoreIPv4.getSourceAddress()) {
					// This location is the authority, update entry with received data
					this.RIPtable.getEntries().get(count).setMetric(metric);
					this.RIPtable.getEntries().get(count).setTime(System.currentTimeMillis());
					return true;
				} 
				// This router must compete with another path
				else{
					// Check if the entry competes with another path
					if (this.RIPtable.getEntries().get(count).getMetric() <= metric) {
						// No updates, router already has better path
						return false;
					} else {
						// This is better path, overwrite existing entry in the table
						this.RIPtable.getEntries().get(count).setMetric(metric);
						this.RIPtable.getEntries().get(count).setTime(System.currentTimeMillis());
						this.RIPtable.getEntries().get(count).setNextHopAddress(tempStoreIPv4.getSourceAddress());
						return true;
					}
				}
			} 
		}

		// The entry is new to the table
		System.out.println("Entry is new to the table in  Router.updateRoutingTable.");

	    // Make sure path isn't infinity, if it is not add to table
	    if (entry.getMetric() < 16) {

			// New an entry for the routing table
			RIPv2Entry newEntry = new RIPv2Entry(targetSubnet, subnetMask, metric, System.currentTimeMillis());

			// Update the last update time
			newEntry.setTime(System.currentTimeMillis());

			// Add the new entry to the routing table
			this.RIPtable.addEntry(newEntry);
			
			// Return true to indicate the table was changed
	        return true;
	    }

		// The entry was not integrated into table
		System.out.println("Entry is was not added to the table in  Router.updateRoutingTable.");

	    // If the existing route is better or equal, or the path given is infinite, return false and no changes
	    return false;
		}

	//------------------------------------- RIP -> UDP packet -> IP packet for order of encapsulation

	/**
	 * BTD - Send a RIP request
	 * @param byte command type of RIP message
	 * @param Iface interface to send the packet on (if this is broadcast, should pass null)
	 */
	public void sendRIP(boolean broadcast, byte command_type)
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

		System.out.println("RIP is active and a proper command type in Router.sendRIP");


		// Set the command type
		this.RIPtable.setCommand(command_type);

		// Check for expired entries
		checkExpiredEntries();

		// Check if message will be a broadcast
		if (broadcast) {
			// Set broadcast IP address for RIP 224.0.0.9
			int braodcastIP = IPv4.toIPv4Address("224.0.0.9");
			// Set broadcast mac address
			MACAddress broadcastMac = MACAddress.valueOf("FF:FF:FF:FF:FF:FF");
			
			// Rotate through interfaces on router
			for (Iface iface : this.interfaces.values()) {
				// Send the packet
				sendIPv4rip(iface, braodcastIP, broadcastMac); // Sending a specific response
			}
		}
		else if ((this.RIPtable.getCommand() == 2) && !broadcast) {
			// Calculate the target interface based off of destination from tempStoreIPv4
			Iface targetIface = this.routeTable.lookup(tempStoreIPv4.getDestinationAddress()).getInterface();
			
			// Send the packet through a specific interface
			sendIPv4rip(targetIface, tempStoreIPv4.getSourceAddress(), tempStoreEthernet.getSourceMAC()); 
		} 
		else {
			System.out.println("Invalid command type. Must be type 2 if sending out targetted interface.");
		}

		// Reset the command type
		this.RIPtable.setCommand((byte) 0);
		return;

	}

	/**
	 * Generate IPv4 for RIP
	 * @param Iface interface to send the packet on (if this is broadcast, should pass null)
	 */
	public void sendIPv4rip(Iface iface,int dest_ip, MACAddress dest_mac)
	{
		// Make sure a valid interface was sent
		if (iface == null) {
			System.out.println("Invalid interface in sendIPv4rip. Cannot send RIP request.");
			return;
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

		// Create an Ethernet packet
		Ethernet etherPacket = new Ethernet();

		// Set the source and destination MAC addresses
		etherPacket.setSourceMACAddress(iface.getMacAddress().toBytes());
		// tempStoreEthernet -- FINISH LATER

		// Make updates to the Ethernet packet
		etherPacket.setDestinationMACAddress(dest_mac.toBytes());
		etherPacket.setSourceMACAddress(iface.getMacAddress().toBytes());
		etherPacket.setPayload(ipv4Packet);

		// Send the packet
		System.out.println("Attempting to send RIP message.");
		if (sendPacket(etherPacket, iface)) // sendPacket(etherPacket, bestMatch.getInterface())
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
		udpPacket.setSourcePort(UDP.RIP_PORT);
		udpPacket.setDestinationPort(UDP.RIP_PORT);

		// Set the length and checksum to 0, calculated in serialization
		udpPacket.setChecksum((short) 0);

		// Set the payload to the RIP packet
		udpPacket.setPayload(this.RIPtable);

		// return the UDP packet
		return udpPacket;

	}

}
