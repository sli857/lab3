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
		// Is this a UDP packet
		if (false){
			return false;
		}

		// Is this a UDP packet hitting expected port 520
		if (false){
			return false;
		}
		
		// If this is a response, update existing data (also handle if it is a request)
		reviewRIPdata();

		return true;
	}

	/**
	 * BTD - Check if Another RIP Request needs sent
	 */
	public void checkLastRIPTime()
	{	
		// Check time
		// Check for expired entries
		// Send responseRIP if needed

	}

	/**
	 * BTD - Check if new data provided from RIP message
	 * @param boolean document whether or not response is required
	 */
	public void reviewRIPdata(boolean needsResponse)
	{

		// OR statement handling, if table was update or a request was sent then send response
	}

	//------------------------------------- RIP -> UDP packet -> IP packet for order of encapsulation

	/**
	 * BTD - Send a RIP request
	 * @param boolean Is this a request
	 */
	public void sendRIP(boolean isRequest)
	{
		// Check for expired entries
		// Will handle broadcast rip, and unsolicited
		// Should be sent out all interfaces
	}

	/**
	 * Generate RIP UDP
	 * @param boolean Is this a reponse to a request
	 */
	public UDP generateUDPrip(boolean is_response)
	{
		// update necessary data in UDP
	}

	/**
	 * Generate IPv4 for RIP
	 * @param UDP UDP packet to be encapsulated
	 */
	public IPv4 generateIPv4rip(UDP udp_packet)
	{

	}

}
