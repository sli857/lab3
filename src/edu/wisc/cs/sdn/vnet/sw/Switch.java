package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
	// Declare the SwitchBindingTable as a member variable
    private SwitchBindingTable mac_table;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
		// Create the mac table
		this.mac_table = new SwitchBindingTable();
	}

	/**
	 * A row containing the details on the binding of the mac address
	 * to a interface on the switch
	 */
	public static class MacPortBinding
	{
		Iface bound_interface; /* The interface the mac address is bound to */
		MACAddress mac_address; /* The mac address */
		double expiration_time; /* The time the entry expires */
	}

	// Create a table to hold details on mac addresses and ports
	public static class SwitchBindingTable
	{
		MacPortBinding[] mapping_table; /* The table to hold the mac address and port bindings */
		int max_table_entries = 1024; /* The number of entries in the table */

		public SwitchBindingTable()
		{
			this.mapping_table = new MacPortBinding[max_table_entries];
		}
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
		

		// Get the source mac address
		MACAddress source_mac = etherPacket.getSourceMAC();

		// Check if mac address is in table
		source_mac_table_eval(source_mac, inIface);

		// Check the table for expired entries
		check_table();

		// Get the destination mac address
		MACAddress dest_mac = etherPacket.getDestinationMAC();

		// Pass in destination mac address and route or broadcast
		System.out.println("Sending packet to destination");		
		send_packet(etherPacket, dest_mac, inIface);
		return;
		
	}

	/**
	 * Evaluate the source mac address against the table of mac addresses
	 * and ports
	 * @param source_mac the source mac address
	 * @param interface the interface the source mac address is bound to
	 */
	public void source_mac_table_eval(MACAddress source_mac, Iface in_face)
	{
		
		// Back out if soure_mac is null
		if (source_mac == null) 
		{ return; }

		// Establish length of table as min of table size or number of entries
		int table_length = this.mac_table.max_table_entries;

		// Check if the source mac address is in the table
		for (int i = 0; i < table_length; i++)
		{
			if (this.mac_table.mapping_table[i] != null)
			{ 
				if (this.mac_table.mapping_table[i].mac_address.equals(source_mac))
				{
					// Update the expiration time to be 15 seconds from now
					this.mac_table.mapping_table[i].expiration_time = System.currentTimeMillis() + 15000;
					return;
				}
			}
		}

		// If not in the table, add the source mac address to the table with it's interface
		for (int i = 0; i < table_length; i++)
		{
			if (this.mac_table.mapping_table[i] == null)
			{
				// Add the source mac address to the table
				this.mac_table.mapping_table[i] = new MacPortBinding();
				this.mac_table.mapping_table[i].mac_address = source_mac;
				this.mac_table.mapping_table[i].bound_interface = in_face;
				this.mac_table.mapping_table[i].expiration_time = System.currentTimeMillis() + 15000;
				break;
			}
		}

	}

	/**
	 * Check the mapping table and remove any expired entries
	 */
	public void check_table()
	{
		// Establish length of table 
		int table_length = mac_table.mapping_table.length;

		// Check for timers on all entries and remove any that are expired
		for (int i = 0; i < table_length; i++)
		{
			// Skip if entry is null
			if (this.mac_table.mapping_table[i] == null) { continue; }
			else if (this.mac_table.mapping_table[i].expiration_time < System.currentTimeMillis())
			{
				// Remove the entry from the table
				this.mac_table.mapping_table[i] = null;
			}
		}
	}

	/**
	 * Send the packet to the correct interface
	 * Or broadcast the packet to all interfaces if not currently in table
	 */
	public void send_packet(Ethernet etherPacket, MACAddress targetmac, Iface inIface)
	{
		
		// Check if mac address is in table
		for (int i = 0; i < this.mac_table.max_table_entries; i++)
		{
			/* Bypass if this entry is null */
			if (this.mac_table.mapping_table[i] == null) { continue; }

			// Check if the mac address is in the table
			else if (this.mac_table.mapping_table[i].mac_address.equals(targetmac))
			{
				// Get the interface from the table
				Iface outIface = this.mac_table.mapping_table[i].bound_interface;

				// Check if the interface is null, and exit loop if so
				if (outIface == null) { break; }

				// Send the packet to the correct interface
				this.sendPacket(etherPacket, outIface);
				System.out.println("Broadcasting packet to correct interface");
				return;

			}
			// Try next if not the right mac address
			else 
			{continue;}
		}

		System.out.println("Broadcasting packet to all interfaces");
		// Broadcast the packet to all interfaces
		for (Iface iface : this.interfaces.values())
		{
			
			if (iface == inIface) { continue; }
			this.sendPacket(etherPacket, iface);
		}
		return;
	}
}
