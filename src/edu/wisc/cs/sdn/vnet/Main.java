package edu.wisc.cs.sdn.vnet;
import edu.wisc.cs.sdn.vnet.rt.Router;
import edu.wisc.cs.sdn.vnet.sw.Switch;
import edu.wisc.cs.sdn.vnet.vns.Command;
import edu.wisc.cs.sdn.vnet.vns.VNSComm;

public class Main 
{
	private static final short NETWORK_PORT = 8888;
	private static final String DEFAULT_SIMULATOR = "localhost";
	
	public static void main(String[] args)
	{
		String deviceName = null;
		String simulatorAddress = DEFAULT_SIMULATOR;
		String routingTablePath = null;
		String arpCachePath = null;
		String logFilePath = null;
		short networkPort = NETWORK_PORT;
		VNSComm networkComm = null;
		Device networkDevice = null;
		
		// Process command line arguments
		for(int i = 0; i < args.length; i++)
		{
			String currentArg = args[i];
			if (currentArg.equals("-h"))
			{
				displayHelp();
				return;
			}
			else if(currentArg.equals("-p"))
			{ networkPort = Short.parseShort(args[++i]); }
			else if (currentArg.equals("-v"))
			{ deviceName = args[++i]; }
			else if (currentArg.equals("-s"))
			{ simulatorAddress = args[++i]; }
			else if (currentArg.equals("-l"))
			{ logFilePath = args[++i]; }
			else if (currentArg.equals("-r"))
			{ routingTablePath = args[++i]; }
			else if (currentArg.equals("-a"))
			{ arpCachePath = args[++i]; }
		}
		
		if (deviceName == null)
		{
			displayHelp();
			return;
		}
		
		// Initialize packet capture for logging
		DumpFile packetCapture = null;
		if (logFilePath != null)
		{
			packetCapture = DumpFile.open(logFilePath);
			if (packetCapture == null)
			{
				System.err.println("Failed to open log file: " + logFilePath);
				return;
			}
		}
		
		// Create appropriate network device based on name prefix
		if (deviceName.startsWith("s"))
		{ 
			networkDevice = new Switch(deviceName, packetCapture); 
		}
		else if (deviceName.startsWith("r"))
		{
			networkDevice = new Router(deviceName, packetCapture);
		}
		else 
		{
			System.err.println("Device name must begin with 's' or 'r'");
			return;
		}
		
		// Establish connection to network simulator
		System.out.println(String.format("Connecting to simulator at %s:%d", 
				simulatorAddress, networkPort));
		networkComm = new VNSComm(networkDevice);
		if (!networkComm.connectToServer(networkPort, simulatorAddress))
		{ System.exit(1); }
		networkComm.readFromServerExpect(Command.VNS_HW_INFO);	
		
		// Configure router-specific settings if applicable
		if (networkDevice instanceof Router) 
		{
			Router routerDevice = (Router)networkDevice;
			
			// Load routing information - either from file or start RIP
			if (routingTablePath != null)
			{ 
				routerDevice.loadRouteTable(routingTablePath); 
			}
			else { 
				routerDevice.startRIPTable(); 
			}
			
			// Load ARP cache if provided
			if (arpCachePath != null)
			{ 
				routerDevice.loadArpCache(arpCachePath); 
			}
		}
		
		// Begin processing network packets
		System.out.println("<-- Ready to process packets -->");
		
		// Main processing loop - with special handling for RIP-enabled routers
		if (routingTablePath == null && networkDevice instanceof Router) {
			// For RIP-enabled routers, check RIP timers between processing packets
			Router ripRouter = (Router)networkDevice;
			while (networkComm.readFromServer()) {
				ripRouter.checkLastRIPTime();
			}
		}
		else {
			// Standard packet processing for other devices
			while (networkComm.readFromServer()) {
				// Process packets without additional RIP checks
			}
		}
		
		// Clean up resources
		networkDevice.destroy();
	}
	
	/**
	 * Displays command-line usage information
	 */
	static void displayHelp()
	{
		System.out.println("Virtual Network Client");
		System.out.println("VNet -v host [-s server] [-p port] [-h]");
		System.out.println("     [-r routing_table] [-a arp_cache] [-l log_file]");
		System.out.println(String.format("  defaults server=%s port=%d", 
				DEFAULT_SIMULATOR, NETWORK_PORT));
	}
}