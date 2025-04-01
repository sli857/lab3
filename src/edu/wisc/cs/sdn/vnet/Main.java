package edu.wisc.cs.sdn.vnet;
import edu.wisc.cs.sdn.vnet.rt.Router;
import edu.wisc.cs.sdn.vnet.sw.Switch;
import edu.wisc.cs.sdn.vnet.vns.Command;
import edu.wisc.cs.sdn.vnet.vns.VNSComm;

public class Main 
{
	private static final short COMM_PORT = 8888;
	private static final String COMM_ADDRESS = "localhost";
	
	public static void main(String[] args)
	{
		String nodeId = null;
		String serverAddress = COMM_ADDRESS;
		String routingConfig = null;
		String arpConfig = null;
		String packetLog = null;
		short serverPort = COMM_PORT;
		VNSComm networkComm = null;
		Device networkNode = null;
		
		// Process command line args
		for(int i = 0; i < args.length; i++)
		{
			String currentArg = args[i];
			if (currentArg.equals("-h"))
			{
				showHelp();
				return;
			}
			else if(currentArg.equals("-p"))
			{ serverPort = Short.parseShort(args[++i]); }
			else if (currentArg.equals("-v"))
			{ nodeId = args[++i]; }
			else if (currentArg.equals("-s"))
			{ serverAddress = args[++i]; }
			else if (currentArg.equals("-l"))
			{ packetLog = args[++i]; }
			else if (currentArg.equals("-r"))
			{ routingConfig = args[++i]; }
			else if (currentArg.equals("-a"))
			{ arpConfig = args[++i]; }
		}
		
		if (nodeId == null)
		{
			showHelp();
			return;
		}
		
		// Configure packet logging if requested
		DumpFile packetDump = null;
		if (packetLog != null)
		{
			packetDump = DumpFile.open(packetLog);
			if (packetDump == null)
			{
				System.err.println("Failed to open log file: " + packetLog);
				return;
			}
		}
		
		// Initialize appropriate network device
		if (nodeId.startsWith("s"))
		{ networkNode = new Switch(nodeId, packetDump); }
		else if (nodeId.startsWith("r"))
		{ networkNode = new Router(nodeId, packetDump); }
		else 
		{
			System.err.println("Invalid device ID format - must begin with 's' or 'r'");
			return;
		}
		
		// Establish connection to network simulator
		System.out.println("Initializing connection to " + serverAddress + ":" + serverPort);
		networkComm = new VNSComm(networkNode);
		if (!networkComm.connectToServer(serverPort, serverAddress))
		{ System.exit(1); }
		networkComm.readFromServerExpect(Command.VNS_HW_INFO);	
		
		// Configure router-specific options if applicable
		if (networkNode instanceof Router) 
		{
			Router routerNode = (Router)networkNode;
			
			if (routingConfig != null)
			{ routerNode.loadRouteTable(routingConfig); }
			else 
			{ routerNode.startRIPTable(); }
			
			if (arpConfig != null)
			{ routerNode.loadArpCache(arpConfig); }
		}
		
		System.out.println(">>> Network device initialized and ready <<<");
		
		// Main processing loop
		if (routingConfig == null && networkNode instanceof Router) {
			handleRIPUpdates((Router)networkNode, networkComm);
		}
		else {
			while (networkComm.readFromServer()) {
				// Process packets until server disconnects
			}
		}
		
		// Clean up resources
		networkNode.destroy();
	}
	
	private static void handleRIPUpdates(Router router, VNSComm comm) {
		boolean[] active = {true};
		Router[] routerRef = {router};
		
		Thread updateThread = new Thread(() -> {
			while (active[0]) {
				try {
					routerRef[0].checkLastRIPTime();
					Thread.sleep(100);
				} catch (InterruptedException e) {
					System.err.println("RIP update thread terminated");
					active[0] = false;
				}
			}
		});
		
		updateThread.start();
		
		while (comm.readFromServer()) {
			// Process packets while maintaining RIP updates
		}
		
		active[0] = false;
		try {
			updateThread.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	static void showHelp()
	{
		System.out.println("SDN Virtual Network Client");
		System.out.println("Usage: VNet -v host [-s server] [-p port] [-h]");
		System.out.println("       [-r routing_table] [-a arp_cache] [-l log_file]");
		System.out.println("Default: server=" + COMM_ADDRESS + ", port=" + COMM_PORT);
	}
}
