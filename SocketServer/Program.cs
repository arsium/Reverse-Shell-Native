using System.Text;

namespace SocketServer
{
    internal class Program
    {
        internal static Dictionary<int, Server> Servers;
        internal static Client CurrentSelectedClient;
        private static bool isInInteractiveMode = false;

        static void Main(string[] args)
        {
            Console.CancelKeyPress += Console_CancelKeyPress;
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Servers = new Dictionary<int, Server>();

            new Thread(static () =>
            {
                Servers.Add(8081, new Server(8081, "*"));
            }).Start();

            MainMenu();
        }

        private static void MainMenu()
        {
            while (true)
            {
                if (!isInInteractiveMode)
                {
                    Console.Write("menu> ");
                }

                string s = Console.ReadLine();

                if (isInInteractiveMode && CurrentSelectedClient != null)
                {
                    CurrentSelectedClient.Write(Encoding.GetEncoding(850).GetBytes(s + "\r\n"));
                    continue;
                }
                string[] split = s.Split(' ');
                string command = split[0].ToLower();

                switch (command)
                {
                    case "display":
                    case "list":
                        foreach (KeyValuePair<int, Server> server in Servers)
                        {
                            foreach (KeyValuePair<string, Client> client in Servers[server.Key].Clients)
                            {
                                Console.WriteLine($"Client: {client.Value.CurrentNetworkEndPoint}");
                            }
                        }
                        break;

                    case "select":
                        if (split.Length < 2)
                        {
                            Console.WriteLine("Usage: select <client_endpoint>");
                            break;
                        }

                        bool found = false;
                        foreach (KeyValuePair<int, Server> server in Servers)
                        {
                            foreach (KeyValuePair<string, Client> client in Servers[server.Key].Clients)
                            {
                                if (client.Value.CurrentNetworkEndPoint.Contains(split[1]))
                                {
                                    CurrentSelectedClient = client.Value;
                                    Console.WriteLine($"[+] Selected client: {client.Value.CurrentNetworkEndPoint}");
                                    found = true;
                                    break;
                                }
                            }
                            if (found) break;
                        }

                        if (!found)
                        {
                            Console.WriteLine("[-] Client not found.");
                        }
                        break;

                    case "interact":
                    case "shell":
                        if (CurrentSelectedClient == null)
                        {
                            Console.WriteLine("[-] No client selected. Use 'select <endpoint>' first.");
                            break;
                        }

                        Console.WriteLine($"[+] Entering interactive mode with {CurrentSelectedClient.CurrentNetworkEndPoint}");
                        Console.WriteLine("[*] Press Ctrl+C to exit interactive mode");
                        isInInteractiveMode = true;
                        CurrentSelectedClient.Write(Encoding.GetEncoding(850).GetBytes("\r\n"));
                        break;

                    case "help":
                        Console.WriteLine("Commands:");
                        Console.WriteLine("  display/list          - Show all connected clients");
                        Console.WriteLine("  select <endpoint>     - Select a client");
                        Console.WriteLine("  interact/shell        - Enter interactive shell with selected client");
                        Console.WriteLine("  exit                  - Exit the program");
                        break;

                    case "exit":
                    case "quit":
                        Console.WriteLine("[*] Exiting program...");
                        Environment.Exit(0);
                        break;

                    default:
                        Console.WriteLine($"Unknown command: {command}. Type 'help' for available commands.");
                        break;
                }
            }
        }

        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true; 
            if (isInInteractiveMode)
            {
                Console.WriteLine("\n[*] Exiting interactive mode...");
                isInInteractiveMode = false;
                CurrentSelectedClient = null;
                Console.WriteLine("[+] Returned to main menu.");
                Console.Write("menu> ");
            }
            else
            {
                Console.WriteLine("\n[*] Press Ctrl+C again to exit or type 'exit'");
            }
        }
    }
}