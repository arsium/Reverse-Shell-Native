
namespace ProxyServerRemote
{
    internal class Program
    {
        internal static Dictionary<int, ProxyServer> ProxyServers;
        internal static string RemoteIP = string.Empty;
        internal static int RemotePort = 0;
        internal static int LocalPort = 0;
        static void Main(string[] args)
        {
            Console.WriteLine("______                               _____ _          _ _   _   _       _   _           \r\n| ___ \\                             /  ___| |        | | | | \\ | |     | | (_)          \r\n| |_/ /_____   _____ _ __ ___  ___  \\ `--.| |__   ___| | | |  \\| | __ _| |_ ___   _____ \r\n|    // _ \\ \\ / / _ \\ '__/ __|/ _ \\  `--. \\ '_ \\ / _ \\ | | | . ` |/ _` | __| \\ \\ / / _ \\\r\n| |\\ \\  __/\\ V /  __/ |  \\__ \\  __/ /\\__/ / | | |  __/ | | | |\\  | (_| | |_| |\\ V /  __/\r\n\\_| \\_\\___| \\_/ \\___|_|  |___/\\___| \\____/|_| |_|\\___|_|_| \\_| \\_/\\__,_|\\__|_| \\_/ \\___|\r\n                                                                                        \r\n                                                                                        ");

          
            Program.LocalPort = int.Parse(args[0]);
            Program.RemoteIP = args[1];
            Program.RemotePort = int.Parse(args[2]);

            Console.WriteLine($"Proxy listening on :{Program.LocalPort}\nRemote EP:{Program.RemoteIP}:{Program.RemotePort}\n");

            ProxyServers = new Dictionary<int, ProxyServer>();
            new Thread(static () =>
            {
                ProxyServers.Add(8082, new ProxyServer(8082, "*"));
            }).Start();

            Thread.Sleep(-1);
        }
    }
}