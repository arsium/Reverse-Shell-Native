using System.Net;
using System.Net.Sockets;

namespace SocketServer
{
    internal class ProxyServer
    {
        private Socket Listener;
        internal int Port;
        internal Dictionary<string, ProxyClient> Clients;
        internal bool IsProtectorEnable;
        internal ProxyServer(int port, string localEndPoint) : base()
        {
            this.IsProtectorEnable = true;
            this.Port = port;
            this.Clients = new Dictionary<string, ProxyClient>();
            this.Listener = new Socket(SocketType.Stream, ProtocolType.Tcp);
            this.Listener.Bind(new IPEndPoint(localEndPoint == "*" ? IPAddress.Any : IPAddress.Parse(localEndPoint), port));
            Task.Run(StartAsync);
        }

        internal async Task StartAsync()
        {
            this.Listener.Listen();

            while (true)
            {
                Socket plainSocket = await Task.Factory.FromAsync(
                    this.Listener.BeginAccept,
                    this.Listener.EndAccept,
                    null);

                _ = HandleClientAsync(plainSocket);
            }
        }

        private async Task HandleClientAsync(Socket plainSocket)
        {
            string ip = ((IPEndPoint)plainSocket.RemoteEndPoint).Address.MapToIPv4().ToString();

            try
            {
                Console.WriteLine($"\nNew proxy client: {plainSocket.RemoteEndPoint}");
                Console.Write("menu>");
                this.Clients.Add(plainSocket.RemoteEndPoint.ToString(), new ProxyClient(plainSocket, plainSocket.RemoteEndPoint.ToString(), ip, this.Port, "192.168.1.2", 8081));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling client: {ex.Message}");
            }
        }
    }
}