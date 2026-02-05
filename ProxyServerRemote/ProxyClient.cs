using System.Net.Sockets;

namespace ProxyServerRemote
{
    internal class ProxyClient : BaseClientProperty
    {
        internal MasterClient MasterClient;
        internal string RemoteIP;
        internal int RemotePort;

        internal ProxyClient(Socket clientSocket, string currentNetworkEndpoint, string baseIP, int serverPort, string remoteIP, int remotePort)
        {
            this.ClientSocket = clientSocket;
            this.CurrentNetworkEndPoint = currentNetworkEndpoint;
            this.BaseIP = baseIP;
            this.ServerPort = serverPort;
            this.RemoteIP = remoteIP;
            this.RemotePort = remotePort;
            this.SendLock = new SemaphoreSlim(1, 1);
            this.DataReceivedCallBack += ReadCallBack;
            this.DataSendCallBack += WriteCallBack;
            this.ErrorCloseCallBack += Clean;

            // Create MasterClient and connect to real server
            this.MasterClient = new MasterClient(remoteIP, remotePort, this);

            // Start reading from incoming client
            Task.Run(Read);
        }

        // Called when CLIENT sends data to proxy
        internal override async Task Read()
        {
            await ExtendClient.ReceiveWithCallbackAsync(
                this.ClientSocket,
                this.SendLock,
                this.ErrorCloseCallBack,
                this.DataReceivedCallBack,
                CancellationToken.None);
        }

        // Client → Proxy: Forward to real server
        internal override async Task ReadCallBack(ulong bytesReceived, byte[] data)
        {
            byte[] actualData = new byte[bytesReceived];
            Array.Copy(data, 0, actualData, 0, (int)bytesReceived);

            // Forward to real server via MasterClient
            await this.MasterClient.Write(actualData);
        }

        // Called by MasterClient when real server sends data back
        internal override async Task Write(byte[] data)
        {
            await ExtendClient.SendWithCallbackAsync(
                this.ClientSocket,
                data,
                this.SendLock,
                this.ErrorCloseCallBack,
                this.DataSendCallBack,
                CancellationToken.None);
        }

        internal override async Task WriteCallBack(ulong bytesSent)
        {
            // Optional: Track sent bytes
        }

        internal override void Clean()
        {
            if (!this.IsDisposed)
            {
                this.IsDisposed = true;
                lock (this.DisposeObject)
                {
                    this.ClientSocket?.Shutdown(SocketShutdown.Both);
                    this.ClientSocket?.Close();
                    this.ClientSocket?.Dispose();
                    this.ClientSocket = null;

                    Program.ProxyServers[this.ServerPort].Clients.Remove(this.CurrentNetworkEndPoint);
                    this.MasterClient?.Clean();
                }
                GC.SuppressFinalize(this);
            }
        }
    }
}