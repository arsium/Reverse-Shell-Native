using System.Net.Sockets;
using System.Text;

namespace ProxyServerRemote
{
    internal class MasterClient : BaseClientProperty
    {
        private ProxyClient ProxyClient; // Reference back to ProxyClient
        internal MasterClient(string baseIP, int serverPort, ProxyClient proxyClient)
        {
            this.BaseIP = baseIP;
            this.ServerPort = serverPort;
            this.ProxyClient = proxyClient;
            this.SendLock = new SemaphoreSlim(1, 1);
            this.DataReceivedCallBack += ReadCallBack;
            this.DataSendCallBack += WriteCallBack;
            this.ErrorCloseCallBack += Clean;

            Task.Run(Connect);
        }

        internal async Task Connect()
        {
            bool connected = await ConnectAsync();
            if (connected && this.ClientSocket.Connected)
            {
                _ = Task.Run(Read);
            }
            else
            {
                await Connect();
            }
        }

        protected async Task<bool> ConnectAsync()
        {
            try
            {
                this.ClientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                await Task.Factory.FromAsync(
                    (callback, state) => this.ClientSocket.BeginConnect(this.BaseIP, this.ServerPort, callback, state),
                    this.ClientSocket.EndConnect,
                    null);

                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        // Read from real server
        internal override async Task Read()
        {
            await ExtendClient.ReceiveWithCallbackAsync(
                this.ClientSocket,
                this.SendLock,
                this.ErrorCloseCallBack,
                this.DataReceivedCallBack,
                CancellationToken.None);
        }

        // Server → Proxy: Forward back to ProxyClient
        internal override async Task ReadCallBack(ulong bytesReceived, byte[] data)
        {
            // Display what the real server sent
       //     string receivedText = Encoding.GetEncoding(850).GetString(data, 0, (int)bytesReceived);
        //    Console.Write(receivedText);

            // Extract only the actual bytes received
            byte[] actualData = new byte[bytesReceived];
            Array.Copy(data, 0, actualData, 0, (int)bytesReceived);

            // Forward back to original client via ProxyClient
            await this.ProxyClient.Write(actualData);
        }

        // ProxyClient calls this to send to real server
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
                }
                GC.SuppressFinalize(this);
            }
        }
    }
}
