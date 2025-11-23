using System.Net.Sockets;
using System.Text;

namespace SocketServer
{
    internal class Client : BaseClientProperty
    {
        internal Client(Socket clientSocket, string currentNetworkEndpoint, string baseIP, int serverPort)
        {
            this.ClientSocket = clientSocket;
            this.CurrentNetworkEndPoint = currentNetworkEndpoint;
            this.BaseIP = baseIP;
            this.ServerPort = serverPort;
            this.SendLock = new SemaphoreSlim(1, 1);
            this.DataReceivedCallBack += ReadCallBack;
            this.DataSendCallBack += WriteCallBack;
            this.ErrorCloseCallBack += Clean;
            Task.Run(Read);
        }

        internal override async Task Read()
        {
            await ExtendClient.ReceiveWithCallbackAsync(
                this.ClientSocket,
                this.SendLock,
                this.ErrorCloseCallBack,
                this.DataReceivedCallBack,
                CancellationToken.None);
        }


        internal override async Task ReadCallBack(ulong bytesReceived, byte[] data)
        {
            if (Program.CurrentSelectedClient == this)
            {
                string receivedText = Encoding.GetEncoding(850).GetString(data, 0, (int)bytesReceived);
                Console.Write(receivedText);
            }
        }

        internal override async Task Write(byte[] data)
        {
            await ExtendClient.SendWithCallbackAsync(this.ClientSocket, data,this.SendLock, this.ErrorCloseCallBack, this.DataSendCallBack, CancellationToken.None);
        }

        internal override async Task WriteCallBack(ulong bytesSent)
        {
           // Console.WriteLine($"Sent : {bytesSent}");
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
                    Program.Servers[this.ServerPort].Clients.Remove(this.CurrentNetworkEndPoint);
                }
            }

            GC.SuppressFinalize(this);
        }
    }
}