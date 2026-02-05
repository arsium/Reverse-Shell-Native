using System.Net.Sockets;

namespace ProxyServerRemote
{
    internal abstract class BaseClientProperty
    {
        internal BaseClientProperty() : base()
        {
            this.IsDisposed = false;
            this.DisposeObject = new object();
        }

        internal Socket  ClientSocket;
        internal string CurrentNetworkEndPoint;
        internal SemaphoreSlim SendLock;
        internal ExtendClient.OnDataSentAsync DataSendCallBack;

        internal ExtendClient.OnDataReceivedAsync DataReceivedCallBack;

        internal ExtendClient.OnErrorClosed ErrorCloseCallBack;
        internal string ServerIP = string.Empty;
        internal int ServerPort = 0;
        internal string BaseIP;
        internal int BasePort;


        internal abstract Task Read();
        internal abstract Task ReadCallBack(ulong bytesReceived, byte[] data);
        internal abstract Task Write(byte[] data);
        internal abstract Task WriteCallBack(ulong bytesSent);
        internal abstract void Clean();

        internal bool IsDisposed;
        internal object DisposeObject;
    }
}