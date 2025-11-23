using System.Net.Sockets;

namespace SocketServer
{
    internal static class ExtendClient
    {

        public delegate Task OnDataSentAsync(ulong bytesSent);

        public delegate Task OnDataReceivedAsync(ulong bytesReceived, byte[] data);

        public delegate void OnErrorClosed();
        internal static async Task SendWithCallbackAsync(Socket socket, byte[] data, SemaphoreSlim sendLock, OnErrorClosed onErrorClosed, OnDataSentAsync callback = null, CancellationToken cancellationToken = default)
        {
            try
            {
                await sendLock.WaitAsync(cancellationToken);
                try
                {
                    ulong totalSent = 0;
                    while (totalSent < (ulong)data.Length)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        int bytesToSend = (int)Math.Min((ulong)data.Length - totalSent, int.MaxValue);
                        int sent = await Task.Factory.FromAsync(
                            (cb, state) => socket.BeginSend(
                                data,
                                (int)totalSent,
                                bytesToSend,
                                SocketFlags.None,
                                cb,
                                state),
                            socket.EndSend,
                            null);

                        if (sent == 0)
                            break;

                        totalSent += (ulong)sent;
                    }
                    if (callback != null)
                    {
                        _ = callback(totalSent);
                    }
                }
                finally
                {
                    sendLock.Release();
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                onErrorClosed();
                Console.WriteLine($"Error sending data: {ex.Message}");
                throw;
            }
        }

  
        internal static async Task ReceiveWithCallbackAsync(Socket socket,SemaphoreSlim sendLock,OnErrorClosed onErrorClosed,OnDataReceivedAsync receivedCallback = null,CancellationToken cancellationToken = default)
        {
            byte[] dataBuffer = new byte[1024];

            while (true)  
            {
                try
                {
                    int bytesRead = await Task.Factory.FromAsync(
                        (cb, state) => socket.BeginReceive(
                            dataBuffer, 0, dataBuffer.Length,
                            SocketFlags.None, cb, state),
                        socket.EndReceive,
                        null);

                    if (bytesRead > 0)
                    {
                        if (receivedCallback != null)
                        {
                            byte[] actualData = new byte[bytesRead];
                            Buffer.BlockCopy(dataBuffer, 0, actualData, 0, bytesRead);
                            await receivedCallback((ulong)bytesRead, actualData);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Remote closed connection");
                        break;  // Exit loop
                    }
                }
                catch (SocketException ex)
                {
                    Console.WriteLine($"Socket error: {ex.SocketErrorCode}");
                    onErrorClosed();
                    break;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                    onErrorClosed();
                    throw;
                }
            }
        }
    }
}