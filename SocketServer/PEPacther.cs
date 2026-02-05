using System.Net;

namespace SocketServer
{
    internal static class PEPacther
    {
        internal static void Patch(string ip, string port, string outName = "patched") 
        {
            if (File.Exists("base.exe"))
            {
                byte[] ipBytes = IPAddress.Parse(ip).GetAddressBytes();
                byte[] portBytes = BitConverter.GetBytes(ushort.Parse(port)); // Already little-endian on Windows
                                                                              //Array.Reverse(ipBytes); // Convert IP from big-endian to little-endian
                Array.Reverse(portBytes);

                byte[] combined = new byte[portBytes.Length + ipBytes.Length];
                Buffer.BlockCopy(portBytes, 0, combined, 0, portBytes.Length);
                Buffer.BlockCopy(ipBytes, 0, combined, portBytes.Length, ipBytes.Length); byte[] data = new byte[] { 0x1F, 0x91, 0x7F, 0x00, 0x00, 0x01 };
                Console.WriteLine("Old network endpoint:" + BytePattern.FormatByteArrayToHex(data));
                Console.WriteLine("New network endpoint:" + BytePattern.FormatByteArrayToHex(combined));
                PatchSignature("base.exe", data, combined, 6 , outName).Wait();
            }
            else 
            {
                Console.WriteLine($"[-] Missing base.exe file !");
            }
        }

        internal static async Task<byte[]> PatchSignature(string filePath, byte[] data, byte[] newData ,int sizeOfData, string outName)//SectionSignature.SIGNATURE_SIZE
        {
            return await Task.Run(() =>
            {
                byte[] raw = File.ReadAllBytes(filePath);

                byte[] patched = BytePattern.ReplacePatternWithSize(raw, data, newData, sizeOfData);

                File.WriteAllBytes(outName + ".exe", patched);

                return newData;
            });
        }
    }
}
