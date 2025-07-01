using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using G_BotZ.Helpers;
using static G_BotZ.Helpers.G_MemzHelper;

namespace G_BotZ.Proxy
{
    public class ReverseProxy
    {
        private readonly string _remoteHost;
        private readonly int _remotePort;
        private readonly int _localPort;
        private bool RC4Active = false;

        public ReverseProxy(string remoteHost, int remotePort, int localPort)
        {
            _remoteHost = remoteHost;
            _remotePort = remotePort;
            _localPort = localPort;
        }

        public async Task StartAsync()
        {
            var listener = new TcpListener(IPAddress.Loopback, _localPort);
            listener.Start();
            Console.WriteLine($"Listening on 127.0.0.1:{_localPort}...");

            while (true)
            {
                var client = await listener.AcceptTcpClientAsync();
                _ = HandleSessionAsync(client);
            }
        }

        private async Task HandleSessionAsync(TcpClient client)
        {
            TcpClient server = null;
            try
            {
                server = new TcpClient();
                await server.ConnectAsync(_remoteHost, _remotePort);

                var clientStream = client.GetStream();
                var serverStream = server.GetStream();

                await Task.WhenAll(
                    ForwardDataAsync(clientStream, serverStream, PacketDirection.Out),
                    ForwardDataAsync(serverStream, clientStream, PacketDirection.In)
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling session: {ex.Message}");
            }
            finally
            {
                client?.Close();
                server?.Close();
            }
        }

        private async Task ForwardDataAsync(NetworkStream fromStream, NetworkStream toStream, PacketDirection direction)
        {
            var buffer = new List<byte>();
            var tempBuffer = new byte[8192];

            try
            {
                while (true)
                {
                    int bytesRead = await fromStream.ReadAsync(tempBuffer, 0, tempBuffer.Length);
                    if (bytesRead == 0) break;

                    buffer.AddRange(new ArraySegment<byte>(tempBuffer, 0, bytesRead));

                    while (buffer.Count >= 4)
                    {
                        if (RC4Active)
                        {
                            string hex = RunGMemzAndGetRc4Hex();
                            Console.WriteLine($"HEX: {hex}");

                            if (buffer.Count >= 6)
                            {
                                var trialBuf = buffer.Take(Math.Min(buffer.Count, 512)).ToArray();
                                var result = BruteforceRC4(hex, trialBuf);

                                if (result.HasValue)
                                {
                                    var (i, j, decrypted) = result.Value;
                                    int len = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(decrypted, 0));
                                    if (len > 0 && decrypted.Length >= len + 4)
                                    {
                                        byte[] cleanPacket = decrypted.Take(len + 4).ToArray();
                                        Console.WriteLine($"✅ Decrypted Packet: {BitConverter.ToString(cleanPacket)}");

                                        var reader = new PacketReader(cleanPacket);
                                        int packetLength = reader.ReadLength();
                                        short header = reader.ReadHeader();
                                        Console.WriteLine($"{direction} [Header: {header}] Length: {packetLength}");

                                        await toStream.WriteAsync(buffer.Take(len + 4).ToArray());
                                        buffer.RemoveRange(0, len + 4);
                                        continue;
                                    }
                                }
                                else Console.WriteLine("❌ Failed to bruteforce RC4.");
                            }

                            break;
                        }
                        else
                        {
                            int length = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(buffer.ToArray(), 0));
                            int fullPacketLength = length + 4;
                            if (buffer.Count < fullPacketLength) break;

                            var packetData = buffer.GetRange(0, fullPacketLength).ToArray();
                            buffer.RemoveRange(0, fullPacketLength);

                            var reader = new PacketReader(packetData);
                            int packetLength = reader.ReadLength();
                            short header = reader.ReadHeader();
                            Console.WriteLine($"{direction} [Header: {header}] Length: {packetLength}");

                            if (header == 4000 && direction == PacketDirection.Out)
                            {
                                string rel = reader.ReadString();
                                string type = reader.ReadString();
                                int major = reader.ReadInt();
                                int minor = reader.ReadInt();
                                Console.WriteLine($"ClientHello -> {rel} {type} {major} {minor}");
                            }
                            else if (header == 3968 && direction == PacketDirection.Out)
                            {
                                Console.WriteLine($"InitDiffieHandshake");
                            }
                            else if (header == 325 && direction == PacketDirection.In)
                            {
                                string dhp = reader.ReadString();
                                string dhg = reader.ReadString();
                                Console.WriteLine($"P: {dhp}\nG: {dhg}");
                            }
                            else if (header == 482 && direction == PacketDirection.Out)
                            {
                                string s = reader.ReadString();
                                Console.WriteLine($"S:{s}");
                            }
                            else if (header == 3578 && direction == PacketDirection.In)
                            {
                                string text = reader.ReadString();
                                bool switchToRC4 = reader.ReadBool();
                                Console.WriteLine($"DH: {text}\nBool: {switchToRC4}");
                                RC4Active = !switchToRC4;
                            }

                            await toStream.WriteAsync(packetData, 0, packetData.Length);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error forwarding data ({direction}): {ex.Message}");
            }
        }
    }

    public enum PacketDirection
    {
        In,
        Out
    }
}
