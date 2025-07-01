using System;
using System.IO;
using System.Net;
using System.Text;

namespace G_BotZ.Helpers
{
    public class PacketReader
    {
        private readonly BinaryReader _reader;

        public PacketReader(byte[] data)
        {
            _reader = new BinaryReader(new MemoryStream(data), Encoding.UTF8);
        }

        public int ReadLength()
        {
            return IPAddress.NetworkToHostOrder(_reader.ReadInt32());
        }

        public short ReadHeader()
        {
            return IPAddress.NetworkToHostOrder(_reader.ReadInt16());
        }

        public short ReadShort()
        {
            return IPAddress.NetworkToHostOrder(_reader.ReadInt16());
        }

        public int ReadInt()
        {
            return IPAddress.NetworkToHostOrder(_reader.ReadInt32());
        }

        public string ReadString()
        {
            short length = ReadShort();
            byte[] bytes = _reader.ReadBytes(length);
            return Encoding.UTF8.GetString(bytes);
        }
        public bool ReadBool()
        {
            return _reader.ReadByte() != 0;
        }

        public byte[] ReadBytes(int count)
        {
            return _reader.ReadBytes(count);
        }

        public void Skip(int count)
        {
            _reader.BaseStream.Seek(count, SeekOrigin.Current);
        }

        public int Remaining => (int)(_reader.BaseStream.Length - _reader.BaseStream.Position);
    }
}
