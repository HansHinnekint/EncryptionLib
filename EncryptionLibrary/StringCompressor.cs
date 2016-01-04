using System;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace EncryptionLibrary
{
    public static class StringCompressor
    {
        public static string CompressString(string TheStringToCompress)
        {
            byte[] myBuffer = Encoding.UTF8.GetBytes(TheStringToCompress);
            var myMemoryStream = new MemoryStream();
            using (var myGZipStream = new GZipStream(myMemoryStream, CompressionMode.Compress, true))
            {
                myGZipStream.Write(myBuffer, 0, myBuffer.Length);
            }

            myMemoryStream.Position = 0;

            var myCompressedData = new byte[myMemoryStream.Length];
            myMemoryStream.Read(myCompressedData, 0, myCompressedData.Length);

            var myGZipBuffer = new byte[myCompressedData.Length + 4];
            Buffer.BlockCopy(myCompressedData, 0, myGZipBuffer, 4, myCompressedData.Length);
            Buffer.BlockCopy(BitConverter.GetBytes(myBuffer.Length), 0, myGZipBuffer, 0, 4);

            return Convert.ToBase64String(myGZipBuffer);
        }

        
        public static string DecompressString(string TheCompressedString)
        {
            byte[] myGZipBuffer = Convert.FromBase64String(TheCompressedString);
            using (var myMemoryStream = new MemoryStream())
            {
                int myDataLength = BitConverter.ToInt32(myGZipBuffer, 0);
                myMemoryStream.Write(myGZipBuffer, 4, myGZipBuffer.Length - 4);

                var myBuffer = new byte[myDataLength];

                myMemoryStream.Position = 0;
                using (var myGZipStream = new GZipStream(myMemoryStream, CompressionMode.Decompress))
                {
                    myGZipStream.Read(myBuffer, 0, myBuffer.Length);
                }

                return Encoding.UTF8.GetString(myBuffer);
            }
        }

    }
}
