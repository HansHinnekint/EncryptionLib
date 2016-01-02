using System;
using System.Threading;
using System.Threading.Tasks;

#if WINDOWS_UWP
using Windows.Storage.Streams;
using Windows.Networking;
using Windows.Networking.Sockets;
#else
using System.Net;
using System.Net.Sockets;
#endif

namespace EncryptionLibrary
{
    public class DateTimeGenerator
    {
#if WINDOWS_UWP
        private TaskCompletionSource<DateTime> myResultCompletionSource;
#endif
        private static DateTimeGenerator myInstance;

        //-------------------------------------------------------------------------------------------------
        //--- Singleton, make sure that only 1 Instance of the class exists
        //-------------------------------------------------------------------------------------------------
        public static DateTimeGenerator Instance
        {
            get
            {
                if (myInstance == null)
                {
                    myInstance = new DateTimeGenerator();
                }

                return myInstance;
            }
        }

        //-------------------------------------------------------------------------------------------------
        //--- Private constructor to initialise the internal variables
        //-------------------------------------------------------------------------------------------------
        private DateTimeGenerator()
        {
#if WINDOWS_UWP
            myResultCompletionSource = null;
#endif 
        }       
        
        //-------------------------------------------------------------------------------------------------
        //--- Get the time from a public NTP server
        //-------------------------------------------------------------------------------------------------
        public async Task<DateTime> GetNetworkUTCTime()
        {
            const string myNTPServer = "pool.ntp.org";
            DateTime TheNetworkTime;


            // NTP message size - 16 bytes of the digest (RFC 2030)
            var myNTPDataArray = new byte[48];

            //Setting the Leap Indicator, Version Number and Mode values
            myNTPDataArray[0] = 0x1B; //LI = 0 (no warning), VN = 3 (IPv4 only), Mode = 3 (Client Mode)

            try
            {
#if WINDOWS_UWP
                using (var mySocket = new DatagramSocket())
                using (var ct = new CancellationTokenSource(3000))
                {
                    ct.Token.Register(() => myResultCompletionSource.TrySetCanceled());

                    mySocket.MessageReceived += OnSocketMessageReceived;
                    //The UDP port number assigned to NTP is 123
                    await mySocket.ConnectAsync(new HostName(myNTPServer), "123");
                    using (var writer = new DataWriter(mySocket.OutputStream))
                    {
                        writer.WriteBytes(myNTPDataArray);
                        await writer.StoreAsync();
                        TheNetworkTime = await myResultCompletionSource.Task;
                    }
                }
#else
                var myAddresses = Dns.GetHostEntry(myNTPServer).AddressList;

                //The UDP port number assigned to NTP is 123
                var myIPEndPoint = new IPEndPoint(myAddresses[0], 123);
                //NTP uses UDP
                using (var mySocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    await Task.Run(() =>
                        {
                            mySocket.Connect(myIPEndPoint);

                            //Stops code hang if NTP is blocked
                            mySocket.ReceiveTimeout = 3000;

                            mySocket.Send(myNTPDataArray);
                            mySocket.Receive(myNTPDataArray);
                        }
                    );
                    mySocket.Close();
                }
#endif
                TheNetworkTime = ParseNetworkTime(myNTPDataArray);
            }
            catch (Exception ex)
            {
                TheNetworkTime = DateTime.UtcNow;
            }

            return TheNetworkTime;
        }

#region Helper Internal methods
        //-------------------------------------------------------------------------------------------------
        //--- Helper Internal methods
        //-------------------------------------------------------------------------------------------------
        private DateTime ParseNetworkTime(byte[] TheByteArray)
        {
            DateTime TheNetworkTime;
            //Offset to get to the "Transmit Timestamp" field (time at which the reply 
            //departed the server for the client, in 64-bit timestamp format."
            const byte TheServerReplyTime = 40;

            //Get the seconds part
            ulong TheIntPart = BitConverter.ToUInt32(TheByteArray, TheServerReplyTime);

            //Get the seconds fraction
            ulong TheFractPart = BitConverter.ToUInt32(TheByteArray, TheServerReplyTime + 4);

            //Convert From big-endian to little-endian
            TheIntPart = SwapEndianness(TheIntPart);
            TheFractPart = SwapEndianness(TheFractPart);

            var TheMilliseconds = (TheIntPart * 1000) + ((TheFractPart * 1000) / 0x100000000L);

            //**UTC** time
            TheNetworkTime = (new DateTime(1900, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds((long)TheMilliseconds);

            //Adapt for empty ByteArray
            if (DateTime.Equals(TheNetworkTime, new DateTime(1900, 1, 1)))
                TheNetworkTime = DateTime.UtcNow;

            return TheNetworkTime;
        }

#if WINDOWS_UWP
        private void OnSocketMessageReceived(DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
            try
            {
                using (var reader = args.GetDataReader())
                {
                    byte[] response = new byte[48];
                    reader.ReadBytes(response);
                    myResultCompletionSource.TrySetResult(ParseNetworkTime(response));
                }
            }
            catch (Exception ex)
            {
                myResultCompletionSource.TrySetException(ex);
            }
        }
#endif

        // stackoverflow.com/a/3294698/162671
        private uint SwapEndianness(ulong x)
        {
            return (uint)(((x & 0x000000ff) << 24) +
                           ((x & 0x0000ff00) << 8) +
                           ((x & 0x00ff0000) >> 8) +
                           ((x & 0xff000000) >> 24));
        }

#endregion

    }
}
