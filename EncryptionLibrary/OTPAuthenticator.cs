using System;
using System.Linq;
using System.Threading.Tasks;


#if WINDOWS_UWP
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
#else
using System.Security.Cryptography;
#endif

namespace EncryptionLibrary
{
    /// <summary>
    /// Simple OneTime Password Generator and Validator
    /// Look at Google Authenticator for samples
    /// </summary>
    /// <remarks>Cleaned up code from https://hanshinnekint.wordpress.com/create-shared-project-for-otp-handling/ </remarks>

    public static class OTPAuthenticator
    {
        //-------------------------------------------------------------------------------------------------
        //--- Generate a OneTime Password from a Guid
        //-------------------------------------------------------------------------------------------------
        public static async Task<int> OTPFromGuid(Guid TheGuid, bool UseNetworkTime = false)
        {
            Int64 myTimeStamp;
            byte[] mySecret;
            byte[] myHmac;
            byte[] myData;
            int myOffset;
            int myOneTimePassword;
            Int64 MyUnixTimestamp;

            mySecret = StringToBytes(TheGuid.ToString("N"));

#if WINDOWS_UWP
            var myCryptprovider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha1);
#else
            HMACSHA1 crypt = new HMACSHA1(mySecret);
#endif
            MyUnixTimestamp = await GetUnixTimestamp(UseNetworkTime);
            myTimeStamp = Convert.ToInt64(MyUnixTimestamp / 30);
            myData = BitConverter.GetBytes(myTimeStamp).Reverse().ToArray();

#if WINDOWS_UWP
            var myBuffer = CryptographicBuffer.CreateFromByteArray(myData);
            var myKeyBuffer = CryptographicBuffer.CreateFromByteArray(mySecret);

            var myKey = myCryptprovider.CreateKey(myKeyBuffer);
            var mySignedBuffer = CryptographicEngine.Sign(myKey, myBuffer);

            CryptographicBuffer.CopyToByteArray(mySignedBuffer, out myHmac);
#else
            myHmac = new HMACSHA1(mySecret).ComputeHash(myData);
#endif
            myOffset = myHmac.Last() & 0x0F;
            myOneTimePassword = (
                ((myHmac[myOffset + 0] & 0x7f) << 24) |
                ((myHmac[myOffset + 1] & 0xff) << 16) |
                ((myHmac[myOffset + 2] & 0xff) << 8) |
                (myHmac[myOffset + 3] & 0xff)
                    ) % 1000000;

            return myOneTimePassword;
        }

        //-------------------------------------------------------------------------------------------------
        //--- Check if a provided OTP is valid for the proviided GUID (allow 3 past + 3 future ones)
        //-------------------------------------------------------------------------------------------------
        public static async Task<bool> IsValidOTPFromGuid(Guid TheGuid, int TheOTPToCheck, bool UseNetworkTime = false)
        {
            bool success = false;
            int myNumberOfOTPs = 7;

            Int64 myTimeStamp;
            byte[] mySecret;
            byte[] myHmac;
            byte[] myData;
            int myOffset;
            int myOneTimePassword;
            Int64 MyUnixTimestamp;

            int[] myAllowedOTPArray = new int[myNumberOfOTPs];

            mySecret = StringToBytes(TheGuid.ToString("N"));

#if WINDOWS_UWP
            var myCryptprovider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha1);
#else
            HMACSHA1 myCryptprovider = new HMACSHA1(mySecret);
#endif
            MyUnixTimestamp = await GetUnixTimestamp(UseNetworkTime);
            myTimeStamp = Convert.ToInt64(MyUnixTimestamp / 30);
            for (int i = 0; i < myNumberOfOTPs; i++)
            {
                //current timestamp = myTimeStamp(-0)
                //So we allow the previous 3 values and future 3 values as well

                myData = BitConverter.GetBytes(myTimeStamp + i - 3).Reverse().ToArray();

#if WINDOWS_UWP
            var myBuffer = CryptographicBuffer.CreateFromByteArray(myData);
            var myKeyBuffer = CryptographicBuffer.CreateFromByteArray(mySecret);

            var myKey = myCryptprovider.CreateKey(myKeyBuffer);
            var mySignedBuffer = CryptographicEngine.Sign(myKey, myBuffer);

            CryptographicBuffer.CopyToByteArray(mySignedBuffer, out myHmac);
#else
                myHmac = new HMACSHA1(mySecret).ComputeHash(myData);
#endif

                myOffset = myHmac.Last() & 0x0F;
                myOneTimePassword = (
                    ((myHmac[myOffset + 0] & 0x7f) << 24) |
                    ((myHmac[myOffset + 1] & 0xff) << 16) |
                    ((myHmac[myOffset + 2] & 0xff) << 8) |
                    (myHmac[myOffset + 3] & 0xff)
                        ) % 1000000;
                myAllowedOTPArray[i] = myOneTimePassword;
            }

            //do the check
            int index = 0;

            while ((index < myNumberOfOTPs) & (!success))
            {
                success = myAllowedOTPArray[index] == TheOTPToCheck;
                index++;
            }
            return success;
        }


    #region Helper Internal methods

    //-------------------------------------------------------------------------------------------------
    //--- Helper Internal methods
    //-------------------------------------------------------------------------------------------------
    private static byte[] StringToBytes(string TheString)
        {
            string myHexString = TheString;

            //The binary key cannot have an odd number of digits, so Add a trailing 0
            if (myHexString.Length % 2 == 1) myHexString = TheString + "0";

            byte[] myArray = new byte[myHexString.Length >> 1];

            for (int i = 0; i < myHexString.Length >> 1; ++i)
            {
                myArray[i] = (byte)((GetHexVal(myHexString[i << 1]) << 4) + (GetHexVal(myHexString[(i << 1) + 1])));
            }

            return myArray;
        }

        private static int GetHexVal(char TheHexChar)
        {
            int myValue = (int)TheHexChar;
            //For uppercase A-F letters:
            //return myValue - (myValue < 58 ? 48 : 55);
            //For lowercase a-f letters:
            //return myValue - (myValue < 58 ? 48 : 87);
            //Or the two combined, but a bit slower:
            return myValue - (myValue < 58 ? 48 : (myValue < 97 ? 55 : 87));
        }

        private static async Task<Int64> GetUnixTimestamp(bool UseNetworkTime = false)
        {
            DateTime TheTime;
            DateTimeGenerator myDTG;

            if (UseNetworkTime)
            {
                myDTG = DateTimeGenerator.Instance;
                TheTime = await myDTG.GetNetworkUTCTime();
            }
            else
            {
                TheTime = DateTime.UtcNow;
            }
            
            return Convert.ToInt64(Math.Round((TheTime - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds));
        }
#endregion

    }
}
