using System;
using System.Text;
using System.IO;
using System.Linq;

#if WINDOWS_UWP
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
#else
using System.Security.Cryptography;
#endif

namespace EncryptionLibrary
{
    /// <summary>
    /// Simple AES encryption/decryption using a random initialization vector
    /// and prepending it to the crypto text.
    /// </summary>
    /// <remarks>Based on multiple answers in http://stackoverflow.com/questions/165808/simple-two-way-encryption-for-c-sharp </remarks>
    /// <remarks>and http://codereview.stackexchange.com/questions/36453/aes-encryption-c-net

    public class StringEncryptor
    {
        private static StringEncryptor myInstance;

        private static Random myRandomGenerator;
        private static byte[] myKeyArray;
        private static UTF8Encoding myEncoder;

#if WINDOWS_UWP
        private static SymmetricKeyAlgorithmProvider myCryptoAlgorithm;
        private static CryptographicKey key;
        private IBuffer keymaterial;
#else
        private static AesCryptoServiceProvider myCryptoAlgorithm;
#endif
        //-------------------------------------------------------------------------------------------------
        //--- Singleton, make sure that only 1 Instance of the class exists
        //-------------------------------------------------------------------------------------------------

        public static StringEncryptor Instance
        {
            get
            {
                if (myInstance == null)
                {
                    myInstance = new StringEncryptor();
                }

                return myInstance;
            }
        }

        //-------------------------------------------------------------------------------------------------
        //--- Private constructor to initialise the internal variables
        //-------------------------------------------------------------------------------------------------

        private StringEncryptor()
        {
            myRandomGenerator = new Random();
            myEncoder = new UTF8Encoding();
            myKeyArray = Convert.FromBase64String("9F11BCE0+DC17+42CA+BE52+6D9CD15A");

#if WINDOWS_UWP
            myCryptoAlgorithm = SymmetricKeyAlgorithmProvider.OpenAlgorithm("AES_CBC_PKCS7");
            keymaterial = CryptographicBuffer.CreateFromByteArray(myKeyArray);
            key = myCryptoAlgorithm.CreateSymmetricKey(keymaterial);
#else
            myCryptoAlgorithm = new AesCryptoServiceProvider();
            myCryptoAlgorithm.Mode = CipherMode.CBC;
            myCryptoAlgorithm.Padding = PaddingMode.PKCS7;

            myCryptoAlgorithm.KeySize = 256;
            myCryptoAlgorithm.BlockSize = 128;
#endif
        }

        //-------------------------------------------------------------------------------------------------
        //--- Method to Encrypt a String
        //-------------------------------------------------------------------------------------------------

        public string Encrypt(string anUnencryptedString)
        {
            var myVector = new byte[16];
            myRandomGenerator.NextBytes(myVector);

            var myCryptogram = myVector.Concat(EncryptFromBuffer(myEncoder.GetBytes(anUnencryptedString), myVector));

            return Convert.ToBase64String(myCryptogram.ToArray());
        }

        //-------------------------------------------------------------------------------------------------
        //--- Method to Decrypt a String
        //-------------------------------------------------------------------------------------------------
        public string Decrypt(string anEncryptedString)
        {
            var myCryptogram = Convert.FromBase64String(anEncryptedString);
            if (myCryptogram.Length < 17)
            {
                throw new ArgumentException("Invalid encrypted string, Too Short", "anEncryptedString");
            }

            var myVector = myCryptogram.Take(16).ToArray();
            var myBuffer = myCryptogram.Skip(16).ToArray();

            return myEncoder.GetString(DecryptFromBuffer(myBuffer, myVector));
        }

#region Helper Internal methods
        //-------------------------------------------------------------------------------------------------
        //--- Helper Internal methods
        //-------------------------------------------------------------------------------------------------

#if WINDOWS_UWP
        private byte[] EncryptFromBuffer(byte[] aBufferArray, byte[] aVectorArray)
        {
            IBuffer IV = CryptographicBuffer.CreateFromByteArray(aVectorArray);
            IBuffer data = CryptographicBuffer.CreateFromByteArray(aBufferArray);

            IBuffer encrypted = CryptographicEngine.Encrypt(key, data, IV);

            DataReader myReader = DataReader.FromBuffer(encrypted);
            byte[] fileContent = new byte[myReader.UnconsumedBufferLength];
            myReader.ReadBytes(fileContent);

            return fileContent;
        }

        private byte[] DecryptFromBuffer(byte[] aBufferArray, byte[] aVectorArray)
        {
            IBuffer IV = CryptographicBuffer.CreateFromByteArray(aVectorArray);
            IBuffer data = CryptographicBuffer.CreateFromByteArray(aBufferArray);

            IBuffer decrypted = CryptographicEngine.Decrypt(key, data, IV);

            DataReader myReader = DataReader.FromBuffer(decrypted);
            byte[] fileContent = new byte[myReader.UnconsumedBufferLength];
            myReader.ReadBytes(fileContent);

            return fileContent;
        }

#else
        private byte[] EncryptFromBuffer(byte[] aBufferArray, byte[] aVectorArray)
        {
            var myEcryptor = myCryptoAlgorithm.CreateEncryptor(myKeyArray, aVectorArray);
            return Transform(aBufferArray, myEcryptor);
        }

        private byte[] DecryptFromBuffer(byte[] aBufferArray, byte[] aVectorArray)
        {
            var myDecryptor = myCryptoAlgorithm.CreateDecryptor(myKeyArray, aVectorArray);
            return Transform(aBufferArray, myDecryptor);
        }

        private byte[] Transform(byte[] aBufferArray, ICryptoTransform aTransform)
        {
            var myStream = new MemoryStream();
            using (var cs = new CryptoStream(myStream, aTransform, CryptoStreamMode.Write))
            {
                cs.Write(aBufferArray, 0, aBufferArray.Length);
            }

            return myStream.ToArray();
        }
#endif
#endregion
    }
}
