using System;
using Newtonsoft.Json;

namespace EncryptionLibrary.Data
{
    /// <summary>
    /// Simple Class to Convert an Infoblock to an Encrypted String and back
    /// </summary>
    public static class InfoBlockConvertor
    {
        private static JsonSerializerSettings theJsonSerializerSettings = new JsonSerializerSettings();
        private static StringEncryptor myStringEncryptor = StringEncryptor.Instance;

        //-------------------------------------------------------------------------------------------------
        //--- Create an Infoblock object out of an Encrypted String 
        //-------------------------------------------------------------------------------------------------
        public static InfoBlock DecodeFromString(string aString)
        {
            InfoBlock myInfoBlock = null;
            theJsonSerializerSettings.TypeNameHandling = TypeNameHandling.None;

            try
            {
                string decryptedString = myStringEncryptor.Decrypt(aString);

                myInfoBlock = JsonConvert.DeserializeObject<InfoBlock>(decryptedString, theJsonSerializerSettings);
            }
            catch (Exception ex)
            {

            }
            return myInfoBlock;
        }

        //-------------------------------------------------------------------------------------------------
        //--- Create an Encrypted String out of an Infoblock object 
        //-------------------------------------------------------------------------------------------------

        public static string EncodeToString(InfoBlock anInfoBlock)
        {
            string myEncryptedString = "";
            string myString;

            theJsonSerializerSettings.TypeNameHandling = TypeNameHandling.None;
            try
            {
                myString = JsonConvert.SerializeObject(anInfoBlock, theJsonSerializerSettings);
                myEncryptedString = myStringEncryptor.Encrypt(myString);
            }
            catch (Exception ex)
            {

            }

            return myEncryptedString;
        }

    }
}
