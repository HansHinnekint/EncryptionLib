﻿using System;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

using EncryptionLibrary;
using EncryptionLibrary.Data;

namespace EncryptionUnitTestProject_UAP
{
    [TestClass]
    public class UnitTest_UAP
    {
        [TestMethod]
        public void UAP_EncryptDecryptString()
        {
            // Arrange
            var subject = StringEncryptor.Instance;
            var originalString = "Testing 123: Add some special characters &é@#'öçà!£$<ù}";

            // Act
            var encryptedString1 = subject.Encrypt(originalString);
            var encryptedString2 = subject.Encrypt(originalString);

            var decryptedString1 = subject.Decrypt(encryptedString1);
            var decryptedString2 = subject.Decrypt(encryptedString2);

            var encryptedString3 = subject.Encrypt(encryptedString2); // Double Encryption
            var decryptedString3 = subject.Decrypt(encryptedString3); // Still encrypted once
            var decryptedString4 = subject.Decrypt(decryptedString3);


            // Assert
            Assert.AreEqual(originalString, decryptedString1, "Decrypted string should match original string");
            Assert.AreEqual(originalString, decryptedString2, "Decrypted string should match original string");
            Assert.AreNotEqual(originalString, encryptedString1, "Encrypted string should not match original string");
            Assert.AreNotEqual(encryptedString1, encryptedString2, "String should never be encrypted the same twice");

            Assert.AreEqual(originalString, decryptedString4, "Double Decrypted string should match original string");
        }

        [TestMethod]
        public void UAP_EncryptDecryptInfoBlock()
        {
            // Arrange
            InfoBlock InfoBlock01 = new InfoBlock();

            // Act
            InfoBlock01.Token = InfoBlock.SOMETHINGELSE;
            InfoBlock01.Data = "Testing 123: Add some special characters &é@#'öçà!£$<ù}";

            var encryptedString1 = InfoBlockConvertor.EncodeToString(InfoBlock01);
            var encryptedString2 = InfoBlockConvertor.EncodeToString(InfoBlock01);

            var InfoBlock02 = InfoBlockConvertor.DecodeFromString(encryptedString2);

            // Assert
            Assert.AreNotEqual(encryptedString1, encryptedString2, "Infoblock should never be encrypted the same twice");
            Assert.AreEqual(InfoBlock01.Token, InfoBlock02.Token, "Tokens should match original value");
            Assert.AreEqual(InfoBlock01.Data, InfoBlock02.Data, "Data should match original value");
        }

        [TestMethod]
        public async Task UAP_ValidateOTP()
        {
            // Arrange
            Guid myGuid = new Guid();
            int OTP01;
            int OTP02;
            int OTP03;

            // Act
            OTP01 = await OTPAuthenticator.OTPFromGuid(myGuid);
            OTP02 = await OTPAuthenticator.OTPFromGuid(myGuid, true);

            // Assert
            Assert.IsTrue(await OTPAuthenticator.IsValidOTPFromGuid(myGuid, OTP01), "Token should be valid");
            Assert.IsTrue(await OTPAuthenticator.IsValidOTPFromGuid(myGuid, OTP02, true), "Token should be valid");


            // Act
            await Task.Delay(31000);

            OTP03 = await OTPAuthenticator.OTPFromGuid(myGuid);

            // Assert
            Assert.IsTrue(await OTPAuthenticator.IsValidOTPFromGuid(myGuid, OTP01), "Token should still be valid");
            Assert.IsTrue(await OTPAuthenticator.IsValidOTPFromGuid(myGuid, OTP01, true), "Token should still be valid");

            Assert.AreNotEqual(OTP01, OTP03, "Token should be different after more than 30 sec");
            Assert.IsTrue(await OTPAuthenticator.IsValidOTPFromGuid(myGuid, OTP03), "Token should also be valid");
        }

        [TestMethod]
        public void UAP_CompressDecomPressString()
        {
            // Arrange
            var subject = StringEncryptor.Instance;
            var originalString = "Testing 123: Add some special characters &é@#'öçà!£$<ù}";

            // Act
            var encryptedString1 = subject.Encrypt(originalString);
            var compressedString1 = StringCompressor.CompressString(encryptedString1);
            var decompressedString1 = StringCompressor.DecompressString(compressedString1);
            var decryptedString1 = subject.Decrypt(decompressedString1);
            var compressedString2 = StringCompressor.CompressString(originalString);
            var decompressedString2 = StringCompressor.DecompressString(compressedString2);



            // Assert
            Assert.AreEqual(originalString, decryptedString1, "Compressed and Decrypted string should match original string");
            //Assert.IsTrue((compressedString1.Length <= encryptedString1.Length), "Compressed Encrypted String should be smaller than the Encrypted string");
            Assert.AreEqual(originalString, decompressedString2, "Decompressed string should match original string");
            //Assert.IsTrue((compressedString2.Length <= originalString.Length), "Compressed String should be smaller than the original");
        }

    }
}
