using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSASamples
{
    [TestClass]
    public class ReRSATest
    {
        private Tuple<string, string> GenerateRSAKeys()
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            var publicKey = rsa.ToXmlString(false);
            var privateKey = rsa.ToXmlString(true);

            return Tuple.Create<string, string>(publicKey, privateKey);
        }

        [TestMethod]
        public void Test_私鑰加密_公鑰解密()
        {
            var contxt = "HasNode:2000,TimeOut:2020/11/25";
            var keys = GenerateRSAKeys();
            var toUserKey = EncryptString(keys.Item2, contxt);
            var txt = DecryptString(keys.Item1, toUserKey);
            Assert.AreEqual(contxt, txt);
        }

        /// <summary>
        /// 私鑰加密
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public string EncryptString(string privateKey, string context)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKey);
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair(rsa);
            IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            c.Init(true, keyPair.Private);
            byte[] DataToEncrypt = Encoding.UTF8.GetBytes(context);
            byte[] outBytes = c.DoFinal(DataToEncrypt);//加密
            string strBase64 = Convert.ToBase64String(outBytes);
            return strBase64;

        }
        /// <summary>
        /// 公鑰解密
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="cryptedContext"></param>
        /// <returns></returns>
        public string DecryptString(string publicKey, string cryptedContext)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);
            RSAParameters rp = rsa.ExportParameters(false);//轉換密鑰
            AsymmetricKeyParameter pbk = DotNetUtilities.GetRsaPublicKey(rp);
            IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding"); //第一個參數爲true表示加密，爲false表示解密；第二個參數表示密鑰
            c.Init(false, pbk);
            byte[] DataToDecrypt = Convert.FromBase64String(cryptedContext);
            byte[] outBytes = c.DoFinal(DataToDecrypt);//解密

            string strDec = Encoding.UTF8.GetString(outBytes);
            return strDec;
        }



    }
}
