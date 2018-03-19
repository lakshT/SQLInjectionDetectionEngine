using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace injLib
{
    class crypto
    {
        public static void EncryptFile(string inputFile, string outputFile)
        {

            try
            {
                string password = @"CPSC711";
                UnicodeEncoding UE = new UnicodeEncoding();
                byte[] key = UE.GetBytes(password);

                string cryptFile = outputFile;
                FileStream fsCrypt = new FileStream(cryptFile, FileMode.Create);

                RijndaelManaged RMCrypto = new RijndaelManaged();

                CryptoStream cs = new CryptoStream(fsCrypt,
                    RMCrypto.CreateEncryptor(key, key),
                    CryptoStreamMode.Write);

                FileStream fsIn = new FileStream(inputFile, FileMode.Open);

                int data;
                while ((data = fsIn.ReadByte()) != -1)
                    cs.WriteByte((byte)data);
                cs.Flush();
                fsCrypt.Flush();
                fsIn.Flush();
                fsIn.Close();
                cs.Close();
                fsCrypt.Close();
                fsCrypt.Dispose();
                fsIn.Dispose();
                cs.Dispose();
            }
            catch (Exception ex)
            {
                //MessageBox.Show(ex.ToString());
            }
            finally
            {

            }
        }
        //Encrypt Over


        /// <summary>
        /// This is a method to decrypt a file with a given key.
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="outputFile"></param>
        public static void DecryptFile(string inputFile, string outputFile)
        {
            try
            {
                string password = @"CPSC711";

                UnicodeEncoding UE = new UnicodeEncoding();
                byte[] key = UE.GetBytes(password);

                FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);

                RijndaelManaged RMCrypto = new RijndaelManaged();

                CryptoStream cs = new CryptoStream(fsCrypt,
                    RMCrypto.CreateDecryptor(key, key),
                    CryptoStreamMode.Read);

                FileStream fsOut = new FileStream(outputFile, FileMode.Create);

                int data;
                while ((data = cs.ReadByte()) != -1)
                    fsOut.WriteByte((byte)data);

                cs.Flush();
                fsCrypt.Flush();
                fsOut.Flush();
                fsOut.Close();
                cs.Close();
                fsCrypt.Close();
                fsOut.Dispose();
                fsCrypt.Dispose();
                cs.Dispose();

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.InnerException.ToString());
            }
            finally
            {

            }
        }

    }
}
