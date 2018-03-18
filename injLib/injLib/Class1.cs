using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace injLib
{
    public class Class1
    {
        static string pathTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "inj.xml");

        public static bool checkInjection(string value, string path, char mode)
        {
            if (mode == 'a')
            {
                //check for all
                bool c1 = generalSQLcheck(value, path);
                bool c2 = tautologyCheck(value, path);
                bool c3 = logiincorrectCheck(value, path);
                bool c4 = UnionKeywordCheck(value, path);
                bool c5 = piggyBackedQueryCheck(value, path);
                bool c6 = alternateEncodingCheck(value, path);

                if (c1 == false || c2 == false || c3 == false || c4 == false || c5 == false || c6 == false)
                {
                    return false;
                }
            }
            else if (mode == 't')
            {
                //Check for Tautology
                if (tautologyCheck(value, path) == false)
                {
                    return false;
                }
            }
            else if (mode == 'l')
            {
                //Check for Logically Incorrect Queries
                if (logiincorrectCheck(value, path) == false)
                {
                    return false;
                }
            }
            else if (mode == 'u')
            {
                //check for Union Queries
                if (UnionKeywordCheck(value, path) == false)
                {
                    return false;
                }
            }
            else if (mode == 'p')
            {
                //check for Piggy Backed Queries
                if (piggyBackedQueryCheck(value, path) == false)
                {
                    return false;
                }
            }
            //else if (mode == 's')
            //{
            //    //check for stored procedure injection
            //}
            else if (mode == 'e')
            {
                //check for Alternate Encoding
                if (alternateEncodingCheck(value, path) == false)
                {
                    return false;
                }
            }
            return true;
        }


        public static List<String> returnKeywords(string attType, string path, char type)
        {
            List<String> keywordList = new List<String>();
            XmlDocument xd = new XmlDocument();
            DecryptFile(path, pathTemp);
            xd.Load(pathTemp);
            File.Delete(pathTemp);
            XmlNode xn = xd.SelectSingleNode("//Root");
            foreach (XmlNode node in xn)
            {
                if (node.Attributes["Name"].Value == attType)
                {
                    foreach (XmlNode childnode in node)
                    {
                        if (type == 's')
                        {
                            keywordList.Add(childnode.Attributes["Name"].Value);
                        }
                        else
                        {
                            keywordList.Add(childnode.InnerText);
                        }
                    }
                }
            }
            return keywordList;
        }



        public static bool generalSQLcheck(string value, string path)
        {
            List<String> lis = returnKeywords("GeneralSQL", path, 's');
            List<String> sublis = new List<String>();
            int tempcheck = 0;


            foreach (string lisvalue in lis)
            {
                DecryptFile(path, pathTemp);
                XmlDocument xd = new XmlDocument();
                xd.Load(pathTemp);
                File.Delete(pathTemp);
                XmlNode xn = xd.SelectSingleNode("//Root//AttackType[@Name = 'GeneralSQL']//SubType[@Name = '" + lisvalue + "']");

                foreach (XmlNode keynode in xn)
                {
                    sublis.Add(keynode.InnerText);
                }
                string tempvalue = value;

                //Check for Injection
                for (int i = 0; i <= sublis.Count - 1; i++)
                {
                    string toCheckstr = sublis[i];

                    if (tempvalue.Contains(toCheckstr + " ") || tempvalue.Contains(" " + toCheckstr))
                    {
                        string[] stringSeparators = new string[] { toCheckstr };
                        string[] tempstrarr = tempvalue.Split(stringSeparators, StringSplitOptions.None);
                        tempvalue = tempstrarr[1];
                        tempcheck++;
                    }
                }


                if (sublis.Count == tempcheck)
                {
                    return false;
                }
                else
                {
                    tempcheck = 0;
                }
                sublis.Clear();

            }
            return true;
        }


        //Demo function for dual words(select) in an input string
        private static bool checkString(List<string> keywords, string[] subStrings)
        {
            string[] tempList = subStrings;
            string[] tempList1 = { };
            for (int i = 1; i < keywords.Count; i++)
            {
                for (int j = 1; j < tempList.Count(); j++)
                {
                    if (tempList[i].Contains(" " + keywords[i] + " "))
                    {
                        string[] stringSeparators = new string[] { " " + keywords[i] + " " };
                        Array.Copy(tempList1, tempList[i].Split(stringSeparators, StringSplitOptions.None), tempList[i].Split(stringSeparators, StringSplitOptions.None).Length - 1);
                    }
                }
                tempList = tempList1;
                Array.Clear(tempList1, 0, tempList1.Length);
            }
            return true;
        }


        //Function to check Tautology
        public static bool tautologyCheck(string value, string path)
        {
            List<String> lis = returnKeywords("tautology", path, 'o');

            //Check Pattern
            string[] arr = value.Split(' ');
            for (int i = 0; i < arr.Length; i++)
            {
                if (i < arr.Length - 2)
                {
                    if (arr[i] == arr[i + 2] && arr[i + 1] == "=")
                    {
                        return false;
                    }
                }

                //check for tautology in each word
                if (arr[i].Contains('='))
                {
                    string[] arr1 = arr[i].Split('=');
                    if (arr1[0] == arr1[1])
                    {
                        return false;
                    }
                }
            }
            return true;
        }


        public static bool logiincorrectCheck(string value, string path)
        {
            if (value.Contains("convert"))
            {
                bool checkQuery = generalSQLcheck(value, path);
                if (checkQuery == false)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool UnionKeywordCheck(string value, string path)
        {
            if (value.Contains("union"))
            {
                bool checkQuery = generalSQLcheck(value, path);
                if (checkQuery == false)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool piggyBackedQueryCheck(string value, string path)
        {
            if (value.Contains(";"))
            {
                bool checkQuery = generalSQLcheck(value, path);
                if (checkQuery == false)
                {
                    return false;
                }

                //also check for SQL keywords such as shutdown.
                string[] valSplit = value.Split(';');
                if (valSplit[1].Contains("exec"))
                {
                    //check for SQL reserved keywords.
                    string[] stringSeparators = new string[] { "exec" };
                    string[] tempstrarr = valSplit[1].Split(stringSeparators, StringSplitOptions.None);
                    bool chk = true;
                    if (tempstrarr.Count() > 0)
                    {
                        chk = resKeywords(tempstrarr[1], path);
                    }
                    else
                    {
                        chk = resKeywords(tempstrarr[0], path);
                    }

                    if (chk == false)
                    {
                        return false;
                    }
                }
                else
                {
                    bool chk = true;
                    if (valSplit.Count() > 0)
                    {
                        chk = resKeywords(valSplit[1], path);
                    }
                    else
                    {
                        chk = resKeywords(valSplit[0], path);
                    }

                    if (chk == false)
                    {
                        return false;
                    }
                }


            }
            return true;
        }

        public static bool resKeywords(string value, string path)
        {
            List<String> lis = returnKeywords("SQLReservedKeywords", path, 'o');
            for (int i = 0; i < lis.Count; i++)
            {
                string chkWord = " " + lis[i] + " ";
                string chkWordFrontSpace = lis[i] + " ";
                if (value.Contains(chkWord) || value.Contains(chkWordFrontSpace))
                {
                    return false;
                }
            }
            return true;
        }


        public static bool alternateEncodingCheck(string value, string path)
        {
            if (value.Contains("exec (char(") || value.Contains("exec(char(") || value.Contains("char("))
            {
                string[] stringSeparators = new string[] { "exec (char(0x", "exec(char(0x", "(char(0x" };
                string[] tempstr = value.Split(stringSeparators, StringSplitOptions.None);
                string[] tempstrnew = tempstr[1].Split(')');
                string str = HexStringToString(tempstrnew[0]);
                List<String> lis = returnKeywords("SQLReservedKeywords", path, 'o');
                if (lis.Contains(str))
                {
                    return false;
                }
                int x = 0;
            }
            return true;
        }

        public static string HexStringToString(string HexString)
        {
            string stringValue = "";
            for (int i = 0; i < HexString.Length / 2; i++)
            {
                string hexChar = HexString.Substring(i * 2, 2);
                int hexValue = Convert.ToInt32(hexChar, 16);
                stringValue += Char.ConvertFromUtf32(hexValue);
            }
            return stringValue;
        }

        public static void EncryptFile(string inputFile, string outputFile)
        {

            try
            {
                string password = @"ProDotDL";
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
                string password = @"ProDotDL"; // Your Key Here

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
                //MessageBox.Show(ex.ToString());
            }
            finally
            {

            }
        }
    }
}
