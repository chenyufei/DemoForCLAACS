#define CONNECT

using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;

namespace DemoForCLAACS
{
    class Program
    {
        [DllImport("Aes128_CMac_Dll.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, EntryPoint = "challenge_identification")]
        static extern void challenge_identification(byte[] appkey, UInt64 appeui, UInt32 appnonce, ref byte challenge);
        private static bool checkEUI(string strEUI)
        {
            if (string.IsNullOrWhiteSpace(strEUI))
            {
                return false;
            }
            string tmpEUI = strEUI.Trim();
            if (16 != tmpEUI.Length)  //长度为固定的16位
            {
                return false;
            }

            string pattern = @"^[a-fA-F0-9]+$";
            Regex regex = new Regex(pattern);
            return regex.IsMatch(tmpEUI);
        }

        private static bool checkAPPKEY(string appkey)
        {
            if (string.IsNullOrWhiteSpace(appkey))
            {
                return false;
            }
          
            if (32 != appkey.Length)  //长度为固定的32位
            {
                return false;
            }
            
            string pattern = @"^[a-fA-F0-9]+$";
            Regex regex = new Regex(pattern);
            return regex.IsMatch(appkey);
        }
#if CONNECT
        private static bool checkIP(string strIP)
        {
            if (string.IsNullOrWhiteSpace(strIP))
            {
                return false;
            }
            string tmpIP = strIP.Trim();
            Regex regex = new Regex(@"((?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d))))");
            return regex.IsMatch(tmpIP);
        }

        private static bool checkPort(string strPort)
        {
            Regex regex = new Regex("^[0-9]*[1-9][0-9]*$");
            return regex.IsMatch(strPort);
        }       
        private  static bool StartSend(string sendString)
        {
            try
            {
                int length = (sendString.Length + 1) & 0xFFFF;
                byte[] senddata = new byte[length + 5];

                int hValue = length >> 8;
                int lValue = length & 0xFF;
                byte[] arr = new byte[] { (byte)'\n', (byte)1, (byte)2, (byte)hValue, (byte)lValue };
                arr.CopyTo(senddata, 0);

                byte[] str = UTF8Encoding.UTF8.GetBytes(sendString);
                Buffer.BlockCopy(str, 0, senddata, 5, sendString.Length);

                senddata[sendString.Length + 5] = UTF8Encoding.UTF8.GetBytes("\0")[0];
                if(m_nkStream.CanWrite)
                {
                    m_nkStream.Write(senddata, 0, senddata.Length);
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static UInt64 getCmdSeq()
        {
            return CmdSeq += CmdSeq + 2;
        }
        private static  bool ConnectHost()
        {
            m_tcpClient = new TcpClient();
            try
            {
                m_tcpClient.Connect(IPAddress.Parse(m_MspIp), Convert.ToInt32(m_Port));
            }
            catch
            {
                return false;
            }

            m_nkStream = m_tcpClient.GetStream();
            m_nkStream.ReadTimeout = 5000;
            return true;
        }
        private static void StartConnect()
        {
            if(ConnectHost())
            {
                string JoinData = string.Format("{{\"cmd\":\"join\",\"cmdseq\":{0},\"appeui\":\"{1}\",\"appnonce\":{2},\"challenge\":\"{3}\"}}", getCmdSeq(), m_APPEUI, randInt, m_challenge);
                bExit = StartSend(JoinData);
                if (bExit)
                {
                    Console.WriteLine(string.Format("数据:{0}发送成功", JoinData));
                }
                else
                {
                    Console.WriteLine(string.Format("数据:{0}发送失败", JoinData));
                }

                while(bExit)
                {
                    string result = string.Empty;
                    byte[] readBytes = new byte[2048];
                    m_nkStream.BeginRead(readBytes, 0, 2048, new AsyncCallback(ReceiveCallBack), readBytes);
                    receiveDone.WaitOne();
                    result = Encoding.UTF8.GetString(readBytes);

                    result = Encoding.UTF8.GetString(readBytes, 5, readBytes.Length - 5);

                    result = result.TrimEnd('\0');
                    Console.WriteLine(string.Format("接收数据为:{0}", result));
                    dealRecvData(result);                   
                }
            }
            else
            {
                Console.WriteLine(string.Format("{0},端口:{1} 失败",m_MspIp,m_Port));
            }

        }
        private static void DisConnectHost()
        {
            m_tcpClient.Close();
            m_tcpClient.Dispose();
        }
        private static void ReceiveCallBack(IAsyncResult ar)
        {
            try
            {
                int bytesRead = m_nkStream.EndRead(ar);
            }
            catch
            {

            }

            receiveDone.Set();
        }
        private static void StopHeartCheckTimer()
        {
            iRecvHeartBeatNumber = 0;
            heartCheckTimer.Enabled = false;
            heartCheckTimer.Stop();
        }

        private static void StartHeartCheckTimer()
        {
            heartCheckTimer.Enabled = true;
            heartCheckTimer.Start();
        }
        private static void sendHeartbeatAck()
        {
            string strheartBeatAck = string.Format("{{\"cmd\":\"heartbeat_ack\"}}");
            iRecvHeartBeatNumber = 0;
            bool bResult = StartSend(strheartBeatAck);
            if (bResult)
            {
                Console.WriteLine(string.Format("心跳响应:{0}发送成功", strheartBeatAck));
            }
            else
            {
                Console.WriteLine(string.Format("心跳响应:{0}发送失败", strheartBeatAck));
            }

            StopHeartCheckTimer();
            StartHeartCheckTimer();
        }
        private static void dealRecvData(string recvData)
        {
            JObject obj;
            try
            {
                obj = JObject.Parse(recvData);
            }
            catch (Exception)
            {
                return;
            }
            try
            {
                string cmd = (null == obj["cmd"] ? "" : (string)obj["cmd"]);
                if (cmd.Equals("join_ack"))
                {
                    int Code = (null == obj["code"] ? 0 : (int)obj["code"]);
                    if (Code.Equals(200) || Code.Equals(203))
                    {
                        StopHeartCheckTimer();
                        StartHeartCheckTimer();
                    }
                }
                else if (cmd.Equals("updata"))
                {
                    StopHeartCheckTimer();
                    StartHeartCheckTimer();
                }
                else if(cmd.Equals("forced_quit"))
                {
                    bExit = true;
                    DisConnectHost();
                    iRecvHeartBeatNumber = 0;
                    StopHeartCheckTimer();

                    System.Threading.Thread.Sleep(1000 * 2);
                    StartConnect();
                }
                else if (cmd.Equals("quit_ack"))
                {
                    bExit = true;
                    DisConnectHost();
                    iRecvHeartBeatNumber = 0;
                    StopHeartCheckTimer();

                    System.Threading.Thread.Sleep(1000 * 2);
                    StartConnect();
                }
                else if (cmd.Equals("heartbeat"))
                {
                    sendHeartbeatAck();
                }
            }
            catch (Exception)
            {
            }
        }

        private static void HeartTimeOut(object source, ElapsedEventArgs e)
        {
            iRecvHeartBeatNumber++;
            string strnumber = string.Format("recv heartbeat number ={0}", iRecvHeartBeatNumber);
            Console.WriteLine(strnumber);
            if (iRecvHeartBeatNumber >= 3)
            {
                iRecvHeartBeatNumber = 0;
                StopHeartCheckTimer();

                System.Threading.Thread.Sleep(1000 * 2);
                DisConnectHost();
                StartConnect();
            }
        }
#endif
        private static byte[] strToToHexByte(string hexString)
        {
            hexString = hexString.Replace(" ", "");
            if ((hexString.Length % 2) != 0)
                hexString += " ";
            byte[] returnBytes = new byte[hexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            return returnBytes;
        }

        private static string GenerateChallenge(string appeui,string appkey, UInt32 appnonce)
        {
            byte[] keyArray = strToToHexByte(appkey);
            UInt64 inAppeui = Convert.ToUInt64(appeui, 16);
            byte[] challenge = new byte[32 + 1];
            challenge_identification(keyArray, inAppeui, appnonce, ref challenge[0]);
            string strChallenge = System.Text.Encoding.Default.GetString(challenge).TrimEnd('\0');
            return strChallenge;
        }
#if CONNECT
        private static string m_MspIp = string.Empty;
        private static string m_Port = string.Empty;
        private static UInt64 CmdSeq = 0;
        private static TcpClient m_tcpClient;
        private static NetworkStream m_nkStream;
        private static AutoResetEvent receiveDone = new AutoResetEvent(false);
        private static System.Timers.Timer heartCheckTimer = new System.Timers.Timer();
        private static int iRecvHeartBeatNumber = 0;
        private static bool bExit = false;
#endif
        private static string m_APPEUI = string.Empty;
        private static string m_APPKEY = string.Empty;
        private static string m_challenge = string.Empty;        
        private static UInt32 randInt;
        static void Main(string[] args)
        {
#if CONNECT
            while(true)
            {
                Console.WriteLine("请输入IP:");
                m_MspIp = Console.ReadLine();
                if(checkIP(m_MspIp))
                {
                    break;
                }
                else
                {
                    Console.WriteLine("输入非法IP");
                }
            }

            while (true)
            {
                Console.WriteLine("请输入port:");
                m_Port = Console.ReadLine();
                if (checkPort(m_Port))
                {
                    break;
                }
                else
                {
                    Console.WriteLine("输入非法端口");
                }
            }
#endif
            while (true)
            {
                Console.WriteLine("请输入appeui");
                m_APPEUI = Console.ReadLine().Replace(":", "").Trim() ;
                if (checkEUI(m_APPEUI))
                {
                    break;
                }
                else
                {
                    Console.WriteLine("输入非法appeui");
                }
            }

            while (true)
            {
                Console.WriteLine("请输入appkey");
                m_APPKEY = Console.ReadLine();
                if (checkAPPKEY(m_APPKEY))
                {
                    break;
                }
                else
                {
                    Console.WriteLine("输入非法appkey");
                }
            }

            Random rd = new Random();
            randInt = (UInt32)rd.Next();
            m_challenge = GenerateChallenge(m_APPEUI, m_APPKEY, randInt);

            Console.WriteLine(string.Format("根据{0},{1},{2} 计算得的挑战字为:{3}",m_APPEUI,m_APPKEY,randInt, m_challenge));
#if CONNECT
            heartCheckTimer.Enabled = false;
            heartCheckTimer.Interval = 62000; //执行间隔时间,单位为毫秒; 这里实际间隔为1分钟2秒  
            heartCheckTimer.Elapsed += new System.Timers.ElapsedEventHandler(HeartTimeOut);
            heartCheckTimer.Stop();

            Thread ConnectMSPThread = new Thread(StartConnect);
            ConnectMSPThread.IsBackground = true;
            ConnectMSPThread.Start();
            Console.ReadLine();
#endif
        }
    }
}
