using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;


namespace NfcAime.Dll {
    public class MainDll {

        public static AimeReader reader;
        static byte[] idm = null;
        static string accessCode = null;
        static AimeReader.CardKind cardKind = AimeReader.CardKind.Null;
        [DllImport("kernel32.dll")]
        private static extern void AllocConsole();
        //返回API版本
        [DllExport("aime_io_get_api_version", CallingConvention = CallingConvention.StdCall)]
        public static ushort GetApiVersion() => 0x0101;

        [DllExport("aime_io_init", CallingConvention = CallingConvention.StdCall)]
        public static int Init()
        {
            AllocConsole();

            // 读取如 "1.0.0-a1b2c3d-master" 这种详细版本信息
            var versionString = Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion;

            Console.WriteLine($"PN532 Aime Reader - Version {versionString}");
            Console.WriteLine("Make With Love By ZCROM - FROM MikuNet");
            Console.WriteLine("---------------------------------------------");
            Console.WriteLine($"{Config.ReaderCOM}   Baud:{Config.ReaderBaud}   Mode:{(Config.IDmMode == 1 ? "IDmMode" : "AccessCodeMode")}");
            reader = new AimeReader(port: Config.ReaderCOM, baud: Config.ReaderBaud);
            return 0;
        }

        //卡轮询
        [DllExport("aime_io_nfc_poll", CallingConvention = CallingConvention.StdCall)]
        public static int NfcPoll(byte unitNo)
        {
            cardKind = AimeReader.CardKind.Null;
            Console.WriteLine(">> Polling...");
            (cardKind, idm, accessCode) = reader.ReadCard();
            if (reader.IsError && idm == new byte[] {0x00}) {
                reader.ClearError();
            }
            // Console.WriteLine($"Card Kind: {cardKind}, IDm: {AimeReader.ToHexString(idm)}, AccessCode: {accessCode}");
            return 0;
        }

        //获取Aime AccessCode
        [DllExport("aime_io_nfc_get_aime_id", CallingConvention = CallingConvention.StdCall)]
        public static int GetAimeId(byte unitNo, IntPtr luid, nint luidSize)
        {

            if (unitNo != 0)
            {
                return 1;
            }

            if (Config.IDmMode == 1 && cardKind == AimeReader.CardKind.Felica)
            {
                return 1;
            }
            if (!reader.IsError && cardKind == AimeReader.CardKind.Null)
            {
                return 1;
            }

            if (reader.IsError || accessCode == null) {
                accessCode = "01234567891234567890";
            }
            //将卡号复制到缓存区以传递给游戏
            Console.WriteLine("IsError: " + reader.IsError);
            Marshal.Copy(AccessCodeFormatter.ToAccessCodeBytes(accessCode), 0, luid, (int)luidSize);
            Console.WriteLine("# " + cardKind + " !!");
            Console.WriteLine("<< AccessCode"+accessCode);
            return 0;
        }

        //获取FeliCa ID
        [DllExport("aime_io_nfc_get_felica_id", CallingConvention = CallingConvention.StdCall)]
        public static unsafe int GetFelicaId(byte unitNo, ulong* iDM)
        {

            if (cardKind == AimeReader.CardKind.Felica && Config.IDmMode == 1) //防止传入M1卡
            {
                if (accessCode == null) {
                    reader.IsError = true;
                }
                ulong idmValue = 0;
                if (!reader.IsError)
                {
                    try {
                        for (int i = 0; i < 8; i++)
                        {
                            idmValue = (idmValue << 8) | idm[i];
                        }
                    }
                    catch (Exception e) {
                        reader.IsError = true;
                    }
                }

                *iDM = idmValue;
                Console.WriteLine("<< IDm");
                cardKind = AimeReader.CardKind.Null;
                return 0;
            }
            return 1;
        }

        //设置LED颜色
        [DllExport("aime_io_led_set_color", CallingConvention = CallingConvention.StdCall)]
        public static void SetLedColour(byte unitNo, byte r, byte g, byte b)
        {
        }
        
        // ==========================================
        // 1.1 新增：VFD 显示屏相关接口
        // ==========================================

        [StructLayout(LayoutKind.Sequential)]
        public struct AimeIoVfdState
        {
            public byte encoding;
            public byte text_speed;
            public byte scroll_enabled;
            public ushort h_scroll;
            public ushort cursor_x;
            public byte cursor_y;
            public ushort wnd_x0;
            public ushort wnd_y0;
            public ushort wnd_x1;
            public ushort wnd_y1;
            public byte rotate;
            public byte brightness;
            public byte screen_on;
            public uint clear_seq;
        }

        /// <summary>
        /// 设置 VFD 屏幕文本
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// </remarks>
        [DllExport("aime_io_vfd_set_text", CallingConvention = CallingConvention.Cdecl)]
        public static void aime_io_vfd_set_text(IntPtr text, nuint text_len, IntPtr state)
        {
        }

        /// <summary>
        /// 设置 VFD 屏幕状态
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// </remarks>
        [DllExport("aime_io_vfd_set_state", CallingConvention = CallingConvention.Cdecl)]
        public static void aime_io_vfd_set_state(IntPtr state)
        {
        }

        /// <summary>
        /// 获取 MIFARE 4 字节 UID
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// </remarks>
        [DllExport("aime_io_nfc_get_mifare_uid", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_get_mifare_uid(byte unit_no, IntPtr uid, nuint uid_size)
        {
            return 1;
        }

        /// <summary>
        /// 选中指定 UID 的卡片
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// </remarks>
        [DllExport("aime_io_nfc_mifare_select", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_select(byte unit_no, IntPtr uid, nuint uid_size)
        {
            return 1;
        }

        /// <summary>
        /// 设置 MIFARE 认证密钥
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// </remarks>
        [DllExport("aime_io_nfc_mifare_set_key", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_set_key(byte unit_no, byte key_type, IntPtr key, nuint key_size)
        {
            return 1;
        }

        /// <summary>
        /// MIFARE 扇区认证
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// </remarks>
        [DllExport("aime_io_nfc_mifare_authenticate", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_authenticate(byte unit_no, byte key_type, IntPtr payload, nuint payload_size)
        {
            return 1;
        }

        /// <summary>
        /// 一个错误计数器，满足>=2时应重置读卡器错误
        /// </summary>
        /// <remarks>
        /// 对于aime_io_nfc_mifare_read_block，segatools会调用 4 次在一次poll周期中
        /// 4次调用需要都返回E_FAIL才会触发错误，故设置一个计数器
        /// </remarks>
        private static int _mifareErrorCount = 0;
        /// <summary>
        /// 读取 MIFARE 16 字节数据块
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// 错误注入：返回 E_FAIL，触发游戏M1“读卡失败”错误
        /// </remarks>
        [DllExport("aime_io_nfc_mifare_read_block", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_read_block(
            byte unit_no,
            IntPtr uid,
            nuint uid_size,
            byte block_no,
            IntPtr block,
            nuint block_size)
        {
            // 若要注入错误触发游戏读卡异常，返回 E_FAIL：
            if (reader.IsError) {
                _mifareErrorCount++;
                if (_mifareErrorCount >= 4) {
                    reader.ClearError();
                    _mifareErrorCount = 0;
                }
                return unchecked((int)0x8000FFFFL);
            }
            return 1;
        }

        /// <summary>
        /// 一个错误计数器，满足>=4时应重置读卡器错误
        /// </summary>
        /// <remarks>
        /// 对于aime_io_nfc_felica_transact，segatools会调用 2 次在一次poll周期中
        /// 2次调用需要都返回E_FAIL才会触发错误，故设置一个计数器
        /// </remarks>
        private static int _feliCaErrorCount = 0;
        /// <summary>
        /// FeliCa 底层请求交互透传
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// 错误注入：返回 E_FAIL，触发游戏Felica“读卡失败”错误
        /// </remarks>
        [DllExport("aime_io_nfc_felica_transact", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_felica_transact(
            byte unit_no,
            IntPtr req,
            nuint req_size,
            IntPtr res,
            nuint res_size,
            IntPtr res_size_written)
        {
            if (reader.IsError) {
                _feliCaErrorCount++;
                if (_feliCaErrorCount >= 2) {
                    reader.ClearError();
                    _feliCaErrorCount = 0;
                }
                return unchecked((int)0x8000FFFFL);
            }
            return 1;
        }

        /// <summary>
        /// 开启射频场
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// </remarks>
        [DllExport("aime_io_nfc_radio_on", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_radio_on(byte unit_no)
        {
            return 1;
        }

        /// <summary>
        /// 关闭射频场
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// </remarks>
        [DllExport("aime_io_nfc_radio_off", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_radio_off(byte unit_no)
        {
            return 1;
        }

        /// <summary>
        /// 进入固件升级模式
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// </remarks>
        [DllExport("aime_io_nfc_to_update_mode", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_to_update_mode(byte unit_no)
        {
            return 1;
        }

        /// <summary>
        /// 发送原生 HEX 数据指令
        /// </summary>
        /// <remarks>
        /// AimeIO API Ver = 1.1;
        /// </remarks>
        [DllExport("aime_io_nfc_send_hex_data", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_send_hex_data(
            byte unit_no,
            IntPtr payload,
            nuint payload_size,
            IntPtr status_out)
        {
            return 1;
        }
    }
}