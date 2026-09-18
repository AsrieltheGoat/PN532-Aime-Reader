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
            Console.WriteLine(">> Polling...");
            (cardKind, idm, accessCode) = reader.ReadCard();
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
            if (accessCode == null)
            {
                return 1;
            }

            if (Config.IDmMode == 1 && cardKind == AimeReader.CardKind.Felica)
            {
                return 1;
            }
            if (cardKind == AimeReader.CardKind.Null)
            {
                return 1;
            }

            //将卡号复制到缓存区以传递给游戏
            Marshal.Copy(AccessCodeFormatter.ToAccessCodeBytes(accessCode), 0, luid, (int)luidSize);
            Console.WriteLine("# " + cardKind + " !!");
            Console.WriteLine("<< AccessCode");
            return 0;
        }

        //获取FeliCa ID
        [DllExport("aime_io_nfc_get_felica_id", CallingConvention = CallingConvention.StdCall)]
        public static unsafe int GetFelicaId(byte unitNo, ulong* iDM)
        {
            if (idm == null)
            {
                return 1;
            }

            if (cardKind == AimeReader.CardKind.Felica && Config.IDmMode == 1) //防止传入M1卡
            {
                ulong idmValue = 0;
                for (var i = 0; i < 8; i++)
                {
                    idmValue = (idmValue << 8) | idm[i];
                }

                *iDM = idmValue;
                Console.WriteLine("<< IDm");
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

        // 设置 VFD 屏幕文本
        [DllExport("aime_io_vfd_set_text", CallingConvention = CallingConvention.Cdecl)]
        public static void aime_io_vfd_set_text(IntPtr text, nuint text_len, IntPtr state)
        {
        }

        // 设置 VFD 屏幕状态
        [DllExport("aime_io_vfd_set_state", CallingConvention = CallingConvention.Cdecl)]
        public static void aime_io_vfd_set_state(IntPtr state)
        {
        }

        // ==========================================
        // aimeio api v1.1 新增：
        // ==========================================

        // 获取 MIFARE 4 字节 UID
        [DllExport("aime_io_nfc_get_mifare_uid", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_get_mifare_uid(byte unit_no, IntPtr uid, nuint uid_size)
        {
            return 1;
        }

        // 选中指定 UID 的卡片
        [DllExport("aime_io_nfc_mifare_select", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_select(byte unit_no, IntPtr uid, nuint uid_size)
        {
            return 1;
        }

        // 设置 MIFARE 认证密钥
        [DllExport("aime_io_nfc_mifare_set_key", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_set_key(byte unit_no, byte key_type, IntPtr key, nuint key_size)
        {
            return 1;
        }

        // MIFARE 扇区认证
        [DllExport("aime_io_nfc_mifare_authenticate", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_authenticate(byte unit_no, byte key_type, IntPtr payload, nuint payload_size)
        {
            return 1;
        }

        // 读取 MIFARE 16 字节数据块
        // 错误注入：返回 E_FAIL，触发游戏M1“读卡失败”错误
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
            // return E_FAIL;

            // 默认正常放行：
            return 1;
        }

        // FeliCa 底层请求交互透传
        // 错误注入：返回 E_FAIL，触发游戏Felica“读卡失败”错误
        [DllExport("aime_io_nfc_felica_transact", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_felica_transact(
            byte unit_no,
            IntPtr req,
            nuint req_size,
            IntPtr res,
            nuint res_size,
            IntPtr res_size_written)
        {
            return 1;
        }

        // 开启射频场
        [DllExport("aime_io_nfc_radio_on", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_radio_on(byte unit_no)
        {
            return 1;
        }

        // 关闭射频场
        [DllExport("aime_io_nfc_radio_off", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_radio_off(byte unit_no)
        {
            return 1;
        }

        // 进入固件升级模式
        [DllExport("aime_io_nfc_to_update_mode", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_to_update_mode(byte unit_no)
        {
            return 1;
        }

        // 发送原生 HEX 数据指令
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