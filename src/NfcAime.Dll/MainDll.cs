using System;
using System.Reflection;
using System.Runtime.InteropServices;
using NfcAime.Dll.PN532;

namespace NfcAime.Dll
{
    public class MainDll
    {
        public static AimeReader reader;

        static byte[] idm = null;
        static string accessCode = null;
        static AimeReader.CardKind cardKind = AimeReader.CardKind.Null;

        // AimeIO 1.1 MIFARE state.
        static byte[] mifareUid = null;
        static byte mifareTarget = 0;
        static byte[] mifareKey = null;
        static byte mifareKeyType = 0;
        static bool mifareSelected = false;

        [DllImport("kernel32.dll")]
        private static extern void AllocConsole();

        [DllExport("aime_io_get_api_version", CallingConvention = CallingConvention.StdCall)]
        public static ushort GetApiVersion() => 0x0101;

        [DllExport("aime_io_init", CallingConvention = CallingConvention.StdCall)]
        public static int Init()
        {
            AllocConsole();

            var versionString = Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion;

            Console.WriteLine($"PN532 Aime Reader - Version {versionString}");
            Console.WriteLine("Make With Love By ZCROM - FROM MikuNet");
            Console.WriteLine("---------------------------------------------");
            Console.WriteLine($"{Config.ReaderCOM}   Baud:{Config.ReaderBaud}   Mode:{(Config.IDmMode == 1 ? "IDmMode" : "AccessCodeMode")}");

            reader = new AimeReader(Config.ReaderCOM, Config.ReaderBaud);
            ClearMifareState();
            return 0;
        }

        [DllExport("aime_io_nfc_poll", CallingConvention = CallingConvention.StdCall)]
        public static int NfcPoll(byte unitNo)
        {
            if (unitNo != 0 || reader == null)
                return 1;

            cardKind = AimeReader.CardKind.Null;
            idm = null;
            accessCode = null;
            ClearMifareState();

            Console.WriteLine(">> Polling...");
            (cardKind, idm, accessCode) = reader.ReadCard();

            if (cardKind == AimeReader.CardKind.MifareClassic &&
                idm != null && idm.Length >= 4)
            {
                mifareUid = (byte[])idm.Clone();

                // AimeReader currently closes its PN532 session after ReadCard().
                // Re-open a fresh session for subsequent AimeIO 1.1 MIFARE calls.
                mifareTarget = 1;

                Console.WriteLine($"MIFARE UID: {AimeReader.ToHexString(mifareUid)}");
            }

            return 0;
        }

        [DllExport("aime_io_nfc_get_aime_id", CallingConvention = CallingConvention.StdCall)]
        public static int GetAimeId(byte unitNo, IntPtr luid, nint luidSize)
        {
            if (unitNo != 0 || luid == IntPtr.Zero || luidSize <= 0 || reader == null)
                return 1;

            if (Config.IDmMode == 1 && cardKind == AimeReader.CardKind.Felica)
                return 1;

            if (!reader.IsError && cardKind == AimeReader.CardKind.Null)
                return 1;

            string code = accessCode;
            if (reader.IsError || String.IsNullOrEmpty(code))
                code = "01234567891234567890";

            var bytes = AccessCodeFormatter.ToAccessCodeBytes(code);
            int count = Math.Min((int)luidSize, bytes.Length);
            Marshal.Copy(bytes, 0, luid, count);

            Console.WriteLine("IsError: " + reader.IsError);
            Console.WriteLine("# " + cardKind + " !!");
            Console.WriteLine("<< AccessCode" + code);
            return 0;
        }

        [DllExport("aime_io_nfc_get_felica_id", CallingConvention = CallingConvention.StdCall)]
        public static unsafe int GetFelicaId(byte unitNo, ulong* iDM)
        {
            if (unitNo != 0 || iDM == null)
                return 1;

            if (cardKind != AimeReader.CardKind.Felica || Config.IDmMode != 1)
                return 1;

            if (reader.IsError || idm == null || idm.Length < 8)
                return 1;

            ulong value = 0;
            for (int i = 0; i < 8; i++)
                value = (value << 8) | idm[i];

            *iDM = value;
            Console.WriteLine("<< IDm");
            return 0;
        }

        [DllExport("aime_io_led_set_color", CallingConvention = CallingConvention.StdCall)]
        public static void SetLedColour(byte unitNo, byte r, byte g, byte b)
        {
        }

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

        [DllExport("aime_io_vfd_set_text", CallingConvention = CallingConvention.Cdecl)]
        public static void aime_io_vfd_set_text(IntPtr text, nuint text_len, IntPtr state)
        {
        }

        [DllExport("aime_io_vfd_set_state", CallingConvention = CallingConvention.Cdecl)]
        public static void aime_io_vfd_set_state(IntPtr state)
        {
        }

        [DllExport("aime_io_nfc_get_mifare_uid", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_get_mifare_uid(byte unit_no, IntPtr uid, nuint uid_size)
        {
            if (unit_no != 0 || uid == IntPtr.Zero || uid_size < 4 ||
                mifareUid == null || mifareUid.Length < 4)
                return 1;

            Marshal.Copy(mifareUid, 0, uid, Math.Min((int)uid_size, mifareUid.Length));
            Console.WriteLine($"MIFARE get UID: {AimeReader.ToHexString(mifareUid)}");
            return 0;
        }

        [DllExport("aime_io_nfc_mifare_select", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_select(byte unit_no, IntPtr uid, nuint uid_size)
        {
            if (unit_no != 0 || uid == IntPtr.Zero || uid_size < 4 ||
                mifareUid == null || mifareUid.Length < 4)
                return 1;

            var requested = new byte[(int)uid_size];
            Marshal.Copy(uid, requested, 0, requested.Length);

            int compareLength = Math.Min(requested.Length, mifareUid.Length);
            if (requested.Length > mifareUid.Length)
                return 1;

            for (int i = 0; i < compareLength; i++)
                if (requested[i] != mifareUid[i])
                    return 1;

            mifareSelected = true;
            mifareKey = null;
            Console.WriteLine($"MIFARE select: {AimeReader.ToHexString(requested)}");
            return 0;
        }

        [DllExport("aime_io_nfc_mifare_set_key", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_set_key(byte unit_no, byte key_type, IntPtr key, nuint key_size)
        {
            if (unit_no != 0 || key == IntPtr.Zero || key_size != 6 ||
                mifareUid == null || mifareUid.Length < 4)
                return 1;

            mifareKey = new byte[6];
            Marshal.Copy(key, mifareKey, 0, 6);
            mifareKeyType = key_type;

            Console.WriteLine($"MIFARE set key type=0x{key_type:X2}");
            return 0;
        }

        [DllExport("aime_io_nfc_mifare_authenticate", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_authenticate(
            byte unit_no,
            byte key_type,
            IntPtr payload,
            nuint payload_size)
        {
            if (unit_no != 0 || payload == IntPtr.Zero || payload_size < 1 ||
                !mifareSelected || mifareUid == null || mifareUid.Length < 4 ||
                mifareKey == null || mifareKey.Length != 6 || reader == null)
                return 1;

            // AimeIO's authenticate payload is a block number.
            byte blockNumber;
            if (payload_size >= 4)
            {
                // Accept either a byte-oriented payload or a 32-bit block field.
                var data = new byte[(int)payload_size];
                Marshal.Copy(payload, data, 0, data.Length);
                blockNumber = data[0];
            }
            else
            {
                blockNumber = Marshal.ReadByte(payload);
            }

            bool keyTypeA;
            if (key_type == 0 || key_type == 0x60)
                keyTypeA = true;
            else if (key_type == 1 || key_type == 0x61)
                keyTypeA = false;
            else
                return 1;

            try
            {
                var session = OpenPn532Session();
                try
                {
                    bool ok = MiFareHandle.TryMifareAuthenticate(
                        session,
                        mifareTarget,
                        blockNumber,
                        keyTypeA,
                        mifareKey,
                        new ReadOnlySpan<byte>(mifareUid, 0, 4));

                    Console.WriteLine($"MIFARE authenticate block={blockNumber} key={(keyTypeA ? "A" : "B")} ok={ok}");
                    return ok ? 0 : 1;
                }
                finally
                {
                    session.Close();
                    session.Dispose();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"MIFARE authenticate failed: {ex.Message}");
                return 1;
            }
        }

        [DllExport("aime_io_nfc_mifare_read_block", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_mifare_read_block(
            byte unit_no,
            IntPtr uid,
            nuint uid_size,
            byte block_no,
            IntPtr block,
            nuint block_size)
        {
            if (unit_no != 0 || uid == IntPtr.Zero || block == IntPtr.Zero ||
                uid_size < 4 || block_size < 16 ||
                mifareUid == null || mifareUid.Length < 4 ||
                !mifareSelected || reader == null)
                return 1;

            var requested = new byte[(int)uid_size];
            Marshal.Copy(uid, requested, 0, requested.Length);
            if (requested.Length > mifareUid.Length)
                return 1;

            for (int i = 0; i < requested.Length; i++)
                if (requested[i] != mifareUid[i])
                    return 1;

            try
            {
                var session = OpenPn532Session();
                try
                {
                    byte[] data = MiFareHandle.ReadMifareBlock(session, mifareTarget, block_no);
                    Marshal.Copy(data, 0, block, 16);
                    Console.WriteLine($"MIFARE read block {block_no}: {AimeReader.ToHexString(data)}");
                    return 0;
                }
                finally
                {
                    session.Close();
                    session.Dispose();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"MIFARE read block {block_no} failed: {ex.Message}");
                return 1;
            }
        }

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

        [DllExport("aime_io_nfc_radio_on", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_radio_on(byte unit_no)
        {
            return unit_no == 0 ? 0 : 1;
        }

        [DllExport("aime_io_nfc_radio_off", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_radio_off(byte unit_no)
        {
            return unit_no == 0 ? 0 : 1;
        }

        [DllExport("aime_io_nfc_to_update_mode", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_to_update_mode(byte unit_no)
        {
            return 1;
        }

        [DllExport("aime_io_nfc_send_hex_data", CallingConvention = CallingConvention.Cdecl)]
        public static int aime_io_nfc_send_hex_data(
            byte unit_no,
            IntPtr payload,
            nuint payload_size,
            IntPtr status_out)
        {
            return 1;
        }

        private static void ClearMifareState()
        {
            mifareUid = null;
            mifareTarget = 0;
            mifareKey = null;
            mifareKeyType = 0;
            mifareSelected = false;
        }

        private static Pn532Session OpenPn532Session()
        {
            // Keep this independent from AimeReader's private session.
            // The low-level AimeIO calls can therefore open/close the serial
            // transport around each MIFARE transaction.
            var transport = new SerialFrameTransport(
                Config.ReaderCOM,
                Config.ReaderBaud,
                TimeSpan.FromMilliseconds(100));

            var session = new Pn532Session(
                transport,
                TimeSpan.FromMilliseconds(100),
                1);

            session.Open();

            try
            {
                ExpectPn532StatusOk(
                    session.SendCommand(new byte[] { 0x14, 0x01 }),
                    0x15);

                ExpectPn532StatusOk(
                    session.SendCommand(new byte[] { 0x32, 0x01, 0x03 }),
                    0x33);

                // Re-select the currently-present Type A card so that the
                // returned target number is valid for this new PN532 session.
                var response = session.SendCommand(
                    new byte[] { 0x4A, 0x01, 0x00 },
                    TimeSpan.FromMilliseconds(600));

                if (response.Kind != Pn532FrameKind.Data ||
                    response.Payload.Length < 8 ||
                    response.Payload[0] != 0x4B ||
                    response.Payload[1] == 0)
                    throw new InvalidOperationException("PN532 could not reselect MIFARE card.");

                byte target = response.Payload[2];
                byte uidLen = response.Payload[6];
                if (uidLen < 4 || response.Payload.Length < 7 + uidLen)
                    throw new InvalidOperationException("PN532 returned an invalid UID.");

                for (int i = 0; i < 4; i++)
                    if (response.Payload[7 + i] != mifareUid[i])
                        throw new InvalidOperationException("PN532 selected a different card.");

                mifareTarget = target;
                return session;
            }
            catch
            {
                session.Close();
                session.Dispose();
                throw;
            }
        }

        private static void ExpectPn532StatusOk(Pn532FrameParseResult response, byte expectedResponseCode)
        {
            AimeReader.ExpectPn532ResponseCode(response, expectedResponseCode);
            if (response.Payload.Length >= 2 && response.Payload[1] != 0x00)
                throw new InvalidOperationException($"PN532 status failed: 0x{response.Payload[1]:X2}");
        }
    }
}
