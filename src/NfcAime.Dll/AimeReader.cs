#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Threading;
using NfcAime.Dll.PN532;
using static NfcAime.Dll.MiFareHandle;

namespace NfcAime.Dll;

public class AimeReader
{
    private string Port = "COM15";
    private int Baud = 115200;

    private Pn532Session session = null;

    public enum CardKind { Felica, MifareClassic, Null}

    /// <summary>
    /// 指示读卡器当前是否处于错误状态。
    /// </summary>
    /// <remarks>
    /// 当读卡或相关操作过程中发生错误时，该变量通常会被设置为 <c>true</c>，
    /// 并且可以通过调用 <see cref="AimeReader.ClearError"/> 方法将其清除。当 <c>IsError</c> 为 <c>true</c> 时，
    /// 表示读卡器遇到了可能影响后续操作正常执行的故障。
    /// </remarks>
    public bool IsError;
    private sealed record FlowResult(CardKind CardKind, byte[]? CardId, string? AccessCode, string? Error);
    private sealed record CardTarget(CardKind Kind, byte Tg, byte[] CardId);

    // 兼容低版本 .NET：实现 ToHexString 和 FromHexString
    public static string ToHexString(byte[]? bytes)
    {
        if (bytes == null || bytes.Length == 0) return string.Empty;
        return BitConverter.ToString(bytes).Replace("-", "");
    }

    public static byte[] FromHexString(string hex)
    {
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Invalid hex string length.");
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    public AimeReader(string port, int baud)
    {
        Port = port;
        Baud = baud;
        ClearError();
        TimeSpan timeout = TimeSpan.FromMilliseconds(100);
        using var transport = new SerialFrameTransport(Port, Baud, timeout);
        session = new Pn532Session(transport, timeout, 0);
    }

    public void ClearError() {
        IsError = false;
    }

    public (CardKind CardKind, byte[]? IDm, string? AccessCode) ReadCard()
    {
        try
        {
            session.Open();
            var result = RunPn532Flow(session);
            if (result.Error != null)
            {
                Console.WriteLine($"Error during card read: {result.Error}");
                IsError = true;
            }
            session.Close();
            return (result.CardKind , result.CardId, result.AccessCode);
        } catch (Exception ex)
        {
            Console.WriteLine($"Open Device Error: {ex.Message}");
            IsError = true;
            return (CardKind.Null, Array.Empty<byte>(), null);
        }
    }

    public void CloseReader()
    {
        session.Close();
    }

    private FlowResult RunPn532Flow(Pn532Session session)
    {
        try {
            ExpectPn532ResponseCode(session.SendCommand(new byte[] { 0x02 }), expectedResponseCode: 0x03);
            ExpectPn532StatusOk(session.SendCommand(new byte[] { 0x14, 0x01 }), expectedResponseCode: 0x15);
            ExpectPn532StatusOk(session.SendCommand(new byte[] { 0x32, 0x01, 0x03 }), expectedResponseCode: 0x33);

            var target = WaitForCard(session);
            Thread.Sleep(100);
            if (target.Kind == CardKind.Null)
            {
                return new FlowResult(target.Kind, target.CardId, null, null);
            }
            if (target.Kind == CardKind.Felica)
            {
                Console.WriteLine($"Card detected! IDm: {ToHexString(target.CardId)}");
                var readCmd = FelicaCommandBuilder.BuildReadWithoutEncryptionCommand(target.CardId);
                var readResponse = SendInDataExchange(session, target.Tg, readCmd, TimeSpan.FromSeconds(5));
                var spad0 = FelicaResponseParser.ParseSpad0(readResponse);
                var decryptor = new FeliCaDecryptor();
                var decrypted = decryptor.Decrypt(spad0);
                var accessCode = AccessCodeFormatter.ToAccessCodeString(decrypted);
                return new FlowResult(target.Kind, target.CardId, accessCode, null);
            }

            Console.WriteLine($"Card detected! TypeA UID: {ToHexString(target.CardId)}");
            var m1AccessCode = TryReadMifareClassicAccessCode(session, target.Tg, target.CardId);
            if (m1AccessCode != null) {
                return new FlowResult(target.Kind, target.CardId, m1AccessCode, null);
            }
            return new FlowResult(target.Kind, target.CardId, m1AccessCode, "Failed to read Mifare Classic AccessCode: no key matched sector 0.");
        }
        catch (Exception e) {
            return new FlowResult(CardKind.Null, null, null, e.Message);
        }

    }

    private byte[] SendInDataExchange(Pn532Session session, byte tg, ReadOnlySpan<byte> payloadToTarget, TimeSpan? timeout = null)
    {
        var pn532Payload = new byte[2 + payloadToTarget.Length];
        pn532Payload[0] = 0x40; pn532Payload[1] = tg;
        payloadToTarget.CopyTo(pn532Payload.AsSpan(2));
        var response = ExpectPn532ResponseCode(session.SendCommand(pn532Payload, responseTimeout: timeout ?? TimeSpan.FromSeconds(4)), expectedResponseCode: 0x41);
        if (response.Payload.Length < 2 || response.Payload[1] != 0x00)
            throw new InvalidOperationException($"InDataExchange failed: 0x{(response.Payload.Length > 1 ? response.Payload[1] : 0):X2}");
        // 替换 System.Range 语法
        return response.Payload.Length == 2 ? Array.Empty<byte>() : response.Payload.Skip(2).ToArray();
    }

    private string? TryReadMifareClassicAccessCode(Pn532Session session, byte tg, ReadOnlySpan<byte> uid)
    {
        const byte blockNumber = 2; // sector 0 block 2
        // Ensure UID is at least 4 bytes before copying; if it's shorter the Mifare
        // authentication can't proceed.
        if (uid.Length < 4) return null;
        var uid4 = uid.Slice(0, 4).ToArray();

        foreach (var keyHex in MifareClassicKeys)
        {
            var key = FromHexString(keyHex);
            if (TryMifareAuthenticate(session, tg, blockNumber, keyTypeA: true, key, uid4) ||
                TryMifareAuthenticate(session, tg, blockNumber, keyTypeA: false, key, uid4))
            {
                var block = ReadMifareBlock(session, tg, blockNumber);
                var hex = ToHexString(block);
                if (hex == "") {
                    throw new InvalidOperationException("Mifare read block returned empty data.");
                }

                return hex.Length <= 20 ? hex : hex.Substring(hex.Length - 20, 20);
            }
        }

        return null;
    }

    public static Pn532FrameParseResult ExpectPn532ResponseCode(Pn532FrameParseResult response, byte expectedResponseCode)
    {
        if (response.Kind != Pn532FrameKind.Data) throw new InvalidOperationException($"PN532 error: {response.Kind} ({response.Error}).");
        if (response.Payload.Length < 1 || response.Payload[0] != expectedResponseCode)
            throw new InvalidOperationException($"Expected 0x{expectedResponseCode:X2}, got 0x{(response.Payload.Length > 0 ? response.Payload[0] : 0):X2}");
        return response;
    }

    private void ExpectPn532StatusOk(Pn532FrameParseResult response, byte expectedResponseCode)
    {
        response = ExpectPn532ResponseCode(response, expectedResponseCode);
        if (response.Payload.Length >= 2 && response.Payload[1] != 0x00) throw new InvalidOperationException($"Status fail: 0x{response.Payload[1]:X2}");
    }

    private CardTarget WaitForCard(Pn532Session session)
    {
        var f212 = session.SendCommand(new byte[] { 0x4A, 0x01, 0x01, 0x00, 0xFF, 0xFF, 0x01, 0x00 }, TimeSpan.FromMilliseconds(500));
        if (ExtractFeliCaTarget(f212, out var target)) return target;

        var a106 = session.SendCommand(new byte[] { 0x4A, 0x01, 0x00 }, TimeSpan.FromMilliseconds(600));
        if (ExtractTypeATarget(a106, out target)) return target;

        if (f212.Error != null) throw new Exception(f212.Error);

        if (a106.Error != null) throw new Exception(a106.Error);

        return new CardTarget(CardKind.Null, 0, [0]);
    }

    private bool ExtractFeliCaTarget(Pn532FrameParseResult result, out CardTarget target)
    {
        target = null;
        if (result.Kind == Pn532FrameKind.Data && result.Payload.Length >= 15 && result.Payload[0] == 0x4B && result.Payload[1] > 0)
        {
            var tg = result.Payload[2];
            var idm = result.Payload.AsSpan(5, 8).ToArray();
            target = new CardTarget(CardKind.Felica, tg, idm);
            return true;
        }
        return false;
    }

    private bool ExtractTypeATarget(Pn532FrameParseResult result, out CardTarget target)
    {
        target = null;
        if (result.Kind == Pn532FrameKind.Data && result.Payload.Length >= 8 && result.Payload[0] == 0x4B && result.Payload[1] > 0)
        {
            var tg = result.Payload[2];
            var uidLen = result.Payload[6];
            var uidOffset = 7;
            if (uidLen > 0 && result.Payload.Length >= uidOffset + uidLen)
            {
                var uid = result.Payload.AsSpan(uidOffset, uidLen).ToArray();
                target = new CardTarget(CardKind.MifareClassic, tg, uid);
                return true;
            }
        }
        return false;
    }
}