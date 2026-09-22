#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Threading;
using NfcAime.Dll.PN532;
using static NfcAime.Dll.MiFareHandle;

namespace NfcAime.Dll;

/// <summary>
/// 表示一个用于处理 Aime 读卡操作的类。
/// </summary>
/// <remarks>
/// AimeReader 提供了对 Aime 卡、Felica 卡及 MifareClassic 卡的读取支持，
/// 并通过控制读卡器进行通信。可通过该类实现初始化读卡器、读取卡信息、
/// 检测和清除错误等操作。
/// </remarks>
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

    /// <summary>
    /// 表示 PN532 指令流执行的结果。
    /// </summary>
    /// <remarks>
    /// 该记录用于封装执行卡片检测及信息读取流程后的详细数据，包括识别出的卡片类型、卡片 ID、访问码以及在执行过程中可能产生的错误信息。
    /// </remarks>
    private sealed record FlowResult(CardKind CardKind, byte[]? CardId, string? AccessCode, string? Error);
    private sealed record CardTarget(CardKind Kind, byte Tg, byte[] CardId);

    /// <summary>
    /// 兼容低版本 .NET：实现 ToHexString
    /// 将字节数组转换为不包含连字符的十六进制字符串。
    /// </summary>
    /// <param name="bytes">要转换的字节数组。</param>
    /// <return>十六进制格式的字符串；如果字节数组为 null 或为空，则返回空字符串。</return>
    public static string ToHexString(byte[]? bytes)
    {
        if (bytes == null || bytes.Length == 0) return string.Empty;
        return BitConverter.ToString(bytes).Replace("-", "");
    }

    /// <summary>
    /// 兼容低版本 .NET：实现 FromHexString
    /// 将十六进制字符串转换为字节数组。
    /// </summary>
    /// <param name="hex">要转换的十六进制字符串。</param>
    /// <return>转换后的字节数组。</return>
    public static byte[] FromHexString(string hex)
    {
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Invalid hex string length.");
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    /// <summary>
    /// 表示一个用于处理 Aime 读卡操作的类。
    /// </summary>
    /// <remarks>
    /// AimeReader 提供了对 Aime 卡、Felica 卡及 MifareClassic 卡的读取支持，
    /// 并通过控制读卡器进行通信。可通过该类实现初始化读卡器、读取卡信息、
    /// 检测和清除错误等操作。
    /// </remarks>
    public AimeReader(string port, int baud)
    {
        Port = port;
        Baud = baud;
        ClearError();
        TimeSpan timeout = TimeSpan.FromMilliseconds(100);
        using var transport = new SerialFrameTransport(Port, Baud, timeout);
        session = new Pn532Session(transport, timeout, 0);
    }

    /// <summary>
    /// 清除读卡器的错误状态。
    /// 将 IsError 标志重置为 false。
    /// </summary>
    public void ClearError() {
        IsError = false;
    }

    /// <summary>
    /// 尝试读取卡片信息。
    /// 通过 PN532 协议流程识别卡片类型，并获取其 IDm 和访问码。
    /// </summary>
    /// <return>包含卡片信息的元组，其中包含卡片类型 (CardKind)、卡片 ID (IDm) 以及访问码 (AccessCode)。如果读取过程中发生错误，则返回 CardKind.Null、空字节数组和 null。</return>
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

    /// <summary>
    /// 关闭读卡器。
    /// </summary>
    /// <remarks>
    /// 通过关闭底层的 PN532 会话来释放相关资源并终止与读卡器的通信。
    /// </remarks>
    public void CloseReader()
    {
        session.Close();
    }

    /// <summary>
    /// 执行 PN532 的指令流以检测卡片并读取相关信息。
    /// 通过与 PN532 进行一系列通信操作，识别卡片类型（如 Felica 或 Mifare Classic），并尝试获取卡片 ID 和访问码。
    /// </summary>
    /// <param name="session">用于与 PN532 芯片通信的会话对象。</param>
    /// <return>包含卡片类型、卡片 ID、访问码以及错误信息的执行结果。</return>
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

    /// <summary>
    /// 校验 PN532 响应帧的类型以及其有效负载中的响应代码是否符合预期。
    /// </summary>
    /// <param name="response">解析后的 PN532 帧结果。</param>
    /// <param name="expectedResponseCode">预期的响应代码。</param>
    /// <return>验证通过后的 PN532 帧解析结果。</return>
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