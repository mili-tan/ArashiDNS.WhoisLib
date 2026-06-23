using System.Net.Sockets;
using System.Text;

namespace ArashiDNS.WhoisLib.Core;

public class WhoisTcpConnection : IDisposable
{
    private const int DefaultPort = 43;
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(5);

    private TcpClient? _client;
    private NetworkStream? _stream;
    private bool _disposed;

    private static bool _encodingRegistered = false;
    private static readonly object _encodingLock = new object();

    private static void EnsureEncodingRegistered()
    {
        if (_encodingRegistered) return;
        
        lock (_encodingLock)
        {
            if (!_encodingRegistered)
            {
                try
                {
                    Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                    _encodingRegistered = true;
                }
                catch
                {
                    // Encoding registration failed, using default encoding
                }
            }
        }
    }

    public async Task<string> QueryAsync(string server, string query, TimeSpan? timeout = null)
    {
        EnsureEncodingRegistered();
        
        var effectiveTimeout = timeout ?? DefaultTimeout;

        using var cts = new CancellationTokenSource(effectiveTimeout);

        try
        {
            _client = new TcpClient();
            _client.ReceiveTimeout = (int)ReadTimeout.TotalMilliseconds;
            _client.SendTimeout = (int)ReadTimeout.TotalMilliseconds;
            
            await _client.ConnectAsync(server, DefaultPort, cts.Token);

            _stream = _client.GetStream();
            _stream.ReadTimeout = (int)ReadTimeout.TotalMilliseconds;

            var queryBytes = Encoding.ASCII.GetBytes(query + "\r\n");
            await _stream.WriteAsync(queryBytes, cts.Token);

            var responseBytes = await ReadResponseBytesAsync(_stream, cts.Token);
            return DecodeResponse(responseBytes);
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException($"WHOIS query to {server} timed out after {effectiveTimeout.TotalSeconds} seconds");
        }
        catch (SocketException ex)
        {
            throw new InvalidOperationException($"Failed to connect to WHOIS server {server}: {ex.Message}", ex);
        }
    }

    private static async Task<byte[]> ReadResponseBytesAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        var result = new MemoryStream();

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                int bytesRead;
                try
                {
                    bytesRead = await stream.ReadAsync(buffer, cancellationToken);
                }
                catch (IOException)
                {
                    break;
                }

                if (bytesRead == 0)
                    break;

                result.Write(buffer, 0, bytesRead);

                if (!stream.DataAvailable)
                {
                    await Task.Delay(100, cancellationToken);
                    if (!stream.DataAvailable)
                        break;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }

        return result.ToArray();
    }

    private static string DecodeResponse(byte[] data)
    {
        if (data.Length == 0)
            return string.Empty;

        // Try UTF-8 decoding
        try
        {
            var utf8 = Encoding.UTF8.GetString(data);
            // Check for replacement characters (sign of decode failure)
            if (!utf8.Contains('\uFFFD'))
                return utf8;
        }
        catch
        {
        }

        // Try GBK decoding
        try
        {
            var gbk = Encoding.GetEncoding("GBK").GetString(data);
            if (!gbk.Contains('\uFFFD'))
                return gbk;
        }
        catch
        {
        }

        // Try GB18030 decoding
        try
        {
            var gb18030 = Encoding.GetEncoding("GB18030").GetString(data);
            if (!gb18030.Contains('\uFFFD'))
                return gb18030;
        }
        catch
        {
        }

        // Fall back to Latin1 (no data loss)
        return Encoding.Latin1.GetString(data);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _stream?.Dispose();
            _client?.Dispose();
            _disposed = true;
        }
    }
}
