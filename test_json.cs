using System;
using System.Net.Http;
using System.Text.Json;

class Program
{
    static async Task Main()
    {
        var client = new HttpClient();
        var json = await client.GetStringAsync("https://rdap.arin.net/registry/ip/8.8.8.8");
        
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        
        Console.WriteLine("Top-level properties:");
        foreach (var prop in root.EnumerateObject())
        {
            Console.WriteLine($"  {prop.Name}: {prop.Value.ValueKind}");
        }
        
        Console.WriteLine("\nKey fields:");
        if (root.TryGetProperty("name", out var name))
            Console.WriteLine($"  name: {name.GetString()}");
        if (root.TryGetProperty("handle", out var handle))
            Console.WriteLine($"  handle: {handle.GetString()}");
        if (root.TryGetProperty("startAddress", out var start))
            Console.WriteLine($"  startAddress: {start.GetString()}");
        if (root.TryGetProperty("endAddress", out var end))
            Console.WriteLine($"  endAddress: {end.GetString()}");
    }
}
