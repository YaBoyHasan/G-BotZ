using G_BotZ.Proxy;

namespace G_BotZ
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
            var proxy = new ReverseProxy("76.223.121.75", 30000, 30000);
            await proxy.StartAsync();
        }
    }
}
