using Dinamo.Hsm;
using System;
namespace TesteData
{
    class Program
    {
        private static string HSM_HOST = "200.201.208.61";
        private static string HSM_USER = "jrcvj";
        private static string HSM_PASS = "tac010203";
        static void Main(string[] args)
        {
            DinamoClient client = new DinamoClient();
            client.Connect(HSM_HOST, HSM_USER, HSM_PASS);
            Console.Out.WriteLine(client.GetHSMDate());
            client.Disconnect();
        }
    }
}
