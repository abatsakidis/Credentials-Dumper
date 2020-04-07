using System;
using System.Linq;

namespace Credentials_Dump
{
    class Program
    {
        static void Main(string[] args)
        {
            Credential cred = Credential.LoadAll().Last();
            Console.WriteLine("Username >> " + cred.Username);
            Console.WriteLine("Password >> " + cred.Password);
            Console.WriteLine("Last Write Time (UTC) >> " + cred.LastWriteTimeUtc);
            Console.WriteLine("Persistence Type >> " + cred.PersistenceType);
            Console.WriteLine("Target >> " + cred.Target);
            while (true)
            {
                Console.Read();
            }
        }
    }
}
