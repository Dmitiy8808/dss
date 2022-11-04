using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace DotnetSample
{
    class Program
    {
         
        static async Task Main()
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "A172EFD2E3167238C45E945D859DC7B45B28A21B", true);  //A172EFD2E3167238C45E945D859DC7B45B28A21B

            if( foundCertColl.Count == 0 )
            {
                Console.WriteLine( "Клиентский сертификат не найден." );
                return;
            }
            if( foundCertColl.Count != 1 )
            {
                Console.WriteLine( "Найдено больше одного клиентского сертификата." );
                return;
            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            HttpClient client = new HttpClient(handler);
           
           try   
            {
                HttpResponseMessage response = await client.GetAsync("https://dss.1stdss.1c.ru/STS/oauth/authorize/certificate?client_id=testClient&response_type=code&scope=dss&redirect_uri={urn:ietf:wg:oauth:2.0:oob:auto}&resource=urn:cryptopro:dss:signserver:signserver");
                // Console.WriteLine($"RESPONSE {response.EnsureSuccessStatusCode()}");
                 response.EnsureSuccessStatusCode();

                string responseBody = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Read {responseBody.Length} characters");
                Console.WriteLine($"Location {response.Headers.Location} auth code");
                Console.WriteLine($"Status code {response.ToString()} ");
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine($"Message: {e.Message} ");
            }

            // Need to call dispose on the HttpClient and HttpClientHandler objects
            // when done using them, so the app doesn't leak resources
            handler.Dispose();
            client.Dispose();

            
        }

        private static bool ServerCertificateCustomValidation(HttpRequestMessage requestMessage, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslErrors)
        {
            // It is possible to inspect the certificate provided by the server.
            Console.WriteLine($"Requested URI: {requestMessage.RequestUri}");
            Console.WriteLine($"Effective date: {certificate.GetEffectiveDateString()}");
            Console.WriteLine($"Exp date: {certificate.GetExpirationDateString()}");
            Console.WriteLine($"Issuer: {certificate.Issuer}");
            Console.WriteLine($"Subject: {certificate.Subject}");

            // Based on the custom logic it is possible to decide whether the client considers certificate valid or not
            Console.WriteLine($"Errors: {sslErrors}");
            return sslErrors == SslPolicyErrors.None;
        }


        
    }
}
