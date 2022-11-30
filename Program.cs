using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;


namespace DotnetSample
{
    class Program
    {


        static async Task Main()
        {
            // var operMarker = await GetAutorizationCode();
            // var access_token = await GetOperatorMarker(operMarker);
            // var delegateMarker = await GetDelegateMarker(access_token, "test_stupin");
            
            // var policy = await GetDssPolicy(access_token);
            // Console.WriteLine(policy);

            // var userId = await RegisterUser("test_user_from_api_phone4"); //Id = 3c8284c4-9a86-482e-b45e-f4a8f9bd45be Пароль b5T6Nog9
            // Console.WriteLine(userId);
                // await DeleteUser("2b4e03be-bab6-4449-9fa3-eb2ae67a89b5");

            // var email = await AddUserEmail("3c8284c4-9a86-482e-b45e-f4a8f9bd45b", "dmitriystupin@mail.ru");

            // var phone = await AddUserPhone("3c8284c4-9a86-482e-b45e-f4a8f9bd45b", "+7(999)123-45-601");

            // Console.WriteLine(phone);

            // var confirmPhone = await ConfirmUserPhone("3c8284c4-9a86-482e-b45e-f4a8f9bd45be", "79606494134");

            // Console.WriteLine(confirmPhone);

            // var userPhones = await GetUserPhones("3c8284c4-9a86-482e-b45e-f4a8f9bd45be");

            // Console.WriteLine(userPhones);

            // var pass = await ResetPassword("3c8284c4-9a86-482e-b45e-f4a8f9bd45be");

            // Console.WriteLine(pass);
            // var idOnly = await RegisterAuthenticationMethodIdonly("3c8284c4-9a86-482e-b45e-f4a8f9bd45be");

            // Console.WriteLine(idOnly);

            // 1. Регистрация логина пользователя await RegisterUser("test_user_from_api_phone");

            // 2. Назначение метода первичной аутентификации await RegisterAuthenticationMethodIdonly("3c8284c4-9a86-482e-b45e-f4a8f9bd45be"); Возвращает statuscode 200

            // 3. Получение QR-кода с ключом аутентификации myDSS awawit GetQRCode("3c8284c4-9a86-482e-b45e-f4a8f9bd45be", "+79606494134")

            //  var QR = await GetQRCodeV2("e02e0056-6249-4fbf-9f8b-f2bea7577fd4", "+79606494134"); //"Kid":"1664198"
            //  Console.WriteLine(QR);

            //  ConvertBase64StringToGif(QR);

           await SetAuthMethodMyDss20("e02e0056-6249-4fbf-9f8b-f2bea7577fd4", "1664198");

        }


        public static void ConvertBase64StringToGif(string base64imageString)
        {
            string filePath = "QR.gif";
            File.WriteAllBytes(filePath, Convert.FromBase64String(base64imageString));
        }

        public static async Task<int> SetAuthMethodMyDss20(string id, string kid)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);


            var jsonContact = new {
                Kid = kid
            };

            var jsonString= JsonSerializer.Serialize(jsonContact);

            var content = new StringContent(jsonString.ToString(), Encoding.UTF8, "application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, $"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}/authmethod/mydss?level=0");

            // установка отправляемого содержимого
            request.Content = content;
            // отправляем запрос
            using var response = await client.SendAsync(request);


            return (int)response.StatusCode;

        }



        public static async Task<string> GetQRCodeV2(string id, string phone)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);
            var jsonContact = new {
                UserContactInfo = phone,
                UserContactInfoType = "PhoneNumber"
            };

            var jsonString= JsonSerializer.Serialize(jsonContact);

            var content = new StringContent(jsonString.ToString(), Encoding.UTF8, "application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, $"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}/mydss/init");


            // установка отправляемого содержимого
            request.Content = content;
            // отправляем запрос
            using var response = await client.SendAsync(request);
            
                // получаем ответ
                string jsonResp = await response.Content.ReadAsStringAsync();

                using (JsonDocument jsonDocument = JsonDocument.Parse(jsonResp))
                {
                    JsonElement root = jsonDocument.RootElement;
                    var access_token = root.GetProperty("QrCode");
                    Console.WriteLine(root.GetProperty("KeyInfo"));
                    return access_token.ToString();
                }
            

        }

        public static async Task<string> GetQRCodeV1(string id, string phone)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);
            var jsonContact = new {
                UserContactInfo = phone,
                UserContactInfoType = "PhoneNumber"
            };

            var jsonString= JsonSerializer.Serialize(jsonContact);

            var content = new StringContent(jsonString.ToString(), Encoding.UTF8, "application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, $"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}/mobileauth");


            // установка отправляемого содержимого
            request.Content = content;
            // отправляем запрос
            using var response = await client.SendAsync(request);
            
                // получаем ответ
                string jsonResp = await response.Content.ReadAsStringAsync();

                using (JsonDocument jsonDocument = JsonDocument.Parse(jsonResp))
                {
                    JsonElement root = jsonDocument.RootElement;
                    var access_token = root.GetProperty("QrCode");
                    return access_token.ToString();
                }
            

        }

        public static async Task<int> RegisterAuthenticationMethodIdonly(string id)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);


            var request = new HttpRequestMessage(HttpMethod.Post, $"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}/authmethod/idonly");
            var response = await client.SendAsync(request);

            var content = await response.Content.ReadAsStringAsync();


            return (int)response.StatusCode;

        }

        public static async Task<string> ResetPassword(string id)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);


            var request = new HttpRequestMessage(HttpMethod.Post, $"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}/password");
            var response = await client.SendAsync(request);

            var content = await response.Content.ReadAsStringAsync();

            return content;

        }

        public static async Task<string> GetUserPhones(string id)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);


            var request = new HttpRequestMessage(HttpMethod.Get, $"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}/phones");
            var response = await client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            return content;

        }
        public static async Task<string> ConfirmUserPhone(string id, string phone)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);


            var request = new HttpRequestMessage(HttpMethod.Post, $"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}/phones/{phone}/confirm");
            var response = await client.SendAsync(request);
            Console.WriteLine(request);
            // response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();

            return content;

        }

        public static async Task<string> AddUserPhone(string id, string phone)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);


            var request = new HttpRequestMessage(HttpMethod.Post, $"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}/phones");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Content = new StringContent("phone=+7(999)123-45-601", Encoding.UTF8);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            var response = await client.SendAsync(request);
            Console.WriteLine(request);
            // response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();

            return content;

        }

        public static async Task<string> AddUserEmail(string id, string email)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);


            //  using StringContent jsonContent = new StringContent (
            //         JsonSerializer.Serialize(new
            //         {
            //             email = email
            //         }),
            //         Encoding.UTF8,
            //         "application/json");
            var stringCont = $"email={email}";
             var content = new StringContent(stringCont, Encoding.UTF8, "application/json");

            var response = await client.PostAsync($"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}/emails", content);

            // using var request = new HttpRequestMessage(HttpMethod.Post, $"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}/emails");

            
            // // установка отправляемого содержимого
            // request.Content = content;

            // Console.WriteLine(request);
            // // отправляем запрос
            // using var response = await client.SendAsync(request);
            // получаем ответ
            string jsonResp = await response.Content.ReadAsStringAsync();

            return jsonResp;

        }
        


        public static async Task DeleteUser(string id)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = false;
            HttpClient client = new HttpClient(handler);


            using var request = new HttpRequestMessage(HttpMethod.Delete, $"https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user/{id}");

            // отправляем запрос
            using var response = await client.SendAsync(request);
            // получаем ответ
            Console.Write((int)response.StatusCode);

        }

        public static async Task<string> RegisterUser(string login)
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = false;
            HttpClient client = new HttpClient(handler);
            var jsonLogin = new {
                Login = login
            };

            var jsonString= JsonSerializer.Serialize(jsonLogin);

            var content = new StringContent(jsonString.ToString(), Encoding.UTF8, "application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, "https://stenddss.cryptopro.ru:4430/npc1cidp/ums/user");


            // установка отправляемого содержимого
            request.Content = content;
            // отправляем запрос
            using var response = await client.SendAsync(request);
            // получаем ответ
            string jsonResp = await response.Content.ReadAsStringAsync();

            return jsonResp;

        }

        public static async Task<string> GetDssPolicy(string token)
        {
             HttpClient httpClient = new HttpClient();

            var opt = new JsonSerializerOptions {
                WriteIndented = true
            };

            using var request = new HttpRequestMessage(HttpMethod.Get, "https://stenddss.cryptopro.ru/npc1css/rest/api/policy");

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            using var response = await httpClient.SendAsync(request);

            string jsonString = await response.Content.ReadAsStringAsync();

            return jsonString;

        }



        private static bool ServerCertificateCustomValidation(HttpRequestMessage requestMessage, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslErrors)
        {
            // It is possible to inspect the certificate provided by the server.
            Console.WriteLine($"Requested URI: {requestMessage.RequestUri}");
            // Console.WriteLine($"Effective date: {certificate.GetEffectiveDateString()}");
            // Console.WriteLine($"Exp date: {certificate.GetExpirationDateString()}");
            // Console.WriteLine($"Issuer: {certificate.Issuer}");
            // Console.WriteLine($"Subject: {certificate.Subject}");

            // Based on the custom logic it is possible to decide whether the client considers certificate valid or not
            Console.WriteLine($"Errors: {sslErrors}");
            return sslErrors == SslPolicyErrors.None;
        }


        

        public static async Task<string> GetDelegateMarker(string actor_token, string unique_name)
        {
            var header = new {
                alg = "none",
                typ = "JWT"
            };

            var jsonHeader = JsonSerializer.Serialize(header);
            
            var payload = new  {
                unique_name = unique_name,
                nbf =  new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds(),
                exp = new DateTimeOffset(DateTime.UtcNow.AddMinutes(5)).ToUnixTimeSeconds(),
                iat = new DateTimeOffset(DateTime.UtcNow.AddMinutes(5)).ToUnixTimeSeconds()
            };

            var jsonPayload = JsonSerializer.Serialize(payload);
            
            var subject_token = Base64Encode(jsonHeader) + "." + Base64Encode(jsonPayload) + ".";


            HttpClient httpClient = new HttpClient();
            StringContent content = new StringContent($"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&resource=urn%3Acryptopro%3Adss%3Asignserver%3Anpc1css&actor_token={actor_token}&actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt&subject_token={subject_token}");
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://stenddss.cryptopro.ru:4430/npc1cidp/oauth/token");

            var authenticationString = $"{"clientnpc1c"}:{""}";
            var base64EncodedAuthenticationString = Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(authenticationString));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", base64EncodedAuthenticationString);
            // установка отправляемого содержимого
            request.Content = content;
            // отправляем запрос
            using var response = await httpClient.SendAsync(request);
            // получаем ответ
            string jsonString = await response.Content.ReadAsStringAsync();
            using (JsonDocument jsonDocument = JsonDocument.Parse(jsonString))
            {
                JsonElement root = jsonDocument.RootElement;
                var access_token = root.GetProperty("access_token");
                return access_token.ToString();
            }
        }

        public static string Base64Encode(string plainText) 
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return  Base64UrlEncoder.Encode(plainTextBytes);
        }

        public static async Task<string> GetOperatorMarker(string code)
        {
            HttpClient httpClient = new HttpClient();
            StringContent content = new StringContent($"grant_type=authorization_code&code={code}&redirect_uri=urn:ietf:wg:oauth:2.0:oob:auto&client_id=clientnpc1c");
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://stenddss.cryptopro.ru:4430/npc1cidp/oauth/token");
            // установка отправляемого содержимого
            request.Content = content;
            // отправляем запрос
            using var response = await httpClient.SendAsync(request);
            // получаем ответ
            string jsonString = await response.Content.ReadAsStringAsync();
            using (JsonDocument jsonDocument = JsonDocument.Parse(jsonString))
            {
                JsonElement root = jsonDocument.RootElement;
                var access_token = root.GetProperty("access_token");
                return access_token.ToString();
            }

        }

        public static async Task<string> GetAutorizationCode()
        {
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);

            // Находим сертификаты с нужным именем и добавляем в коллекцию.
            X509Certificate2Collection signerCertsColl = new
                X509Certificate2Collection();
            X509Certificate2Collection foundCertColl = storeMy.
                Certificates.Find(X509FindType.FindByThumbprint,
                "5F010E5687098E8F8CAC8DC83AFB203D0FAE7985", true);

            if (foundCertColl.Count == 0)
            {
                Console.WriteLine("Клиентский сертификат не найден.");

            }
            if (foundCertColl.Count != 1)
            {
                Console.WriteLine("Найдено больше одного клиентского сертификата.");

            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;
            handler.ClientCertificates.Add(foundCertColl[0]);
            handler.AllowAutoRedirect = false;
            HttpClient client = new HttpClient(handler);

            try
            {
                HttpResponseMessage response = await client.GetAsync("https://stenddss.cryptopro.ru:4430/npc1cidp/oauth/authorize/certificate?client_id=clientnpc1c&response_type=code&scope=dss&redirect_uri=urn:ietf:wg:oauth:2.0:oob:auto&resource=urn:cryptopro:dss:signserver:npc1css");

                string responseBody = await response.Content.ReadAsStringAsync();
                var marker = response.Headers.Location.ToString().Split("=")[1];
                return marker;

            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine($"Message: {e.Message} ");
                return e.Message;

            }
            finally
            {
                // Need to call dispose on the HttpClient and HttpClientHandler objects
                // when done using them, so the app doesn't leak resources
                handler.Dispose();
                client.Dispose();
            }

        }



    }
}
