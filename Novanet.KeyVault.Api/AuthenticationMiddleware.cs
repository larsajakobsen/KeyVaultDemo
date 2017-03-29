using Microsoft.AspNetCore.Http;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Novanet.KeyVault.Api
{
    public class AuthenticationMiddleware
    {
        private readonly RequestDelegate _next;

        public AuthenticationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            string authHeader = context.Request.Headers["Authorization"];
            if (authHeader != null && authHeader.StartsWith("Basic"))
            {
                string passwordFromHeader = GetPasswordFromHeader(authHeader);

                var keyVaultSecret = GetSecretFromKeyVault("https://invoicereceiver-stest.vault.azure.net/secrets/InvoiceApiPassword");

                if (passwordFromHeader == keyVaultSecret)
                {
                    await _next.Invoke(context);
                }
                else
                {
                    context.Response.StatusCode = 401; //Unauthorized
                    return;
                }
            }
            else
            {
                // no authorization header
                context.Response.StatusCode = 401; //Unauthorized
                return;
            }
        }

        private static string GetPasswordFromHeader(string authHeader)
        {
            string encodedUsernamePassword = authHeader.Substring("Basic ".Length).Trim();
            Encoding encoding = Encoding.GetEncoding("iso-8859-1");
            string usernamePassword = encoding.GetString(Convert.FromBase64String(encodedUsernamePassword));

            int seperatorIndex = usernamePassword.IndexOf(':');

            var password = usernamePassword.Substring(seperatorIndex + 1);
            return password;
        }

        private static string GetSecretFromKeyVault(string authority)
        {
            var kv = new KeyVaultClient(GetToken);
            var task = kv.GetSecretAsync(authority);
            task.Wait();
            return task.Result.Value;
        }

        public static async Task<string> GetToken(string authority, string resource, string scope)
        {
            try
            {
                var authContext = new AuthenticationContext(authority);

                ClientCredential clientCred = new ClientCredential("eb25b6ea-65bf-47b1-a3b9-d92fbe88b43b", "A0M80f2IjqCevHM20N8CVe99i6K+C40r++pYDMSvLwQ=");

                AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

                if (result == null)
                {
                    throw new InvalidOperationException("Failed to obtain the Access token");

                }

                return result.AccessToken;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}
