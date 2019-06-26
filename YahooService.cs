using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace YahooServices
{
    public class YahooService
    {
        const string appId = "";
        const string consumerKey = "";
        const string consumerSecret = "";
        const string url = "https://weather-ydn-yql.media.yahoo.com/forecastrss";
        private static string authorizationLine;

        public void Initialize()
        {
            long timeStamp = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            byte[] nonce = new byte[32];
            Random rand = new Random();
            rand.NextBytes(nonce);
            string oauthNonce = new string(Convert.ToBase64String(nonce).ToArray());
            oauthNonce = Regex.Replace(oauthNonce, @"[^0-9a-zA-Z]+", "");

            List<string> parameters = new List<string>
        {
            "oauth_consumer_key=" + consumerKey,
            "oauth_nonce=" + oauthNonce,
            "oauth_signature_method=HMAC-SHA1",
            "oauth_timestamp=" + timeStamp,
            "oauth_version=1.0",
            // Make sure value is encoded
            "location=" + System.Net.WebUtility.UrlEncode("sunnyvale,ca"),
            "format=json"
        };
            parameters.Sort();

            StringBuilder parametersList = new StringBuilder();
            for (int i = 0; i < parameters.Count; i++)
            {
                parametersList.Append(((i > 0) ? "&" : "") + parameters[i]);
            }

            string signatureString = "GET&" +
                System.Net.WebUtility.UrlEncode(url) + "&" +
                System.Net.WebUtility.UrlEncode(parametersList.ToString());

            string signature = null;
            try
            {
                byte[] signingKey = Encoding.UTF8.GetBytes(consumerSecret);
                signature = GetSignature(signatureString, consumerSecret);
            }
            catch (Exception)
            {
                //System.Diagnostics.Debug.WriteLine("Unable to append signature");
                //Environment.Exit(0);
            }

            authorizationLine = "OAuth " +
                "oauth_consumer_key=\"" + consumerKey + "\", " +
                "oauth_nonce=\"" + oauthNonce + "\", " +
                "oauth_timestamp=\"" + timeStamp + "\", " +
                "oauth_signature_method=\"HMAC-SHA1\", " +
                "oauth_signature=\"" + signature + "\", " +
    "oauth_version=\"1.0\"";
        }

        public string GetSignature(string sigBaseString, string consumerSecretKey)
        {
            IBuffer KeyMaterial = CryptographicBuffer.ConvertStringToBinary(consumerSecretKey + "&", BinaryStringEncoding.Utf8);
            MacAlgorithmProvider HmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
            CryptographicKey MacKey = HmacSha1Provider.CreateKey(KeyMaterial);
            IBuffer DataToBeSigned = CryptographicBuffer.ConvertStringToBinary(sigBaseString, BinaryStringEncoding.Utf8);
            IBuffer SignatureBuffer = CryptographicEngine.Sign(MacKey, DataToBeSigned);
            string Signature = CryptographicBuffer.EncodeToBase64String(SignatureBuffer);

            return Signature;
        }

        public async static Task<string> GetJsonString(string uri)
        {
            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.Headers["Authorization"] = authorizationLine;
            request.Headers["Yahoo-App-Id"] = appId;
            request.ContentType = "application/json";
            //request.ContentType = "application/xml";

            var response = (HttpWebResponse) await request.GetResponseAsync();
            var responseString = new System.IO.StreamReader(response.GetResponseStream()).ReadToEnd();
            return responseString;
        }

        public async static Task GetYahooWeather(string location)
        {
            var uri = $"https://weather-ydn-yql.media.yahoo.com/forecastrss?location={location}&format=json";
            var jsonString = await GetJsonString(uri);
        }
    }
}
