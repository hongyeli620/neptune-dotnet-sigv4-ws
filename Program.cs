using System;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Gremlin.Net;
using Gremlin.Net.Driver;
using Gremlin.Net.Driver.Remote;
using Gremlin.Net.Process;
using Gremlin.Net.Process.Traversal;
using Gremlin.Net.Structure;
using static Gremlin.Net.Process.Traversal.AnonymousTraversalSource;
using static Gremlin.Net.Process.Traversal.__;
using static Gremlin.Net.Process.Traversal.P;
using static Gremlin.Net.Process.Traversal.Order;
using static Gremlin.Net.Process.Traversal.Operator;
using static Gremlin.Net.Process.Traversal.Pop;
using static Gremlin.Net.Process.Traversal.Scope;
using static Gremlin.Net.Process.Traversal.TextP;
using static Gremlin.Net.Process.Traversal.Column;
using static Gremlin.Net.Process.Traversal.Direction;
using static Gremlin.Net.Process.Traversal.T;

namespace Aws4RequestSigner
{
    public class AWS4RequestSigner
    {
        private readonly string _access_key;
        private readonly string _secret_key;
        private readonly SHA256 _sha256;
        private const string algorithm = "AWS4-HMAC-SHA256";

        /* Constructor
         *
         *
         *
         *
         */
        public AWS4RequestSigner(string accessKey, string secretKey)
        {

            if (string.IsNullOrEmpty(accessKey))
            {
                throw new ArgumentOutOfRangeException(nameof(accessKey), accessKey, "Not a valid access_key.");
            }

            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentOutOfRangeException(nameof(secretKey), secretKey, "Not a valid secret_key.");
            }

            _access_key = accessKey;
            _secret_key = secretKey;
            _sha256 = SHA256.Create();
        }


        /******************** AWS SIGNING FUNCTIONS *********************/
        private string Hash(byte[] bytesToHash)
        {
            var result = _sha256.ComputeHash(bytesToHash);
            return ToHexString(result);
        }

        private static byte[] HmacSHA256(byte[] key, string data)
        {
            var hashAlgorithm = new HMACSHA256(key);
            return hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        private static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
        {
            byte[] kSecret = Encoding.UTF8.GetBytes("AWS4" + key);
            byte[] kDate = HmacSHA256(kSecret, dateStamp);
            byte[] kRegion = HmacSHA256(kDate, regionName);
            byte[] kService = HmacSHA256(kRegion, serviceName);
            byte[] kSigning = HmacSHA256(kService, "aws4_request");
            return kSigning;
        }

        private static string ToHexString(byte[] array)
        {
            var hex = new StringBuilder(array.Length * 2);
            foreach (byte b in array) {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }

        public HttpRequestMessage Sign(HttpRequestMessage request, string service, string region)
        {
            if (string.IsNullOrEmpty(service)) {
                throw new ArgumentOutOfRangeException(nameof(service), service, "Not a valid service.");
            }

            if (string.IsNullOrEmpty(region)) {
                throw new ArgumentOutOfRangeException(nameof(region), region, "Not a valid region.");
            }

            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            if (request.Headers.Host == null) {
                request.Headers.Host = request.RequestUri.Host + ":" + request.RequestUri.Port;
            }

            var t = DateTimeOffset.UtcNow;
            var amzdate = t.ToString("yyyyMMddTHHmmssZ");
            request.Headers.Add("x-amz-date", amzdate);
            var datestamp=t.ToString("yyyyMMdd");

            var canonical_request = new StringBuilder();
            canonical_request.Append(request.Method + "\n");
            canonical_request.Append(request.RequestUri.AbsolutePath + "\n");

            var canonicalQueryParams = GetCanonicalQueryParams(request);

            canonical_request.Append(canonicalQueryParams + "\n");

            var signedHeadersList = new List<string>();

            foreach (var header in request.Headers.OrderBy(a => a.Key.ToLowerInvariant()))
            {
                canonical_request.Append(header.Key.ToLowerInvariant());
                canonical_request.Append(":");
                canonical_request.Append(string.Join(",", header.Value.Select(s => s.Trim())));
                canonical_request.Append("\n");
                signedHeadersList.Add(header.Key.ToLowerInvariant());
            }

            canonical_request.Append("\n");
            
            var signed_headers = string.Join(";", signedHeadersList);

            canonical_request.Append(signed_headers + "\n");

            var content =  new byte[0];
            var payload_hash = Hash(content);

            canonical_request.Append(payload_hash);
            var credential_scope = $"{datestamp}/{region}/{service}/aws4_request";
                       
            var string_to_sign = $"{algorithm}\n{amzdate}\n{credential_scope}\n" + Hash(Encoding.UTF8.GetBytes(canonical_request.ToString()));

            var signing_key = GetSignatureKey(_secret_key, datestamp, region, service);
            var signature = ToHexString(HmacSHA256(signing_key, string_to_sign));
            
            request.Headers.TryAddWithoutValidation("Authorization", $"{algorithm} Credential={_access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}");
            
            return request;
        }

        private static string GetCanonicalQueryParams(HttpRequestMessage request)
        {
            var querystring = HttpUtility.ParseQueryString(request.RequestUri.Query);
            var keys = querystring.AllKeys.OrderBy(a => a).ToArray();

            // Query params must be escaped in upper case (i.e. "%2C", not "%2c").
            var queryParams = keys.Select(key => $"{key}={Uri.EscapeDataString(querystring[key])}");
            var canonicalQueryParams = string.Join("&", queryParams);
            return canonicalQueryParams;
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            
            var access_key = "";
            var secret_key = "";
            var neptune_endpoint = ""; // ex: mycluster.cluster.us-east-1.neptune.amazonaws.com
            var neptune_region = ""; //ex: us-east-1
            var using_ELB = false; //Set to True if using and ELB and define ELB URL via ELB_endpoint variable
            var ELB_endpoint = ""; //ex: myelb.elb.us-east-1.amazonaws.com

            /* The AWS4RequestSigner library was intented to pass a signed request to an HTTP endpoint.
             * Since we're using websockets, we will create the HTTP request and sign the request, however
             * we will pull the headers from the signed request in order to create a webSocketConfiguration
             * object with these same headers. 
             */
            var neptunesigner = new AWS4RequestSigner(access_key,secret_key);
            var request = new HttpRequestMessage {
                Method = HttpMethod.Get,
                RequestUri = new Uri("http://" + neptune_endpoint + "/gremlin")
            };
            var signedrequest = neptunesigner.Sign(request, "neptune-db", neptune_region);
            var authText = signedrequest.Headers.GetValues("Authorization").FirstOrDefault();
            var authDate = signedrequest.Headers.GetValues("x-amz-date").FirstOrDefault();

            var webSocketConfiguration = new Action<ClientWebSocketOptions>(options => { 
                    options.SetRequestHeader("host", neptune_endpoint);
                    options.SetRequestHeader("x-amz-date", authDate);
                    options.SetRequestHeader("Authorization",authText);
                    }); 

            /* GremlinServer() accepts the hostname and port as separate parameters.  
             * Split the endpoint into both variables to pass to GremlinServer()
             *
             * Also - determine if an ELB is used.  If using an ELB, connect using the ELB hostname.
             */
            var neptune_host = ""; 
            if(using_ELB) {
                neptune_host = ELB_endpoint;
            } else {
                neptune_host = neptune_endpoint.Split(':')[0];
            }
            var neptune_port = int.Parse(neptune_endpoint.Split(':')[1]);

            var gremlinServer = new GremlinServer(neptune_host, neptune_port);
            var gremlinClient = new GremlinClient(gremlinServer, webSocketConfiguration: webSocketConfiguration);
            var remoteConnection = new DriverRemoteConnection(gremlinClient);
            var g = Traversal().WithRemote(remoteConnection);

            /* Example code to pull the first 5 vertices in a graph. */
            Console.WriteLine("Get List of Node Labels:");
            Int32 limitValue = 5;
            var output = g.V().Limit<Vertex>(limitValue).ToList();
            foreach(var item in output) {
                Console.WriteLine(item);
            }
        }
    }

}
