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
