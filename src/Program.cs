using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;
using MQTTnet;
using MQTTnet.Adapter;
using MQTTnet.Client;
using MQTTnet.Client.Connecting;
using MQTTnet.Client.Options;
using MQTTnet.Client.Publishing;
using MQTTnet.Client.Subscribing;
using MQTTnet.Diagnostics;
using MQTTnet.Packets;
using MQTTnet.Protocol;

namespace Microsoft.Azure.Devices.Client.Samples
{
    class Program
    {
        IMqttClient client;
        ConcurrentDictionary<int, TaskCompletionSource<MqttApplicationMessage>> serverRequestMap =
            new ConcurrentDictionary<int, TaskCompletionSource<MqttApplicationMessage>>();
        int correlationId = 0;

        static async Task Main(string[] args)
        {
            var parser = new Parser(with => with.EnableDashDash = true);
            var parserResult = parser.ParseArguments<Options>(args);
            await parserResult.WithNotParsed(x =>
                {
                    var helpText = HelpText.AutoBuild(parserResult, h =>
                    {
                        h.AutoVersion = false;
                        return HelpText.DefaultParsingErrorsHandler(parserResult, h);
                    }, e => e);
                    Console.WriteLine(helpText);
                })
                .WithParsedAsync(RunAsync);
        }

        static async Task RunAsync(Options options)
        {
            Console.WriteLine("Connecting to IoT Hub...");
            var program = new Program();
            var closedPromise = new TaskCompletionSource<int>();
            await program.ConnectAsync(options, closedPromise);
            Console.WriteLine("Connected");

            Console.WriteLine("Sending telemetry message...");
            await program.SendTelemetryAsync();
            Console.WriteLine("Sent telemetry message");

            Console.WriteLine("Getting twin...");
            var twin = await program.GetTwinAsync();
            Console.WriteLine($"Twin: {twin}");

            Console.WriteLine("Patching twin reported state...");
            var newVersion = await program.PatchTwinAsync();
            Console.WriteLine($"Patched Twin/reported; new version: {newVersion}");

            // Keep running to continue receiving messages from IoT Hub, unless disconnect happens
            var exitCode = await closedPromise.Task;
            Environment.ExitCode = exitCode;
        }

        public async Task ConnectAsync(Options options, TaskCompletionSource<int> closedPromise)
        {
            if (options.Verbose)
            {
                MqttNetGlobalLogger.LogMessagePublished += (s, e) =>
                {
                    var trace = $">> [{e.LogMessage.Timestamp:O}] [{e.LogMessage.ThreadId}] [{e.LogMessage.Source}] [{e.LogMessage.Level}]: {e.LogMessage.Message}";
                    if (e.LogMessage.Exception != null)
                    {
                        trace += Environment.NewLine + e.LogMessage.Exception.ToString();
                    }

                    Console.WriteLine(trace);
                };
            }

            var factory = new MqttFactory();
            var client = factory.CreateMqttClient();
            client.UseApplicationMessageReceivedHandler(msg => this.HandleMessageAsync(msg));

            var tlsOptions = new MqttClientOptionsBuilderTlsParameters();
            tlsOptions.UseTls = true;

            var clientOptions = new MqttClientOptionsBuilder()
                .WithTcpServer(opt => opt.NoDelay = true)
                .WithClientId(options.ClientId)
                .WithTcpServer(options.Hostname, 8883)
                .WithTls(tlsOptions)
                .WithProtocolVersion(MQTTnet.Formatter.MqttProtocolVersion.V500)
                // .WithUserProperty("host", hostName) // normally it is not needed as SNI is added by most TLS implementations.  
                .WithUserProperty("api-version", "2020-10-01-preview")
                .WithCommunicationTimeout(TimeSpan.FromSeconds(30))
                .WithKeepAlivePeriod(TimeSpan.FromSeconds(300))
                .WithCleanSession(false); // keep existing subscriptions 

            if (string.IsNullOrEmpty(options.SasKey))
            {
                tlsOptions.Certificates = new[] { new X509Certificate(options.ClientCertificatePath, options.ClientCertificatePassword) };
                clientOptions.WithAuthentication("X509", null);
            }
            else
            {
                var at = DateTimeOffset.UtcNow;
                var atString = at.ToUnixTimeMilliseconds().ToString();
                var expiry = at.AddMinutes(40);
                var expiryString = expiry.ToUnixTimeMilliseconds().ToString();
                string toSign = $"{options.Hostname}\n{options.ClientId}\n{options.SasPolicy}\n{atString}\n{expiryString}\n";
                var hmac = new HMACSHA256(Convert.FromBase64String(options.SasKey));
                var sas = hmac.ComputeHash(Encoding.UTF8.GetBytes(toSign));

                clientOptions
                    .WithAuthentication("SAS", sas)
                    .WithUserProperty("sas-at", atString)
                    .WithUserProperty("sas-expiry", expiryString);
                if (!string.IsNullOrEmpty(options.SasPolicy))
                {
                    // include only if using SAS policy
                    clientOptions.WithUserProperty("sas-policy", options.SasPolicy);
                }
            }
            
            // Set up disconnection handling: print out details and allow process to close
            client.UseDisconnectedHandler(disconnectArgs =>
            {
                Console.WriteLine($"Disconnected: {disconnectArgs.ReasonCode}");
                if (disconnectArgs.AuthenticateResult?.UserProperties != null)
                {
                    foreach (var prop in disconnectArgs.AuthenticateResult.UserProperties)
                    {
                        Console.WriteLine($"{prop.Name}: {prop.Value}");
                    }
                }
                closedPromise.SetResult(1);
            });

            try
            {
                // once connection is established, we may start receiving messages based on subscriptions
                // from previous connections - better set client before connection.
                this.client = client; 
                
                var connectResult = await client.ConnectAsync(clientOptions.Build(), CancellationToken.None);
                if (connectResult.ResultCode != MqttClientConnectResultCode.Success)
                {
                    var status = GetStatus(connectResult.UserProperties)?.ToString("x4");
                    throw new Exception($"Connect failed. Status: {connectResult.ResultCode}; status: {status}");
                }

                if (!connectResult.IsSessionPresent)
                {
                    // only subscribe if haven't subscribed already.
                    // This optimization only works of a single SUBSCRIBE is used to subscribe to everything at once or
                    // if app keeps track of what has been successfully acknowledged by server.
                    var subscribeResult = await client.SubscribeAsync(
                        new MqttTopicFilter
                        {
                            Topic = "$iothub/methods/+",
                            QualityOfServiceLevel = MqttQualityOfServiceLevel.AtMostOnce
                        },
                        new MqttTopicFilter
                        {
                            Topic = "$iothub/commands",
                            QualityOfServiceLevel = MqttQualityOfServiceLevel.AtLeastOnce
                        },
                        new MqttTopicFilter
                        {
                            Topic = "$iothub/twin/patch/desired",
                            QualityOfServiceLevel = MqttQualityOfServiceLevel.AtMostOnce
                        });

                    // make sure subscriptions were successful
                    if (subscribeResult.Items.Count != 3
                        || subscribeResult.Items[0].ResultCode != MqttClientSubscribeResultCode.GrantedQoS0
                        || subscribeResult.Items[1].ResultCode != MqttClientSubscribeResultCode.GrantedQoS1
                        || subscribeResult.Items[2].ResultCode != MqttClientSubscribeResultCode.GrantedQoS0)
                    {
                        throw new ApplicationException("Failed to subscribe");
                    }
                }
            }
            catch (MqttConnectingFailedException ex)
            {
                Console.WriteLine($"Failed to connect, reason code: {ex.ResultCode}");
                if (ex.Result?.UserProperties != null)
                {
                    foreach (var prop in ex.Result.UserProperties)
                    {
                        Console.WriteLine($"{prop.Name}: {prop.Value}");
                    }
                }
                throw;
            }
        }

        /// Handles all the incoming messages
        private async Task HandleMessageAsync(MqttApplicationMessageReceivedEventArgs args)
        {
            var msg = args.ApplicationMessage;
            if (msg.Topic == "$iothub/responses")
            {
                // Got the response for request sent out earlier (e.g. Get Twin or Patch Twin)
                int cid;
                try
                {
                    cid = BitConverter.ToInt32(msg.CorrelationData);
                }
                catch (ArgumentOutOfRangeException ex)
                {
                    throw new Exception("Invalid Correlation Data for response.", ex);
                }

                if (this.serverRequestMap.TryRemove(cid, out var responsePromise))
                {
                    responsePromise.TrySetResult(msg);
                    return;
                }
            }
            else if (msg.Topic.StartsWith("$iothub/methods/"))
            {
                var fork = Task.Run(async () =>
                {
                    var response = await this.HandleMethodAsync(msg);
                    await this.client.PublishAsync(response);
                });
            }
            else if (msg.Topic == "$iothub/commands")
            {
                await this.HandleCommandAsync(msg);
            }
            else if (msg.Topic == "$iothub/twin/patch/desired")
            {
                await this.HandleTwinDesiredAsync(msg);
            }
        }

        /// Sends telemetry message
        private async Task SendTelemetryAsync()
        {
            var message = new MqttApplicationMessageBuilder()
                .WithAtLeastOnceQoS()
                .WithTopic("$iothub/telemetry")
                .WithContentType("application/json") // optional: sets `content-type` system property on message
                .WithUserProperty("@myProperty", "my value") // optional: adds custom property `myProperty`
                .WithUserProperty("creation-time", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString()) // optional: sets `creation-time` system property on message
                .WithPayload(Encoding.UTF8.GetBytes("\"test payload\""))
                .Build();

            var response = await this.client.PublishAsync(message);
            if (response.ReasonCode != MqttClientPublishReasonCode.Success)
            {
                throw new Exception($"Failed to send telemetry event. Reason Code: {response.ReasonCode}; Status: {GetStatus(response.UserProperties)?.ToString("x4") ?? "-"}");
            }
        }

        /// Gets Twin
        private async Task<string> GetTwinAsync()
        {
            var message = new MqttApplicationMessageBuilder()
                .WithTopic("$iothub/twin/get")
                .WithAtMostOnceQoS()
                .Build();

            var response = await this.SendRequestAsync(message);
            var status = GetStatus(response.UserProperties);
            if ((status ?? 0) == 0)
            {
                return Encoding.UTF8.GetString(response.Payload); // twin
            }
            throw new Exception($"Call failed: {status}");
        }

        /// Updates reported properties
        private async Task<string> PatchTwinAsync()
        {
            var message = new MqttApplicationMessageBuilder()
                .WithTopic("$iothub/twin/patch/reported")
                .WithAtMostOnceQoS()
                .WithPayload($"{{\"test\": \"{Guid.NewGuid()}\"}}")
                .Build();

            var response = await this.SendRequestAsync(message);
            var status = GetStatus(response.UserProperties);
            if ((status ?? 0) == 0)
            {
                return response.UserProperties.First(p => p.Name == "version").Value;
            }
            throw new Exception($"Call failed: {status}");
        }

        /// Handles direct method calls for "method1" method.
        private async Task<MqttApplicationMessage> HandleMethodAsync(MqttApplicationMessage message)
        {
            Console.WriteLine($"Received method call:\ntopic:{message.Topic}\npayload as a string: {Encoding.UTF8.GetString(message.Payload)}");
            return new MqttApplicationMessageBuilder()
                .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtMostOnce)
                .WithTopic("$iothub/responses")
                .WithCorrelationData(message.CorrelationData)
                .WithUserProperty("response-code", "200")
                .WithPayload("{\"test\":123}")
                .Build();
        }

        /// Handles notifications for updates to twin desired state
        private async Task HandleTwinDesiredAsync(MqttApplicationMessage msg)
        {
            Console.WriteLine($"Received Twin Desired state update:\n{Encoding.UTF8.GetString(msg.Payload)}");
        }

        /// Handles incoming commands
        private async Task HandleCommandAsync(MqttApplicationMessage message)
        {
            Console.WriteLine($"Received command:\npayload as string: {Encoding.UTF8.GetString(message.Payload)}");
        }

        /// Handles client-server request-response interactions
        private async Task<MqttApplicationMessage> SendRequestAsync(MqttApplicationMessage request)
        {
            int correlation = Interlocked.Increment(ref this.correlationId);
            var promise = new TaskCompletionSource<MqttApplicationMessage>();
            try
            {
                request.CorrelationData = BitConverter.GetBytes(correlation);
                this.serverRequestMap.TryAdd(correlation, promise);
                await this.client.PublishAsync(request);
            }
            catch (Exception)
            {
                TaskCompletionSource<MqttApplicationMessage> removed;
                this.serverRequestMap.TryRemove(correlation, out removed);
                throw;
            }
            return await promise.Task;
        }

        /// Parses status from packet properties
        private int? GetStatus(List<MqttUserProperty> properties)
        {
            var status = properties.FirstOrDefault(up => up.Name == "status");
            if (status == null)
            {
                return null;
            }
            return int.Parse(status.Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }
    }
}
