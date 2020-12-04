using CommandLine;

namespace Microsoft.Azure.Devices.Client.Samples
{
    class Options
    {
        [Value(0,
            MetaName = "HOSTNAME",
            Required = true,
            HelpText = "Host name of the IoT Hub to connect to.")]
        public string Hostname { get; set; }

        [Value(1,
            MetaName = "ClientId",
            Required = true,
            HelpText = "ID of connecting client.")]
        public string ClientId { get; set; }

        [Option(
            's',
            "sas-key",
            SetName = "SAS",
            Required = true,
            HelpText = "SAS Key to use for authentication")]
        public string SasKey { get; set; }

        [Option(
            'p',
            "sas-policy",
            Default = "",
            SetName = "SAS",
            HelpText = "SAS Policy name to use for authentication")]
        public string SasPolicy { get; set; }

        [Option(
            'c',
            "cert-file",
            SetName = "X509",
            Required = true,
            HelpText = "Path to client certificate PFX file to use for authentication")]
        public string ClientCertificatePath { get; set; }

        [Option(
            'w',
            "cert-password",
            SetName = "X509",
            Required = true,
            HelpText = "Password for client certificate PFX file to use for authentication")]
        public string ClientCertificatePassword { get; set; }

        [Option(
            'v',
            "verbose",
            HelpText = "Enable verbose output")]
        public bool Verbose { get; set; }
    }
}