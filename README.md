# Azure IoT Hub Data Plane MQTT 5 API Sample for C# (.NET) - Preview

A sample showing how to use MQTT 5 API to interact with Azure IoT Hub.

## Features

This sample highlights how to:

- Establish connection to Azure IoT Hub using MQTT 5
- Send telemetry messages
- Subscribe and handle C2D commands
- Subscribe and handle Direct Method calls
- Get and update Device Twin state

## Getting Started

### Prerequisites

- [Azure IoT Hub (Preview mode)](https://docs.microsoft.com/azure/iot-hub/iot-hub-preview-mode) with device created

### Installation

- Get the [.NET Core 3.1 SDK](https://dotnet.microsoft.com/download)

### Quickstart

1. Clone the repo: `git clone https://github.com/Azure-Samples/iot-hub-mqtt-5-preview-samples-csharp.git`

1. Open the source directory: `cd src`

1. Run sample application according to type of credentials:

    - SAS based on client's symmetrical keys:

      `dotnet run -- <hostname> <client-id> -s <SAS-key>`

    - X.509 certificate:
  
      `dotnet run -- <hostname> <client-id> -c <certificate-path> -w <certificate-password>`

    - SAS based on IoT hub access policy:

      `dotnet run -- <hostname> <client-id> -s <SAS-key> -p <policy-name>`

For example,

`dotnet run -- abc.azure-devices.net device1/module1 -s AAA...`

will run sample application, connect to `abc` IoT hub as `module1` module  `device1` device using SAS key `AAA...`.

## Resources

- To learn more about IoT Hub's MQTT 5 support in preview, see [IoT Hub MQTT 5 support overview (preview)](https://docs.microsoft.com/azure/iot-hub/iot-hub-mqtt-5)

- To see the API reference, visit [IoT Hub data plane MQTT 5 API reference](https://docs.microsoft.com/azure/iot-hub/iot-hub-mqtt-5-reference)
