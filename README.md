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

- Azure IoT Hub (Preview mode) with device created
- .NET Core 3.1 SDK

### Running a Sample

- open `src` directory in terminal
- Run sample application according to type of credentials:
  - SAS based on client's symmetrical keys:

    `dotnet run -- <hostname> <client-id> -s <SAS-key>`

  - X.509 certificate:
  
    `dotnet run -- <hostname> <client-id> -c <certificate-path> -w <certificate-password>`

  - SAS based on IoT hub access policy:

    `dotnet run -- <hostname> <client-id> -s <SAS-key> -p <policy-name>`

For example,

`dotnet run -- abc.azure-devices.net device1/module1 -s AAA...`

will run sample application, connect to `abc` IoT hub as `module1` module  `device1` device using SAS key `AAA...`.
