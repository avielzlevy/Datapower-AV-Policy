# Datapower AV Policy

This directory contains DataPower GatewayScript policies for:

- **Base64 AV**: Validates and processes base64-encoded PDF files, sending them to an antivirus service for scanning and optional content disarm and reconstruction (CDR).
- **Custom JSON Match**: Reads JSON input, extracts a message name, and dynamically invokes a rule based on the message.

## Files

- `base64Av.js`: Main antivirus scanning policy.
- `customJSONMatch.js`: Dynamic rule invocation based on JSON input.

## Usage

These scripts are intended to be deployed on IBM DataPower Gateway as GatewayScript policies. They require DataPower-provided modules (e.g., `urlopen`, `service-metadata`, `header-metadata`, etc.) and are not intended to be run outside of DataPower.

## Configuration

- The antivirus endpoint and API key are hardcoded in `base64Av.js`. Adjust as needed for your environment.
- The `AllowEmpty` session parameter can be set to control handling of empty base64 fields.

## License

Proprietary/Confidential (adjust as appropriate)
