<img src="https://github.com/lorenhx/CortexXSOAR-OpenAI-API-Integration-IncidentGenerator/assets/33938788/bc6aff13-8b40-4d75-a182-1f1bc06fb374" width="15%" height="15%">

# CortexXSOAR-OpenAI-API-Integration-IncidentGenerator
Integration for Cortex XSOAR (demisto), which uses Open AI APIs to generate incidents. It simulates a SIEM through a custom prompt. It generates about 20 incidents.


## Instructions
Use the yml file to import the integration in the XSOAR.
To generate alerts, run the command !RED-start in the war room.
Set incidentgenerator.red-start.timeout (key) with 1800 (value) in settings->about->troubleshooting, Add Server Configuration
