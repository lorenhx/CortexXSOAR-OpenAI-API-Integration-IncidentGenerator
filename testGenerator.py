def create_incident(json_alert):
    incident_data = {
        "type": "SECURITY",
        "name": f"Security Alert - {json_alert.get('alert_id')}",
        "details": json.dumps(json_alert, indent=2),
    }

    # Creating the incident using the Demisto 'createIncident' function
    incident = demisto.createIncidents(incident_data, lastRun=None, userID=None)
    if isError(incident):
        demisto.log(f"Error creating incident: {incident[0].get('Contents')}")
    else:
        demisto.log("Incident created successfully.")

# Replace 'json_alert' with your actual security alert JSON object
json_alert = {
    "alert_id": "123456",
    "timestamp": "2023-12-15T08:30:00Z",
    "severity": "High",
    # ... (other alert details)
}

create_incident(json_alert)
