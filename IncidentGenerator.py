register_module_line('Incident Generator', 'start', __line__())
import requests
import json
import time
import re
import urllib3
from datetime import datetime
# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """ Client class to interact with the OpenAI ChatGPT API v3
    """

    def __init__(self, api_key: str, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {'Authorization': f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def chatgpt(self, options):

        return self._http_request(method='POST', url_suffix='v1/chat/completions', json_data=options, headers=self.headers)

def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    Returning 'ok' indicates that connection to the service is successful.
    Raises exceptions if something goes wrong.
    """
    data = {
    "model": "gpt-3.5-turbo",
    "messages": [{'role': 'user', 'content': 'Hello'}],
    "temperature": 0.7
    }
    demisto.results("entro nel test module")
    try:
        response = client.chatgpt(data)
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error("Failed to communicate with Open AI Api. Error: " + str(e))

    status = ''
    try:
        if response:
            status = 'ok'
            return status
    except Exception as e:
        exception_text = str(e).lower()
        if 'forbidden' in exception_text or 'authorization' in exception_text:
            status = 'Authorization Error: make sure API Key is correctly set'
            return status
        else:
            raise e

    return status


class OpenAIAssistant:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {
            'Authorization': f"Bearer {self.api_key}",
            'Content-Type': 'application/json'
        }
        #Messages to send to the Open AI api in the content field
        self.messages = []
        #Parsed responses from the Open AI api with the generated alerts in json format
        self.responses = [] 

    def set_message(self, content, role='system'):
        self.messages.append({'role': role, 'content': content})

    #Saves alerts in self.rensponses (list of json) and return the message to append

    def parser(self, response):

        rep = json.dumps(response)
        repJSON = json.loads(rep)
        generated_content = repJSON.get('choices', [])
        # Extract generated content from the API response

        #Finds all the json in the response
        matches = re.findall(r'\{[^\{\}]+\}', str(generated_content[0].get('message', {}).get('content', "").strip('\n')))
        for m in matches:
            self.responses.append(json.loads(m))

        #Return the last message to append to the next request
        return generated_content[0].get('message', {})

    def create_session(self, continue_prompts=2): 
        time.sleep(31)
        url = 'https://api.openai.com/'

        # Prompt to set the system role
        self.set_message("You are the Google Chronicle SIEM who produces security alerts that you take from different sources inside an enterprise. The fields of the JSON must be: timestamp, description, event_type, source_ip, destination_ip and severity. Severity has to be: [low, medium, high, critical]. Don't change for no reason the names of the fields!!")

        # Initial user prompt
        self.set_message("Generate 30 alerts, where you hide an alerts of an attack between casual alerts which will compose some noise to better simulate the SIEM. The attack must be  the complete Cyber Kill Chain attack with Qbot malware which enters an organization via infected USB through the scheduled window tasks it does privilege escalation and manages to access lsas and finally recover email credentials and browser accounts. Every response you give me has to be a list of  2 JSON that has to be closed and opened in every response you give me. I will next ask you to continue the output, so split the output. Use the actual time for the timestamps", role='user')

        # Communicate with the Open AI api
        data = {
            "model": "gpt-3.5-turbo",
            "messages": self.messages,
            "temperature": 0.7
        }
        try:
            client = Client(api_key=self.api_key, base_url=url, verify=False, proxy=False)
            response = client.chatgpt(data)
        except Exception as e:
            demisto.error(traceback.format_exc())  # print the traceback
            return_error("Failed to communicate with Open AI Api. Error: " + str(e))

        toappend = self.parser(response)

        #Token used
        rep = json.dumps(response)
        repJSON = json.loads(rep)
        total_tokens = int(repJSON.get('usage', {}).get('total_tokens', 0))
        if total_tokens > 4000:
            return

        # Add "continue" prompts to generate more alerts
        for i in range(continue_prompts):
            #Wait 21 seconds to avoid overcoming the 3 requests per minute limit
            time.sleep(31)

            self.messages.append(toappend)

            self.set_message("continue", role = "user")
            data = {
                    "model": "gpt-3.5-turbo",
                    "messages": self.messages,
                    "temperature": 0.7
                }
            try:
                client = Client(api_key=self.api_key, base_url=url, verify=False, proxy=False)
                response = client.chatgpt(data)

                #Control used tokens
                rep = json.dumps(response)
                repJSON = json.loads(rep)
                total_tokens = int(repJSON.get('usage', {}).get('total_tokens', 0))
                if total_tokens > 4000:
                    return

            except Exception as e:
                demisto.error(traceback.format_exc())  # print the traceback
                return_error("Failed to communicate with Open AI Api. Error: " + str(e))


            toappend = self.parser(response)

        print("parsed content:\n", self.responses)


    def get_responses(self):
        return self.responses
def createIncidents(client: Client) -> str:

    time.sleep(31)
    openai_assistant = OpenAIAssistant(str(demisto.params().get('api_key')))

    # Create a session (send messages to the OpenAI API)

    openai_assistant.create_session(continue_prompts=50)

    # Get all parsed responses
    parsed_responses = openai_assistant.get_responses()
    # Send generated alerts to Cortex XSOAR
    for response_json in parsed_responses:
        print(response_json)
        if response_json["severity"] == "low":
            response_json["severity"] = 1
        elif response_json["severity"] == "medium":
            response_json["severity"] = 2
        elif response_json["severity"] == "high":
            response_json["severity"] = 3
        elif response_json["severity"] == "critical":
            response_json["severity"] = 4
        incident = {
                'name': response_json["description"],
                'occurred': response_json["timestamp"],
                'rawJSON': json.dumps(response_json),
                'type':response_json["event_type"],
                'details': "source ip: " + response_json["source_ip"] + " destination ip: " + response_json["destination_ip"],
                'severity':response_json["severity"],
            }


        demisto.createIncidents([incident], lastRun=None, userID=None)
    return

def main():
    params = demisto.params()
    api_key = str(params.get('api_key'))
    first_fetch_time = params.get('fetch_time', '3 days').strip()
    command = demisto.command()
    args = demisto.args()
    demisto.debug(f'Command being called is {command}')
    url='https://api.openai.com/'

    try:

        client = Client(api_key, base_url=url, verify=False, proxy=False)


        if command == 'test-module':

            # This is the call made when clicking the integration Test button.
            return_results(test_module(client))
        elif command == 'RED-test-api':
            return_results(test_module(client))
        elif command == 'RED-start':
            return_results(createIncidents(client))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    except requests.exceptions.RequestException as e:
        print(f'Failed to execute {command} command. Error: {str(e)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
