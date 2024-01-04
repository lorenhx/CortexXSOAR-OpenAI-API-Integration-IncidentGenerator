import requests
import json
import time
import re

class OpenAIAssistant:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {
            'Authorization': f"Bearer {self.api_key}",
            'Content-Type': 'application/json'
        }
        self.messages = [] #messages to send to the Open AI api in the content field
        self.responses = [] #parsed responses from the Open AI api with the generated alerts in json format

    def set_message(self, content, role='system'):
        self.messages.append({'role': role, 'content': content})
    
    #Saves alerts in self.rensponses (list of json) and return the message to append
    
    def parser(self, response):
        response.raise_for_status()

        # Extract generated content from the API response
        generated_content = response.json().get('choices', [])
        
        #Finds all the json in the response
        matches = re.findall(r'\{[^\{\}]+\}', str(generated_content[0]['message']['content']))
        for m in matches:
            self.responses.append(json.loads(m))
        
        #Return the last message to append to the next request
        return generated_content[0]["message"]

    def create_session(self, continue_prompts=2): #con 4 non ce la con il contesto
        url = 'https://api.openai.com/v1/chat/completions'

        # Prompt to set the system role
        self.set_message("You are the Google Chronicle SIEM who produces security alerts that you take from different sources inside an enterprise. You give in output only a list of JSON of this alerts and not a single line of text. You give at least 10 alert for every request, that can be to simulate a particular attack in the Cyber Kill Chain and hide it between noise alerts. You only write alerts not a single line of text")

        # Initial user prompt
        self.set_message("Generate 30 alert, one every second where you hide an attack on a windows machine starting with a phishing and then finish with exfiltration, between casual alerts which will compose some noise to better simulate the SIEM. Every response you give me has to be a list of  2 JSON that has to be closed and opened in every response you give me. I will next ask you to continue the output, so split the output. I repeat: every response has to be only a list of 2 JSON not incomplete and don't put any text other than the list. Use the actual time for the timestamps", role='user')

        # Communicate with the Open AI api
        data = {
            "model": "gpt-3.5-turbo",
            "messages": self.messages,
            "temperature": 0.7
        }
        response = requests.post(url, headers=self.headers, json=data)
        if response.status_code != 200:
            raise Exception(f"Error {response.status_code}: {response.text}")
        
        toappend = self.parser(response) 
        
        #first messages are about 40 chars long
        lenghts = 40 
        
        # Add "continue" prompts to generate more alerts
        for i in range(continue_prompts):
            #wait 21 seconds to avoid overcoming the 3 requests per minute limit
            time.sleep(21) 
            
            self.messages.append(toappend)
           
            
            # 1 token ~= 4 chars in English, controls the max number of tokens to avoid overcoming 4097 tokens
            lenghts += len(str(toappend))
            if lenghts > 3000 * 4:  
                break
            
            self.set_message("continue", role = "user")
            data = {
                    "model": "gpt-3.5-turbo",
                    "messages": self.messages,
                    "temperature": 0.7
                }
            response = requests.post(url, headers=self.headers, json=data)
            if response.status_code != 200:
                raise Exception(f"Error {response.status_code}: {response.text}")

            toappend = self.parser(response)

        print("parsed content:\n", self.responses)


    def get_responses(self):
        return self.responses

def main():
    api_key = str(demisto.params().get('api_key'))
    try:
        openai_assistant = OpenAIAssistant(api_key)

        # Create a session (send messages to the OpenAI API)

        openai_assistant.create_session(continue_prompts=2)

        # Get all parsed responses
        parsed_responses = openai_assistant.get_responses()

        # Send generated alerts to Cortex XSOAR
        for response_json in parsed_responses:
            print(response_json)

            demisto.incidents([{
                'name': response_json["description"],
                'occurred': response_json["timestamp"],
                'rawJSON': json.dumps(response_json),
                'type':response_json["event_type"],
                'details': "source ip: " + response_json["source_ip"] + " destination ip: " + response_json["destination_ip"] ,
                'severity':response_json["severity"],
            }])

        print('Alerts successfully generated using ChatGPT API and sent to Cortex XSOAR.')
    except requests.exceptions.RequestException as e:
        print(f'Error making request to OpenAI API: {str(e)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
