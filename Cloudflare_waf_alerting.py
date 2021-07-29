import sys
import os
import json
import requests
import datetime



def firewall_events():

    current = datetime.datetime.utcnow()
    currenttime = current.strftime('%Y-%m-%dT%H:%M:%S')
    last24  = datetime.datetime.utcnow() - datetime.timedelta(seconds=900)
    last24hourstime = last24.strftime('%Y-%m-%dT%H:%M:%S')
    headers = {
    'X-Auth-Email': 'email',
    'Authorization': 'Bearer Cloudflare API Token',
    'Content-Type': 'application/json',
    }

    query2 = """
    {{
    viewer {{
        zones(filter: {{ zoneTag: "Zone ID" }}) {{
        firewallEventsAdaptiveGroups(
            limit: 100
            filter: {{ datetime_gt: "{0}Z", datetime_lt: "{1}Z", action:"block"}}
            orderBy: [count_DESC]
        ) {{ count
            dimensions {{
                action
                clientRequestPath
                clientRequestHTTPHost
                clientIP
                userAgent
                ruleId
            }}
        }}
        }}
    }}
    }}""".format(last24hourstime, currenttime)


    request = requests.post('https://api.cloudflare.com/client/v4/graphql', json={'query': query2}, headers=headers)
    print(request.json())
    events = request.json()['data']['viewer']['zones'][0]['firewallEventsAdaptiveGroups']
    template = {}
    template['attachments'] = [{}]
    template['attachments'][0]['fallback'] = 'unable to display this message !'
    template['attachments'][0]['color'] = '#36a64f'
    template['attachments'][0]['pretext'] = "Cloudflare WAF Alerts "
    template['attachments'][0]['title'] = "Cloudflare WAF Alerts"
    template['attachments'][0]['fields'] = [{"title": "Cloudflare WAF Alerts"}]
    template['attachments'][0]['fields'] = [{"title": "Number of Blocked request in last 5 mins "}]
    for i in events:
        count = i['count']
        if i['count'] >= 50:
            action = i['dimensions']['action']
            IP = i['dimensions']['clientIP']
            #botscore = i['dimensions']['botScore']
            #botScoreSrcName = i['dimensions']['botScoreSrcName']
            clientRequestHTTPHost = i['dimensions']['clientRequestHTTPHost']
            clientRequestPath = i['dimensions']['clientRequestPath']
            ruleId = i['dimensions']['ruleId']
            userAgent = i['dimensions']['userAgent']
            template['attachments'][0]['fields'].append({"title": "Action"})
            template['attachments'][0]['fields'].append({"value": action})
            template['attachments'][0]['fields'].append({"title": "Blocked Request"})
            template['attachments'][0]['fields'].append({"value": count})
            template['attachments'][0]['fields'].append({"title": "Client IP"})
            template['attachments'][0]['fields'].append({"value": IP})
            template['attachments'][0]['fields'].append({"title": "Host"})
            template['attachments'][0]['fields'].append({"value": clientRequestHTTPHost})
            template['attachments'][0]['fields'].append({"title": "Path"})
            template['attachments'][0]['fields'].append({"value": clientRequestPath})
            template['attachments'][0]['fields'].append({"title": "user-agent"})
            template['attachments'][0]['fields'].append({"value": userAgent})
            #template['attachments'][0]['fields'].append({"title": " Bot Score"})
            #template['attachments'][0]['fields'].append({"value": botscore})
            #template['attachments'][0]['fields'].append({"title": "botScoreSrcName"})
            #template['attachments'][0]['fields'].append({"value": botScoreSrcName})
            template['attachments'][0]['fields'].append({"title": " Rule ID"})
            template['attachments'][0]['fields'].append({"value": ruleId})
            json_template = json.dumps(template)
            requests.post(url='Incoming Webhook URL', data=json_template)



def lambda_handler(event, context):
    firewall_events()
