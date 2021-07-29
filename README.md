# Cloudflare_waf_alerting

### Purpose
 The purpose of this automation is to send cloudflare block request alerts on slack when the block count is greater than 50 from a particular IP. By using this automation anyone can have the visibility over cloudflare block requests. 

### Deployment Options
AWS Lambda, Rundeck or any cron. set this cron for every 5mins or depending on the traffic on cloudflare waf.

### Prerequisites
1. Cloudflare API Token
2. Slack Incoming webhook URL

### Configuration Steps
1. Follow this for creating Cloudflare API token: https://developers.cloudflare.com/analytics/graphql-api/getting-started/authentication/api-token-auth
2. After obtaining API change it in the code and also put the email id which is used on Cloudflare.
3. Put Slack Incoming webhook URL in the code.
4. Run this code on your AWS Lambda.
5. Trigger Lambda with Cloudwatch rule, which triggers the lambda in every 5 mins.



### References
1. Cloudflare API token https://developers.cloudflare.com/analytics/graphql-api/getting-started/authentication/api-token-auth
2. https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-firewall-events
