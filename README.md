# shell_integration_project

## Overview
thies demonstration showcases how malicious QR codes can be used to compromise Discored accounts throught token theft.
purpose: educate users and devlopers about:
Social engineering risks
Discord token security
Webhook-based data exfiltration
QR code phishing awareness

## How it works: 
User scans a QR code that holdes the .exe file
the script extracts the discord token from local storage
token is sent to attacker via Discored webhook
attacker can use token to access the account

## Requirements:

**QR Code**: Social engineering vector  

**Client-side** script: Token extraction logic  

**Webhook**: data exfiltration

## Testing:
to test this demo:
### Prerequisites:
- Own both test Discored Accounts
- a VM (Isolated testing environment)

### Testing steps:
- Create a dedicated Discord server for testing
- Set up a webhook in your testing server
- Run the demo only against your own test account
- Immediately revoke the compromised token
- Document findings (for educational purposes)




## Protective measures:
### For Users:

- Never scan untrusted QR codes
- Regularly rotate your Discord password
- Enable two-factor authentication (2FA)
- Log out of unused sessions in Discord settings
- Use Discord's "Authorized Apps" panel to review permissions

### For Devloppers: 
- Implement Content Security Policy (CSP)
- Validate and sanitize all user inputs
- Use HTTP-only cookies when possible
- Educate users about social engineering risks

## Incident Response: 

1. Immediately change your Discord password
2. Enable 2FA if not already active
3. Go to Settings → Authorized Apps → remove suspicious applications
4. Check active sessions and log out unknown devices
5. Contact Discord Trust & Safety if needed


## Educational resources: 

[Discord Security Tips](https://discord.com/safety)

