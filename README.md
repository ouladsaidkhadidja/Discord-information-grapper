# Discord-token-graper

## Explanation :
This demonstration shows a **real Discord token graper** that steals the victim’s session and how malicious QR codes can be used to compromise Discored accounts 
. purpose:  
educate users and devlopers about:
- Social engineering risks
- Discord token security
- Webhook-based data exfiltration
- QR code phishing awareness

## Tutorial : 
1. User scans a QR code that holdes the .exe file
2. the script extracts the discord token from local storage
3. token is sent to attacker via Discored webhook
4. attacker can use token to access the account

## Requirements:
. Python 3.11+

. pip install **pyinstaller** discord.py requests

. **QR Code**: Social engineering vector  

. **Client-side** script: Token extraction logic  

. **Fake Discord account** : (for webhook)

. **Webhook**: data exfiltration

. **VM** (Isolated testing environment)



## Testing:
to test this demo:


### Testing steps:
- Create a dedicated Discord server for testing
- Set up a webhook in your testing server
- Run the demo only against your own test account
- Immediately revoke the compromised token
- Document findings (for educational purposes)


## Consequences of the Attack :
- Read ALL private DMs  
- Join any server the victim is in  
- Speak as the victim  
- Spam / raid / delete channels

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
6. never open random .exe files 


## Additional Resources : 

[Discord Security Tips](https://discord.com/safety)

[official Discord guidance; QR and token safety tips](https://discord.com/safety/protecting-users-from-scams-on-discord?)

[OWASP — Session Hijacking](https://owasp.org/www-community/attacks/Session_hijacking_attack?)




