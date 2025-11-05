# Discord-Token-Grapper

## Explanation :
This demonstration shows a **Real Discord Token Grapper** that steals the victim’s session by just oppening the malicious .exe file (demo 1 ) and how malicious QR codes can be used to compromise Discored accounts (demo 2)  
. purpose:  
educate users and devlopers about:
- Social engineering risks
- Discord token security
- Webhook-based data exfiltration
- QR code phishing awareness

## Tutorial : 
1. The victim opens the file.exe
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



## Demo 1  :
1. the victim opens the malicious .exe file (sent by the attacker)

2. it appears to the victim a black screen with Shellmates logo 

   <img width="1918" height="1000" alt="done" src="https://github.com/user-attachments/assets/692090ca-9720-4fe7-830a-f2de923571e8" />


3. the attacker recives the Discord webhook embed output
   
<img width="551" height="832" alt="output" src="https://github.com/user-attachments/assets/fad86e2f-8e1d-40cd-87b5-8cf45adc3158" />

4. the attacker must go to the **discord.com/login** , open console and type "allow pasting" , then add the token :
   
   <img width="1915" height="1024" alt="console" src="https://github.com/user-attachments/assets/45bedd40-4b5e-4dad-aefe-611bce15d180" />
5. login to the account succsesfuly 
   
<img width="1919" height="1031" alt="login" src="https://github.com/user-attachments/assets/43ed2f43-14ae-47eb-9074-594446a40fc5" />


## Demo 2 : 




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




