# Discord-Token-Grapper

## Explanation :

This demonstration shows a **Discord Token Grapper** that steals the victim’s session by just oppening the malicious.exe file (demo 1 ) and how malicious QR codes can be used to compromise Discored accounts (demo 2)  
. purpose:  
educate users and devlopers about:
- Social engineering risks
- Discord token security
- Webhook-based data exfiltration
- QR code phishing awareness

## Tutorial : 

1. The victim opens the MP16.exe.
2. The script extracts the discord token, discord user informations (username, discord ID...) from local storage.
3. Token is sent to attacker via Discord webhook.
4. Attacker can use token to access the account.

## Requirements:

. Python 3.11+

. pip install **pyinstaller**

. **Client-side** script: Token extraction logic  

. **Fake Discord account** : (for demo)

. **Webhook**: data exfiltration

. **VM** (Isolated testing environment for the victim role)



## Demo 1  :

1. The victim opens the MP16.exe file (sent by the attacker).

2. It appears to the victim a black screen with Shellmates logo.

<img width="1918" height="1000" alt="done" src="https://github.com/user-attachments/assets/692090ca-9720-4fe7-830a-f2de923571e8" />


3. The attacker recives the Discord webhook embed output.
   
<img width="551" height="832" alt="output" src="https://github.com/user-attachments/assets/fad86e2f-8e1d-40cd-87b5-8cf45adc3158" />

4. The attacker must go to the discord.com**/login** (doesn't work on discord.com), open developer tools (Shift+Ctrl+i), go to "Console" and type "allow pasting", then paste the "Ready Token Login" :
   
<img width="1915" height="1024" alt="console" src="https://github.com/user-attachments/assets/45bedd40-4b5e-4dad-aefe-611bce15d180" />
   
5. Login to the account succsesfuly ✅.
   
<img width="1919" height="1031" alt="login" src="https://github.com/user-attachments/assets/43ed2f43-14ae-47eb-9074-594446a40fc5" />


## Demo 2 : 




### Testing steps:

- Create a dedicated Discord server for testing.
- Set up a webhook in your testing server.
- Run the demo only against your own test account (for educational purposes).


## Consequences of the Attack :

- Read ALL private DMs.
- Change Name and profile picture.  
- Join any server the victim is in . 
- Speak as the victim.
- Spam / raid / delete channels.

## Protective measures:

- Regularly change your Discord password.
- Enable two-factor authentication (2FA).
- Log out of unused sessions in Discord settings.
- Use Discord's "Authorized Apps" panel to review permissions.


## Incident Response:

1. Immediately change your Discord password.
2. Enable 2FA if not already active.
3. Go to Settings → Authorized Apps → remove suspicious applications.
4. Check active sessions and log out unknown devices.
5. Contact Discord Trust & Safety if needed.
6. Never run random .exe files.


## Additional Resources : 

[Discord Security Tips](https://discord.com/safety).

[official Discord guidance; QR and token safety tips](https://discord.com/safety/protecting-users-from-scams-on-discord?).

[OWASP — Session Hijacking](https://owasp.org/www-community/attacks/Session_hijacking_attack?).




