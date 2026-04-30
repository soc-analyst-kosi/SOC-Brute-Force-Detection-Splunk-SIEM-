DAY 5 – BRUTE FORCE ATTACK DETECTION (Splunk SIEM)

 OBJECTIVE
Detect brute force login attempts using Windows Security logs by analyzing failed authentication events.

 TOOLS USED
Splunk Enterprise
Windows Event Logs

 LOG ANALYSIS
Event ID 4625 – Failed Login Attempts

 DETECTION LOGIC
index=* EventCode=4625
| bucket _time span=1m
| stats count by _time, Account_Name, Source_Network_Address
| where count >= 5

 OBSERVATIONS 
Multiple failed login attempts were detected within a 1-minute time window
Affected accounts:
user
MICRO$
Each account recorded 5 failed attempts
Source IP: 127.0.0.1

 ANALYSIS 

The repeated failed login attempts within a short time interval indicate a password guessing / brute-force attack pattern.

The activity originated from 127.0.0.1 (localhost), which confirms this was a controlled lab simulation rather than an external attack.

 RISK ASSESSMENT 
Potential unauthorized access if successful
Account compromise risk
Possible lateral movement if attacker gains access

 MITRE ATT&CK Mapping
Tactic: Credential Access
Technique: Brute Force (T1110)

🛡️ RECOMMENDED MITIGATION
Enforce account lockout policies
Implement Multi-Factor Authentication (MFA)
Monitor login thresholds and alert on anomalies
Restrict repeated authentication attempts

