## Description
<p>This project was part of the Sybex Comptia CYSA+ Study Guide written by Mike Chapple and David Seidl. The task was to download and install tenables Nessus vulnerability scanner 
on to Kali linux, and then use the scanner to conduct an vulnerability scan on a server. I choose to use a Metasploitanle2 server running on a VM to use as my target instead of using one of the cloud service providers listed in the book. The server was on the same VM network as my Kali machine. I found this project to be a fun way to get hands on experience with everything I was learning while studying for the certification.</p>

## Tools used
<p>-Oracle VirtualBox</p>
<p>-Kali Linux</p>
<p>-Nessus Vulnerability Scanner</p>
<p>-Metasploitable 2</p>

## Process 

<p>I started a Metasploitable 2 server on VirtualBox and had Nessus running on Kali using VirtualBox as well.</p>
  <img width="766" height="200" alt="biznizz" src="https://github.com/user-attachments/assets/549d2ccd-55b3-4ccf-a378-ca8ec14b8370" />
<p>Scan Complete</p>
  <img width="600" height="242" alt="scan_resultsresize" src="https://github.com/user-attachments/assets/e220337e-ec4f-4d1c-a1d4-d04f72c3b500" />

## Results
<p>Overall 71 of the results were rated as info, 3 rated at medium, 5 rated at high, and 2 rated at critical. Below I will give a brief analysis of 1 of the
critical vulnerabilities and 1 of the vulnerabilities rated as high, just to briefly showcase my analysis</p>

# Vulnerability 3 
<img width="1307" height="592" alt="ruby_rack_vuln" src="https://github.com/user-attachments/assets/54c292ff-6590-4f31-8237-fafd4bbff028" />

<p>The first vulnerability with a severity score of high was the Ruby Rack < 2.2.14/3.0.16/3.1.14 DoS Vulnerability(meaning Ruby Rack version is less than versions 2.2.14/3.0.16/3.1.14). 
As shown in the scan results in the image above, this vulnerability provide an attacker the ability to cause a Dos situation by sending a specially crafted HTTP request, leading to memory exhaustion or pin CPU resources stallingor crashing the server.</p>
 
  <img width="1302" height="571" alt="cvss_score" src="https://github.com/user-attachments/assets/6359b9a7-3610-4b01-8ece-1f6ca404f74f" />
 
<p>In the photo above below you will see(highlighted in yellow) the CVSS v3.0 score of 7.5 along with the "vector" listed as AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H. I would like to provide details on what this vector is indicating piece by piece to provide a deeper understanding of what led to the score of 7.5 and what it means.</p>
<p>-First we see the AV:N,  AV = Attack Vector and the N = Network meaning that an attacker would be able to exploit this vulnerability remotley, which makes up .85 points of the total score.</p> 
<p>-Next we have AC:L, AC = Attack Complexity(the difficulty of actually exploiting the vulnerability), and the L = Low, meaning that exploiting the vulnerability requires no special conditions that would be hard to find adding another .77 points to the total score.</p>
<p>-Next we see the PR:N, PR = Priveleges Required(account access needed for attack), N = None, meaning no authentication is needed for the exploit to occur which contributes another .85 points to the total score.</p> 
<p>- Next we see the UI:N, UI = User interaction(whether the attacker needs to invole another human in the attack), N = None, meaning the attacker can work alone leading to an addition .85 points to the overall score.</p>
<p>- The S:U breaks down as S = scope(whether or not the vulnerability can effect components beyond the scope of the vulnerability), and U = unchanged, meaning that the vulnerability can only affect resources managed by the same security authority.</p>
<p>-C:N means that if the vulnerability is exploited, confidentiality(C) will not be impacted (N) </p>
<p>-I:N means that if the vulnerability is exploited, integrtiy(I) will not be impacted (N) </p>
<p>-A:H meand that if the vulnerability is exploited, availability(A) will be comepletly shut down(H)</p>
<p>The good news is as you can see highlighted in green there is a easy way to remidiate this vulnerability and the is to upgrade to a Rack version 2.2.14/ 3.0.16/ 3.1.14 or later</p>

