

## Description
&nbsp;&nbsp;&nbsp;&nbsp;This project was part of the Sybex CompTIA CYSA+ Study Guide written by Mike Chapple and David Seidl. The task was to download and install Tenable Nessus vulnerability scanner 
on to Kali Linux, and then use the scanner to conduct a vulnerability scan on a server. I choose to use a Metasploitable 2 server running on a VM to use as my target instead of using one of the
cloud service providers listed in the book. I configured a NAT network on VirtualBox so that the server was on the same network as my Kali machine. I actaully overlooked that step the first time around and accidentally scanned
the Kali machine. Overall I found this project to be a fun way to get hands on experience with everything I was learning while studying for the certification.

## Tools used

-Oracle VirtualBox

-Kali Linux

-Nessus Vulnerability Scanner

-Metasploitable 2

## Purpose   

&nbsp;&nbsp;&nbsp;&nbsp;The purpose of this task was for me to get hands on experience running and analyzing a vulnerability scan using Nessus. At the time I was conducting this activity I was in the process 
of preparing for the CompTIA CYSA+ certification while enrolled at WGU. For educational purposes I will be choosing two of the vulnerabilities found during the scan to analyze and report on. One will be rated as a critical vulnerability,
and the other will be rated as a high vulnerability. 

## Process 

&nbsp;&nbsp;&nbsp;&nbsp;I started a Metasploitable 2 server on VirtualBox and had Nessus running on Kali using VirtualBox as well, as you can see by the IP addresses highlighted in blue they are both on the same network.
 
  
  <img width="1225" height="150" alt="metasploitable_redo" src="https://github.com/user-attachments/assets/fb279745-9940-4c82-8048-153419c26fcb" />

&nbsp;&nbsp;&nbsp;&nbsp;I choose to do an advanced scan which you can see circled in red in teh photo below.

  <img width="1333" height="617" alt="metaploitable_redo_scan_select" src="https://github.com/user-attachments/assets/6829b07d-6939-4ef9-a4d0-98655fc2bcf8" />



&nbsp;&nbsp;&nbsp;&nbsp;Here is a visual high-level overview of the completed scan.
  
 
  <img width="1707" height="625" alt="metaploitable_redo_scan_complete" src="https://github.com/user-attachments/assets/f645e3c6-16cc-4664-bb4c-16f61ee054af" />


## Results
&nbsp;&nbsp;&nbsp;&nbsp;There were a total of 70 vulnerabilities found during the scan as you can see circled in red in the below photo. There was 9 critical, 7 high, 23 medium, and 9 low, the rest were rated as info.


  <img width="1718" height="623" alt="metasploitable_redo_70" src="https://github.com/user-attachments/assets/cdc5bd0a-101b-40b5-836d-9dd84c964c8d" />

### Vulnerability 1 (Critical)

 
  <img width="1726" height="535" alt="metasploitable_redo_critical_vuln_1" src="https://github.com/user-attachments/assets/4035b4b2-fd5a-4a3b-b63c-d7d658c662be" />


 &nbsp;&nbsp;&nbsp;&nbsp;If you look at the above photo, I have circled the severity rating in red, both on the left side of the photo and the right. This vulnerability is a weakness in the remote SSH key due to a lack of entropy (randomness) in the remote version of OpenSSL. This allows an attacker the ability to easily obtain the private part of the key, allowing them to decipher a remote session, or set up a man in the middle attack which would allow for eavesdropping.  I have circled the Critical Vulnerabilities and Exposure (referred to as CVE )  number in red at the bottom. To access more information on this vulnerability please click the link <a href="https://nvd.nist.gov/vuln/detail/CVE-2008-0166">CVE-2008-0166</a>. Lastly, if you pay attention to the Vulnerability Information section circled in yellow on the photo below. It lets us know that there are available exploits existing for this vulnerability. 

 
  
  <img width="1722" height="757" alt="metasploitable2_redo_critical_vuln2" src="https://github.com/user-attachments/assets/2919a9f1-112d-4d97-9a19-75eb175ab7f3" />

 
&nbsp;&nbsp;&nbsp;&nbsp;Next, I would like to address the CVSS Vector (AV:N/AC:L/Au:N/C:C/I:C/A:C) highlighted in green on the right-hand side of the photo above. Also note the CVSS Severity score of 10.0 right above the vector. Now due to the age of this vulnerability this is represented using CVSS version 2.0, which is outdated compared to the current version 3.0. Looking at this string of characters may be daunting and leave you wondering what value it may have. So, I am going to break this down and explain what it represents to give more insight into the severity of this vulnerability. 

 
&nbsp;&nbsp;- The first metric we have listed is AV:N.  AV stands for Access Vector which represents HOW the vulnerability is exploited. Next, we see the N, which stands for network. This lets us know that the vulnerability may be exploited remotely, meaning that no local network access is needed in order to conduct the exploitation process. 

 
&nbsp;&nbsp;- AC:L is going to be the next metric listed. AC stands for Access Complexity which represents the complexity of the attack required once the attacker has obtained access to the target system. The L listed after AC stands for low. Low means that no specialized access conditions or extenuating circumstances exist, and that the attack requires a low level of skill to carry out. Which means it's vulnerable to a wider array of attackers. 

 
&nbsp;&nbsp;- Next you will see Au:N. Au represents Authentication. This describes the number of times an attacker will need to authenticate to the target to conduct the exploit. In this case we have the letter N next to the AU which represents none. So, in this case, there is no authentication required in order for an attacker to exploit the vulnerability. 

 
&nbsp;&nbsp;- Next in line is C:C. The first C stands for confidentiality. This metric represents the impact an attack would have on the confidentiality of information stored on the target system. Confidentiality can be thought of as protecting access to information and other data from unauthorized users. The second C stands for complete, which means that if an attacker is successful, they will be able to access and read all the systems data. 

 
&nbsp;&nbsp;- Next is I:C. The I stands for Integrity. Think of integrity as whether or not the data can be altered or not. You want to ensure that your data remains accurate and un-modified unless done so by an authorized user. The C stands for complete, and means that if an attacker gains access, they will have the freedom to modify the data as they see fit. 

 
&nbsp;&nbsp;- Last up we have the A:C. This represents the Availability of the system, so think accessibility. The C once again stands for Complete, meaning that if an attacker is successful, they will have the ability to completely shut down or restrict access to the system 

#### Remediation
&nbsp; &nbsp; &nbsp; &nbsp;If you look at the 1st photo provided with this vulnerability you will see a section named Solution. It states that all cryptographic material generated on the remote host should be considered guessable. It states that all SSH, SSL, and OpenVPN key material should be re-generated.  I would suggest updating the system to a more current version and then ensure all keys are regenerated via the updated system.  



### Vulnerability 2 (High)
  <img width="1723" height="622" alt="metasploitable_redo_high_vuln_1" src="https://github.com/user-attachments/assets/da813311-fa8a-41a1-a902-ff9bf237c62d" />


&nbsp; &nbsp; &nbsp; &nbsp; The next vulnerability I will be going over has a severity rating of high as you can see circled in red in the above photo. The system is running a very outdated program called rlogin or remote login. As the name suggests it was used to access a computer remotely over a network and provided the ability to access the command-line. Data is sent in the clear between the server and client meaning that it has no security in transit and may be read by anyone smart enough to gain access (Man in the middle attack). The program also had flaws in its authentication process making it easy to crack credentials, or better yet for an attacker they may be able to log in with no password at all.  

&nbsp; &nbsp; &nbsp; &nbsp; This vulnerability is listed as CVE-1999-0651. I will provide a link to NIST’s NVD for the CVE however there really isn’t much useful information there outside of what was provided by Nessus. The page can be found here at <a href="https://nvd.nist.gov/vuln/detail/CVE-1999-0651">CVE-1999-0651</a>. Lastly you can see that the CVVS V2.0 base score is 7.5 which is located right above the CVSS vector highlighted in green. Next, I will be providing a breakdown of what the CVSS vector represents. 
 
 <img width="1713" height="731" alt="metasploitable_redo_high_vuln_2" src="https://github.com/user-attachments/assets/6fc8e663-189b-4f59-ab91-251a5aad0764" />

&nbsp; &nbsp; &nbsp; &nbsp;Next, I would like to address the CVSS Vector (AV:N/AC:L/Au:N/C:P/I:P/A:P) highlighted in green on the right-hand side of the photo above. Now due to the age of this vulnerability this is represented using CVSS version 2.0, which is outdated compared to the current version 3.0. Looking at this string of characters may be daunting and leave you wondering what value it may have. So, I am going to break this down and explain what it represents to give more insight into the severity of this vulnerability. Notice the P at the end of C,I, and A on this one. Those 3 metrics have an impact on why this is scored lower compared to the critical vulnerability discussed above. As you will read in their descriptions below the level of access and capabilities the attacker would have are a bit lower risk. 

 
&nbsp;&nbsp;- The first metric we have listed is AV:N.  AV stands for Access Vector which represents HOW the vulnerability is exploited. Next, we see the N, which stands for network. This lets us know that the vulnerability may be exploited remotely, meaning that no local network access is needed in order to conduct the exploitation process. 

 
&nbsp;&nbsp;- AC:L is going to be the next metric listed. AC stands for Access Complexity which represents the complexity of the attack required once the attacker has obtained access to the target system. The L listed after AC stands for low. Low means that no specialized access conditions or extenuating circumstances exist, and that the attack requires a low level of skill to carry out. Which means it's vulnerable to a wider array of attackers. 

 
&nbsp;&nbsp;- Next you will see Au:N. Au represents Authentication. This describes the number of times an attacker will need to authenticate to the target to conduct the exploit. In this case we have the letter N next to the AU which represents none. So, in this case, there is no authentication required in order for an attacker to exploit the vulnerability. 

 
&nbsp;&nbsp;- Next in line is C:P. The first C stands for confidentiality. This metric represents the impact an attack would have on the confidentiality of information stored on the target system. Confidentiality can be thought of as protecting access to information and other data from unauthorized users. Next, we have a P which stands for partial, which in the case of confidentiality means that there is a risk of substantial disclosure of information, however the attacker does not have control over what is obtained. 

 
&nbsp;&nbsp;- Next is I:P. The I stands for Integrity. Think of integrity as whether or not the data can be altered or not. You want to ensure that your data remains accurate and un-modified unless done so by an authorized user. The p stands for partial, which in the case of integrity means that some modification of files is possible, but the scope is limited, and the attacker does not have control over what can be modified. 


&nbsp;&nbsp;- Last up we have the A:P. This represents the Availability of the system, so think accessibility. The P once again stands for partial, meaning that if an attacker is successful, performance will be reduced or/and there will be interruptions in resource availability. 

#### Remidiation
&nbsp; &nbsp; &nbsp; &nbsp;If you look at the 1st photo provided with this vulnerability you will see a section named Solution. It recommends commenting out the “login” line in /etc/inetd and then restarting the service or you can disable the service and use SSH instead. My recommendation would be to disable the service and switch over to the most recently updated version of SSH that is compatible with the system. This program is severely outdated and there are much more secure and readily available new solutions. 
