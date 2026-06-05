## A> \NFOTACT QF SOLUTIONS & CO. 

## Week 4: Alerting, Testing, and Final Reporting 

The final week is dedicated to safety and visualization ~~.~~ The intern must implement a rollback mechanism allowing SOC analysts to reverse an automated firewall rule if a false positive occurs ~~.~~ They will finalize the Kibana dashboard to visualize the blocked threats and ensure the GitHub repository contains all scripts and architectural documentation ~~.~~ 

## Project 2: Healthcare - loT Deception Honeypot Network 

## Executive Problem Statement 

Healthcare environments are increasingly reliant on smart, connected cyber ~~-p~~ hysical systems, ranging from patient vitals monitors to smart HVAC infrastructure ~~.~~ Unfortunately, many of these Internet of Things (loT) devices lack robust built ~~-~~ in security, making them prime targets for botnets and ransomware gangs seeking to pivot into the broader hospital network. 

The objective of this project is to develop an loT Deception Honeypot Network ~~.~~ The intern will architect a virtual environment consisting of simulated, low ~~-i~~ nteraction vulnerable loT devices to proactively deceive attackers, trap them, and analyze their behavioral patterns and exploit techniques before they can reach actual medical equipment. 

## Business Objectives and Key Performance Indicators 

The strategic goal is to shift from reactive defense to proactive threat intelligence gathering ~~.~~ By utilizing deception, the organization can identify reconnaissance attempts and zero ~~-~~ day exploits targeting specific medical loT protocols ~~.~~ 

Success is measured by the honeypot's ability to convincingly simulate a device, successfully log an attacker's interaction (IPs, payloads, commands attempted), and visualize these attack vectors on a centralized threat analysis dashboard without allowing the attacker to escape the sandboxed environment. 

## User Personas and Operational Workflows 

|Persona|Primary Operational<br>Needs|Operational | System Interaction and Workflow|
|---|---|---|
|Threat<br>Researcher<br>(Intern)|Safe environment to<br>capture and analyze<br>live malware~~.~~|Deploys the honeypot nodes,<br>monitors attacker behavior, and<br>extracts dropped malware payloads<br>for reverse engineering~~.~~|



4 

## A> \NFOTACT <o# SOLUTIONS & CO. 

|Network<br>Administrator|Early warning system<br>for internal lateral<br>movement~~.~~|Receives immediate alerts ifan<br>internal IP address attempts to<br>interact with the hidden honeypot,<br>signaling<br>a compromised internal<br>machine~~.~~|
|---|---|---|
|Compliance<br>Auditor|Proofofadvanced,<br>proactive security<br>measures~~.~~|Utilizes the threat intelligence<br>gathered to justify network<br>segmentation policies required for<br>HIPAA compliance~~.~~|



## Minimum Viable Product Specifications 

The foundational requirement is the Virtual Honeypot Deployment. The intern must utilize tools to simulate the behavior and open ports of typical loT devices (e ~~.~~ g ~~.,~~ default SSH/Telnet credentials, unauthenticated web panels) ~~.~~ 

The core deliverable is the Logging and Analysis Engine ~~.~~ When an attacker connects to the honeypot, the system must meticulously record every keystroke, uploaded file, and network request ~~.~~ This data must be parsed and visualized to identify the origin of the attacks and the specific vulnerabilities being targeted. 

## Architectural Directives and Technology Stack 

||Technology|Architectural Rationale|
|---|---|---|
|Honeypot<br>Software|Cowrie / Honeyd|Open~~-s~~ource, low~~-~~t~~o~~-medium interaction<br>honeypots designed specifically to log brute<br>force attacks and shell interaction.|
|Infrastructure|Docker / Virtual<br>Machines|Essential for strictly isolating the honeypot<br>from the host system, ensuring attackers<br>cannot pivot into the real network.|



5 

A> \NFOTACT QF SOLUTIONS & CO. 

**==> picture [404 x 26] intentionally omitted <==**

**----- Start of picture text -----**<br>
Data Python / Splunk Used to aggregate the raw logs into a<br>Visualization comprehensive threat analysis dashboard .<br>**----- End of picture text -----**<br>


## Fou ~~r-~~ Week Engineering Roadmap 

## Week 1: Environment Setup and Device Simulation 

The project begins with designing the deception strategy. The intern will configure an isolated Docker environment and deploy Cowrie or Honeyd ~~.~~ They must configure the honeypot to mimic a specific medical loT device by altering its simulated filesystem, banner grabbing responses, and open ports ~~.~~ 

## Week 2: Exposure and Data Capture 

Week two focuses on controlled exposure ~~.~~ The intern will safely expose the honeypot to a controlled testing network (or the open internet, if heavily sandboxed and approved) ~~.~~ They will verify that the system is properly capturing connection attempts, login brute ~~-f~~ orcing, and malicious payload drops ~~.~~ 

## Week 3: Log Parsing and Threat Intelligence Extraction 

The third week targets data engineering ~~.~~ The intern will write Python scripts to parse the complex JSON/text logs generated by the honeypot ~~.~~ They will extract key indicators of compromise (loCs) such as attacker IP addresses, uploaded malware hashes, and executed terminal commands ~~.~~ 

## Week 4: Dashboarding and Geolocation Analysis 

The final sprint is dedicated to intelligence visualization ~~.~~ The intern will enhance the data with IP geolocation ~~.~~ They will build a dashboard visualizing the attack origins on a world map and categorizing the most frequent exploit techniques ~~.~~ The final GitHub repository must contain the deployment configuration, safe architectural diagrams, and a comprehensive analytical report. 

## Project 3: E ~~-~~ commerce ~~-~~ Enterprise laC Pipeline 

## Executive Problem Statement 

In the highly competitive e ~~-~~ commerce sector, rapid deployment is essential. However, the shift towards cloud ~~-n~~ ative architectures means that infrastructure is now defined by code (laC) ~~.~~ Misconfigurations in cloud templates or unpatched dependencies can instantly expose vast databases of consumer information ~~.~~ Traditional Cl/CD pipelines that only check for software bugs are no longer sufficient ~~.~~ 

6 

