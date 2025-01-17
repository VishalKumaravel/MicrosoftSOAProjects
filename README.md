# MicrosoftSOAProjects
Here are some mini-project ideas aligned with the SC-200 certification modules to showcase your skills:

**2. Endpoint Threat Protection with Microsoft Defender for Endpoint**
Description: Implement Microsoft Defender for Endpoint to protect a simulated network of virtual machines. Perform vulnerability assessments and respond to detected threats.
Key Deliverables:
Endpoint risk assessment report.
Threat mitigation steps, such as isolating infected devices or removing malicious files.
Documentation of threat investigation and resolution process.


# **Project: Threat Detection and Response with Microsoft 365 Defender**
Objective: Configure Microsoft 365 Defender to monitor and detect phishing and ransomware attacks, and set up automated incident response workflows.

### Step-by-Step Guide: **Environment Setup for Microsoft 365 Defender**

The first step in configuring Microsoft 365 Defender for threat detection and response is setting up the environment. Here's a detailed breakdown of every small step to ensure a successful setup:  

---

### **1. Create a Microsoft 365 Account**  
1. **Visit Microsoft 365 Plans Page**:  
   - Navigate to the [Microsoft 365](https://www.microsoft.com/microsoft-365) website.  
   - Choose a plan that includes advanced security features (e.g., Microsoft 365 E5 or Defender add-ons).  

2. **Sign Up for a Trial (Optional)**:  
   - If you’re exploring, use the free trial option for Microsoft 365 E5.  
   - Provide your email address and follow the sign-up prompts.  

3. **Enter Your Information**:  
   - Fill out your organization’s name, country/region, and admin contact details.  
   - Verify your identity via phone or email.  

4. **Set Up Your Tenant**:  
   - Choose a tenant name (e.g., `yourcompany.onmicrosoft.com`). This will be your organization’s unique identifier.  
   - Complete the registration to access your Microsoft 365 admin portal.  

---

### **2. Configure Licenses**  
1. **Access Admin Center**:  
   - Go to [Microsoft 365 Admin Center](https://admin.microsoft.com).  
   - Log in using your admin credentials.  

2. **Assign Licenses**:  
   - Navigate to **Users > Active Users**.  
   - Click **Add User** and create test accounts for your simulated organization.  
   - Assign each user the Microsoft 365 E5 license (or equivalent).  

3. **Enable Security Add-Ons**:  
   - Ensure licenses include Microsoft Defender for Office 365, Microsoft Defender for Endpoint, and Azure AD Premium (P1 or P2).  

---

### **3. Create a Simulated Organization**  
1. **Add Test Users**:  
   - In the **Active Users** tab, create multiple users to simulate employees.  
   - Example:  
     - Alice (Finance Team)  
     - Bob (HR Team)  
     - Charlie (IT Team)  

2. **Define Roles**:  
   - Assign appropriate admin or user roles to test accounts.  
   - Example: Charlie (Global Admin), Alice (User), Bob (Security Admin).  

3. **Simulate Groups**:  
   - Create Microsoft 365 Groups to mimic real-world departments:  
     - Finance  
     - HR  
     - IT  

4. **Set Up Devices**:  
   - Use virtual machines (VMs) or physical devices for testing.  
   - Install Windows 10/11 or macOS and join these devices to **Azure AD**.  
     - For Windows: Go to **Settings > Accounts > Access work or school > Connect** and sign in with test user credentials.  

---

### **4. Configure Basic Security Settings**  
1. **Enable MFA (Multi-Factor Authentication)**:  
   - Go to **Azure Active Directory > Security > MFA**.  
   - Enforce MFA for all test users to mimic secure access practices.  

2. **Set Up Conditional Access**:  
   - Navigate to **Azure AD > Security > Conditional Access**.  
   - Create policies to control access based on user location, device compliance, or risk level.  

3. **Enable Audit Logs and Sign-In Logs**:  
   - In **Azure AD > Monitoring**, enable audit logs and sign-in logs to track user activities.  

---

### **5. Verify Environment**  
1. **Check Connectivity**:  
   - Log in as test users on assigned devices.  
   - Ensure they can access email, Teams, and other services.  

2. **Test Tenant Functionality**:  
   - Send test emails between users to confirm Exchange Online functionality.  
   - Access SharePoint or OneDrive to validate file-sharing capabilities.  

---
### Step-by-Step Guide: **Configure Microsoft 365 Defender**

After setting up the environment, the next step is to enable and configure key services in **Microsoft 365 Defender**. This involves setting up email protection, endpoint security, and integrating with Azure Active Directory to ensure unified monitoring and access control.  

---

### **1. Enable and Configure Email Protection (Defender for Office 365)**  

#### **Step 1.1: Access Microsoft Defender for Office 365**  
1. Log in to the **Microsoft 365 Security & Compliance Center** ([https://security.microsoft.com](https://security.microsoft.com)).  
2. In the left-hand menu, navigate to **Policies & Rules > Threat Policies**.  

#### **Step 1.2: Configure Anti-Phishing Policies**  
1. Go to **Anti-Phishing** under Threat Policies.  
2. Click **+ Create Policy** to define a new policy.  
   - **Name**: Give the policy a name (e.g., "Anti-Phishing for Organization").  
   - **Users/Groups**: Select all users or specific groups to apply the policy.  
   - **Impersonation Protection**: Add executives or critical users to protect against impersonation attacks.  
3. Enable **Action Settings**:  
   - Automatically quarantine phishing emails.  
   - Notify users when an email is quarantined.  
4. Save and apply the policy.  

#### **Step 1.3: Configure Anti-Malware Policies**  
1. In the Threat Policies section, go to **Anti-Malware**.  
2. Edit the default policy or create a new one:  
   - Enable scanning for all file types and attachments.  
   - Configure notification settings for admins and end-users.  
3. Save the policy.  

---

### **2. Configure Endpoint Security (Microsoft Defender for Endpoint)**  

#### **Step 2.1: Access Endpoint Manager**  
1. Log in to the **Microsoft Endpoint Manager Admin Center** ([https://endpoint.microsoft.com](https://endpoint.microsoft.com)).  
2. Navigate to **Devices > Configuration Profiles**.  

#### **Step 2.2: Enable Defender for Endpoint**  
1. Go to **Endpoint Security > Microsoft Defender for Endpoint**.  
2. Onboard devices:  
   - Choose the type of devices (e.g., Windows, macOS, Linux) you want to onboard.  
   - Follow the onboarding instructions to deploy the required Defender configuration on test devices.  

#### **Step 2.3: Configure Security Policies**  
1. Create a new **Endpoint Protection Policy**:  
   - Go to **Endpoint Security > Attack Surface Reduction Rules**.  
   - Enable key rules:  
     - Block executable content from email and web downloads.  
     - Block credential stealing from LSASS.  
   - Assign the policy to your test user group.  
2. Enable **Device Compliance Policies**:  
   - Define rules for device encryption, antivirus status, and firewall protection.  

#### **Step 2.4: Validate Endpoint Protection**  
1. Simulate endpoint threats by running test scripts or tools (e.g., EICAR test files).  
2. Confirm that Defender detects and blocks malicious activity.  

---

### **3. Integrate Microsoft 365 Defender with Azure Active Directory (Azure AD)**  

#### **Step 3.1: Enable Unified Monitoring**  
1. In the **Microsoft 365 Security Portal**, go to **Settings > Identities**.  
2. Enable integration with **Azure Active Directory** for identity-based threat monitoring.  

#### **Step 3.2: Configure Conditional Access Policies**  
1. Log in to **Azure Active Directory Admin Center** ([https://aad.portal.azure.com](https://aad.portal.azure.com)).  
2. Navigate to **Security > Conditional Access**.  
3. Create a new policy:  
   - **Assignments**: Apply to all users or specific roles/groups.  
   - **Conditions**: Enable conditions for risky sign-ins or untrusted devices.  
   - **Controls**: Require MFA for high-risk logins or block access altogether.  

#### **Step 3.3: Enable Identity Protection**  
1. Go to **Azure AD > Security > Identity Protection**.  
2. Enable user risk and sign-in risk policies:  
   - Automatically block high-risk sign-ins.  
   - Notify administrators of risky user behavior.  

---

### **4. Verify Configuration**  
1. Test email protection by sending simulated phishing or malware-laden emails to test accounts.  
2. Validate endpoint security by executing harmless test scripts (e.g., EICAR files).  
3. Simulate risky sign-ins (e.g., logging in from an unfamiliar location) to ensure Azure AD policies trigger alerts.  

---

### Step-by-Step Guide: **Simulate Attacks in Microsoft 365 Defender**

Simulating attacks is a crucial step to evaluate the effectiveness of your security configurations. This section outlines how to simulate phishing attacks and ransomware behavior safely in a controlled environment.

---

### **1. Simulate Phishing Attacks**  

#### **Step 1.1: Set Up a Phishing Campaign**  
1. **Access Microsoft Defender Attack Simulation**:  
   - Navigate to the [Microsoft 365 Security & Compliance Center](https://security.microsoft.com).  
   - Go to **Email & Collaboration > Attack Simulation Training**.  

2. **Create a New Simulation**:  
   - Click **Launch Simulation** and choose **Phishing Campaign**.  
   - Select a predefined phishing payload or create a custom one.  
     - Example: A fake email from IT support requesting password changes.  

3. **Target Users**:  
   - Add test users or groups (e.g., Finance Team or HR Team).  

4. **Configure Campaign Settings**:  
   - Set a start and end date for the campaign.  
   - Choose how emails should be delivered (e.g., randomly or all at once).  

5. **Run the Campaign**:  
   - Launch the simulation and monitor user behavior.  
   - Track metrics like who clicked the link, submitted credentials, or ignored the email.  

#### **Step 1.2: Analyze Results**  
1. View the simulation report in the **Attack Simulation Training** dashboard.  
   - Metrics include click-through rates, credential submission rates, and non-responses.  

2. Identify Users at Risk:  
   - Highlight users who interacted with the phishing email for further training.  

---

### **2. Simulate Ransomware Behavior**  

#### **Step 2.1: Prepare the Test Endpoint**  
1. **Use a Dedicated Test Environment**:  
   - Set up a virtual machine (VM) or physical test device enrolled in **Microsoft Defender for Endpoint**.  
   - Ensure the test endpoint is isolated from production systems.  

2. **Install the Microsoft Defender Test Tool**:  
   - Download the **Microsoft Defender Evaluation Tool** ([official documentation here](https://docs.microsoft.com/en-us/microsoft-365/security/)).  
   - Deploy the tool on the test endpoint to simulate safe attacks.  

#### **Step 2.2: Simulate Ransomware Activity**  
1. **Run a Safe Malware Test**:  
   - Use the EICAR test file to simulate malicious file behavior:  
     - Create a text file with the following content:  
       ```
       X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
       ```
     - Save it as `eicar.com`.  
   - Upload the file to the test endpoint and monitor Defender’s response.  

2. **Simulate File Encryption**:  
   - Use a harmless encryption script to mimic ransomware activity:  
     - Encrypt files in a specific folder using PowerShell or a tool like **SafeCrypto**.  
   - Verify that Defender detects and flags the activity.  

#### **Step 2.3: Analyze Detection and Response**  
1. Review alerts in the **Microsoft Defender Security Center**:  
   - Go to **Incidents & Alerts** and locate alerts related to the simulated ransomware.  
2. Verify Automated Response:  
   - Confirm that Defender isolated the affected device or blocked further encryption attempts.  

---

### **3. Report and Validate Results**  

#### **Step 3.1: Document Findings**  
1. **For Phishing Simulation**:  
   - Include metrics like:  
     - Number of emails delivered, opened, clicked, and reported.  
   - Provide recommendations for users who interacted with phishing emails.  

2. **For Ransomware Simulation**:  
   - Document Defender’s detection and response actions:  
     - Files scanned and quarantined.  
     - Endpoint isolation or mitigation steps taken.  

#### **Step 3.2: Test Remediation Capabilities**  
- Use Defender playbooks to remediate the test incidents.  
- Ensure that logs capture all activities for auditing purposes.  

---

### Step-by-Step Guide: **Detect and Investigate Threats in Microsoft 365 Defender**

This step focuses on reviewing alerts, investigating threats, and understanding incident logs in the **Microsoft 365 Defender Security Portal** to assess how well your simulated attacks were detected and managed.

---

### **1. Detect Alerts for Simulated Attacks**  

#### **Step 1.1: Access the Microsoft 365 Defender Security Portal**  
1. Navigate to the [Microsoft 365 Defender Portal](https://security.microsoft.com).  
2. Log in using your administrator credentials.  

#### **Step 1.2: Review Alerts Dashboard**  
1. Go to **Incidents & Alerts > Alerts** from the left-hand menu.  
2. Filter alerts to show recent activity related to your simulations:  
   - Use filters like **Severity**, **Category**, or **Source** (e.g., email, endpoint).  
3. Look for alerts related to:  
   - **Phishing Simulation**: Emails flagged as phishing attempts.  
   - **Ransomware Simulation**: Malicious file activity or encryption detected on endpoints.  

#### **Step 1.3: Analyze Alert Details**  
1. Click on an individual alert to view its details:  
   - **Alert Summary**: Provides a high-level description of the threat.  
   - **Mitigation Actions**: Lists automated or recommended actions taken by Microsoft Defender.  
   - **Alert Timeline**: Tracks the sequence of events, such as when the threat was detected and remediated.  

---

### **2. Investigate Phishing Attempts**  

#### **Step 2.1: Review Phishing Incident Logs**  
1. Go to **Incidents & Alerts > Incidents** to view grouped alerts for the phishing simulation.  
2. Click on the phishing incident to open the detailed investigation page.  

#### **Step 2.2: Investigate the Phishing Campaign**  
1. **Message Trace**:  
   - Track the journey of the simulated phishing email:  
     - Whether it was delivered, flagged, quarantined, or reported by users.  
2. **Affected Users**:  
   - Identify users who interacted with the email (clicked links, submitted credentials).  
3. **Email Content Analysis**:  
   - Check the headers, subject, and links in the simulated phishing email.  

#### **Step 2.3: Validate Automated Responses**  
1. Confirm that the email was quarantined or flagged as malicious.  
2. Check if users received notification of the phishing attempt.  

---

### **3. Investigate Ransomware Activities**  

#### **Step 3.1: Review Endpoint Alerts**  
1. In the **Incidents & Alerts > Alerts** section, filter alerts by **Source > Microsoft Defender for Endpoint**.  
2. Locate alerts related to the ransomware simulation:  
   - File encryption activity.  
   - Malicious file (e.g., EICAR test file) detected.  

#### **Step 3.2: Analyze Endpoint Logs**  
1. Click on the alert to access the **Alert Investigation Page**:  
   - **Threat Description**: Learn about the specific ransomware behavior flagged.  
   - **Affected Files**: Identify files that were encrypted or flagged as malicious.  
   - **Device Timeline**: Review the sequence of activities on the affected endpoint (e.g., file creation, encryption, quarantine).  

#### **Step 3.3: Verify Remediation Steps**  
1. Check if the affected endpoint was automatically isolated from the network.  
2. Review actions taken to block further activity, such as deleting malicious files or stopping processes.  

---

### **4. Generate Reports and Insights**  

#### **Step 4.1: Create Incident Reports**  
1. Go to **Reports > Threat Protection Status** to download detailed logs for simulated attacks.  
2. Include the following in your report:  
   - **Phishing Attempts**: Number of emails flagged, delivered, clicked, or reported.  
   - **Ransomware Activities**: Devices affected, files encrypted, and remediation actions taken.  

#### **Step 4.2: Provide Recommendations**  
1. Based on investigation findings, recommend:  
   - Security awareness training for users who interacted with phishing emails.  
   - Enhanced endpoint policies to prevent ransomware activities.  

---

### Step-by-Step Guide: **Automate Incident Response and Build a Monitoring Dashboard in Microsoft 365 Defender**

---

### **5. Automate Incident Response**  
Automating incident response minimizes the time to mitigate threats and ensures consistent handling of security incidents. Below are the steps to create automated playbooks for phishing email quarantine and endpoint isolation.  

---

#### **Step 5.1: Create an Automated Playbook for Phishing Emails**  

##### **Step 5.1.1: Access the Automation Section**  
1. Log in to the [Microsoft 365 Defender Portal](https://security.microsoft.com).  
2. Navigate to **Settings > Rules > Automation**.  
3. Click **+ Create Automation Rule**.  

##### **Step 5.1.2: Define the Automation Rule**  
1. **Name and Scope**:  
   - **Name**: "Quarantine Phishing Emails Automatically".  
   - **Scope**: Select **Email & Collaboration**.  
2. **Conditions**:  
   - Set a condition for email alerts classified as phishing or malware.  
     - Example: **Alert Title Contains** "Phishing attempt".  
3. **Actions**:  
   - Select **Quarantine email** as the response action.  

##### **Step 5.1.3: Apply and Save**  
1. Assign the rule to apply to all users or specific groups.  
2. Save and activate the automation rule.  

---

#### **Step 5.2: Create an Automated Playbook for Endpoint Isolation**  

##### **Step 5.2.1: Configure Endpoint Isolation**  
1. Go to the **Microsoft Endpoint Manager Admin Center** ([https://endpoint.microsoft.com](https://endpoint.microsoft.com)).  
2. Navigate to **Endpoint Security > Automation Rules**.  
3. Create a new automation rule for isolating endpoints.  

##### **Step 5.2.2: Define the Playbook**  
1. **Name**: "Isolate Infected Endpoints Automatically".  
2. **Trigger**:  
   - Set the condition to trigger on high-severity alerts from Defender for Endpoint.  
     - Example: Alerts detecting malware or unauthorized file encryption.  
3. **Response Action**:  
   - Select **Isolate Device** to disconnect it from the network while maintaining Defender's connection.  

##### **Step 5.2.3: Apply and Test**  
1. Assign the rule to your test devices or groups.  
2. Save and test by simulating a ransomware or malware attack.  

---

### **6. Build a Monitoring Dashboard**  
Creating a dashboard provides a centralized view of detection metrics, incident timelines, and response actions for enhanced monitoring.  

---

#### **Step 6.1: Access Microsoft Defender Reports**  
1. Log in to the [Microsoft 365 Defender Portal](https://security.microsoft.com).  
2. Navigate to **Reports > Threat Protection Status**.  

---

#### **Step 6.2: Create a Custom Dashboard**  

##### **Step 6.2.1: Define Dashboard Goals**  
1. Metrics to Display:  
   - Number of phishing emails detected and quarantined.  
   - Number of endpoints isolated due to malicious activity.  
2. Incident Timelines:  
   - Show when threats were detected, escalated, and resolved.  

##### **Step 6.2.2: Use the Dashboard Feature**  
1. In the **Reports** section, click **+ Add New Widget** to customize your dashboard.  
2. Select widgets for:  
   - **Email Threats**: Display phishing and malware email counts.  
   - **Endpoint Threats**: Show metrics for endpoint detections and isolations.  
   - **Incident Timelines**: Track the lifecycle of major incidents.  
3. Arrange widgets for clarity and usability.  

---

#### **Step 6.3: Integrate with Power BI (Optional)**  
1. Export data from Defender to **Power BI** for advanced visualization:  
   - Go to **Reports > Export Logs**.  
   - Import the data into Power BI and create custom visualizations.  
2. Use Power BI to create charts for detection trends, response efficiency, and incident categories.  

---

### **Key Outputs**  

#### **Automated Incident Response**:  
- Phishing emails are quarantined without manual intervention.  
- Infected endpoints are isolated automatically to prevent lateral movement.  

#### **Monitoring Dashboard**:  
- A visual dashboard in Microsoft 365 Defender displaying:  
  - Threat detection and response metrics.  
  - Real-time incident timelines and automated response actions.  

These configurations enhance operational efficiency, providing a streamlined view of your security posture and quick responses to active threats.
