# Wazuh-FalsePositive-Analysis-Lab
Practical SOC Analyst lab documenting real-world Wazuh &amp; Sysmon alert triaging, False Positive identification, and SIEM rule tuning.


> [!NOTE]
> ### 🔎 Alert Analysis: Wazuh Alert Breakdown

#### 🚨 Main Event (Sysmon EID 13)
A **Registry Value Set** event was detected, performed by the legitimate Windows system process `services.exe`.

* **🗂️ Registry Key Written:** A new service was registered with the name `P9RdrService_457c9`.
* **⚙️ Executable Path (`ImagePath`):** `C:\WINDOWS\system32\svchost.exe -k P9RdrService -p`
* **🎯 Associated MITRE Technique:** [T1543.003 – Windows Service Creation](https://attack.mitre.org/techniques/T1543/003/)
  * *Context:* Commonly associated with **Persistence** 🔐 and can be abused by attackers. However, in this specific case, it represents a standard Windows system mechanism ✅.

---

### ❓ Why Is This Alert Considered a False Positive?

#### 1. 🪟 Legitimate Service (Plan 9 Redirector)
* The `P9RdrService` (**Plan 9 File System Redirector**) is a legitimate Windows component used to support **WSL2** (Windows Subsystem for Linux) 🐧 and the **Plan 9 Network Provider** 🌐.
* The random-looking suffix at the end of the service name (`_457c9`) is consistent with Windows per-user service naming conventions and is generated for services associated with a specific user session 👤.

#### 2. 🔐 Trusted Process & Binary Verification
* **Executing Process:** The process responsible for writing the registry key is `services.exe`, running under the highly privileged `NT AUTHORITY\SYSTEM` account 🛡️.
* **Service Execution:** It launches `svchost.exe`, which is digitally signed by Microsoft ✅ and located in the expected Windows system directory:
  ```cmd
  C:\Windows\System32\svchost.exe



> [!NOTE]
> ### 🔎 Alert Analysis: Wazuh Alert Breakdown

#### 🚨 Event (Sysmon EID 13)
The legitimate Windows system process `services.exe` created a new registry value (**Registry Value Set**).

* **⚙️ Service Name:** `PimIndexMaintenanceSvc_457c9`
* **📂 Executable Path (`ImagePath`):** `C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup`
* **👤 Responsible User:** `NT AUTHORITY\SYSTEM`

---

### ❓ Why Is This Alert Considered a False Positive?

#### 1. 🪟 Legitimate Service (Contact Data / PIM Index Maintenance)
* The `PimIndexMaintenanceSvc` service is a legitimate, built-in Windows component.
* It is responsible for indexing and maintaining users' personal information data 📇, such as contacts and calendar data 📅 associated with Windows applications and User Data services.
* This activity is part of normal Windows functionality and does not indicate malicious behavior ✅.

#### 2. 🔢 Random-Looking Suffix (`_457c9`)
* The service name contains the same suffix (`_457c9`) as seen in related per-user service alerts.
* In Windows 10 and 11 🪟, Windows utilizes **Per-User Services** 👤, which append automatically generated session identifiers to service names upon user login.
* This design allows Windows to manage individual service instances per user session while grouping them under unified hosts like `UnistackSvcGroup` ⚙️.
* The suffix `_457c9` aligns with standard OS execution and is not an indicator of compromise (IOC) 🛡️.

#### 3. 🔐 Execution Chain Integrity
* **Parent Execution:** The process responsible for creating the registry key is the legitimate `services.exe` process ✅.
* **Service Host:** It launches standard `svchost.exe` from the verified system directory 📂:
  ```cmd
  C:\Windows\System32\svchost.exe



  > [!NOTE]
> ### 🔎 Alert Analysis: Wazuh Alert Breakdown

#### 🚨 Event (Sysmon EID 1)
A new process creation event was detected involving `cmd.exe`.

* **👨‍👩‍👦 Parent Process:** `C:\Windows\System32\runonce.exe` (Launched using `runonce.exe /Explorer`)
* **💻 Executed CommandLine:**
  ```cmd
  "C:\Windows\System32\cmd.exe" /q /c del /q "C:\Program Files\Microsoft OneDrive\Update\OneDriveSetup.exe"


