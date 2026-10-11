<img width="1098" height="499" alt="image" src="https://github.com/user-attachments/assets/43d1a158-b33d-4037-9904-27b0dc1df1e5" />
# Tor Browser Threat Hunt

**Investigation of Unauthorized Tor Browser Installation and Activity**

## Executive Summary

This capstone investigates Tor Browser activity on `jh-tor-hunt-01` using Microsoft Defender for Endpoint and Kusto Query Language (KQL). The investigation examines file activity, installer execution, browser processes, network connections, and scenario artifacts within a controlled Microsoft Azure environment.

The initial discovery query returned **135 matching file events** for October 5, 2026. A recorded process observation identifies execution of the Tor Browser 15.0.20 installer by account `employee` at `2026-10-05T05:29:45.230539Z`.

This report distinguishes documented observations from findings requiring additional event-level verification.

## Investigation Profile

| Attribute | Detail |
| --- | --- |
| Author and Analyst | John Hernandez |
| GitHub | [jhernandezcyber](https://github.com/jhernandezcyber) |
| Project | Endpoint Threat Hunt: Unauthorized TOR Usage |
| Environment | Microsoft Azure–Hosted Security Testing Environment |
| Operating System | Windows 11 |
| Endpoint | `jh-tor-hunt-01` |
| Activity Account | `employee` |
| Investigation Window | October 5, 2026, 00:00–24:00 UTC |
| EDR Platform | Microsoft Defender for Endpoint |
| Query Language | Kusto Query Language (KQL) |

[View Scenario Creation](https://github.com/jhernandezcyber/threat-hunting-tor-browser/blob/main/threat-hunting-scenario-tor-creation)

## Scenario

Management suspects an employee is using Tor Browser to bypass organizational network restrictions. The investigation evaluates whether endpoint telemetry supports installer execution, browser use, and associated network activity.

The activity was generated in a controlled lab. Unauthorized use represents the scenario’s simulated acceptable-use policy violation.

## Investigation Objectives

- Identify Tor Browser installer activity.
- Examine installer execution and command-line arguments.
- Identify Tor Browser and Tor component processes.
- Investigate connections associated with those processes.
- Examine the lifecycle of `tor-shopping-list.txt`.
- Reconstruct a chronological sequence from observed events.
- Document findings and response recommendations.

## Investigation Methodology

The hunt correlates file, process, and network telemetry using endpoint identity, timestamps, accounts, executable paths, and process context.

| Telemetry Source | Investigation Focus |
| --- | --- |
| `DeviceFileEvents` | Installer files, browser components, and scenario artifacts |
| `DeviceProcessEvents` | Installer execution, command lines, and browser processes |
| `DeviceNetworkEvents` | Connections attributed to Tor Browser components |

## Technical Analysis

### 1. Tor-Related File Discovery

Searched `DeviceFileEvents` for filenames containing `tor` and paths associated with the Tor Browser directory. The query returned **135 matching events** within the investigation window.

This broad filter identifies discovery candidates and can include unrelated files. The result count does not represent 135 confirmed Tor events.

```kql
DeviceFileEvents
| where Timestamp >= datetime(2026-10-05T00:00:00Z)
| where Timestamp < datetime(2026-10-06T00:00:00Z)
| where DeviceName =~ "jh-tor-hunt-01"
    or DeviceName startswith "jh-tor-hunt-01."
| where FileName contains "tor"
    or FolderPath contains @"\Tor Browser\"
| project Timestamp, DeviceName, ActionType,
    FileName, FolderPath,
    Account = InitiatingProcessAccountName,
    InitiatingProcessFileName, FileOriginUrl, SHA256
| order by Timestamp asc
```
<img width="1124" height="589" alt="image" src="https://github.com/user-attachments/assets/b1561d18-0aea-47a7-bfb0-01a6a582001d" />


*Figure 1. File-discovery query and results for `jh-tor-hunt-01`.*

**Evidence assessment:** The discovery result count is documented. Specific installer file actions and download origin require review of the corresponding event records.

### 2. Tor Browser Installer Execution

The recorded process observation identifies execution of:

- **Executable:** `tor-browser-windows-x86_64-portable-15.0.20.exe`
- **Endpoint:** `jh-tor-hunt-01`
- **Account:** `employee`
- **Timestamp:** `2026-10-05T05:29:45.230539Z`
- **Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.20.exe`

The following query retrieves installer execution details and the complete command line.

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2026-10-05T00:00:00Z)
| where Timestamp < datetime(2026-10-06T00:00:00Z)
| where DeviceName =~ "jh-tor-hunt-01"
    or DeviceName startswith "jh-tor-hunt-01."
| where FileName =~ "tor-browser-windows-x86_64-portable-15.0.20.exe"
    or ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.20.exe"
| project Timestamp, DeviceName, AccountName, ActionType,
    FileName, FolderPath, ProcessCommandLine,
    ProcessId, InitiatingProcessFileName, SHA256
| order by Timestamp asc
```

<img width="1098" height="323" alt="image" src="https://github.com/user-attachments/assets/aa48ddb4-49ff-4e88-82e4-e1d133e61a35" />



*Figure 2. Tor Browser installer process investigation.*

**Evidence assessment:** Installer execution is recorded in the investigation notes. The full event details must corroborate the observation. Silent invocation requires `/S` in the recorded command line; successful installation requires supporting component activity.

### 3. Tor Browser Component Execution

The process query identifies `tor.exe` and browser executables associated with Tor Browser directories. Executable paths and parent-process information provide context for distinguishing Tor Browser from ordinary Firefox activity.

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2026-10-05T00:00:00Z)
| where Timestamp < datetime(2026-10-06T00:00:00Z)
| where DeviceName =~ "jh-tor-hunt-01"
    or DeviceName startswith "jh-tor-hunt-01."
| where FileName in~ ("tor.exe", "firefox.exe", "tor-browser.exe")
| where FileName =~ "tor.exe"
    or FolderPath contains @"\Tor Browser\"
    or FolderPath contains @"\TorBrowser\"
| project Timestamp, DeviceName, AccountName, ActionType,
    FileName, FolderPath, ProcessCommandLine,
    ProcessId, InitiatingProcessFileName,
    InitiatingProcessFolderPath
| order by Timestamp asc
```

<img width="1041" height="352" alt="image" src="https://github.com/user-attachments/assets/3ff7473c-9881-4f9c-8f01-25b2d704eb8f" />




*Figure 3. Investigation of Tor Browser and Tor component processes.*

**Evidence assessment:** Browser launch and Tor component execution require verification of the returned process records.

### 4. Network Activity Associated with Tor Processes

The network query examines connections initiated by `tor.exe` or Firefox processes located within Tor Browser directories. It preserves connection outcomes, destination information, and initiating-process details without restricting discovery to predetermined ports.

```kql
DeviceNetworkEvents
| where Timestamp >= datetime(2026-10-05T00:00:00Z)
| where Timestamp < datetime(2026-10-06T00:00:00Z)
| where DeviceName =~ "jh-tor-hunt-01"
    or DeviceName startswith "jh-tor-hunt-01."
| where InitiatingProcessFileName =~ "tor.exe"
    or (
        InitiatingProcessFileName =~ "firefox.exe"
        and (
            InitiatingProcessFolderPath contains @"\Tor Browser\"
            or InitiatingProcessFolderPath contains @"\TorBrowser\"
        )
    )
| project Timestamp, DeviceName,
    Account = InitiatingProcessAccountName,
    ActionType, RemoteIP, RemotePort, RemoteUrl,
    LocalIP, LocalPort, Protocol,
    InitiatingProcessFileName, InitiatingProcessFolderPath,
    InitiatingProcessId
| order by Timestamp asc
```

<img width="1010" height="520" alt="image" src="https://github.com/user-attachments/assets/f3771437-770a-4804-8fe2-4023031c97e0" />


<img width="884" height="531" alt="image" src="https://github.com/user-attachments/assets/3d40a445-c7f7-48ad-b0eb-0e31f8a754e7" />


*Figure 4. Network investigation using initiating-process attribution.*

**Evidence assessment:** Successful connections require verification of event outcomes and process attribution. Port numbers alone do not establish Tor activity. Relay identification requires separate destination validation, and loopback connections represent local activity.

### 5. Scenario Artifact Investigation

The artifact query examines file activity involving `tor-shopping-list.txt`, preserving its action type, path, account, and initiating-process context.

```kql
DeviceFileEvents
| where Timestamp >= datetime(2026-10-05T00:00:00Z)
| where Timestamp < datetime(2026-10-06T00:00:00Z)
| where DeviceName =~ "jh-tor-hunt-01"
    or DeviceName startswith "jh-tor-hunt-01."
| where FileName =~ "tor-shopping-list.txt"
| project Timestamp, DeviceName, ActionType,
    FileName, FolderPath,
    Account = InitiatingProcessAccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="1071" height="90" alt="image" src="https://github.com/user-attachments/assets/eecc74ee-3bc0-4f4d-bff8-430968e905c1" />

<img width="1050" height="95" alt="image" src="https://github.com/user-attachments/assets/f14d4ed7-5187-4cde-908f-48ec8d8b7ae9" />


*Figure 5. Investigation of the scenario text-file artifact.*

**Evidence assessment:** Creation, modification, and deletion findings depend on the returned action types. File-event telemetry does not establish the file’s contents or the actor’s intent.

## Recorded Event Timeline

| Timestamp (UTC) | Endpoint | Account | Observation |
| --- | --- | --- | --- |
| `2026-10-05T05:29:45.230539Z` | `jh-tor-hunt-01` | `employee` | Recorded execution of the Tor Browser 15.0.20 installer |

Additional timeline entries require verified file, process, network, and artifact timestamps. Report timestamps use UTC; screenshots may display the portal’s configured local timezone.

## Findings and Evidence Status

| Investigation Area | Current Evidence Status |
| --- | --- |
| File discovery | 135 matching events documented |
| Installer execution | Recorded observation; supporting event details require verification |
| Silent installation | Requires verification of `/S` in the command line |
| Browser execution | Requires verification of component process events |
| Network activity | Requires verification of connection outcomes and initiating processes |
| Scenario artifact | Requires verification of file-event action types |

## Business Implications

Unauthorized anonymizing software can create policy and monitoring concerns when organizational rules prohibit its use. Correlating installer, process, and network evidence provides a basis for evaluating that concern and determining whether escalation is appropriate.

The evidence presented does not establish specific browsing destinations, successful bypass of network controls, data exfiltration, or malicious intent.

## Response and Recommendations

### Documented Actions

The investigation queries and file-discovery results were documented as part of the controlled lab exercise. Endpoint isolation and management notification are not documented as completed response actions.

### Recommended Actions

1. Corroborate installer execution with the complete process event and command line.
2. Verify browser component execution and associated network connections.
3. Preserve event exports and screenshots with consistent evidence references.
4. Assess authorization against applicable acceptable-use policy.
5. Escalate confirmed violations through the established security process and select containment measures based on incident context.

## Conclusion

The investigation identifies Tor-related file-discovery candidates and recorded installer execution on `jh-tor-hunt-01`. The project demonstrates an endpoint investigation method spanning file, process, network, and artifact analysis.

A final determination of Tor Browser use depends on corroborating the browser and network event records.

## Author

**John Hernandez**  
[GitHub: jhernandezcyber](https://github.com/jhernandezcyber)

## Revision History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | October 4, 2026 | Initial capstone documentation | John Hernandez |
| 1.1 | October 11, 2026 | Updated investigation scope, KQL queries, and evidence assessment | John Hernandez |
