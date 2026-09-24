# Sigma Detection Engineering — Home Lab

Writing Sigma rules against real endpoint telemetry, converting them, deploying them to Wazuh, and proving they fire.

Each rule in this repo has been tested against events generated on a live endpoint. Nothing here is theoretical.

---

## Lab environment

| Component | Detail |
|---|---|
| SIEM | Wazuh 4.14.7 (manager, indexer, dashboard) on Ubuntu 26.04 LTS |
| Endpoint | Windows 11 Enterprise LTSC (build 26100), VirtualBox |
| Telemetry | Sysmon 15.22 with SwiftOnSecurity config |
| Rule tooling | sigma-cli 3.1.0, pySigma, `opensearch_lucene` backend, `sysmon` pipeline |
| Network | Bridged, both VMs on the same /24 |

Host is a single 16GB laptop running both VMs concurrently.

---

## Rule 001 — Encoded PowerShell Command Execution (T1059.001)

**Detects:** PowerShell invoked with a base64-encoded command argument (`-enc`, `-encodedcommand`, `-ec`).

**Why it matters:** Encoding hides the payload from anyone eyeballing a command line and defeats naive string matching on the actual commands being run. It is common in loaders, living-off-the-land chains, and post-exploitation tooling.

- Sigma rule: [`rules/sigma/encoded_powershell.yml`](rules/sigma/encoded_powershell.yml)
- Deployed Wazuh rule: [`rules/wazuh/local_rules.xml`](rules/wazuh/local_rules.xml)
- ATT&CK: [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

### Converted query

```
sigma convert -t opensearch_lucene -p sysmon rules/sigma/encoded_powershell.yml
```

```
EventID:1 AND ((Image:(*\\powershell.exe OR *\\pwsh.exe)) AND (CommandLine:(*\ \-enc\ * OR *\ \-encodedcommand\ * OR *\ \-ec\ *)))
```

The `EventID:1` was injected by the `sysmon` pipeline — the rule itself only declares `category: process_creation`. That mapping from generic category to concrete event ID is the pipeline's job, not the rule author's.

### Validation

Fired on a live endpoint under two separate parent processes:

| Parent | Command | Result |
|---|---|---|
| `powershell.exe` | `powershell.exe -enc <b64>` | Alert 100101, level 12 |
| `cmd.exe` | `cmd /c powershell.exe -enc <b64>` | Alert 100101, level 12 |

Testing both parents was deliberate — see finding 3 below.

### Known false positives

Not hypothetical; these are the patterns that would realistically trip this rule in a production estate.

- **Software deployment and provisioning tooling.** Encoding arguments is a common way to avoid shell-quoting problems when a management platform passes a script to an endpoint. SCCM, Intune and various RMM agents all do this.
- **Backup and monitoring agents** that invoke scheduled encoded PowerShell.
- **Wazuh's own SCA scans.** Observed directly in this lab: after an agent restart, the SCA module runs `net.exe` discovery commands that trigger Wazuh's built-in discovery rules (92031, 92039). The SIEM detects itself. Worth knowing before anyone spends an afternoon chasing it.

Any exclusion added for the above should be scoped to a specific parent image or signed binary path, not a blanket `-enc` suppression. Every exclusion is a hole in the net.

---

## Findings

Three things this exercise surfaced that are not in the tutorials.

### 1. `Image` and `CommandLine` can disagree on WOW64 systems

Raw Sysmon Event ID 1 from the validation run:

```
Image:       C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -enc ...
```

The same process reports a 32-bit path in `Image` and a 64-bit path in `CommandLine`. This is filesystem redirection: the command was launched from a 32-bit PowerShell host, so Windows redirected `System32` to `SysWOW64` at execution time while the command line retained the literal string that was typed.

**Consequence:** a rule matching `System32` in the `Image` field would have missed this execution entirely. Matching on `OriginalFileName` instead avoids both the path problem and the backslash-escaping problem below.

### 2. There is no Sigma backend for Wazuh

`sigma plugin list` has no Wazuh entry, and the [SigmaHQ plugin directory discussion](https://github.com/SigmaHQ/pySigma-plugin-directory/discussions/52) confirms nobody has implemented one. Conversion to Wazuh is a manual step.

The workflow that does work is two-track:

- **Hunting** — convert with `opensearch_lucene`, paste into the Wazuh dashboard. Wazuh's indexer is OpenSearch, so Lucene syntax works directly.
- **Alerting** — hand-write the equivalent rule in `local_rules.xml`.

Field mapping required for the manual step:

| Sigma field | Wazuh dashboard (DQL) | Wazuh rule XML |
|---|---|---|
| `EventID` | `data.win.system.eventID` | `win.system.eventID` |
| `Image` | `data.win.eventdata.image` | `win.eventdata.image` |
| `CommandLine` | `data.win.eventdata.commandLine` | `win.eventdata.commandLine` |
| `OriginalFileName` | `data.win.eventdata.originalFileName` | `win.eventdata.originalFileName` |

Note the camelCase with a lowercase first letter — Sigma's `CommandLine` becomes Wazuh's `commandLine`. Also note the dashboard requires the `data.` prefix while the rule XML does not.

Also worth knowing: the plugin identifier is `opensearch`, but the conversion target is `opensearch_lucene`. Installing a plugin can register several targets under different names.

### 3. Wazuh fires one rule per event, so custom rules need explicit parent chaining

Wazuh walks its rule tree, matches the first applicable rule, and stops. A custom rule that is a sibling of a built-in rule will never be evaluated if the built-in matches first.

The encoded PowerShell event was being consumed by built-in rule **92027** ("Powershell process spawned powershell instance"). A custom rule with correct field matching still never fired, because execution never reached it.

The fix is `<if_sid>`, chaining the custom rule as a child of a rule that does match. But the choice of parent determines coverage:

| Parent | Coverage |
|---|---|
| `<if_sid>92027</if_sid>` | Only fires when PowerShell spawns PowerShell. Misses execution from cmd, scheduled tasks, Office macros. |
| `<if_sid>61603</if_sid>` | Fires on any Sysmon Event ID 1. Full coverage. |

Rule 61603 is the base Sysmon process-creation rule, level 0, which every EID1 event passes through. Chaining there rather than to a specific detection is what closed the gap.

**Generalisable point:** in a single-match rule engine, the narrower your parent, the narrower your detection — regardless of how good the rule's own logic is. This is invisible when testing with one execution method.

---

## Debugging notes

Kept because the process is more instructive than the result.

The rule did not fire on the first four attempts. Causes, in the order they were eliminated:

1. **Wrong regex engine.** Wazuh `<field>` uses OS_Regex by default; PCRE syntax like `(?i)` requires `type="pcre2"` on the field.
2. **Wrong group name.** Assumed `sysmon_event1` as an `if_group`; the event's actual groups were `sysmon`, `sysmon_eid1_detections`, `windows`.
3. **Backslash escaping.** Matching `\\powershell.exe` against a path that survives decoder and JSON escaping is fragile. `OriginalFileName` has no path separators and sidesteps the problem.
4. **Rule tree precedence.** The real cause — see finding 3.

Two tools that shortened this:

- `sudo grep -a "Total rules enabled" /var/ossec/logs/ossec.log | tail -1` — confirms the ruleset actually reloaded after an edit, and the count changing confirms your rule loaded. The `-a` flag matters; the log contains binary data and grep silently truncates without it.
- **Bisecting the rule.** Stripping it to `if_sid` plus a description, with no field conditions at all, separated "can a custom rule fire here" from "is my regex right". Adding conditions back one at a time isolated each one.

Order of operations that avoids wasted cycles: **edit → restart → verify reload timestamp → generate event → search.** Getting this wrong produces a false negative that looks identical to a broken rule.

---

## Roadmap

- [ ] Rule 002 — Scheduled task creation (T1053.005)
- [ ] Rule 003 — Local account creation (T1136.001)
- [ ] Replace hand-typed test commands with Atomic Red Team
- [ ] Baseline period to quantify false positive rate rather than listing them qualitatively
- [ ] Linux endpoint with auditd telemetry for cross-platform coverage

---

**Author:** Mohemed Abdulla Irfan
