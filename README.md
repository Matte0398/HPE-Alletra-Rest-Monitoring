# HPE Alletra REST Monitoring

Python monitoring plugin for **HPE Alletra Storage MP**, using the WSAPI REST interface. It opens a session, collects storage information, evaluates checks and closes the session.

Use it for Nagios-compatible active checks, Checkmk local-check output, JSON integrations or manual troubleshooting. The plugin uses only the Python standard library; Python 3.9 or later is recommended.

## Quick start

Run these commands from the project directory on the monitoring server. Replace every `<PLACEHOLDER>` with the corresponding environment-specific setting; keep placeholders quoted in shell commands.

The server needs HTTPS access to the array management endpoint (default port `443`). Use a dedicated monitoring account with permission to read the required WSAPI resources.

```bash
chmod 755 check_hpe_alletra.py
cp examples/credentials.env.example '<CREDENTIALS_FILE_PATH>'
chmod 600 '<CREDENTIALS_FILE_PATH>'
```

Edit the copied credentials file:

```dotenv
ALLETRA_USER=<MONITORING_USER>
ALLETRA_PASSWORD=<MONITORING_PASSWORD>
```

Then run a single check or the complete report:

```bash
./check_hpe_alletra.py \
  --host '<ALLETRA_HOST_OR_IP>' \
  --credentials-file '<CREDENTIALS_FILE_PATH>' \
  --check system

./check_hpe_alletra.py \
  --host '<ALLETRA_HOST_OR_IP>' \
  --credentials-file '<CREDENTIALS_FILE_PATH>' \
  --check all
```

TLS certificate verification is enabled by default. If necessary for a test environment, add `--no-cert-check`; otherwise ensure the issuing CA is trusted by the monitoring server.

## Project layout and example outputs

```text
HPE-Alletra-Rest-Monitoring/
|-- check_hpe_alletra.py
|-- README.md
|-- LICENSE
|-- .gitignore
`-- examples/
    |-- credentials.env.example
    `-- output/
        |-- check_all.txt
        |-- check_all_checkmk.txt
        |-- check_alerts.txt
        |-- check_capacity.txt
        |-- check_ports.json
        `-- discover_disks.txt
```

The following are the six available output files. Individual checks without a dedicated sample can be inspected in the complete reports.

| File | Contents |
| --- | --- |
| [check_all.txt](examples/output/check_all.txt) | All ten checks, grouped by check type, with an overall `CRIT` state and exit code `2`. |
| [check_all_checkmk.txt](examples/output/check_all_checkmk.txt) | Complete collection as a `<<<local>>>` section, with one state per service and process exit code `0`. |
| [check_alerts.txt](examples/output/check_alerts.txt) | Three scenarios in one file: alerts present, missing `category` returning `UNKNOWN`, and no alerts returning `OK`. |
| [check_capacity.txt](examples/output/check_capacity.txt) | Capacity report with warning and critical thresholds. |
| [check_ports.json](examples/output/check_ports.json) | Structured port results, derived fields and the raw WSAPI payload. |
| [discover_disks.txt](examples/output/discover_disks.txt) | Disk identifiers returned by `--discover disks`. |

These files contain illustrative samples. Their commands and identifiers are examples to adapt to your environment. Some retained samples classify `MINOR` alerts as `WARN`; the current script classifies them as `CRIT`. Use the check policies below as the reference for current behavior.

All commands and output templates in this README use placeholders for environment-specific information. Numeric defaults, API enumeration values and status codes describe the implementation.

## Authentication

Select **exactly one** authentication method:

| Method | Arguments | Requirements |
| --- | --- | --- |
| Credentials file | `--credentials-file '<CREDENTIALS_FILE_PATH>'` | File containing `ALLETRA_USER` and `ALLETRA_PASSWORD`; no group or other-user permissions (`0600` or stricter). |
| Password from stdin | `--user '<MONITORING_USER>' --password-stdin` | Prompts without echo on an interactive terminal; reads one line when stdin is redirected. |
| Checkmk Password Store | `--user '<MONITORING_USER>' --password-id '<PASSWORD_STORE_ID>'` | Must run in a Checkmk Python environment with access to the password store. |

The credentials file also accepts the keys `HPE_ALLETRA_USER` and `HPE_ALLETRA_PASSWORD`. A file supplies both username and password; `--user` is required for the other two methods.

Interactive example:

```bash
./check_hpe_alletra.py \
  --host '<ALLETRA_HOST_OR_IP>' \
  --user '<MONITORING_USER>' \
  --password-stdin \
  --check system
```

## Available checks

Use `--check '<CHECK_NAME>'` for one check, or `--check all` for all ten. During a complete collection, `system`, `nodes` and `capacity` share a cached `/api/v1/system` response. A collection error is reported as `UNKNOWN`; `all` continues with the remaining checks.

| Check | GET endpoint | Current behavior |
| --- | --- | --- |
| `system` | `/api/v1/system` | Reports WSAPI reachability, system name, model and software version. |
| `nodes` | `/api/v1/system` | Evaluates node availability, cluster membership and master node. |
| `capacity` | `/api/v1/system` | Evaluates allocated capacity percentage and failed capacity. |
| `disks` | `/api/v1/disks` | Evaluates physical disk state and reports hardware details. |
| `cpgs` | `/api/v1/cpgs` | Evaluates pool usage and textual health when available. |
| `volumes` | `/api/v1/volumes` | Lists discovered objects and raw state/status; does not evaluate volume health. |
| `hosts` | `/api/v1/hosts` | Reports configured hosts and available persona, domain and path counts; does not evaluate path health. |
| `ports` | `/api/v1/ports` | Evaluates link state; reports mode, protocol and hardware type. |
| `remotecopy` | `/api/v1/remotecopygroups` | Evaluates replication group/target state and volume synchronization. |
| `alerts` | `/api/v1/eventlog/minutes:<N>` | Filters recent events locally for alert category `2`, then evaluates severity. |

### Nodes

The check reads `totalNodes`, `onlineNodes`, `clusterNodes` and `masterNode`. Fewer online nodes than expected, or a master node that is not online, produces `CRIT`. Incomplete nonempty cluster membership produces `WARN` when no critical condition applies.

### Capacity and CPGs

Default thresholds are `--warn 80` and `--crit 90`. Usage at or above a threshold produces the corresponding state. Arguments must satisfy `0 <= warn < crit <= 100`.

```bash
./check_hpe_alletra.py \
  --host '<ALLETRA_HOST_OR_IP>' \
  --credentials-file '<CREDENTIALS_FILE_PATH>' \
  --check capacity --warn 80 --crit 90
```

System capacity uses `totalCapacityMiB`, `allocatedCapacityMiB`, `freeCapacityMiB` and `failedCapacityMiB`. Any positive failed capacity produces `CRIT`.

CPG capacity is derived from `UsrUsage`, `SDUsage` and `SAUsage` (including lowercase variants), using used/total fields or deriving usage from total/free fields. Unusable capacity information produces `UNKNOWN`; textual pool health also contributes to the state.

### Disks

| WSAPI state | Meaning | Monitoring state |
| --- | --- | --- |
| `1` | Normal | `OK` |
| `2` | Degraded | `CRIT` |
| `3` | New | `WARN` |
| `4` | Failed | `CRIT` |
| `99` or unrecognized | Unknown | `UNKNOWN` |

### Ports

Port identifiers are normalized as `node:slot:cardPort`.

| Link states | Monitoring state |
| --- | --- |
| `READY` | `OK` |
| `CONFIG_WAIT`, `ALPA_WAIT`, `LOGIN_WAIT`, `LOSS_SYNC`, `NONPARTICIPATE`, `IDLE_FOR_RESET`, `DHCP_IN_PROGRESS`, `PENDING_RESET`, `NEW`, `DISABLED`, `PURGING` | `WARN` |
| `ERROR_STATE`, `COREDUMP`, `OFFLINE`, `FWDEAD`, `DOWN`, `FAILED` | `CRIT` |
| `XXX` or unrecognized link state | `UNKNOWN` |

### Remote Copy

Group state is used when present; otherwise the check derives the mode from target states. `STARTED` and `BACKUP` are healthy modes. `NEW`, `STARTING`, `RESTART` and `LOGGING` produce `WARN`; `STOPPED` and `FAILSAFE` produce `CRIT`.

Volume synchronization contributes to health: `SYNCED` is `OK`; transitional states produce `WARN`; `UNSYNC`, `STALE`, `STOPPED` and `FAILSAFE` produce `CRIT`. Unknown state values produce `UNKNOWN`. A `STARTED` group with degraded synchronization produces `CRIT`. If no volume synchronization entries exist, the synchronization status is reported as `N/A`.

### Alerts

The default window is `--alerts-minutes 60`; it must be at least one minute. The script retrieves the time window and filters `category=2` locally, avoiding a server-side category query that some firmware versions reject.

| Severity | Monitoring state |
| --- | --- |
| `FATAL`, `CRITICAL`, `MAJOR`, `MINOR`, `DEGRADED` | `CRIT` |
| `INFORMATIONAL`, `DEBUG` | `OK` |
| Unknown or unrecognized | `UNKNOWN` |

An event missing `category`, or an alert missing `severity`, produces `UNKNOWN`. No matching alerts produces `OK`. This check evaluates events in the selected window, rather than an inventory of currently active alarms. Large windows can increase response size and cause timeouts.

```bash
./check_hpe_alletra.py \
  --host '<ALLETRA_HOST_OR_IP>' \
  --credentials-file '<CREDENTIALS_FILE_PATH>' \
  --check alerts --alerts-minutes 60
```

## Output formats and exit codes

| Format | Behavior |
| --- | --- |
| `nagios` (default) | Single-check summary with object counts; grouped report for `--check all`. |
| `text` | Legacy alias for `nagios`. |
| `json` | Object containing `host`, `overall_state` and `results`; `--include-raw` adds the collected payload under `raw`. |
| `checkmk` | `<<<local>>>` section followed by individual service lines. The metric field is `-`; no performance metrics are emitted. |

Each JSON result contains `check`, `item`, `state`, `state_name`, `summary` and `details`. `details` can contain object fields even without `--include-raw`.

For Nagios/text and JSON checks, exit codes are `0` for `OK`, `1` for `WARN`, `2` for `CRIT`, and `3` for `UNKNOWN`. Aggregation uses priority **CRIT > WARN > UNKNOWN > OK**, rather than numeric order.

Checkmk output normally exits `0`, including handled collector errors, because service lines carry the states. Argument validation failures can still return a nonzero exit code.

```bash
./check_hpe_alletra.py \
  --host '<ALLETRA_HOST_OR_IP>' \
  --credentials-file '<CREDENTIALS_FILE_PATH>' \
  --check ports --output json --include-raw
```

Output templates (placeholders are not literal runtime output):

```text
OK - objects=1, ok=1, warn=0, crit=0, unknown=0 - WSAPI reachable - system <SYSTEM_NAME> (model=<SYSTEM_MODEL>, version=<SOFTWARE_VERSION>)
```

```text
<<<local>>>
0 "Alletra System" - WSAPI reachable - system <SYSTEM_NAME> (model=<SYSTEM_MODEL>, version=<SOFTWARE_VERSION>)
2 "Alletra Port <PORT_ID>" - mode=TARGET, link=DOWN, protocol=FC, hardware=FC
```

## Discovery

`--discover` is mutually exclusive with `--check`. Supported object types are `disks`, `cpgs`, `volumes`, `hosts`, `ports` and `remotecopy`.

```bash
./check_hpe_alletra.py \
  --host '<ALLETRA_HOST_OR_IP>' \
  --credentials-file '<CREDENTIALS_FILE_PATH>' \
  --discover disks
```

Default discovery output lists identifiers, one per line. With `--output json`, it returns an array of objects with `item` and `data` fields, containing the identifier and source object. Successful discovery exits `0`, independently of individual object health.

## Checkmk integration

Install the executable under the site-specific custom plugin directory:

```bash
cp check_hpe_alletra.py '/omd/sites/<SITE>/local/lib/nagios/plugins/check_hpe_alletra.py'
chown '<SITE>:<SITE>' '/omd/sites/<SITE>/local/lib/nagios/plugins/check_hpe_alletra.py'
chmod 755 '/omd/sites/<SITE>/local/lib/nagios/plugins/check_hpe_alletra.py'
```

For an active check, configure execution in Nagios format. A single check normally creates one service:

```bash
'/omd/sites/<SITE>/local/lib/nagios/plugins/check_hpe_alletra.py' \
  --host '<ALLETRA_HOST_OR_IP>' \
  --user '<MONITORING_USER>' \
  --password-id '<PASSWORD_STORE_ID>' \
  --check nodes --output nagios
```

For multiple services from one collection, configure a data source program to execute the script with `--check all --output checkmk` and consume its agent-style output. The script does not create Checkmk rules automatically.

Password Store access requires execution in the Checkmk Python environment. In distributed monitoring, install the executable and make credentials available on the site that actually runs the collection.

## CLI reference

| Argument | Default / purpose |
| --- | --- |
| `--host` | Required array hostname or IP; supply no URL scheme or API path. |
| `--port` | HTTPS port, default `443`. |
| `--timeout` | Request timeout in seconds, default `20`. |
| `--check` / `--discover` | Select exactly one operation. |
| `--credentials-file` / `--password-stdin` / `--password-id` | Select exactly one credential source. |
| `--user` | Required for stdin and Password Store authentication. |
| `--warn` / `--crit` | Capacity and CPG thresholds, default `80` / `90` percent. |
| `--alerts-minutes` | Event lookback window, default `60`. |
| `--output` | `nagios`, `text`, `json` or `checkmk`; default `nagios`. |
| `--include-raw` | Adds collected WSAPI responses to JSON check output. |
| `--no-cert-check` | Disables TLS certificate verification. |
| `--debug` | Writes request method/path and HTTP status diagnostics to stderr. |
| `--help` / `--version` | Displays usage / plugin version. |

## Troubleshooting and direct WSAPI requests

Start with `./check_hpe_alletra.py --help`, then test a single check. Add `--debug` for request diagnostics or use JSON output to inspect returned fields.

Required-field and collection-schema checks return `UNKNOWN` when the response cannot be interpreted. These checks are specific to each evaluator; volume discovery and host listing do not provide a full health assessment.

For a manual API test, create a session:

```bash
curl --silent --show-error \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{"user":"<MONITORING_USER>","password":"<MONITORING_PASSWORD>","sessionType":1}' \
  'https://<ALLETRA_HOST_OR_IP>:<WSAPI_PORT>/api/v1/credentials'
```

The response contains the session key:

```json
{"key": "<WSAPI_SESSION_KEY>"}
```

Query an endpoint using that key:

```bash
curl --silent --show-error \
  --header 'X-HP3PAR-WSAPI-SessionKey: <WSAPI_SESSION_KEY>' \
  'https://<ALLETRA_HOST_OR_IP>:<WSAPI_PORT>/api/v1/system'
```

Use the endpoints in the checks table for other resources. Close the session when finished:

```bash
curl --silent --show-error \
  --request DELETE \
  --header 'X-HP3PAR-WSAPI-SessionKey: <WSAPI_SESSION_KEY>' \
  'https://<ALLETRA_HOST_OR_IP>:<WSAPI_PORT>/api/v1/credentials'
```

These curl commands are request templates. Handle actual passwords and session keys securely; command-line arguments can be visible to other processes. Review JSON output before sharing it, since results and raw payloads can contain environment identifiers.

## License

Released under the MIT License. See [LICENSE](LICENSE).
