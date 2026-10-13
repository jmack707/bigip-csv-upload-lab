# Appendix A: scripted build

`bigip/apply.py` builds everything in chapters 5 to 9 through the BIG-IP's
REST interface. It uses only the Python standard library, creates what is
missing, updates what exists, and can be run again safely.

```bash
export BIGIP_HOST=<bigip-mgmt> BIGIP_USER=admin BIGIP_PASS='<password>'
export LAB_HOST=<lab-host> ICAP_AV_HOST=<av-host>
export VIP_IP=<vip> INNER_VS_IP=<inner-ip>
export LAB_ROUTE_GW=<gateway>      # only if a lab host is not on a BIG-IP VLAN
RESTART_ASM=1 python3 bigip/apply.py
```

`RESTART_ASM=1` lets the script restart the Application Security service
when the antivirus server address changes. Without it the script prints a
reminder and leaves the restart to you.

**You should see** the run end with both pools up and no unapplied changes:

```
  policy applied: isModified=False enforcement=blocking active=True
  pool_csv_validator_icap <lab-host>:1345: state=up
  pool_csv_sink <lab-host>:8081: state=up
done
```

`python3 bigip/teardown.py` removes everything the script created, and
clears the antivirus server setting.

The password is read from the environment and is never written to disk.

# Appendix B: object inventory

Everything is in partition `CSV` except the last row.

| Object | Name | Purpose |
|---|---|---|
| Routes | `csv_lab_host`, `csv_lab_icap_av` | Reach lab hosts that are not on a BIG-IP VLAN |
| Certificate and key | `csv_lab` | Server certificate for `<vip>` |
| Client SSL profile | `clientssl_csv_lab` | Terminates HTTPS |
| HTTP profile | `http_csv_lab` | Adds `X-Forwarded-For` |
| Monitors | `mon_csv_validator`, `mon_csv_sink` | Health of the two services |
| Pools | `pool_csv_validator_icap`, `pool_csv_sink` | The validator's ICAP port; the application |
| Security policy | `waf_csv_lab` | The WAF rules, the antivirus switch |
| ICAP profile | `icap_csv_validator` | How to call the validator |
| Internal virtual server | `ivs_csv_validator` | Target of request adapt |
| Request Adapt profile | `reqadapt_csv_lab` | Sends requests for a verdict; resets if the validator is down |
| Inner virtual server | `vs_csv_inner` | Validator hop, then the application. On no VLAN |
| LTM policy | `ltm_csv_lab` | Turns on the WAF, then forwards to the inner virtual server |
| Outer virtual server | `vs_csv_lab` | What clients connect to |
| Anti-Virus Protection server | (device-wide) | Where the WAF sends files for scanning |

# Appendix C: what the validator checks

The checks run in this order. The first failure decides the answer.

| Check | Rule | Reason code |
|---|---|---|
| Request | Only `POST /upload`. A declared length of at most 1,310,720 bytes. No chunked transfer | `NOT_FOUND`, `METHOD_NOT_ALLOWED`, `REQUEST_LENGTH_REQUIRED`, `REQUEST_TOO_LARGE` |
| Form | A well-formed `multipart/form-data` body with exactly one part, named `file`, carrying a file | `NOT_MULTIPART`, `MALFORMED_MULTIPART`, `UNEXPECTED_PART`, `MISSING_FILE_FIELD` |
| File name | Plain ASCII; no path; letters, digits, `_` and `-`, then one lower-case `.csv`. The encoded form `filename*=` is refused | `FILENAME_ENCODING`, `FILENAME_PATH`, `FILENAME_EXTENSION`, `FILENAME_MISSING` |
| Declared type | `text/csv`, `application/csv` or `application/vnd.ms-excel` | `CONTENT_TYPE` |
| Size | 1 byte to 1,048,576 bytes | `EMPTY_FILE`, `FILE_TOO_LARGE` |
| Encoding | Valid UTF-8 with no NUL bytes | `INVALID_UTF8` |
| Delimiter | Comma, semicolon or tab, whichever the header line uses. At least two columns and two records | `CSV_UNSUPPORTED_DELIMITER`, `CSV_AMBIGUOUS_DELIMITER`, `CSV_TOO_FEW_RECORDS` |
| Quoting | RFC 4180: quotes only around a whole field, doubled inside it, and closed | `CSV_BAD_QUOTING`, `CSV_UNCLOSED_QUOTE` |
| Shape | Every record has as many fields as the header. No blank lines | `CSV_FIELD_COUNT`, `CSV_BLANK_LINE`, `CSV_BAD_LINE_ENDING` |
| Cross-check | A second, independent CSV parser must read the same records | `CSV_PARSER_DISAGREEMENT` |
| Formulas and markup | See below | `CSV_FORMULA_CELL`, `CSV_ACTIVE_MARKUP`, `CSV_ACTIVE_CONTENT` |

## The formula rule

Spreadsheet programs run a cell that begins with `=`, `+`, `-` or `@` as a
formula. The validator removes leading spaces, tabs and quote characters
from each cell, and from each line of a cell that spans lines, and then
refuses the file if what is left begins with one of those characters.

| Cell | Result | Why |
|---|---|---|
| `=1+1`, `@SUM(A1)` | Refused | Begins with `=` or `@` |
| `-5`, `+3.20`, `-.5` | Accepted | A plain signed number |
| `-2+3`, `+cmd...` | Refused | Begins with a sign and is not a plain number |
| `555-0100`, `(555) 010-0100` | Accepted | Does not begin with a trigger character |
| `+1 555 0100` | **Refused** | Begins with `+` and is not a plain number. A known limitation: quote such values differently, or relax the rule |
| three spaces then `=1` | Refused | Leading white space is ignored first |
| `"=1+1"` | Refused | Quoting a field does not make it safe |
| a quoted cell whose second line is `=1+1` | Refused | Every line of a cell is checked |
| `<script>`, `<!DOCTYPE`, `</p>` | Refused | Markup |
| `a < b` | Accepted | Not a tag |
| `javascript:`, `vbscript:`, `data:text/html` | Refused | A link that runs code |

Passing these checks does not make a file safe to open in every program. It
means the file obeys these rules.

# Appendix D: things to know about BIG-IP 21.1.0.2

These were found while building and testing the lab.

- **Antivirus server changes need a restart** of the Application Security
  service. Chapter 7.
- **The antivirus server is one setting for the whole BIG-IP.**
- **Request adapt runs before the WAF** when both are on one virtual
  server. Chapter 8.
- **Request adapt fails open by default.** Chapter 8.
- **An uploaded file's name is a parameter called `filename`.** Its regular
  expression needs the **Enable** box, and its violation is off by default.
  Chapter 6.
- **Response codes are enforced.** A code the policy does not list is
  replaced by the block page. Chapter 6.
- **The built-in executable check recognises Windows (PE), Linux (ELF) and
  macOS (Mach-O) programs only.** Scripts such as `.sh` and `.bat` are not
  detected by it. In this lab the file name rule, the validator and the
  antivirus cover them.
- **Antivirus scanning does not check that a file is a CSV**, and CSV
  validation does not look for malware. The lab needs both.

# Appendix E: references

- K64356849: Configuring BIG-IP ASM to block file uploads containing binary
  executable content
- K000138456: The Disallow File Upload of Executables feature does not block
  script files
- K78925560: Configuring BIG-IP ASM to restrict file uploads based on file
  extensions
- K000151407: How to test anti-virus (ICAP) integration with BIG-IP
  ASM/Advanced WAF
- K16221101: iRules LX limitations
- BIG-IP 21.1 documentation: *Configuring General ASM System Options*,
  external anti-virus protection
- RFC 3507: Internet Content Adaptation Protocol (ICAP)
- RFC 4180: Common Format and MIME Type for CSV Files
