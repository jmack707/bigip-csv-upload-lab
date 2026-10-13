# Operations

## Finding out what happened to an upload

| Outcome | The client sees | Where the detail is |
|---|---|---|
| Blocked by the WAF | 403 and a support ID | **Security › Event Logs › Application › Requests**. Filter by the support ID. The entry names the violation, for example *Parameter value does not comply with regular expression* on parameter `filename` |
| Blocked by the antivirus | 403 and a support ID | The same log, violation *Virus detected*. On the antivirus host, `podman logs csv-icap-av` shows `action=blocked virus=<name>` at the same second |
| Rejected by the validator | 4xx, an upload ID and a reason code | `podman logs csv-validator`: a line with `"event": "rejected"`, the client address and the file hash |
| Delivered | 200, an upload ID and the file hash | On VM 1: validator log, `"event": "validated"`; application log, `"event": "received"`; `curl http://127.0.0.1:8081/received?upload_id=<id>` returns the record |

The request log in this lab records blocked requests only. To see allowed
requests there as well, change the log profile on `vs_csv_lab` to *Log all
requests*.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Every upload, including good ones, gets 403 | The antivirus cannot be reached | Check the container is running and that TCP 1344 is open from the BIG-IP |
| The EICAR test file is delivered | The Application Security service was not restarted after the antivirus server was set | `bigstart restart asm`, then repeat the upload |
| `report.txt` is rejected by the validator, not the WAF | The file name pattern is not being enforced | Chapter 6: the **Enable** box beside the regular expression, and the *Parameter value does not comply with regular expression* violation |
| The validator's rejections arrive as 403 block pages | A response code is missing | Chapter 6, *Allowed Response Status Codes* |
| Every upload is reset | The validator pool is down | Check `curl http://<lab-host>:8080/ready` and the pool status |
| The application answers 403 `BAD_SIGNATURE` | The validator and the application have different secrets | Recreate both containers from the same `.env` |
| A pool stays red although the service answers locally | The BIG-IP cannot reach the host from a self IP | Chapter 5, routes; check for a host firewall |
| The antivirus container stops in full mode | It could not download signatures, or ran out of memory | Check outbound HTTPS and give it 2 GB, or use test mode |
| The policy shows pending changes | Something was edited after the last apply | Click **Apply Policy** |

## Things to try

The lab is yours to change. Some experiments that teach the most:

- **Relax one control and re-run the tests.** Clear the **Enable** box on the
  file name pattern. `bigip_ext_txt` now fails the test, because the request
  gets past the WAF and it is the validator that refuses it. The file still
  does not arrive: that is defence in depth.
- **Move request adapt to the outer virtual server** and watch the validator
  receive requests the WAF should have stopped.
- **Change *Service Down Action* to *Ignore***, stop the validator, and see a
  file delivered with no verdict. Change it back.
- **Switch the WAF policy to *Transparent*.** Violations are logged but
  nothing is blocked, and the validator and antivirus still do their part.
- **Upload your own CSV files**, including exports from the application you
  have in mind. Appendix C lists the rules they are judged against.

## Removing the lab

With the **Partition** selector on `CSV`, delete in this order. Each delete
fails while something still refers to the object.

1. Virtual server `vs_csv_lab`.
2. LTM policy `ltm_csv_lab`.
3. Virtual server `vs_csv_inner`.
4. Request Adapt profile `reqadapt_csv_lab`.
5. Virtual server `ivs_csv_validator`, then ICAP profile `icap_csv_validator`.
6. Security policy `waf_csv_lab`.
7. **Security › Options › Application Security › Integrated Services ›
   Anti-Virus Protection**: clear the server address and **Save**.
8. Both pools, the node, both monitors.
9. Profiles `http_csv_lab` and `clientssl_csv_lab`, certificate `csv_lab`,
   and any routes.
10. Partition `CSV`.

On the lab hosts:

```bash
podman-compose down -v                        # validator and application
(cd icap-av && podman-compose down -v)        # antivirus
```
