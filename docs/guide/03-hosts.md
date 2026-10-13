# Prepare the two Linux VMs

Create two VMs on your hypervisor with the sizes from chapter 2, a current
Ubuntu or Debian cloud image, a static address each, and an account you can
`sudo` from. Then prepare each one with the script in the bundle. The script
is small and readable; what it does is listed below so that you can do it by
hand instead.

## Run the preparation script

Copy the bundle to each VM. On VM 1:

```bash
sudo scripts/prepare-host.sh --role app --allow <bigip-self-ip>
```

On VM 2:

```bash
sudo scripts/prepare-host.sh --role av --allow <bigip-self-ip>
```

Add `--check` to either command to see what it would change without
changing anything. `--allow` takes a comma-separated list if more than one
address should reach the lab, for example a second BIG-IP or the host you
run the tests from.

**You should see** each run end with `done` and the next commands to run.

## What the script does, and why

| Step | What | Why |
|---|---|---|
| Packages | `podman`, `podman-compose`, `uidmap`, `slirp4netns`, `nftables`, `git`, `curl`, `python3`, `openssl` | Rootless Podman needs the user-namespace helpers; the lab scripts need the rest |
| Account `csvlab` | A normal user with a 65,536-ID subordinate range in `/etc/subuid` and `/etc/subgid` | The containers run as this user, not as root. Without the subordinate range, Podman cannot unpack images |
| Linger | `loginctl enable-linger csvlab` | The containers keep running after you log out and come back after a reboot |
| Log driver | `log_driver = "k8s-file"` in the user's `containers.conf` | The default driver writes to the journal, which a normal user cannot read; `podman logs` would show nothing |
| Low ports | `net.ipv4.ip_unprivileged_port_start = 1024` | The ICAP ports 1344 and 1345 are below Podman's rootless default of 1024 |
| Firewall | nftables: SSH open, the lab ports open to `--allow` only, everything else dropped | The BIG-IP is the only legitimate caller of the validator, the antivirus and the application. Anything else reaching them bypasses the WAF |

## Check connectivity from the BIG-IP

The BIG-IP must reach the VMs from a self IP, not from its management
address. From the BIG-IP command line:

```bash
ping -c 2 -I <bigip-self-ip> <lab-host>
ping -c 2 -I <bigip-self-ip> <av-host>
```

If the VMs are on a VLAN the BIG-IP is not connected to, the pings fail
until the route in chapter 5 exists. If they fail with the route in place,
look at the VM firewall (`sudo nft list ruleset`) and the network in
between.

**You should see** replies from both addresses.

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `podman build` fails with "potentially insufficient UIDs or GIDs" | No subordinate ID range for the account | Re-run the script; it adds a range if `useradd` did not. Then `podman system migrate` as the account |
| `podman logs` prints nothing | Log driver is journald | The script sets `k8s-file`; recreate the containers afterwards |
| Port 1344 or 1345 "permission denied" | Rootless Podman cannot bind below 1024 | The sysctl the script sets, then restart the containers |
| The BIG-IP monitor stays red though the service answers locally | Firewall, or the BIG-IP is reaching from the wrong address | `--allow` must list the self IP on the VLAN the BIG-IP uses towards the VM. Check with `nft list ruleset` and a packet capture on the VM |
| `apt` hangs on an IPv6 address | The VM resolves mirrors to IPv6 but has no IPv6 route | Set `Acquire::ForceIPv4 "true";` in `/etc/apt/apt.conf.d/99force-ipv4` |
