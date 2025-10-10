---
layout: research
title: "Turning the Tables on GlobalProtect: Behind the CVEs"
date: 2025-01-27
author: Alex Bourla
description: "A deep dive into vulnerabilities discovered in Palo Alto Networks' GlobalProtect VPN client, including privilege escalation and VPN bypass techniques."
tags: [VPN Security, Privilege Escalation, macOS, Linux, CVE-2025-0135, CVE-2025-0140, CVE-2025-0141, CVE-2025-2179]
permalink: /research/turning-the-table-on-globalprotect/
---

## Introduction

What happens when enterprise VPN software designed to protect your systems opens them up to exploitation instead?
In this post, I unpack a series of vulnerabilities we discovered in Palo Alto Networks' (PAN) GlobalProtect client that could be used to bypass the VPN or escalate privileges on MacOS and Linux endpoints with GlobalProtect installed. 

This post builds upon a talk I gave at Black Hat USA 2025 (abstract and slides are available [here](https://www.blackhat.com/us-25/briefings/schedule/#turning-the-tables-on-globalprotect-use-and-abuse-of-palo-altos-remote-access-solution-46051), and video recording to follow on Black Hat's YouTube channel in the coming months), providing more technical details surrounding the vulnerabilities and the fundamental design decisions that directly contributed to their existence.

This research was done together with the invaluable contributions of [Graham Brereton](https://www.linkedin.com/in/graham-brereton/) and represents both our collaborative work. 

## Vulnerability Summary

Between April and October 2024 we reported 5 vulnerabilities affecting Global Protect client on Mac and Linux. In July 2025 PAN patched 4 of the vulnerabilities, with one bypass remaining open as PAN didn't consider it a vulnerability that they would fix. 

Please see the table below summarising the state of the reported vulnerabilities:

| Vulnerability (CVE) | Reported | Status | Fixed | Notes / Mitigation |
|---------------------|----------|--------|-------|---------------------|
| **VPN Bypass:** DNS Spoofing, Wildcard Split Tunnel Domain | April 2024 | 🔴 **WON'T FIX** | N/A | *"After investigation, we have determined that we do not consider this a vulnerability in the GlobalProtect macOS app."*<br><br>**Potential mitigation:** Combine `Split Tunnel Domain` **and** `Split DNS` features. |
| **VPN Bypass:** Forged IPC Disconnect (macOS) | October 2024 | 🟢 **PATCHED**<br><br>**CVE-2025-0135**<br>CVSS v4 Base: <span class="cvss-medium">**5.7**</span> | July 2025<br><br>Initial patch ineffective, repatched in:<br>- `6.2.8-h3` (6.2.8-c263)<br>- `6.3.3-h2` (6.3.3-c676) | Palo Alto reported to fix under CVE-2025-0135, however vulnerability still present<br><br>Repatched successfully under original CVE-2025-0135 |
| **VPN Bypass:** Forged IPC Disconnect (Linux) | October 2024 | 🟢 **PATCHED**<br><br>**CVE-2025-2179**<br>CVSS v4 Base: <span class="cvss-high">**6.8**</span> | July 2025<br><br>Initial patch ineffective, repatched in:<br>- `6.2.9` | Palo Alto reported to fix under CVE-2025-0140, however vulnerability still present<br><br>Repatched successfully under CVE-2025-2179 |
| **VPN Bypass:** Plist File Modification (macOS) | October 2024 | 🟢 **PATCHED**<br><br>**CVE-2025-0140**<br>CVSS v4 Base: <span class="cvss-high">**6.8**</span> | July 2025<br><br>Patched in:<br>- `6.2.8-h2` (6.2.8-c233)<br>- `6.3.3-h1` (6.3.3-c650) | Although initially reported for macOS, Palo Alto reported to affect:<br>- Linux<br>- macOS |
| **Privilege Escalation:** SUID Binary Abuse (macOS) | October 2024 | 🟢 **PATCHED**<br><br>**CVE-2025-0141**<br>CVSS v4 Base: <span class="cvss-critical">**8.4**</span> | July 2025<br><br>Patched in:<br>- `6.2.8-h2` (6.2.8-c233)<br>- `6.3.3-h1` (6.3.3-c650) | Although initially reported for macOS, Palo Alto reported to affect:<br>- Windows<br>- Linux<br>- macOS |

In the sections that follow, I'll break down each vulnerability, explain the root cause, and walk through how we found it.

## Under the Hood: GlobalProtect Architecture and Attack Surface

### Research Goals 

GlobalProtect is a 'Secure Remote Access' solution from PAN, used by thousands of enterprise customers worldwide to securely connect remote workers, offices, or data-centre networks, as well as providing fine-grained policy enforcement and monitoring of traffic within the network or egressing to the Internet - a critical security control within a typical enterprise network.

PAN provides clients for a range of mobile and desktop endpoints, however we chose to limit our initial research to Mac and Linux clients only with two primary goals:
* To find vulnerabilities that could allow a, low privileged, local user bypass the GlobalProtect VPN tunnel
* Find a way to abuse GlobalProtect to escalate privileges on the local device

These goals were chosen as they represented the highest impact threats associated with the threat model of the local GlobalProtect client. The client itself includes components that run as `root` on the device making it a good target for privilege escalation, while bypassing the tunnel undermines the security provided by the GlobalProtect enterprise security product. 

A typical attacker could use these vulnerabilities for a range of motivations including to:
* Gain access to unauthorised website categories without detection e.g. gambling or social media
* Initiate a command and control (C2) tunnel outside of the GlobalProtect VPN
* Exfiltrate internal data to Cloud Storage or Transfer services without detection

### High Level Architecture

The diagram below provides a high-level overview of the core components that make up the GlobalProtect client on macOS. Similar components exist on Linux, but with some important differences in implementation and privilege boundaries that will become relevant in the context of the vulnerabilities discussed later.

![High-level-architecture-macOS](img/globalprotect-architecture-overview.png)

The main unprivileged component is the user interface process, `PanGPA`. This allows the logged-in user to interact with the GlobalProtect client, for example, to authenticate, configure preferences, or run diagnostics.

The remaining components primarily run with elevated privileges (`root`), including:
* `PanGPS`: the core VPN daemon responsible for establishing tunnels, setting routes, enforcing security policies, and coordinating with other components.
* `PanGPHip` and `PanGPHipMP`: binaries involved in the [Host Information (HIP) feature](https://docs.paloaltonetworks.com/globalprotect/10-1/globalprotect-admin/host-information), used by administrators to enforce device posture policies (e.g., OS version, patch level) before allowing access to internal resources.

There is also a system extension, `GlobalProtectExtension`  which is used to implement the [Split Tunnel feature](https://docs.paloaltonetworks.com/globalprotect/10-1/globalprotect-admin/globalprotect-gateways/split-tunnel-traffic-on-globalprotect-gateways). This feature allows traffic to bypass the VPN tunnel based on either the application making the request or the destination domain.

Collectively, these components contribute to the security model of the software and each was involved in one or more of the vulnerabilities discussed in the sections that follow.

## Wildcard Split Tunnel Abuse

The _Split Tunnel Traffic_ feature of the GlobalProtect gateway allows system administrators to configure certain traffic to bypass the VPN tunnel and egress directly to the internet, based on specific criteria. 

Common use cases for split tunnelling include sending latency-sensitive traffic like VoIP directly to the internet, or excluding bandwidth-heavy services such as YouTube and Netflix from the VPN tunnel to reduce load on the gateway ([see PAN docs](https://docs.paloaltonetworks.com/globalprotect/9-1/globalprotect-admin/globalprotect-gateways/split-tunnel-traffic-on-globalprotect-gateways)).

Administrators can configure split tunnel rules using destination domains, including wildcard domains like `*.target.com`, to exclude entire applications or services from the VPN tunnel ([docs](https://docs.paloaltonetworks.com/globalprotect/9-1/globalprotect-admin/globalprotect-gateways/split-tunnel-traffic-on-globalprotect-gateways/configure-a-split-tunnel-based-on-the-domain-and-application#id0687b049-6664-4054-96dc-ba880f8c92c9)).

We found that, if such a configuration was in place, this feature can be abused to allow egress to _any_ arbitrary domain e.g. `attacker.evil.com`. 

The following steps are needed to exploit this vulnerability:
1. Perform a DNS lookup from the host to an arbitrary subdomain of a allowlisted wildcard domain e.g. `foo.target.com` using an attacker controlled DNS server i.e. `dig foo.target.com @[attacker-controlled-DNS-server]`.
2. The attacker controlled DNS server should return a spoofed response which includes the IP address of `attacker.evil.com`
3. The GlobalProtect App will then wrongly associate, and allowlist, the IP address for `attacker.evil.com` with the allowlisted domain of `foo.target.com`
4. From this point, the attacker has unrestricted egress to `attacker.evil.com` through browser, `curl`, or any other HTTP client.

The following diagram shows the sequence of calls described above:
![Wildcard Split Tunnel Domain Flow](img/wildcard-split-tunnel-flow.png)

The root cause of this issue lies in the way that GlobalProtect allowlists domains, and in particular how it allowlists wildcard domains. 

The GlobalProtect system network extension is responsible for routing split tunnel traffic through the endpoints primary interface, configuring it to route directly to the Local Area Network's (LAN) default gateway it effectively bypasses the VPN tunnel. Critically, this has to be done based on IP address only. 

This approach is relatively simple for a fully qualified domain name (FQDN) such as `example.target.com` as the IP can be resolved ahead of time and configured to bypass the VPN, for example.

However, if a wildcard is configured e.g. `*.target.com` then the GlobalProtect App does not know what FQDN the user may make an HTTP request to. 

To work around this limitation, the `PanGPS` daemon monitors DNS traffic in real time and dynamically allowlists IP addresses (via the system extension) if a split tunnel domain is encountered.

For example, if the user tries to visit `foo.target.com` in their browser then the system will first try to resolve the domain `foo.target.com` using the system-configured DNS server (e.g. `8.8.8.8`). The GlobalProtect App will then allowlist the IP address that the DNS server responds with and all communication with `foo.target.com` from that point will bypass the VPN.

If, instead of using the system-configured DNS server, a hand-crafted request is made to an attacker-controlled DNS server, it was found that GlobalProtect still trusted the response, and allowlisted the IP address within the DNS response. By altering the IP included in this DNS response, it's possible to bypass the GlobalProtect VPN tunnel and gain egress to any arbitrary IP, and consequently an arbitrary domain, on the Internet.

Fundamentally this issue is a consequence of misplaced trust in DNS. Consider just a few of the core challenges:
* Unless speaking to the authoritative DNS server for a domain, how can you trust the response, especially when making a security decision like allowlisting traffic based on it?
* Even if the response appears to come from the authoritative DNS server, how can you trust it when using unauthenticated DNS (e.g. UDP/53)?
* Even if you could authenticate the DNS server and response (e.g. with DoH/DoT + DNSSEC), there still isn't a 1:1 mapping between domain and IP. For example, with [Cloudflare Anycast](https://www.cloudflare.com/en-gb/learning/cdn/glossary/anycast-network/), _any_ domain behind Cloudflare may resolve to the same IP. So configuring a wildcard domain for split tunneling could accidentally allow all Cloudflare-hosted domains through.

And that's before we even get into the fundamental architectural mismatch: VPNs operate at the Internet Layer (IP) but domain names operate within the Application Layer (DNS). So how do you reliably enforce an IP-based network boundary, using DNS-layer input, on an endpoint you don't fully trust?

In my opinion, by its very nature, this feature appears almost impossible to design securely, and remains exploitable to this day.

### Demonstrating the Attack

Two elements are needed to demonstrate the vulnerability:
1. An Internet-hosted, attacker-controlled, DNS server
2. A script run on the vulnerable endpoint to gain egress to an arbitrary Internet domain

To carry out the attack reliably, there are a few edge cases to consider. One involves the use of Anycast CDN networks, as mentioned earlier. These networks return different IP addresses depending on where a DNS query is made from geographically. As a result, even if the attacker-controlled DNS server queries the legitimate domain itself, it may not receive the same IP addresses that the victim machine would. 

To address this, our PoC implements a simple signalling protocol within the DNS request itself. The local script first resolves the target domain using the system DNS, then encodes the resulting IP addresses into a DNS query to the attacker-controlled server, using the following format:
```
[base64-encoded-IP-list].a.[allowlisted-domain]
```

The screenshot below shows this mechanism in action, in this case, tunnelling access to `example.com` by spoofing a response under an allowlisted wildcard domain:
![DNS-PoC-protocol](img/dns-spoofing-protocol.png)

Bringing it all together, the video below demonstrates how this technique is used to gain unrestricted access to `dropbox.com`, a domain that was explicitly blocked, by leveraging a split tunnel rule that allowed `*.zoom.us`.

<video controls muted style="margin: 2rem auto; display: block; border: 2px solid var(--border-color); border-radius: 8px;">
  <source src="vid/Split_tunnel_bypass_exploit_demo.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

The timer in the video above demonstrates that the target domain, or more precisely, its associated IPs, remained accessible even after the bypass script was stopped. This is because GlobalProtect respects the Time To Live (TTL) value in the DNS response, and will continue to allowlist the returned IPs for as long as the TTL dictates. Since the attacker controls the DNS server, they can set an artificially long TTL, effectively keeping the IPs unblocked indefinitely with just a single spoofed DNS lookup.

## Inter Process Communication (IPC) Hijacking

One of the areas we explored was the IPC between GlobalProtect components, a key boundary between unprivileged and privileged logic. Compromising this boundary could mean the ability to influence core VPN behaviour from a non-root context.

We identified the IPC channel used to facilitate communication between the privileged `PanGPS` daemon and the unprivileged `PanGPA` UI. Specifically, it was found that `PanGPS` sets up a TCP server listening on `localhost:4767`, as highlighted in the diagram below:
![IPC-server](img/ipc-server-communication.png)

If you look into the content sent over the channel it appears to be encrypted, although does seem to include a plaintext header, strongly suggesting some kind of custom or non-standard encryption routine is in use:
![Encrypted IPC communication](img/ipc-encrypted-communication.png)

### Weak Encryption Design

The specific details of the algorithm and keys involved, was determined through reverse engineering of `PanGPS` and is summarised in the diagram below:
![IPC Encryption Summary](img/ipc-encryption-summary.png)

Most critically, the key and initialisation vectors are not set, or stored, securely because:
* On MacOS the key is a secure random string but is stored in an insecure location of the local user's _Login_ keychain (which is accessible from the perspective of our our considered attacker, a low privileged user)
* On Linux the key is simply hardcoded and can be retrieved through decompilation of the `PanGPS` binary
* In both cases the initilisation vector is hardcoded and set to a predictable value of all zeros

While a process of encryption was in place, our analysis found it adds no real protection and does _nothing_ to protect the integrity or confidentiality of the IPC connection; a low privileged attacker can trivially decrypt the communication, or construct their own encrypted messages. 

### Forging Disconnect Requests

The impact of this weak encryption becomes most apparent when examining the messages sent by the 'disconnect' functionality in the UI. This feature typically requires a passcode set by the administrator, intended for use in edge cases (e.g. remote support when the VPN is broken), as shown below:

<video controls autoplay loop muted class="disconnect-demo" style="margin: 2rem auto; display: block; border: 2px solid var(--border-color); border-radius: 8px;">
  <source src="img/disconnect-loop-demo.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

If the correct key is entered, the following decrypted IPC message is observed:
```xml
<request>
<type>disable</type>
<user>Unknown</user>
<time>Tue Aug 27 02:59:09 2024</time>
<pid>1534</pid>
<reason>. Override(s)=2</reason>
</request>
```

Note that the key itself is not sent in the request (this should already be raising alarm bells about the design of the disconnect feature, more on that later). You might assume that an attacker could simply forge a disconnect message, encrypt it with the known algorithm, and send it to `PanGPS`, which would then dutifully disable the VPN and allow unrestricted Internet access.

Except… it's not quite that simple. Attempting this triggers a security control designed specifically to prevent such attacks:

![IPC Connection Security Control](img/ipc-security-control.png)

As highlighted above, if we monitor the `PanGPS.log` file whilst sending a forged disconnect command we see that it rejects the connection to the IPC server. It turns out there's a security control that does the following:
1. Determines which process initiated the connection to the IPC server on `localhost:4767`
2. Closes the connection if the process is not located inside: `/Applications/GlobalProtect.app/`

To perform this attack successfully we'll have to bypass this control.

### Bypassing the IPC Connection Control 

During the course of our research we found two different weaknesses in the control which allow you to bypass it in two rather different ways.

#### The Harder Way - Injecting a Legitimate-Looking Process into lsof Output

Reverse engineering `PanGPS` shows how it handles and attempts to authenticate new TCP connections to the IPC server:
1. Runs `lsof -i:4767` and extracts the process `pid` by:
    * Parsing the first non-header line of the output
    * Splitting by space delimiters to retrieve the second column (`pid`)
2. Uses the `proc_pidpath` system call to get the full path of the process from its `pid`
3. Verifies that the path starts with `/Applications/GlobalProtect.app/`

The biggest weakness lies in the first step, where the string output of a system command is parsed in a fairly crude way. If an attacker can manipulate the output such that a legitimate GlobalProtect process appears first in the `lsof` results, while their malicious process is hidden further down the list, the check can be bypassed.

The command `lsof -i :4767` returns _any_ process connected to, or listening on, port `4767` - regardless of the remote host. For example, if you run the command `nc portquiz.net 4767` (`portquiz.net` is a public host that listens on all TCP ports. This is used for testing, in reality any Internet-facing host listening on port `4767` could be used) and monitor the output of the `lsof` command the following is seen:
![nc to Internet host](img/ipc-netcat-portquiz-demo.png)

As highlighted by this demonstration it's possible to successfully inject a different process into the first line of `lsof :4767`. However, it would still not bypass the authentication logic because the path of the process would be `/usr/bin/nc` (in this case) which does not begin with `/Applications/GlobalProtect.app/`.

This demonstration can be extended further by exploiting the 'TCP redirection' feature of `bash` which allows you to redirect the output of any command to an internal, or external, host via TCP using a syntax of `[command] > /dev/tcp/host/port`. If we repeat the experiment above but this time redirect the output of a legitimate GlobalProtect binary (e.g. `/Applications/GlobalProtect.app/Contents/Resources/PanGpHipMp`) to an Internet facing host on port `4767` via `bash` the following is seen: 
![alt text](img/ipc-bash-tcp-redirect-demo.png)

In the demonstration above we have not only injected a different process into the first line, but a legitimate GlobalProtect process. The path of the process highlighted is `/Applications/GlobalProtect.app/Contents/Resources/PanGpHipMp` which begins with `/Applications/GlobalProtect.app/` as required. 

While the bash TCP redirect process is running, and the original `PanGPA` UI process stopped, the IPC authentication logic in PanGPS can be bypassed. If another process then connects to `localhost:4767` while the bash redirect is active, it would be further down the `lsof` output, and since `PanGPS` only checks the first line, it will find the bash redirect process (`PanGpHipMp` in the example) and validate its path, ignoring the later-connecting malicious process. This is demonstrated below:

![lsof bypass demo](img/ipc-lsof-bypass-demo.png)

As shown above the calling process `spoofedConnection` appears third in the `lsof` output but `PanGPS` only looks at the first which line which is a legitimate GlobalProtect binary `PanGpHipMp` (this binary was chosen as it takes around 30 seconds to complete which provides enough time to send a forged IPC command). 

Monitoring `PanGPS` logs during this period we see the following message confirming the bypass was successful: 
> `P77540-T13827 09/25/2024 13:32:05:209 Debug(  96): Connected by process from GP folder`

Combining this with the ability to forge the correct encrypted packets to send a 'Disconnect' command to `PanGPS`, we can bypass the VPN as a low privileged user, as shown in the video demo below: 

<video controls muted style="margin: 2rem auto; display: block; border: 2px solid var(--border-color); border-radius: 8px;">
  <source src="vid/CVE-2025-0135_IPC_Disconnect_Mac.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

#### The Easier Way - Exploiting Fail-Open Design

Getting deeper under the hood of the control, and understanding exactly _how_ the parsing of the ASCII output of the `lsof` command works, we find the following logic:
![isConnectedByPan Flowchart](img/ipc-connection-verification-flow.png)

As highlighted in the diagram, as well as the general fragility of parsing the ASCII output, the biggest security flaw lies in the way errors are handled. If _any_ of the various parsing steps fail then the verification passes. This is entirely at odds with the secure design principle of systems failing in a secure state. 

Knowing this, there's actually a simpler way to bypass the logic - just need need to find a way to get one of the steps to error. Consider what happens if we initiate the IPC connection from a process with a short process name, less than 9 characters:
1. Run `lsof -i :4767`:
![Parse lsof, short binary, step 1](img/ipc-short-process-step1.png)
2. Discard header line and read next line:
![Parse lsof, short binary, step 2](img/ipc-short-process-step2.png)
3. Read the text between the first two delimiters:
![Parse lsof, short binary, step 3](img/ipc-short-process-step3.png)

As shown above, the logic gets confused by the excess number of spaces, and pulls out an empty string `""` instead of the real `pid`. Now when the remaining logic is followed we have an issue:
![short_proc_4](img/ipc-short-process-step4.png)

You cannot convert an empty string to a number, so (as per the logic) it defaults to `0`. Then when trying to get the path of process with `pid == 0` this fails as no such process exists (process ids are always `>=1`). At this point the logic errors, as clearly seen by monitoring the `PanGPS.log` file:
![Short Process Name Error](img/ipc-short-process-error.png)

Again, combining this alternative approach with our ability to forge the correct encrypted packets to send a 'Disconnect' IPC command to `PanGPS`, we can bypass the VPN as a low privileged user, as shown in the video demo below: 

<video controls muted style="margin: 2rem auto; display: block; border: 2px solid var(--border-color); border-radius: 8px;">
  <source src="vid/CVE-2025-0135_IPC_Disconnect_Mac_Short_Binary.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

### What about Linux?

As mentioned, on the face of it, the Linux client works quite similarly to the MacOS one including components such as `PanGPS`, `PanGPA`, an IPC service listening on `localhost:4767` etc. However, attempting to send the same spoofed IPC disconnect command from a new, low-privileged process fails.

This is because the security control which checks the calling process works differently on Linux and was found (in our testing, anyway!) to be robust, and could not be bypassed. Again, by reversing PanGPS, we find that on Linux the control within `PanGPS` is using the `/proc` pseudo-filesystem to determine which process initiated a connection to its IPC server. 

This pseudo-filesystem does not exist on MacOS, only Linux, and using it, it is possible to accurately determine the calling process with relative ease, as shown in the example below: 
![Linux /proc pseudo-filesystem](img/linux-proc-filesystem.png)

Whilst this restricts the ability to send an IPC command from a new, attacker-controlled, process, the Linux security model opens a different path: spoof the IPC command not from an attacker-controlled binary, but from a legitimate PAN binary instead.

We can do this via [dynamic linker hijacking](https://attack.mitre.org/techniques/T1574/006/). On MacOS this attack path is essentially dead-in-the-water in most cases if you have the [Software Integrity Protection (SIP)](https://support.apple.com/en-us/102149) feature enabled (which you absolutely should!). In contrast, Linux, in general, does not have such a feature leaving it open to exploitation in most cases. The table below provides a summary of the differences between MacOS and Linux:
![Dynamic Linker Summary between MacOS and Linux](img/linux-dynamic-linker-comparison.png)

#### Exploiting LD_PRELOAD environment variable

By launching a legitimate PanGPA binary with `LD_PRELOAD` set to our own custom shared library, we are able to execute arbitrary code in the context of a legitimate GlobalProtect binary:
![LD_PRELOAD example attacker](img/linux-ld-preload-attack.png)

Whilst we could use this to do a range of malicious actions, one of the most impactful for our goal is to send an encrypted disconnect IPC command to `PanGPS`. The resulting disconnect command comes from the legitimate `PanGPA` binary and is indistinguishable from valid IPC traffic, allowing us to bypass the VPN, as shown in the video below:

<video controls muted style="margin: 2rem auto; display: block; border: 2px solid var(--border-color); border-radius: 8px;">
  <source src="vid/CVE-2025-0140_IPC_Disconnect_Linux.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

### The Real Problem

As alluded to earlier, the deeper issue lies in the design of the 'Disconnect' feature, which is fundamentally insecure by nature. This feature determines when to disconnect the VPN and includes an authorisation control, typically requiring a passcode from the system administrator.

The absence of the passcode in the resulting IPC message clearly shows that authorisation is handled only within `PanGPA` as shown below:
![Disconnect Control Trust Boundary](img/disconnect-trust-boundary-diagram.png)

In my opinion, as long as the decision is made by an unprivileged user-space process, on the wrong side of the trust boundary, an attacker will always have a way in and the integrity of the GlobalProtect VPN cannot be guaranteed.

To really drive this point home, here's a video showing yet another way to bypass this control - this time by simply modifying `PanGPA`'s local configuration file:

<video controls muted style="margin: 2rem auto; display: block; border: 2px solid var(--border-color); border-radius: 8px;">
  <source src="vid/CVE-2025-0140-Weak-Perms-GPA-Settings-Manual.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

Any low-privileged attacker who can undermine this control can effectively bypass administrator intent and break the "always-on" VPN model that GlobalProtect markets itself on.

## Privilege Escalation via SUID Binary

As previously mentioned, the `PanGPS` daemon runs as `root` in order to have the privileges to setup VPN tunnels etc. One key difference we noticed early on between MacOS and Linux is the permission set on this binary. In MacOS `PanGPS` has the Set User ID (SUID) bit set, as shown below:
```
> ls -l /Applications/GlobalProtect.app/Contents/Resources/PanGPS
-rwsr-xr-x  1 root  wheel  15607248  9 Jun 22:03 /Applications/GlobalProtect.app/Contents/Resources/PanGPS
```

The SUID bit indicates that the binary should be executed as `root` even if started by a low-privileged user. This pattern makes it vulnerable to attacks such as modifying the environment variables such as `$PATH` to escalate privileges on the local machine. In many ways this pattern is considered legacy, for example, with many operating system maintainers making active efforts to restrict the use of SUID binaries and providing more secure ways for applications to obtain more fine-grained privileges, if and when they require them. 

It appears that, for GlobalProtect this pattern was chosen in order to allow `PanGPS` to be launched automatically at login via a Launch Agent, in the context of the local user. It seems unclear why the maintainers didn't instead choose to use a Launch Daemon though which is better suited to this task, and wouldn't require security sacrifices such as the SUID bit. You can find more information on Launch Agents or Daemons [here](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

In any case, having discovered this, it became an obvious place to look as a means to exploit GlobalProtect to escalate privileges on the machine.

### Exploiting Environment Variables

As mentioned, environment variables are the most obvious means to exploit SUID binaries for privilege escalation as they affect the behavior of the binary (which will run as `root`) but are in the direct control of the low-privileged user. 

The first environment variable we attempted to exploit was the `$PATH`, which controls where the system looks for executables when a program invokes another command without specifying its full path.  For example, if a binary runs `cp` rather than `/bin/cp`, the system will search through each directory in `$PATH` until it finds a matching executable.  An attacker could abuse this by placing a malicious `cp` binary in a directory they control and manipulating `$PATH` so that their version is found first. allowing arbitrary code execution with elevated privileges.

An example attack would therefore involve running something like this as a low privileged user:
![Example PATH Variable Abuse](img/path-variable-attack-example.png)

This attack didn't work, when launching `PanGPS` this way, we see an error in the console output as highlighted below:
![Path Abuse PanGPS Error](img/path-variable-attack-error.png)

It turns out there's yet another security control, and again PAN have considered this specific attack vector and incorporated a security control to try prevent it. In fact there were two controls to cover this attack which we uncovered through reverse engineering.

Firstly, there's a control which determines which process launched `PanGPS` as a means to prevent the SUID abuse I described earlier. This control works as follows:
1. `PanGPS` determines which process started to it. 
2. Terminate the `PanGPS` process if not launched by `/sbin/launchd`

Secondly, it turns out there's a control specifically designed to prevent abuse of the `$PATH` variable in particular, by hardcoding this variable to a set of trusted locations an attacker cannot control:
![Sanitisation of PATH Environment Variable](img/path-variable-sanitization.png)

Again, to perform this attack successfully we'll have to bypass these controls.

### Bypassing the Parent Process Check

The following is a psuedo-code representation of the security control, derived from decompiling the `PanGPS` binary:
![CheckProcessName Function](img/process-name-verification.png)

The control works by:
1. Get the `pid` of the parent process that launched `PanGPS`
2. Obtain the full path from this `pid` using the unix `ps` command 
3. Check that full path is equal to `/sbin/launchd`

As highlighted in the pseudo-code representation of the `CheckProcessName` function, a key weakness lies in its use of the `ps` command. Specifically, `ps` determines the process name or path by inspecting the first element of the `argv` array for the given process, a value that can be arbitrarily controlled by the process itself.

We can bypass this check by writing our own custom wrapper which will launch `PanGPS` after having changed the value of `argv[0]` to `/sbin/launchd`, which we can do as long as the real path of the wrapper is at least 13 bytes long (the length of `/sbin/launchd`) so there's enough space to overwrite it. An example wrapper function is shown below:
![PanGPS wrapper source code](img/argv-overwrite-bypass.png)

The screenshot below shows `PanGPS` being launched via our wrapper, alongside a small test program that replicates the behavior of `CheckProcessName`. Together, they confirm that the wrapper successfully bypasses the check, allowing `PanGPS` to be launched from an arbitrary, user-controlled process:  
![PanGPS wrapper execution](img/process-wrapper-bypass.png)

### Finding an Exploitable Environment Variable

Now that we can launch the process, the next step is to identify an environment variable that can actually be exploited to escalate privileges. Unfortunately, `$PATH` is off the table due to the other protections in place.

A promising lead comes from decompiling `PanGPS` and searching for uses of the `getenv` function, a common way programs read environment variables.

This reveals functions like the one below:
![ossl_safe_get_env](img/openssl-environment-function.png)

This particular function appears designed to defend against abuse of `OPENSSL`-related environment variables. Specifically, it restricts the evaluation of variables like `OPENSSL_CONF` and `OPENSSL_ENGINE` to cases where the program is executed directly by the `root` user and not when it is launched by a regular user (as a SUID binary).

#### Abusing OPENSSL_CONF

Looking deeper into the purpose of `OPENSSL_CONF`, the security risk becomes clearer. `OPENSSL_CONF` is an environment variable that accepts a path to a custom OpenSSL configuration file, like the example below:
![Example custom OPENSSL configuration file](img/openssl-configuration-example.png)

For more information see the OpenSSL docs [here](https://docs.openssl.org/3.1/man5/config/#environment).

As shown above, this can include a custom _engine_, which is effectively custom binary that will be executed when the `OPENSSL` library is used. This _engine_ can be attack controlled, which is precisely why the use of  `OPENSSL_*` environment variables is restricted (via `ossl_safe_get_env` function) to prevent privilege escalation.

OpenSSL itself has also considered this attack path and includes a built-in safeguard, as shown in the official docs:
![OPENSSL_CONF documentation](img/openssl-documentation.png)

I say all this to emphasise: this attack should not work. OpenSSL has a defense. `PanGPS` has a defense. The conditions for exploitation _should_ be blocked.

But... curiously this is what happens when we try it:
<video controls muted style="margin: 2rem auto; display: block; border: 2px solid var(--border-color); border-radius: 8px;">
  <source src="vid/CVE-2025-0141-Mac-SUID-PE.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

#### Why did this work?

Both the protections inside OpenSSL and `PanGPS` rely on answering a simple question:
* Was this binary launched with elevated privileges via SUID?

In Unix-like systems, this is typically determined by comparing the real and effective user IDs, as summarised below:

| Concept | Value in a typical SUID binary |
|---------|-------------------------------|
| UID (Real UID) | The user who launched the binary (e.g. you) |
| EUID (Effective UID) | The owner of the binary: typically root if it's a SUID root binary |

Looking again at the high-level architecture of GlobalProtect, and considering the values of these IDs at various different parts of the execution chain, it becomes clearer why the attack worked:
![[GP Architecture and values of UID and EUID]](img/uid-euid-architecture-diagram.png)

From the perspective of code running within `PanGPS`, the binary was indeed launched via SUID (because `UID != EUID`). However, for code running within `PanGPHipMP`, the binary appears to be launched directly by `root` (because `UID == EUID == 0`).

The OpenSSL library is used by multiple GlobalProtect binaries, and in this case, the privilege escalation occurred within`PanGPHipMP`, not `PanGPS`. Crucially, the environment variables set before launching `PanGPS` are inherited throughout the execution chain, enabling the attack despite individual protections.

#### The Real Problem

The fundamental design issue here is one of least privilege. Granting `PanGPS` the SUID bit gives it unnecessary and is excessive privilege, dramatically expanding the attack surface of the system.

Despite layered protections, both in `PanGPS` and OpenSSL, they proved insufficient, illustrating a key security principle: you can't patch around bad design. Defensive layers are important, but if the foundational trust boundaries are flawed, vulnerabilities will inevitably emerge.

A more robust approach might be to run `PanGPS` as a macOS Launch Daemon, where privilege can be granted more selectively and in line with the intended execution model. Without full insight into all the architectural constraints, it's hard to say definitively but, based on the risks demonstrated here, this seems like a worthwhile direction for PAN to explore, if they haven't already.

## Patching, Disclosure, and What Went Wrong

As described in the summary at the beginning, these vulnerabilities were reported to PAN between April and October 2024, and patched in July 2025. 

As the fixes were released, we retested the issues using our original proof-of-concept code included in our vulnerability reports.

In two case (CVE-2025-0135 and CVE-2025-2179) we found the initial patches to be ineffective. These issues were later repatched following further coordination. We'll explore one of these failed fixes in more detail in the next section.

Another interesting aspect of the disclosure process was learning that some vulnerabilities also affected platforms we hadn't tested including the Windows client. It was encouraging to see PAN take a broader view during remediation and apply fixes more widely where appropriate. It was also rewarding to see our work lead to wider security improvements across multiple platforms.

### CVE-2025-0135 - The Ineffective Patch

CVE-2025-0135 addressed the forged IPC disconnect for macOS. As a reminder, exploiting this vulnerability required bypassing the security control shown below:

| Defensive Control | Bypass Technique |
|-------------------|------------------|
| `lsof` check | ✅ Fooled by Bash redirection or short binary |

However, during retesting, we discovered that this defensive check wasn't strengthened, it was removed entirely. As a result, _any_ process could now send a forged disconnect message, without needing bypass any controls.

We were curious why this happened, and reverse engineered the patched binary to understand more. Below is a flowchart representation of the new `isConnectedByPan(clientPort)` implementation (where `clientPort` is the ephemeral port of the client connecting to the IPC server):
![isConnectedByPan new implementation](img/ipc-connection-verification-patched.png)

The key bug is highlighted in red.

To explain the problem more clearly, we need to consider the values of the local and remote ports from both sides of the connection, as shown in the diagram below:
![Local and remote ports for PanGPS IPC connection](img/ipc-port-comparison-diagram.png)

Walking through the flowchart, and focusing on the flawed logic, highlighted in red on the diagram:
* `local port == 4767?` -  ✅ true for `PanGPS`
* `remote port == clientPort?` - ✅ also true for `PanGPS`

In other words, the verification logic is checking the wrong side of the connection. It always ends up identifying `PanGPS` itself (a trusted PAN binary) and therefore the check _always_ passes.

## Final Thoughts

I'd like to thank the security team at PAN for taking the majority of the vulnerability reports seriously, and for working with the application teams to apply patches which, based on our testing, appear robust. One reported issue (related to wildcard domain matching) was ultimately not patched, but we believe it remains a valid concern and hope it will be revisited by PAN in future.

GlobalProtect, like any endpoint software, security-related or otherwise, has an attack surface and a threat model.  As an enterprise VPN product, it includes components that run with elevated privileges, inherently increasing its risk profile. That makes secure design and robust application security even more critical.

Our research suggests that some of the foundational design decisions in the GlobalProtect client may have fallen short. For example: granting too much control to user-space processes, failing to enforce privilege boundaries, and relying on bolt-on checks rather than structural safeguards. 

While the recent patches do appear more robust, in some cases they still don't fully address the root causes. Hopefully, the examples we've shown reinforce a simple truth: bad design can't just be patched, it needs to be rebuilt.

That said, these issues aren't unique to GlobalProtect. Any software installed on an endpoint, especially with elevated privileges, adds to the system's attack surface and could potentially undermine its security.

As system administrators and security professionals, it's our responsibility to stay conscious of this. Security software is still just software and like any other, it's not immune to flaws or unintended consequences. We can mitigate this risk by understanding what a tool does, what privileges it requires, and where it's deployed; balancing its defensive value against its potential to introduce new vulnerabilities.

For example, do you _really_ need multiple endpoint security tools running on a backend database server? What's the likelihood that an attacker reaches that server undetected, versus the risk of disruption or exploitation if that software misbehaves or introduces new vulnerabilities itself?

In many cases, such systems are already heavily restricted by firewalls, network segmentation, and access controls, and relying on those well-established layers of defence _may_ be more effective than introducing additional complex, privileged software with its own risks. When it comes to security tooling, more isn’t _always_ better. It’s about deploying the right tools in the right places, with a clear understanding of their trade-offs.

And finally, if you have questions, want to collaborate, or are interested in working together to secure your systems or products, [get in touch](https://alexbourla.com/#contact).
