# SSBlocker - Super Simple Blocker

**Super Simple Blocker** is fail2ban/denyhost/sshguard like script that scans log file and blocks offending IP.
It's short simple script but it supports

- **Easy and flexible config file**
- **Usable with any service logs and firewall commands**
- **Custom attack count/detection time thresholds**
- **Block time throttling**
- **Unblocking**
- **While list**
- **Complex rule by scripting (Rules can be PHP functions)**
- **Command scripting (CMD_INIT/BLOCK/UNBLOCK/REPORT can be PHP functions)**
- **Log file rotation (SSBlocker has loose rotation detection. Use HUP signal to reopen log file for precise detection)**
- **Internal stat dump**

Homepage:

- <https://github.com/yohgaki/ssblocker/>

## Rationale

SSBlocker alternatives are too complex and/or aren't suitable for custom service blocking. e.g. Web applications. SSBlocker uses simple PCRE regex and rule to scan log files and block attacks according to how attackers attacks.

Modern secure web applications should have proper attack monitoring and preventions. Fail2ban/denyhost/sshguard are not suitable for this.

- <https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/>
- <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/>

Web developers may simply log attacks in their web apps and let SSBlocker to block attackers. This is easy with SSBlocker even when you have distributed traffic.

Note: For web application, it is not good idea to block IP forever. You may block many legitimate users behind behind firewall.

## Requirement

- Requires basic PHP command line binary only.
- Requires only 2 files (a script and config)

## Installation & Usage (Short Version)

If your system has sshd, git, PHP, journald and iptables, following would work for sshd.

1. **Clone repo to "`/etc/ssblocker`"**
2. **`cd /etc/ssblocker; ln -s ssblocker ssblocker-sshd; ln -s ipv4-iptable.cfg/ssblocker-sshd.cfg`**
3. **`journalctl -u sshd -f | ./ssblocker-sshd`**

Try to login with invalid user 4 times from remote host, then you should be blocked. (Make sure you don't block yourself!) Try "`iptables -L`" to see you are blocked.

SSBlocker is no more than a log scanner that executes commands for matching rule. It does not have any command line options.

## Installation & Usage (Long Version)

SSBlocker scans log files. It does not have command capability. There are only 2 usages:

```bash
tail -f /path/to/log | ssblocker
```

OR

```bash
ssblocker /path/to/log
```

PHP command line is required. Install PHP if it is needed.

### Alpine Linux

```bash
apk add php80 php80-pcntl
```

### Fedora (or like)

```bash
dnf install php-cli
```

PCNTL module is builtin.

### Setup

   1. **Place SSBlocker script to standard location.**

       e.g. `/usr/local/bin/ssblocker`

   2. **Create symlinks to ssblocker for each service.**

       e.g. `ln -s ssblocker ssblocker-ipv4-sshd`

   3. **Edit RULES in .cfg. Place it to /etc/ssblocker/, /etc/, /usr/local/etc/ or .**

       e.g. `cp sshblocker-ipv4-sshd.cfg /etc/ssblocker-ipv4-sshd.cfg; vi /etc/ssblocker-ipv4-sshd.cfg`
        See ssblocker-example.cfg and *.cfg dir

   4. **Execute `ssblocker-log-type /path/to/log` OR `cat /path/to/log | ssblocker-log-type`**

       e.g. `ssblocker-ipv4-sshd /var/log/sshd.log` OR `journalctl -u sshd -f | ssblocker-ipv4-sshd`

See ssblocker-example.cfg file for configuration. See *.cfg directory for usable configurations.

### Tips

It is recommended to create dedicated firewall chain, e.g. create `ssblocker_sshd` and `ssblocker_sqmail_smtpd` iptables chain, so that you can distinguish what service blocked which IP. This also prevents multiple blocking rule evaluation which is  waste of resource.

If you have reverse proxy, use SSBlocker on proxy. Never try to use SSBlocker on web server if there is reverse proxy. If you have to execute SSBlocker on web server, you may send command to reverse proxy so that it can block traffic. If traffic is distributed by reverse proxy, you'll need a manager app.

Since you may have as many SSBlocker as you want, I recommend you to have dedicated SSBlocker for each service you are monitoring.

### SSBlocker log

SSBlocker log will look like:

```text
PCNTL enabled
Use USR1 to dump internal status.  i.e. kill -USR1 `cat /var/run/ssblocker-qmail-submission.pid`
Use HUP to reopen log file.  i.e. kill -HUP `cat /var/run/ssblocker-qmail-submission.pid`
2022-09-19T11:13:20+00:00 SSBlocker (ssblocker-qmail-submission) start blocking attacker IP
2022-09-19T11:21:31+00:00 Attacked: @40000000632850c42bd80d6c qmail-smtpd: reject (auth not available without TLS): (null) from 34.226.152.180 to (null) helo ADMIN
2022-09-19T11:21:31+00:00 Rules and internal status: ssblocker-qmail-submission
2022-09-19T11:21:31+00:00 Blocked: 34.226.152.180 forever (Blocked: -1 times) (Active/Unlimited Blocks: 1/1)
2022-09-19T11:27:23+00:00 Attacked: @40000000632852251c562874 qmail-smtpd: reject (auth not available without TLS): (null) from 180.188.196.117 to (null) helo ADMIN
2022-09-19T11:27:23+00:00 Blocked: 180.188.196.117 forever (Blocked: -1 times) (Active/Unlimited Blocks: 2/2)
```

`Attacked:` line is attack log line. `Blocked:` line is SSBlocker message.

```text
Blocked: 180.188.196.117 forever (Blocked: -1 times) (Active/Unlimited Blocks: 2/2)
```

This line mean "SSBlocker blocked IP address 180.188.196.117 'forever'. '-1' blocked times means it is blocked forever. Active count is actively blocked IP. Unlimited count is number of IPs blocked forever.

## Executing at startup

Executing via local init script facility would be good enough for most users. If you have process supervisor, supervising SSBlocker is recommended.

### Alpine Linux (OpenRC)

Create something like this as /etc/local.d/ssblocker.start

```bash
#!/bin/sh
exec /etc/ssblocker/ssblocker-qmail-submission /var/log/qmail/submission/current  > /var/log/ssblocker-qmail-submission.log &
exec /etc/ssblocker/ssblocker-qmail-smtpd /var/log/qmail/smtpd/current  > /var/log/ssblocker-qmail-smtpd.log &
#exec /etc/issblocker/ssblocker-sshd /var/log/sshd.log  > /var/log/ssblocker-sshd.log &
```

Make sure "ssblocker-*"

NOTE: OpenRC can be process supervisor.

### Fedora (Systemd)

Enable rc.local compatibility.

```bash
systemctl enable rc-local
```

/etc/rc.local script is executed at system startup.

Execute ssblocker via pipe. For example,

```bash
journalctl -u sshd -f | ssblocker-ipv4-sshd &
```

## Trouble Shooting

If traffic isn't blocked, check firewall settings and SSBlocker BLOCK commands. Make sure BLOCK/UNBLOCK command actually block/unblock.

### TEST_MODE=true

If you set `TEST_MODE=true` in your cfg file, SSBlocker does not send CMD_BLOCK/UNBLOCK commands.

### DEBUG_MODE=true / DEBUG_MODE=num

If you set `TEST_MODE=true` in your cfg file, some debug output is enabled. If you set `TEST_MODE=num` in you cfg file, for every `num` attack events, SSBlocker dumps internal status just like USR1 signal.

### USR1 Signal

When you pass log data as file to SSBlocker, internal status data is dumped with USR1 signal. You may try something like

```bash
kill -USR1 `cat /var/run/ssblocker-qmail-smtpd.pid`
```

You'll see something like this in SSBlocker log file for working configurations.

```php
# tail -f /var/log/ssblocker-qmail-smtpd.log
2022-09-25T19:53:09+00:00 Rules and internal status: ssblocker-qmail-smtpd
<?php
$time         = 1664135589;
$script       = 'ssblocker-qmail-smtpd';
$RULES        = array (
  '#qmail-smtpd: reject \\(auth not available.* from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) to#' => 
  array (
    0 => 1,
    1 => 7200,
  ),
  '#qmail-smtpd: read failed \\(connection closed by the client before the quit cmd\\): .* from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) to #' => 
  array (
    0 => 1,
    1 => 3600,
  ),
);
$ip_attacked  = array (
  '#qmail-smtpd: read failed \\(connection closed by the client before the quit cmd\\): .* from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) to #' => 
  array (
    '54.148.43.154' => 
    array (
      '1664930853.94' => '@40000000632fa52f31390554 qmail-smtpd: read failed (connection closed by the client before the quit cmd): check@mx-check.com from 54.148.43.154 to postmaster@getyourbest.com helo mx-check.com
',
    ),
    '54.151.45.207' => 
    array (
      '1664930859.942' => '@40000000632fa53506d8385c qmail-smtpd: read failed (connection closed by the client before the quit cmd): check@mx-check.com from 54.151.45.207 to arpirastot_312@getyourbest.com helo mx-check.com
',
    ),
    '34.193.99.165' => 
    array (
      '1664930859.942' => '@40000000632fa535339e8404 qmail-smtpd: read failed (connection closed by the client before the quit cmd): check@mx-check.com from 34.193.99.165 to postmaster@getyourbest.com helo mx-check.com
',
    ),
    '54.241.255.94' => 
    array (
      '1664930862.9425' => '@40000000632fa53804bd7294 qmail-smtpd: read failed (connection closed by the client before the quit cmd): check@mx-check.com from 54.241.255.94 to arpirastot_312@getyourbest.com helo mx-check.com
',
    ),
    '52.52.62.254' => 
    array (
      '1664931845.1318' => '@40000000632fa90e0b148e34 qmail-smtpd: read failed (connection closed by the client before the quit cmd): check@mx-check.com from 52.52.62.254 to arpirastot_312@getyourbest.com helo mx-check.com
',
    ),
    '180.120.74.223' => 
    array (
      '1664932241.2132' => '@40000000632faa9a11920624 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 180.120.74.223 to mlil@lmbeeuv.me helo lmbeeuv.me
',
    ),
    '120.33.137.113' => 
    array (
      '1664934618.6562' => '@40000000632fb3e40c97712c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 120.33.137.113 to (null) helo unknown
',
    ),
    '152.32.197.89' => 
    array (
      '1664934737.6746' => '@40000000632fb45b16ce302c qmail-smtpd: read failed (connection closed by the client before the quit cmd): mksquq@eki-net.com from 152.32.197.89 to info@matsubara21.jp helo eki-net.com
',
    ),
    '220.173.190.172' => 
    array (
      '1664936273.9646' => '@40000000632fba5b1d6e996c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 220.173.190.172 to kjcortuq@oWL.@rakuten.co.jp helo oWL.@rakuten.co.jp
',
    ),
    '119.112.212.216' => 
    array (
      '1664937004.1124' => '@40000000632fbd3533fc0d54 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 119.112.212.216 to Sales88@hsdalexporting.com helo hsdalexporting.com
',
    ),
    '166.252.203.191' => 
    array (
      '1664937141.1391' => '@40000000632fbdbe2ad3091c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 166.252.203.191 to (null) helo 191.sub-166-252-203.myvzw.com
',
    ),
    '45.155.165.207' => 
    array (
      '1664938574.4238' => '@40000000632fc35816c6e8e4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 45.155.165.207 to (null) helo 3U0EEgyrWe
',
      '1664938597.4347' => '@40000000632fc36a0dc4ae5c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 45.155.165.207 to (null) helo ZOuQToDYc
',
    ),
    '103.92.36.187' => 
    array (
      '1664943571.3463' => '@40000000632fd6dc24e52ae4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 103.92.36.187 to (null) helo ip-103-92-36-187.metrasat.co.id
',
    ),
    '212.73.75.82' => 
    array (
      '1664946054.7932' => '@40000000632fe0901e0e05ec qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 212.73.75.82 to (null) helo unknown
',
    ),
    '179.40.18.220' => 
    array (
      '1664947217.0165' => '@40000000632fe51a27d764ec qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 179.40.18.220 to (null) helo 179-40-18-220.mrse.com.ar
',
    ),
    '137.220.180.41' => 
    array (
      '1664949061.3733' => '@40000000632fec4f06025e44 qmail-smtpd: read failed (connection closed by the client before the quit cmd): necia@kikou-plan.com from 137.220.180.41 to shigeo@ohgaki.net helo kikou-plan.com
',
    ),
    '93.43.28.43' => 
    array (
      '1664950263.6175' => '@40000000632ff100311e554c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 93.43.28.43 to (null) helo 93-43-28-43.ip90.fastwebnet.it
',
    ),
    '124.116.216.199' => 
    array (
      '1664950691.6625' => '@40000000632ff2ad1e7d59ec qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 124.116.216.199 to Sales62@piowexy.com helo piowexy.com
',
    ),
    '119.3.170.192' => 
    array (
      '1664950855.6864' => '@40000000632ff3502f4f908c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 119.3.170.192 to (null) helo ecs-119-3-170-192.compute.hwclouds-dns.com
',
    ),
    '182.113.197.101' => 
    array (
      '1664951258.7552' => '@40000000632ff4e339e893cc qmail-smtpd: read failed (connection closed by the client before the quit cmd): info@Amazon.co.jp from 182.113.197.101 to sales@matsubara21.jp helo Amazon.co.jp
',
    ),
    '37.25.35.99' => 
    array (
      '1664952103.9211' => '@40000000632ff830394dc6e4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 37.25.35.99 to (null) helo unknown
',
    ),
    '218.64.84.74' => 
    array (
      '1664953534.2172' => '@40000000632ffdc802f57c04 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 218.64.84.74 to (null) helo 74.84.64.218.broad.ja.jx.dynamic.163data.com.cn
',
    ),
    '106.110.195.149' => 
    array (
      '1664953785.2671' => '@40000000632ffec304205bbc qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 106.110.195.149 to (null) helo t9J9qsp1UD
',
      '1664953847.2819' => '@40000000632ffefc1da92d84 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 106.110.195.149 to (null) helo IUo9JT
',
    ),
    '79.110.62.169' => 
    array (
      '1664955666.6335' => '@400000006330061c0a58d784 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 79.110.62.169 to (null) helo noh0PG4k
',
      '1664955706.6402' => '@400000006330063f19e55f24 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 79.110.62.169 to (null) helo vxABMId
',
    ),
    '219.139.131.21' => 
    array (
      '1664956323.7425' => '@40000000633008ad1ad5fccc qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 219.139.131.21 to (null) helo unknown
',
    ),
    '94.28.56.54' => 
    array (
      '1664956564.7924' => '@400000006330099d39f6f764 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 94.28.56.54 to (null) helo unknown
',
    ),
    '193.239.164.108' => 
    array (
      '1664956822.8509' => '@4000000063300aa02436977c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 193.239.164.108 to (null) helo iTFRCA0wL
',
      '1664957049.8985' => '@4000000063300b7e3af33984 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 193.239.164.108 to (null) helo 5F3pUkVm
',
      '1664999254.1547' => '@400000006330b05a2ee58034 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 193.239.164.108 to (null) helo yKiX6bv
',
    ),
    '125.143.53.1' => 
    array (
      '1664958214.1314' => '@400000006330100f2ccf0414 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 125.143.53.1 to (null) helo unknown
',
      '1664992452.7872' => '@40000000633095cd3138b34c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 125.143.53.1 to (null) helo unknown
',
    ),
    '121.32.183.25' => 
    array (
      '1664958831.2506' => '@40000000633012782b62318c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 121.32.183.25 to Sales.6@dokhfiuvjhd.com helo dokhfiuvjhd.com
',
    ),
    '103.39.222.129' => 
    array (
      '1664965448.5629' => '@4000000063302c52067799fc qmail-smtpd: read failed (connection closed by the client before the quit cmd): sales04@xmrontage.ink from 103.39.222.129 to info@es-i.jp helo xmrontage.ink
',
    ),
    '112.192.34.227' => 
    array (
      '1664967875.0018' => '@40000000633035cc1ba90ff4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 112.192.34.227 to (null) helo unknown
',
    ),
    '195.133.159.15' => 
    array (
      '1664969376.3203' => '@4000000063303ba9187f917c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 195.133.159.15 to (null) helo unknown
',
    ),
    '172.20.0.1' => 
    array (
      '1664969560.3574' => '@4000000063303c613aa84604 qmail-smtpd: read failed (connection closed by the client before the quit cmd): youremail@gmail.com from 172.20.0.1 to adrao03ue09ko6@outlook.com helo www.provesolution.com
',
    ),
    '183.223.170.211' => 
    array (
      '1664972849.9807' => '@400000006330493b220b33cc qmail-smtpd: read failed (connection closed by the client before the quit cmd): Sales.28@resistor.com from 183.223.170.211 to info@es-i.jp helo resistor.com
',
    ),
    '114.228.21.174' => 
    array (
      '1664974615.3383' => '@40000000633050201a8d66c4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): uwrpihhwt@ymh.org from 114.228.21.174 to shigeo@ohgaki.net helo ymh.org
',
    ),
    '103.240.103.141' => 
    array (
      '1664974617.3387' => '@400000006330502216b42c04 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 103.240.103.141 to (null) helo microsenseindia.net
',
    ),
    '171.114.170.143' => 
    array (
      '1664975728.5675' => '@400000006330547a1520a73c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 171.114.170.143 to (null) helo unknown
',
      '1664975728.5677' => '@400000006330547a1580342c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 171.114.170.143 to (null) helo unknown
',
    ),
    '121.233.45.245' => 
    array (
      '1664977727.9364' => '@4000000063305c490f58852c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 121.233.45.245 to (null) helo unknown
',
      '1664977841.9607' => '@4000000063305cbb358c4a44 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 121.233.45.245 to (null) helo unknown
',
    ),
    '103.140.104.211' => 
    array (
      '1664978320.0578' => '@4000000063305e9938c495cc qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 103.140.104.211 to (null) helo 211-104-140-103.inetindo.net.id
',
    ),
    '114.225.253.166' => 
    array (
      '1664979487.2826' => '@40000000633063282ec57ce4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 114.225.253.166 to nzty@skdxbegdq.cn helo skdxbegdq.cn
',
    ),
    '122.239.145.5' => 
    array (
      '1664981560.6676' => '@4000000063306b4207fd288c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 122.239.145.5 to evt@dvzwhqxft.com helo dvzwhqxft.com
',
    ),
    '185.236.217.129' => 
    array (
      '1664984013.1546' => '@40000000633074d62046eaa4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 185.236.217.129 to (null) helo ip-129.217.236.185.azinet.ru
',
    ),
    '24.97.253.246' => 
    array (
      '1664985287.4179' => '@40000000633079d1070c38dc qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 24.97.253.246 to (null) helo rrcs-24-97-253-246.nys.biz.rr.com
',
    ),
    '175.148.78.220' => 
    array (
      '1664985814.531' => '@4000000063307be0094632ec qmail-smtpd: read failed (connection closed by the client before the quit cmd): uuwy@gmail.com from 175.148.78.220 to info@matsubara21.jp helo gmail.com
',
    ),
    '195.133.157.239' => 
    array (
      '1664987675.871' => '@40000000633083251b84ea0c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 195.133.157.239 to (null) helo unknown
',
    ),
    '175.175.222.243' => 
    array (
      '1664988145.9673' => '@40000000633084fb14c0c45c qmail-smtpd: read failed (connection closed by the client before the quit cmd): lwgqg@hotmail.com from 175.175.222.243 to yasuo.ohgaki@es-i.jp helo hotmail.com
',
    ),
    '112.113.241.207' => 
    array (
      '1664991942.6912' => '@40000000633093cf2d1e0e74 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 112.113.241.207 to (null) helo unknown
',
    ),
    '103.184.105.254' => 
    array (
      '1664992040.7067' => '@400000006330943224e142e4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 103.184.105.254 to (null) helo unknown
',
    ),
    '61.183.232.62' => 
    array (
      '1664996564.6198' => '@400000006330a5de1b1386b4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 61.183.232.62 to (null) helo unknown
',
    ),
    '137.220.180.66' => 
    array (
      '1664997048.6856' => '@400000006330a7c21633d48c qmail-smtpd: read failed (connection closed by the client before the quit cmd): ufdrwsj@kikou-plan.com from 137.220.180.66 to shigeo@ohgaki.net helo kikou-plan.com
',
    ),
    '14.162.12.221' => 
    array (
      '1664997394.7501' => '@400000006330a91c24c5d75c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 14.162.12.221 to sqnfc@ezr2000plus.com helo 2883ca6195517b74872d64cf2aae848ef430d5
',
    ),
    '219.141.207.183' => 
    array (
      '1664997410.7538' => '@400000006330a92c14d8e424 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 219.141.207.183 to sqnfc@ezr2000plus.com helo 2883ca6195517b74872d64cf2aae848ef430d5
',
    ),
    '189.56.184.189' => 
    array (
      '1664997430.7598' => '@400000006330a93f31254a8c qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 189.56.184.189 to (null) helo 189-56-184-189.customer.tdatabrasil.net.br
',
    ),
    '114.97.92.240' => 
    array (
      '1664998059.8972' => '@400000006330abb52c02f9b4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): (null) from 114.97.92.240 to (null) helo unknown
',
    ),
    '113.229.58.89' => 
    array (
      '1664998640.0241' => '@400000006330adf93a4f641c qmail-smtpd: read failed (connection closed by the client before the quit cmd): ahnkeprg@gmail.com from 113.229.58.89 to sales@matsubara21.jp helo gmail.com
',
    ),
    '123.188.37.39' => 
    array (
      '1664998681.0311' => '@400000006330ae22105b62b4 qmail-smtpd: read failed (connection closed by the client before the quit cmd): hv@gmail.com from 123.188.37.39 to yohgaki@ohgaki.net helo gmail.com
',
    ),
    '137.220.181.250' => 
    array (
      '1664999009.102' => '@400000006330af6a2052dd3c qmail-smtpd: read failed (connection closed by the client before the quit cmd): ybkttzfegs@kikou-plan.com from 137.220.181.250 to yohgaki@ohgaki.net helo kikou-plan.com
',
    ),
  ),
  '#qmail-smtpd: reject \\(auth not available.* from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) to#' => 
  array (
    '162.144.93.133' => 
    array (
      '1664931544.0744' => '@40000000632fa7e135bec80c qmail-smtpd: reject (auth not available): (null) from 162.144.93.133 to (null) helo ADMIN
',
      '1664934071.5803' => '@40000000632fb1c11c52251c qmail-smtpd: reject (auth not available): (null) from 162.144.93.133 to (null) helo ADMIN
',
      '1664941679.9806' => '@40000000632fcf790ad1dfe4 qmail-smtpd: reject (auth not available): (null) from 162.144.93.133 to (null) helo ADMIN
',
      '1664956646.8086' => '@40000000633009f00427d9b4 qmail-smtpd: reject (auth not available): (null) from 162.144.93.133 to (null) helo ADMIN
',
      '1664986912.7153' => '@400000006330802a1099522c qmail-smtpd: reject (auth not available): (null) from 162.144.93.133 to (null) helo ADMIN
',
    ),
    '185.239.242.40' => 
    array (
      '1664932757.3173' => '@40000000632fac9f0f0f3f5c qmail-smtpd: reject (auth not available): (null) from 185.239.242.40 to (null) helo User
',
      '1664939869.6514' => '@40000000632fc8662b7addf4 qmail-smtpd: reject (auth not available): (null) from 185.239.242.40 to (null) helo User
',
      '1664954108.3382' => '@4000000063300005309e2cb4 qmail-smtpd: reject (auth not available): (null) from 185.239.242.40 to (null) helo User
',
      '1664968827.2019' => '@400000006330398224d5e4bc qmail-smtpd: reject (auth not available): (null) from 185.239.242.40 to (null) helo User
',
    ),
    '45.155.165.168' => 
    array (
      '1664936381.9853' => '@40000000632fbac72121dd6c qmail-smtpd: reject (auth not available): (null) from 45.155.165.168 to (null) helo User
',
      '1664937673.2436' => '@40000000632fbfd23459aa2c qmail-smtpd: reject (auth not available): (null) from 45.155.165.168 to (null) helo User
',
      '1664953253.1552' => '@40000000632ffcaf04dbeb5c qmail-smtpd: reject (auth not available): (null) from 45.155.165.168 to (null) helo User
',
      '1664968822.1956' => '@400000006330397f34c15d0c qmail-smtpd: reject (auth not available): (null) from 45.155.165.168 to (null) helo User
',
    ),
    '45.155.165.207' => 
    array (
      '1664938574.4236' => '@40000000632fc3580666e0bc qmail-smtpd: reject (auth not available): (null) from 45.155.165.207 to (null) helo 3U0EEgyrWe
',
      '1664938592.428' => '@40000000632fc3693a4ddd7c qmail-smtpd: reject (auth not available): (null) from 45.155.165.207 to (null) helo ZOuQToDYc
',
    ),
    '106.110.195.149' => 
    array (
      '1664953785.2669' => '@40000000632ffec231231bf4 qmail-smtpd: reject (auth not available): (null) from 106.110.195.149 to (null) helo t9J9qsp1UD
',
      '1664953842.2798' => '@40000000632ffefc0ff79fa4 qmail-smtpd: reject (auth not available): (null) from 106.110.195.149 to (null) helo IUo9JT
',
    ),
    '79.110.62.169' => 
    array (
      '1664955666.6333' => '@400000006330061b31ff4354 qmail-smtpd: reject (auth not available): (null) from 79.110.62.169 to (null) helo noh0PG4k
',
      '1664955701.6382' => '@400000006330063f0ae59aac qmail-smtpd: reject (auth not available): (null) from 79.110.62.169 to (null) helo vxABMId
',
    ),
    '193.239.164.108' => 
    array (
      '1664956822.8508' => '@4000000063300a9f3873705c qmail-smtpd: reject (auth not available): (null) from 193.239.164.108 to (null) helo iTFRCA0wL
',
      '1664957044.8921' => '@4000000063300b7d37f416cc qmail-smtpd: reject (auth not available): (null) from 193.239.164.108 to (null) helo 5F3pUkVm
',
      '1664999249.1526' => '@400000006330b05a1e630f74 qmail-smtpd: reject (auth not available): (null) from 193.239.164.108 to (null) helo yKiX6bv
',
    ),
  ),
);
$ts_unblock   = array (
  '1664149649.1526' => '193.239.164.108',
  '1664180512.7153' => '162.144.93.133',
);
$ip_blocked   = array (
  '162.144.93.133' => 3,
  '45.155.165.168' => 2,
  '45.155.165.207' => 0,
  '185.239.242.40' => 2,
  '106.110.195.149' => 0,
  '79.110.62.169' => 0,
  '193.239.164.108' => 1,
  '171.114.170.143' => 0,
  '121.233.45.245' => 0,
  '125.143.53.1' => 0,
);
$ip_managed   = array (
  '162.144.93.133' => 
  array (
    0 => '2022-09-25T16:21:52+00:00',
    1 => '@400000006330802a1099522c qmail-smtpd: reject (auth not available): (null) from 162.144.93.133 to (null) helo ADMIN
',
  ),
  '193.239.164.108' => 
  array (
    0 => '2022-09-25T19:47:29+00:00',
    1 => '@400000006330b05a1e630f74 qmail-smtpd: reject (auth not available): (null) from 193.239.164.108 to (null) helo yKiX6bv
',
  ),
);
$ip_unmanaged = array (
);
$ip_attacked_cnt  = 153;
$ts_unblock_cnt   = 2;
$ip_managed_cnt   = 6;
$ip_unmanaged_cnt = 0;
$block_cnt        = 18;
$unmanaged_cnt    = 0;
$attack_cnt       = 87;
$num_lines        = 11685;
# Memory usage: 543.29KB
$memory           = 543288;
# Memory peak usage: 584.25KB
$memory_peak      = 584248;
?>

```

You should see SSBlocker chain(s) as a first rule for INPUT. SSBlocker chain rule target should be DROP.

```text
/etc/ssblocker# iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ssblocker_dovecot_pop3  all  --  anywhere             anywhere            
ssblocker_qmail_smtpd  all  --  anywhere             anywhere            
ssblocker_qmail_submission  all  --  anywhere             anywhere            

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         

Chain ssblocker_dovecot_pop3 (1 references)
target     prot opt source               destination         

Chain ssblocker_qmail_smtpd (1 references)
target     prot opt source               destination         
DROP       all  --  193.239.164.108      anywhere            
DROP       all  --  vps.alsharq.co.ke    anywhere            

Chain ssblocker_qmail_submission (1 references)
target     prot opt source               destination         
DROP       all  --  tend.zvknice.com     anywhere            
DROP       all  --  20.65.115.67         anywhere            
DROP       all  --  20.225.148.16        anywhere            
DROP       all  --  81.161.229.129       anywhere            
DROP       all  --  tabatic.org.uk       anywhere            
DROP       all  --  104.81.74.97.host.secureserver.net  anywhere            
DROP       all  --  146.56.141.40        anywhere            
DROP       all  --  mail.tuanagrupmobilya.com.tr  anywhere            
DROP       all  --  ip121.ip-149-202-8.eu  anywhere            
DROP       all  --  ec2-34-226-152-180.compute-1.amazonaws.com  anywhere          
```

## Bug Report

Please use github issue. Pull requests are appreciated, documentation fix and additional sample cfg especially.

Please post questions to online tech forums [Stack Overflow](https://stackoverflow.com/) , [Reddit](https://www.reddit.com/) , etc.

## License

MIT

## Author

Yasuo Ohgaki <yohgaki@ohgaki.net>
