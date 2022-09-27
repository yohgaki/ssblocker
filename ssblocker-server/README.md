# Sample SSBlocker server

SSBlocker client may use "report only" command. "Report only" may be used to send attack record to central SSBlocker server.

SSBlocker Server requires:

- SSBlocker Server script (ssblocker-server.php)
- Config file (ssblocker-server.php in /etc/ssblocker:/etc/:.)
- ssblocker-block.sh amd ssblocker-unblock.sh in path
- SSBlocker clients

## Testing SSBlocker server

This sample does not have block/unblock script, so you can play with this as follows.

```bash
sudo touch /var/log/ssblocker-server.php.log
sudo chown <your_user_id> /var/log/ssblocker-server.php.log
php -S 127.0.0.1:8899
gnome-open http://127.0.0.1:8899/ssblocker-server.php?action=report&ip=192.168.100.60&rule=I1RFU1QgKFtcZC5dezcsMTV9KSM&line=VEVTVCAxOTIuMTY4LjEwMC42MCBhc2RiYXNkZmFzZGZhcw&salt=sadfas&info=1763895722-127.0.0.1-e0d4035ebf3812a5e04d08ba678b4334a013e080631a54463e7875e5cd4c9cb1&key=Ch/hljK4ExMM3Jqvg5m6VdYWRsX/ygiyF4kJSbFHP4g
```

SSBlocker server has several actions:

- Report: <http://127.0.0.1:8899/ssblocker-server.php?action=report>
- Status: <http://127.0.0.1:8899/ssblocker-server.php?action=stat>
- GC: <http://127.0.0.1:8899/ssblocker-server.php?action=gc>
- Clear: <http://127.0.0.1:8899/ssblocker-server.php?action=clear>
- IP: <http://127.0.0.1:8899/ssblocker-server.php?action=myip>

This sample SSBlocker server script only protect "report" action. You should protect other actions for production.

## Production use with IPTables

- Create ssblocker-server IPTable chain and insert it to INPUT chain.
- Write SUID ssblocker-block.sh/ssblocker-unblock.sh does blocking/unblocking.
- Modify ssblocker-server.php.cfg.
- Modify ssblocker client.cfg.

## Example SSBlocker SERVER configuration

```php
<?php
// Ssblocker server example config
const RULES = [
    '#Web App: Login failure from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})#'
        => [10, 3600],
    '#Web App: Authrization failure from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})#'
        => [10, 3600],
    '#TEST ([\d.]{7,15})#'
        => [4, 60],

];

const WHITE_LIST_IP    = ['172.20.0.1'];
const DETECT        = 86400*3;
const STATUS_DUMP   = false;
const LOG_TIMESTAMP = true;
const TEST_MODE     = false;
const DEBUG_MODE    = false;
const TRACK_UNMANAGED = true;

// const CMD_INIT      = 'iptables -N ssblocker_server > /dev/null 2>&1; iptables -D INPUT -j ssblocker_server > /dev/null 2>&1; iptables -I INPUT -j server';
const CMD_INIT      = ''; // Ignored. Should be initialized manually
const CMD_BLOCK     = 'ssblocker-block.sh %s';   // Safe SUID script does 'iptables -I ssblocker_server -s %s -j DROP'
const CMD_UNBLOCK   = 'ssblocker-unblock.sh %s'; // Safe SUID script does 'iptables -D ssblocker_server -s %s -j DROP'
const CMD_REPORT    = ''; // Ignored

const CMD_WAIT_SEC  = 5; // Ignored

const BLOCK_CNT_DEC = 3600;
const BLOCK_CNT_MIN = 2;
const BLOCK_BASE    = 2;
```

## Example SSBlocker CLIENT configuration

```php
<?php
RULES = [
    '#attack log ([\d.]{7,15})#' => [-1, -1], // [-1, -1] is report only.
];

const WHITE_LIST_IP    = ['172.20.0.1'];
const DETECT        = 864000;
const STATUS_DUMP   = 100;
const LOG_TIMESTAMP = true;
const TEST_MODE     = false;
const DEBUG_MODE    = false;
const TRACK_UNMANAGED = true;

function b64ue($str) { return trim(strtr(base64_encode($str), '+/=', '-_ ')); };

const HKDF_KEY = 'random shared secret key';
const MY_IP = '10.10.10.10';

const CMD_INIT      = '';
const CMD_BLOCK     = '';
const CMD_UNBLOCK   = '';

const CMD_REPORT    = function($rule, $ip, $line) {
    # Salt must be random for better security
    $salt = base64url_encode(random_bytes(32));
    # Build query param
    $q = ['action'=>'report', 'ip'=>$ip, 'rule'=>b64ue($rule), 'line'=>b64ue($line)];
    # $info = <key expiration time>-<Client IP>-<parameter SHA256 hash>
    $info = time()+10 .'-'. MY_IP .'-'. hash('sha256', http_build_query($q));
    # Derived key is usable only 10 sec for specific IP, log
    $key = hash_hkdf('sha256', HKDF_KEY, 0, $info, $salt);
    $q += ['salt'=>$salt, 'info'=>$info, 'key'=>$key];
    list($status, $msg) = file_get_contents('http://server/ssblocker-server.php?'. http_build_query($q));
};


const CMD_WAIT_SEC  = 5;

const BLOCK_CNT_DEC = 86400;
const BLOCK_CNT_MIN = 2;
const BLOCK_BASE    = 2;
```
