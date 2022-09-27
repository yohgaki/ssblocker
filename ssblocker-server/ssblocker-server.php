<?php
//
// SSBlocker Server <ssblocker-server.php>
//
// License: MIT
// Author: Yasuo Ohgaki <yohgaki@ohgaki.net>
//
// SSBlocker Server manage block/unblock on reverse proxy/firewall
//
// Usage:
//  Install this script to PHP enabled web server and send request from ssblocker client CMD_REPORT.
//  See ssblocker-server.php.cfg for SERVER config
//
//  Sample ssblocker CLIENT config.
/*
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

function u($str) { return trim(strtr(base64_encode($str), '+/=', '-_ ')); };

HKDF_KEY = 'random shared secret key';
MY_IP = '10.10.10.10';

const CMD_INIT      = '';
const CMD_BLOCK     = '';
const CMD_UNBLOCK   = '';

const CMD_REPORT    = function($rule, $ip, $line) {
    # Salt must be random for better security
    $salt = base64url_encode(random_bytes(32));
    # Build query param
    $q = ['action'=>'report', 'ip'=>$ip, 'rule'=>$rule, 'line'=>$line];
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
*/


//  If you would like to test/debug this script, you may try
/*
sudo touch /var/log/<$SCRIPT_NAME>.log
sudo chown <your_user_id> /var/log/<$SCRIPT_NAME>.log
php -S 127.0.0.1:8899
gnome-open http://127.0.0.1:8899/ssblocker-server.php?action=report&ip=192.168.100.60&rule=I1RFU1QgKFtcZC5dezcsMTV9KSM&line=VEVTVCAxOTIuMTY4LjEwMC42MCBhc2RiYXNkZmFzZGZhcw&salt=sadfas&info=1763895722-127.0.0.1-e0d4035ebf3812a5e04d08ba678b4334a013e080631a54463e7875e5cd4c9cb1&key=Ch/hljK4ExMM3Jqvg5m6VdYWRsX/ygiyF4kJSbFHP4g
*/
//  Edit <$SCRIPT_NAME>.cfg to enable debug/test mode.
//

/*********** START SERVER CONFIG *************/
// Shared secret
const HKDF_KEY = 'random shared secret key';
// SEM/SHM keys - If you have key collision, change these keys
const SEM_KEY = 0x3424;
const SHM_KEY = 0x3424;
/*********** END SERVER CONFIG *************/

$SCRIPT_NAME = basename($_SERVER['SCRIPT_NAME']);
ini_set('include_path', '/etc/ssblocker:/etc:/usr/local/etc:.');
require($SCRIPT_NAME . '.cfg');
//$LOG_FILE    = '/var/log/'. $SCRIPT_NAME .'.log';
$LOG_FILE = '/tmp/' . $SCRIPT_NAME . '.log';

// RULE config array index meanings
const ATTACK_COUNT = 0;
const BLOCK_TIME = 1;
const DETECT_TIME = 2;
const RULE_FUNC = 3;
// $ip_managed/unmanaged array index
const IB_TIME = 0; // DATE_ATOM
const IB_ATTACK = 1; // Attack log
// JSON return value keys
const SUCCESS = 'success';
const MSG = 'msg';

/*
$ip_attacked        = []; // [rule =>[ip_addr => [ts_attacked1 => msg1, ts_attacked2 => msg2, ... ], ...], ...]
$attack_cnt         = 0;
$ts_unblock         = []; // [ts_unblock => ip_addr, ...]
$ip_blocked         = []; // [ip_addr => blocked_count, ...]
$ip_managed         = []; // [ip_addr => [IB_TIME, IB_ATTACK], ...]
$block_cnt          = 0;
$ip_unmanaged       = []; // [ip_addr => [IB_TIME, IB_ATTACK], ...]
$unmanaged_cnt      = 0;
$ts_next_unblock    = 0;
$ts_next_cleanup    = 0;
$ts_next_bcnt_clear = time() + BLOCK_CNT_DEC;
$num_lines          = 0; // # of parsed lines
*/

header('Content-Type: application/json');
$fp_log = fopen($LOG_FILE, 'a');
if (!$fp_log) {
    echo json_encode([SUCCESS => false, MSG => 'Failed to open log file: ' . $LOG_FILE]);
    exit(255);
}


switch ($_GET['action']) {
case 'report': // Handle attack report
    list($status, $msg) = handle_attack();
    echo json_encode([SUCCESS => $status, MSG => $msg]);
break;
case 'myip': // Return client IP
    echo json_encode([SUCCESS => true, MSG => ['ip'=>$_SERVER['REMOTE_ADDR']]], JSON_PRETTY_PRINT);
break;
case 'gc': // Perform GC. Use cron for periodic gc.
    list($status, $msg) = handle_gc();
    echo json_encode([SUCCESS => $status, MSG => $msg], JSON_PRETTY_PRINT);
break;
case 'stat': // Return internal status
    list($status, $msg) = handle_stat();
    echo json_encode([SUCCESS => $status, MSG => $msg], JSON_PRETTY_PRINT);
break;
case 'clear': // Clear internal status
    list($status, $msg) = handle_clear();
    echo json_encode([SUCCESS => $status, MSG => $msg], JSON_PRETTY_PRINT);
break;
default:
    echo json_encode([SUCCESS => false, MSG => ['error'=>'Invalid action: '. $_GET['action']]]);
}

exit(0); // Make sure exit here


function handle_attack()
{
    assert(isset($_GET['ip']));
    assert(isset($_GET['rule']));
    assert(isset($_GET['line']));
    assert(is_array(RULES[base64url_decode($rule)]));

    handle_attack_validate_inputs();

    $ip = $_GET['ip'];
    $rule = base64url_decode($_GET['rule']);
    $line = base64url_decode($_GET['line']);
    $cfg = RULES[$rule];

    $t = microtime(true);
    $T = LOG_TIMESTAMP ? date(DATE_ATOM, $t) : '';

    list($shm, $dat) = shm_init();

    gc_attack_record($dat['ip_attacked'], $rule, $ip, $t, $T);
    $th = $cfg[DETECT_TIME] ?? DETECT;
    $dat['ip_attacked'][$rule][$ip][(string)($t + $th)] = $line;
    $dat['attack_cnt']++;
    shm_put_var($shm, SHM_KEY, $dat);
    fwrite($GLOBALS['fp_log'], $T . ' Attacked: ' . trim($line) .PHP_EOL);

    if (is_int(DEBUG_MODE) && !($dat['attack_cnt'] % DEBUG_MODE)) {
        dump_internal_status($dat);
    }
    if (!isset($dat['WHITE_LIST_IP'])) {
        $dat['WHITE_LIST_IP'] = array_flip(WHITE_LIST_IP);
    }
    if (isset($dat['WHITE_LIST_IP'][$ip])) {
        return [true, 'White list IP: ' . $ip];
    }
    if (WHITE_LIST_DOM && !preg_match(WHITE_LIST_DOM, gethostbyaddr($ip))) {
        return [true, 'White list domain: ' . $ip];
    }

    // Manage attack and block
    if (count($dat['ip_attacked'][$rule][$ip]) > $cfg[ATTACK_COUNT]) {
        if (isset($dat['ip_managed'][$ip]) || isset($ip_unmanaged[$ip])) {
            return [true, 'Already blocked IP: ' . $ip]; // Prevent multiple blocks for extreme attackers
        }
        if ($cfg[BLOCK_TIME]) {
            $dat['ip_blocked'][$ip] = isset($dat['ip_blocked'][$ip]) ? ++$dat['ip_blocked'][$ip] : 0;
            $dat['ip_managed'][$ip][IB_TIME] = date(DATE_ATOM, $t);
            $dat['ip_managed'][$ip][IB_ATTACK] = $line;
            $t_unblock = ($cfg[BLOCK_TIME]) * (BLOCK_BASE ** ($dat['ip_blocked'][$ip]));
            $dat['ts_unblock'][(string)($t + $t_unblock)] = $ip; // Extremely busy system may lost blocked IP info, but this is good enough for me.
            $block_msg = ' until ' . date(DATE_ATOM, (int)($t + $t_unblock)) . ' (' . $t_unblock . ' sec) (Blocked: ' . $dat['ip_blocked'][$ip] . ' times)';
        }
        else {
            if (TRACK_UNMANAGED) {
                // Flushing firewall rule may increment unlimited block count
                $dat['ip_blocked'][$ip] = isset($dat['ip_blocked'][$ip]) ? ++$dat['ip_blocked'][$ip] : 0;
                $dat['ip_unmanaged'][$ip][IB_TIME] = date(DATE_ATOM, $t);
                $dat['ip_unmanaged'][$ip][IB_ATTACK] = $line;
            }
            $dat['unmanaged_cnt']++;
            $block_msg = ' forever (Blocked: ' . $dat['ip_blocked'][$ip] . ' times) ';
        }

        $dat['block_cnt']++;
        ksort($dat['ts_unblock'], SORT_NATURAL); // Due to custom block time and throttling, sort is required. This sort can be removed, but O(n log n) shouldn't be a issue
        fwrite($GLOBALS['fp_log'], $T . ' Blocked: ' . $ip . $block_msg . ' (Managed / Unmanaged Blocks: ' . count($dat['ts_unblock']) . ' / ' . $dat['unmanaged_cnt'] . ')' . PHP_EOL);
        if (STATUS_DUMP && !($dat['block_cnt'] % STATUS_DUMP)) {
            dump_internal_status( $dat);
        }
        if (DEBUG_MODE) {
            fwrite($GLOBALS['fp_log'], $T . ' Command: ' . CMD_BLOCK . PHP_EOL);
        }
        if (!TEST_MODE) {
            execute_cmd($T, CMD_BLOCK, $ip, $rule);
        }
    }

    gc($dat);

    shm_put_var($shm, SHM_KEY, $dat);
    //if (DEBUG_MODE) var_dump($dat, __LINE__);
    return [true, 'processed IP: ' . $ip];
}


function handle_gc()
{
    if (!sem_lock()) {
        return [false, 'GC: Failed to get semaphore. '. __LINE__];
    }
    list($shm, $dat) = shm_init();
    $ret['gc'] = gc($dat);
    shm_put_var($shm, SHM_KEY, $dat);
    return [true, $ret];
}


function handle_stat()
{
    if (!sem_lock()) {
        return [false, 'Stat: Failed to get semaphore.'. __LINE__];
    }
    list($shm, $dat) = shm_init();
    $gc = gc($dat);
    shm_put_var($shm, SHM_KEY, $dat);
    $ret['dat']  = $dat;
    $ret['gc']   = $gc;
    $ret['memory']['current'] = memory_get_usage();
    $ret['memory']['peak'] = memory_get_peak_usage();
    $ret['time'] = [date(DATE_ATOM), microtime(true)];
    return [true, $ret];
}


function handle_clear()
{
    if (!sem_lock()) {
        return [false, 'Stat: Failed to get semaphore.'. __LINE__];
    }
    list($shm, $dat) = shm_init();
    $dat = [];
    $dat['ip_attacked']        = []; // [rule => [ip_addr => [ts_attacked1 => msg1, ts_attacked2 => msg2, ... ], ...], ...]
    $dat['attack_cnt']         = 0;
    $dat['ts_unblock']         = []; // [ts_unblock => ip_addr, ...]
    $dat['ip_blocked']         = []; // [ip_addr => blocked_count, ...]
    $dat['ip_managed']         = []; // [ip_addr => [IB_TIME, IB_ATTACK], ...]
    $dat['block_cnt']          = 0;
    $dat['ip_unmanaged']       = []; // [ip_addr => [IB_TIME, IB_ATTACK], ...]
    $dat['unmanaged_cnt']      = 0;
    $dat['ts_next_unblock']    = 0;
    $dat['ts_next_cleanup']    = 0;
    $dat['ts_next_bcnt_clear'] = time() + BLOCK_CNT_DEC;
    shm_put_var($shm, SHM_KEY, $dat);
    $ret['dat'] = $dat;
    return [true, $ret];
}


/****************************************************************************************************************************************************/

function handle_attack_validate_inputs()
{
    $T = LOG_TIMESTAMP ? date(DATE_ATOM) : '';

    if (count($_GET) > 7) {
        fwrite($GLOBALS['fp_log'], $T . ' Excessive parameter from IP: ' . $_SERVER['REMOTE_ADDR'] . ' URI: ' .$_SERVER['REQUEST_URI'] .PHP_EOL);
        echo json_encode([ SUCCESS => false, MSG => 'Excessive Parameter: ' . $_SERVER['REQUEST_URI'] ]);
        exit;
    }
    // Input validation
    if (!isset($_GET['action']) || !isset($_GET['ip']) || !isset($_GET['rule']) || !isset($_GET['line'])|| !isset($_GET['salt']) || !isset($_GET['info']) || !isset($_GET['key'])) {
        fwrite($GLOBALS['fp_log'], $T . ' Missing parameter from IP: ' . $_SERVER['REMOTE_ADDR'] . ' URI: ' .$_SERVER['REQUEST_URI'] .PHP_EOL);
        echo json_encode([ SUCCESS => false, MSG => 'Missing Parameter: ' . $_SERVER['REQUEST_URI'] ]);
        exit;
    }
    // Valid rule
    $rule = base64url_decode($_GET['rule']);
    if (!isset(RULES[$rule])) {
        fwrite($GLOBALS['fp_log'], $T . ' Invalid block rule: ' . $_SERVER['REMOTE_ADDR'] . ' URI: ' .$_SERVER['REQUEST_URI'] .PHP_EOL);
        echo json_encode([ SUCCESS => false, MSG => 'Invalid block rule: '. $rule .' URI:'. $_SERVER['REQUEST_URI'] ]);
        exit;
    }
    // HKDF key validation
    $key = hash_hkdf('sha256', HKDF_KEY, 0, $_GET['info'], $_GET['salt']);
    if (base64url_decode($_GET['key']) !== $key) {
        fwrite($GLOBALS['fp_log'], $T . ' Invalid key from IP: ' . $_SERVER['REMOTE_ADDR'] . ' URI: ' . $_SERVER['REQUEST_URI'] .PHP_EOL);
        if (DEBUG_MODE) {
            echo 'Key:  '. base64url_encode($key) . PHP_EOL;
        }
        echo json_encode([ SUCCESS => false, MSG => 'Invalid key: ' . $_SERVER['REQUEST_URI'] ]);
        exit;
    }
    if (!$_GET['salt']) {
        // User must use salt always unless you have to work with broken system. RFC5869 states
        /*
         * 3.1. To Salt or not to Salt
         *
         * HKDF is defined to operate with and without random salt. This is
         * done to accommodate applications where a salt value is not available.
         * We stress, however, that the use of salt adds significantly to the
         * strength of HKDF, ensuring independence between different uses of the
         * hash function, supporting "source-independent" extraction, and
         * strengthening the analytical results that back the HKDF design.
         */
        fwrite($GLOBALS['fp_log'], $T . ' Invalid salt from IP: ' . $_SERVER['REMOTE_ADDR'] . ' URI: ' . $_SERVER['REQUEST_URI'] .PHP_EOL);
        echo json_encode([ SUCCESS => false, MSG => 'Invalid salt: ' . $_SERVER['REQUEST_URI'] ]);
        exit;
    }
    list($expire, $allowed_ip, $data_hash) = preg_split('#-#', $_GET['info']);
    if ($expire < time()) {
        fwrite($GLOBALS['fp_log'], $T . ' Expired key from IP: ' . $_SERVER['REMOTE_ADDR'] . ' URI: ' . $_SERVER['REQUEST_URI'] .PHP_EOL);
        echo json_encode([ SUCCESS=> false, MSG => 'Expired key: ' . $_SERVER['REQUEST_URI'] ]);
        exit;
    }
    if ($allowed_ip !== $_SERVER['REMOTE_ADDR']) {
        fwrite($GLOBALS['fp_log'], $T . ' Request host IP mismatch: ' . $_SERVER['REMOTE_ADDR'] . ' URI: ' .$_SERVER['REQUEST_URI'] .PHP_EOL);
        echo json_encode([ SUCCESS => false, MSG => 'Request host IP mismatch: ' . $_SERVER['REQUEST_URI'] ]);
        exit;
    }
    // Check $_GET's action, ip, rule, line hash value
    if ($data_hash !== hash('sha256', http_build_query(array_slice($_GET, 0, 4)))) {
        fwrite($GLOBALS['fp_log'], $T . ' Request data is tampered: ' . $_SERVER['REMOTE_ADDR'] . ' URI: ' .$_SERVER['REQUEST_URI'] .PHP_EOL);
        if (DEBUG_MODE) {
            var_dump(hash('sha256', http_build_query(array_slice($_GET, 0, 4))));
        }
        echo json_encode([ SUCCESS => false, MSG => 'Request data is tampered: ' . $_SERVER['REQUEST_URI'] ]);
        exit;
    }
}


function &shm_init()
{
    if (!sem_lock()) {
        $ret = [false, 'Failed to get lock. '. __LINE__];
        return $ret;
    }

    $shm = @shm_attach(SHM_KEY, null, 0640);
    if (!$shm) {
        $ret =  [false, 'Failed to attach shared memory. '. __LINE__];
        return $ret;
    }
    $dat = @shm_get_var($shm, SHM_KEY);
    if (!isset($dat['ip_attacked'])) {
        $dat['ip_attacked']        = []; // [rule => [ip_addr => [ts_attacked1 => msg1, ts_attacked2 => msg2, ... ], ...], ...]
        $dat['attack_cnt']         = 0;
        $dat['ts_unblock']         = []; // [ts_unblock => ip_addr, ...]
        $dat['ip_blocked']         = []; // [ip_addr => blocked_count, ...]
        $dat['ip_managed']         = []; // [ip_addr => [IB_TIME, IB_ATTACK], ...]
        $dat['block_cnt']          = 0;
        $dat['ip_unmanaged']       = []; // [ip_addr => [IB_TIME, IB_ATTACK], ...]
        $dat['unmanaged_cnt']      = 0;
        $dat['ts_next_unblock']    = 0;
        $dat['ts_next_cleanup']    = 0;
        $dat['ts_next_bcnt_clear'] = time() + BLOCK_CNT_DEC;
    }
    $ret = [$shm, $dat];
    return $ret;
}

function gc(&$dat)
{
    $t = microtime(true);
    $T = LOG_TIMESTAMP ? date(DATE_ATOM, $t) : '';

    $attack = 0;
    $unblock = 0;
    $block_counter = 0;

    // Cleanup old attack records
    if ($dat['ts_next_cleanup'] < $t) {
        foreach ($dat['ip_attacked'] as $rule => $ips) {
            foreach ($ips as $ip => $tmp) {
                gc_attack_record($dat['ip_attacked'], $rule, $ip, $t, $T, $attack);
            }
        }
        $dat['ts_next_cleanup'] = $t + 3600;
    }
    // Release blocked IPs
    if ($dat['ts_next_unblock'] < $t) {
        foreach ($dat['ts_unblock'] as $ts => $ip) {
            if ($ts > $t) {
                break;
            }
            $unblock++;
            unset($dat['ts_unblock'][$ts]);
            unset($dat['ip_managed'][$ip]);
            fwrite($GLOBALS['fp_log'], $T .' Unblocked: '. $ip .' TS: '. $ts . PHP_EOL);
            if (DEBUG_MODE) {
                fwrite($GLOBALS['fp_log'], $T .' Command: '. (is_callable($cmd) ? 'Unblock PHP function' : CMD_UNBLOCK) . PHP_EOL);
            }
            if (!TEST_MODE) {
                execute_cmd($T, CMD_UNBLOCK, $ip);
            }
        }
        $dat['ts_next_unblock'] = $t + 60;
    }
    // Decrement block(attack) counter
    if ($dat['ts_next_bcnt_clear'] < $t) {
        foreach ($dat['ip_blocked'] as $ip => &$cnt) {
            if ($cnt > BLOCK_CNT_MIN) {
                $block_counter++;
                $cnt--;
            }
        }
        $dat['ts_next_bcnt_clear'] += BLOCK_CNT_DEC;
    }
    return ['attack_list'=>$attack, 'unblock_list'=>$unblock, 'block_counter'=>$block_counter];
}

function gc_attack_record(&$ip_attacked, $rule, $ip, $t, $T, &$cnt = 0)
{
    if (isset($ip_attacked[$rule][$ip])) {
        foreach ($ip_attacked[$rule][$ip] as $ts => $attack) {
            if ($ts > $t) {
                break;
            }
            if (DEBUG_MODE) {
                fwrite($GLOBALS['fp_log'], $T . ' Removed attack record: ' . $ip . ' (' . date(DATE_ATOM, $ts) . ') : ' . $attack . PHP_EOL);
            }
            unset($ip_attacked[$rule][$ip][$ts]);
            $cnt++;
        }
        if (!count($ip_attacked[$rule][$ip])) {
            unset($ip_attacked[$rule][$ip]);
        }
    }
}

function execute_cmd($T, $cmd, $ip = NULL, $rule = NULL)
{
    if (is_callable($cmd)) {
        $err = $cmd($ip, $rule);
        $status = 0;
        return [true, 'CMD: PHP_Function'];
    }
    $c = sprintf($cmd, e($ip));
    $err = exec($c, $output, $status);
    if ($err || $status) {
        $msg = $T . ' CMD: ' . $c .'  ('. $status .')'. PHP_EOL . implode("\n", $output) . PHP_EOL;
        fwrite($GLOBALS['fp_log'], $msg);
        return [false, $msg];
    }
    return [true, 'CMD: ' . $cmd];
}

function dump_internal_status($dat)
{
    $msg = date(DATE_ATOM) . ' Rules and internal status: ' . $GLOBALS['SCRIPT_NAME'] . PHP_EOL;
    $msg .= '<?php' . PHP_EOL;
    $msg .= '$time         = ' . time() . ';' . PHP_EOL;
    $msg .= '$script       = \'' . $GLOBALS['SCRIPT_NAME'] . '\';' . PHP_EOL;
    $msg .= '$RULES        = ' . var_export(RULES, true) . ';' . PHP_EOL;
    $msg .= '$ip_attacked  = ' . var_export($dat['ip_attacked'], true) . ';' . PHP_EOL;
    $msg .= '$ts_unblock   = ' . var_export($dat['ts_unblock'], true) . ';' . PHP_EOL;
    $msg .= '$ts_blocked   = ' . var_export($dat['ts_blocked'], true) . ';' . PHP_EOL;
    $msg .= '$ip_managed   = ' . var_export($dat['ip_managed'], true) . ';' . PHP_EOL;
    $msg .= '$ip_unmanaged = ' . var_export($dat['ip_unmanaged'], true) . ';' . PHP_EOL;
    $msg .= '$ip_attacked_cnt  = ' . count($dat['ip_attacked'], COUNT_RECURSIVE) . ';' . PHP_EOL;
    $msg .= '$ts_unblock_cnt   = ' . count($dat['ts_unblock'], true) . ';' . PHP_EOL;
    $msg .= '$ip_managed_cnt   = ' . count($dat['ip_managed'], true) . ';' . PHP_EOL;
    $msg .= '$ip_unmanaged_cnt = ' . count($dat['ip_unmanaged'], true) . ';' . PHP_EOL;
    $msg .= '$block_cnt        = ' . $dat['block_cnt'] . ';' . PHP_EOL;
    $msg .= '$unmanaged_cnt    = ' . $dat['unmanaged_cnt'] . ';' . PHP_EOL;
    $msg .= '$attack_cnt       = ' . $dat['attack_cnt'] . ';' . PHP_EOL;
    $m = memory_get_usage();
    $e = (int)(log10($m) / 3); // array(1,2,3)[1] selects 2nd array elem. KB/MB/GB. Not KiB/MiB/GiB
    $msg .= '# Memory usage: ' . sprintf('%.2f', $m / 1e3 ** $e) . ['', 'KB', 'MB', 'GB'][$e] . PHP_EOL;
    $msg .= '$memory           = ' . $m . ';' . PHP_EOL;
    $m = memory_get_peak_usage();
    $e = (int)(log10($m) / 3);
    $msg .= '# Memory peak usage: ' . sprintf('%.2f', $m / 1e3 ** $e) . ['', 'KB', 'MB', 'GB'][$e] . PHP_EOL;
    $msg .= '$memory_peak      = ' . $m . ';' . PHP_EOL;
    $msg .= '?>' . PHP_EOL;
    fwrite($GLOBALS['fp_log'], $msg);
}

function sem_lock() {
    $sem = sem_get(SEM_KEY, 1, 0640);
    if (!$sem) {
        return false;
    }
    if (!sem_acquire($sem)) {
        return false;
    }
    return true;
}

function e($str)
{
    return escapeshellarg($str);
}

function base64url_decode($str)
{
    return base64_decode(strtr($str, ['-'=>'+', '_'=>'\\']));
}

function base64url_encode($str)
{
    return strtr(base64_encode($str), ['+'=>'-', '\\'=>'_', '='=>'']);
}
