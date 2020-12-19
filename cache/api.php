<?php
namespace BitFire {

class api {
    /**
     * return the decrypted api command from an API call
     */
    protected function get_command() {
        $cmd = $_POST[BITFIRE_COMMAND] ?? null;
        if ($cmd) {
            // remove spaces
            $pass = str_replace(' ', '', $_POST['passwd'] ?? '');
            // limit password length to 18 characters and escape the command
            $pass = escapeshellarg(substr($pass, 0, 18));
            switch($cmd) {
                case "unlock":
                case "lock":
                    $lockpath = WAF_DIR . "filelock.sh";
                    $st = stat($lockpath);
                    $mode = intval(substr(decoct($st['mode']), -3));
                    if ($st['uid'] !== 0) {
                        die("filelock script must be owned by root");
                    }
                    if ($mode !== 750) {
                        die("filelock script must be permission wrx-rx--- (0750)");
                    }
                    $cmdmode = ($cmd === "unlock") ? "unlock" : "lock";
                    $sys = "echo $pass | sudo -k -S " . WAF_DIR . "filelock.sh $cmdmode";
                    $result = system($sys);
                    die("$cmdmode [$result]");
                    break;
                break;
                default:
                    die("unknown command");
                break;
            }
        }
        return $cmd;
    }

    /**
     * api command to api function mapping
     */
    public function make_api_map() {
        return array(
            "ini" => "update_ini",
            "block" => "add_block",
            "upgrade" => "upgrade_waf",
            "locksite" => "locksite",
            "unlocksite" => "unlocksite"
        );
    }

    /**
     * handle remote API commands from the API server
     * This syncs the configuration with the remote server.
     */
    public function handle_api_commands() {
        $cmd = $this->get_command();
        if ($cmd) {
            $apimap = $this->make_api_map();
            assert($cmd['cmd'] ?? false, "api request missing command");
            $call = $apimap[$cmd['cmd']] ?? null;
            if (is_callable(array($this, $call))) {
                $this->$call($cmd);
            } else {
            }
        }
    }

    /**
     * download $cmds[ver] from bitslip6.com and upgrade the software
     */
    protected function upgrade_waf(array $cmds) {
        $ver = $cmds['ver'] ?? 0;
        assert(is_int($ver) && $ver > 0, "unable to upgrade BitFire without a version");
        $filename = "bitfire_$ver.tgz";
        $localfile = WAF_DIR . $filename;

        if (!is_writable(WAF_DIR)) {
            return die("waf not writeable");
        }

        $raw_tgz = \TF\bit_http_request("GET", "http://www.bitslip6.com/files/$filename", "");
        if (strlen($raw_tgz) > 10) {
            \file_put_contents($localfile, $raw_tgz);
            \system("tar zxf $localfile");
            $code = \file_get_contents(WAF_DIR . "/startup.txt");
            \file_put_contents(WAF_DIR . "/startup.php", "<?php\ndefine('WAF_DIR', '".WAF_DIR."');define('BLOCK_DIR', '".WAF_DIR."/block');\n$code");
            include(WAF_DIR . "/test/test.php");
            include(WAF_DIR . "/test/install.php");
        } else {
            return die("empty download binary");
        }
    }

    /**
     * update the configuration with server supplied configuration
     */
    protected function update_ini(array $cmds) {
        assert(strlen($cmds['ini']) > 128, 'updated ini is empty');
        if (\is_writable(BITFIRE_CONFIG)) {
            \file_put_contents(BITFIRE_CONFIG, $cmds['data'], 0);
        } else {
        }
    }

}
}