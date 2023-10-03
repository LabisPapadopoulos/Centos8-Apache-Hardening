#!/bin/bash

#
# @author Labis Papadopoulos (ch.papadopoulos@ssl-unipi.gr || labisp@di.uoa.gr)
#

DEV=1
SCRIPT_NAME='centos8-apache-hardening'
PWD=$(pwd)
FILE=${PWD}'/step.dat'
LOCK_FILE=${PWD}"/${SCRIPT_NAME}.lok"

NEW_LINE=" "
PREREQUISITES_PACKAGES='yum-utils vim wget httpd-devel expect net-tools at epel-release'
IPTABLES_CONFIG='/etc/sysconfig/iptables'
IPTABLES_PACKAGE='iptables-services'
MOD_SECURITY='mod_security mod_security_crs'
MOD_EVASIVE='mod_evasive'
MOD_EVASIVE_TEST_SCRIPT='/usr/share/doc/mod_evasive/test.pl'
HTTPD_CONF='/etc/httpd/conf/httpd.conf'
HTTPD_HTML='/var/www/html/index.html'
BASE_MODULES='/etc/httpd/conf.modules.d/00-base.conf'
MOD_SECURITY_CONF='/etc/httpd/conf.d/mod_security.conf'
MOD_EVASIVE_CONF='/etc/httpd/conf.d/mod_evasive.conf'
CUSTOM_CRS_CONF='/etc/httpd/modsecurity.d/custom-crs.conf'
SSHD_CONFIG='/etc/ssh/sshd_config'
SSHD_PAM='/etc/pam.d/sshd'
ISSUE_NET='/etc/issue.net'
CURRENT_USER=${SUDO_USER:-$USER}
GRUB_SUPERUSER='vagrant'
GRUB_PASSPHRASE='vagrant'
MKPASSWD='/usr/bin/grub2-mkpasswd-pbkdf2'
DEFAULTGRUB='/etc/default/grub'
EXPECT='/usr/bin/expect'
GRUB_40_CUSTOM='/etc/grub.d/40_custom'

UNW_PROT='dccp sctp rds tipc'
UNW_SERVICES='rpcbind'
MOD='bluetooth firewire-core net-pf-31 soundcore thunderbolt usb-midi usb-storage'
UNW_FS='cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat'
DISABLEFS='/etc/modprobe.d/disablemnt.conf'
DISABLEMOD='/etc/modprobe.d/disablemod.conf'
DISABLENET='/etc/modprobe.d/disablenet.conf'
SYSTEMCONF='/etc/systemd/system.conf'
USERCONF='/etc/systemd/user.conf'
COREDUMPCONF='/etc/systemd/coredump.conf'
LOGROTATE='/etc/logrotate.conf'
JOURNALDCONF='/etc/systemd/journald.conf'
SYSCTL='/etc/sysctl.conf'
LIMITSCONF='/etc/security/limits.conf'
ETC_PROFILE='/etc/profile'
ETC_BASHRC='/etc/bashrc'

HOSTS_ALLOW='/etc/hosts.allow'
HOSTS_DENY='/etc/hosts.deny'

LOGINDCONF='/etc/systemd/logind.conf'
LOGINDEFS='/etc/login.defs'
USERADD='/etc/default/useradd'
NETCONFIG='/etc/netconfig'
RESOLVEDCONF='/etc/systemd/resolved.conf'
NSSWITCH='/etc/nsswitch.conf'
RKHUNTER_PACKAGE='rkhunter'
RKHUNTERCONF='/etc/rkhunter.conf'
CLAMAV_PACKAGES='clamav clamav-update clamd'
CLAMAVCONF='/etc/clamd.d/scan.conf'
CLAMAVSERVICE='/usr/lib/systemd/system/clamd@.service'
CRON_DAILY_CLAMSCAN='/etc/cron.daily/user_clamscan'

AIDE_PACKAGE='aide'
AIDECONFIG='/etc/aide.conf'
AIDE_CHECK_SERVICE='/etc/systemd/system/aidecheck.service'
AIDE_CHECK_TIMER='/etc/systemd/system/aidecheck.timer'

FAIL2BAN_PACKAGE='fail2ban'
FAIL2BAN_CONFIG='/etc/fail2ban/jail.local'
FAIL2BAN_SERVICE_SYMLINK='/etc/systemd/system/multi-user.target.wants/fail2ban.service'

# Colors source: https://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux
COLOR_DEFAULT="\e[39m"
COLOR_GREEN="\e[32m"
COLOR_RED="\e[91m"
COLOR_BLUE='\033[0;34m'
BOLD_BLUE='\033[1;34m'

# Processes description
array[0]="Prerequisites checks..."
array[1]="SSH Hardening..."
array[2]="Secure Bootloader..."
array[3]="Disabling unneeded modules..."
array[4]="Secure mounts..."
array[5]="Configuring sysctl parameters..."
array[6]="Configure user limits..."
array[7]="Remove suid bits..."
array[8]="Securing user and services host files..."
array[9]="Configuring TCP Wrappers..."
array[10]="Configuring logindefs..."
array[11]="Configuring loginconf..."
array[12]="Locking new users..."
array[13]="Remove unneeded users..."
array[14]="Disabling ipv6..."
array[15]="Configuring DNS resolvers..."
array[16]="Locking cronjobs..."
array[17]="Configuring logrotate..."
array[18]="Enable rkhunter..."
array[19]="Enable clamav..."
array[20]="Enable aide IDS..."
array[21]="Enable Fail2ban..."
array[22]="IPTables Hardening..."
array[23]="Apache Hardening..."
array[24]="Mod Security..."
array[25]="Mod Evasive..."
array[26]="Auto cleanup..."
array[27]="Checking for restart..."

max_processes_num="27"

step=''
IFS=''

START=$(date +%s)

#===  FUNCTION  ==========================================================
#          NAME: script_logo
#   DESCRIPTION: Print the logo of script
#     PARAMETER: ---
#========================================================================
function script_logo()
{
	echo
	echo -e "${BOLD_BLUE}  ____           _               ___       _                     _            _   _               _            _${COLOR_DEFAULT}"
	echo -e "${BOLD_BLUE} / ___|___ _ __ | |_ ___  ___   ( _ )     / \   _ __   __ _  ___| |__   ___  | | | | __ _ _ __ __| | ___ _ __ (_)_ __   __ _${COLOR_DEFAULT}"
	echo -e "${BOLD_BLUE}| |   / _ \ |_ \| __/ _ \/ __|  / _ \    / _ \ | |_ \ / _\ |/ __| |_ \ / _ \ | |_| |/ _\ | |__/ _\ |/ _ \ |_ \| | |_ \ / _\ |${COLOR_DEFAULT}"
	echo -e "${BOLD_BLUE}| |__|  __/ | | | || (_) \__ \ | (_) |  / ___ \| |_) | (_| | (__| | | |  __/ |  _  | (_| | | | (_| |  __/ | | | | | | | (_| |${COLOR_DEFAULT}"
	echo -e "${BOLD_BLUE} \____\___|_| |_|\__\___/|___/  \___/  /_/   \_\ .__/ \__,_|\___|_| |_|\___| |_| |_|\__,_|_|  \__,_|\___|_| |_|_|_| |_|\__, |${COLOR_DEFAULT}"
	echo -e "${BOLD_BLUE}                                               |_|                                                                     |___/${COLOR_DEFAULT}"
	echo -e "${BOLD_BLUE}${COLOR_DEFAULT}"
}

#===  FUNCTION  ==========================================================
#          NAME: log_info
#   DESCRIPTION: Print the input info text.
#     PARAMETER: Text to print.
#========================================================================
function log_info {
    echo -e "[${BOLD_BLUE}INFO${COLOR_DEFAULT}] $1"
}

#===  FUNCTION  ==========================================================
#          NAME: log_info
#   DESCRIPTION: Print the input info text.
#     PARAMETER: Text to print.
#========================================================================
function log_error {
    echo -e "${COLOR_RED}[ERROR] $1${COLOR_DEFAULT}"
}

#===  FUNCTION  ==========================================================
#          NAME: backup_file
#   DESCRIPTION: Backup a file.
#     PARAMETER: Path to file.
#========================================================================
function backup_file {
    cp $1{,.bak}
}

#===  FUNCTION  ==========================================================
#          NAME: comment_parameter
#   DESCRIPTION: Comment out a parameter in the configuration file.
#    PARAMETERS: 1. parameter name (escaped special characters)
#                2. configuration file path
#========================================================================
function comment_parameter {
    sed -i $2 -e "/$1/s/^/#/"
}

#===  FUNCTION  ==========================================================
#          NAME: _exit
#   DESCRIPTION: Terminate the script execution
#     PARAMETER: ---
#========================================================================
function _exit()
{
	# Check system delta
	systemd-delta --no-pager
	release_lock
	END=$(date +%s)
	DIFF=$(( $END - $START ))
	secs=$DIFF
	echo -n "The execution time is: "
	printf '%dh:%dm:%ds\n' $(($secs/3600)) $(($secs%3600/60)) $(($secs%60))
	exit 1
}

#===  FUNCTION  ==========================================================
#          NAME: acquire_lock
#   DESCRIPTION: Create a lock file if not exists,
#				 otherwise print error message that lock file exists
#     PARAMETER: ---
#========================================================================
function acquire_lock() 
{
	# echo ">>> Is going to check for lock file: $LOCK_FILE"
	# if we don't have the lock file, start at zero
	# if ! test -f "$LOCK_FILE"; then
	if [ ! -f "$LOCK_FILE" ]; then
		log_info "Lock file not found. So we will create one"
		touch $LOCK_FILE
	else # otherwise the hardening script is being executed
		log_error "Found lock file: ${LOCK_FILE} which means the script ${SCRIPT_NAME} is is being executed!"
		log_error "If not, please remove the lock file ${LOCK_FILE}"
		exit 1
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: release_lock
#   DESCRIPTION: Remove the lock file from filesystem
#     PARAMETER: ---
#========================================================================
function release_lock()
{
	if [ -f "$LOCK_FILE" ]; then
		rm -rf $LOCK_FILE
	else
		log_info "Lock file not found to release lock"
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: retrieve_step
#   DESCRIPTION: Retrieve the current step of step.dat file, 
#				 else initialize the step to zero
#     PARAMETER: ---
#========================================================================
function retrieve_step()
{
	# if we don't have a file, start at zero
	if [ ! -f "$FILE" ]; then
	  step=0
	  # log_info "Step file not found"
	# otherwise read the step from the file
	else
	  step=`cat $FILE`
	  log_info "Found step: ${step}"
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: increase_step
#   DESCRIPTION: Increase the current step value by one
#     PARAMETER: 1. currentStep value is passed in order to increased
#========================================================================
function increase_step()
{
	currentStep=$1
	[[ -z "$currentStep" ]] && { log_error "First parameter (currentStep) is empty in function increase_step"; _exit; }
	# increment the step
	step=$((currentStep + 1))
}

#===  FUNCTION  ==========================================================
#          NAME: save_step
#   DESCRIPTION: Save the currentStep into step.dat file
#     PARAMETER: 1. currentStep value is passed in order to be saved
#========================================================================
function save_step() {

	currentStep=$1
	[[ -z "$currentStep" ]] && { log_error "First parameter (currentStep) is empty in function save_step"; _exit; }
	# show it to the user
	# echo "step: ${currentStep}"

	# and save it for next time
	echo "${currentStep}" > $FILE
}

#===  FUNCTION  ==========================================================
#          NAME: get_value
#   DESCRIPTION: Retrieve the value of processes description array
#     PARAMETER: 1. currentStep value is passed
#========================================================================
function get_value()
{
	currentStep=$1
	[[ -z "$currentStep" ]] && { log_error "First parameter (currentStep) is empty in function get_value"; _exit; }
	#for i in "${!array[@]}"
	#do
	#  echo "key  : $i / value: ${array[$i]}"
	#done

	# Retrieve value from hash map ($array[$i])
	# echo "step value: ${array[$currentStep]}"
	echo "${array[$currentStep]}"
}

#===  FUNCTION  ==========================================================
#          NAME: get_diff_lines
#   DESCRIPTION: Save the number of different lines in the specified files to the
#                variable "DIFF_LINES"
#    PARAMETERS: 1. file 1 (e. g. "/boot/grub/grub.cfg")
#                2. file 2 (e. g. "/boot/grub/grub.cfg.bak")
#========================================================================
function get_diff_lines {
    DIFF_LINES=$(diff -y --suppress-common-lines $1 $2 | grep '^' | wc -l)
}

#===  FUNCTION  ==========================================================
#          NAME: set_parameter
#   DESCRIPTION: Set the parameters in the configuration file. If the parameter does not exist in
#                the configuration file, add it.
#    PARAMETERS: 1. parameter name (escaped special characters)
#                2. parameter value (escaped special characters)
#                3. configuration path
#                4. OPTIONAL - prefix for value (default is the space)
#========================================================================
function set_parameter {
    grep -qE "^(#\s)?$1" $3
    local EXIT_STATUS=$?
    if [[ ${EXIT_STATUS} -ne 0 ]]; then
        echo -e "$1${4-" "}$2" >> $3
    else
        sed -i.old -E "/^$1/c\\$1${4-" "}$2" $3
        get_diff_lines $3 $3.old
        grep -qE "^$1${4-" "}$2" $3
        local EXIT_STATUS=$?
        if [[ ${DIFF_LINES} -eq 0 ]] && [[ ${EXIT_STATUS} -ne 0 ]]; then
            sed -i.old -E "/^(#)?$1/c\\$1${4-" "}$2" $3
            get_diff_lines $3 $3.old
            if [[ ${DIFF_LINES} -eq 0 ]]; then
                sed -i.old -E "/^(#\s)?$1/c\\$1${4-" "}$2" $3
            fi
        fi
        rm $3.old
    fi
}

#===  FUNCTION  ==========================================================
#          NAME: set_permission
#   DESCRIPTION: Set the ownership and permissions for a file.
#    PARAMETERS: 1. ownership (e. g. "root:root")
#                2. permission (e. g. "0644")
#                3. file (e. g. "/boot/grub/grub.cfg")
#========================================================================
function set_permission {
    chown $1 $3
    chmod $2 $3
}

#===  FUNCTION  ==========================================================
#          NAME: set_permission_recursive
#   DESCRIPTION: Set recursive ownership and permissions for a directory.
#    PARAMETERS: 1. ownership (e. g. "root:root")
#                2. permission (e. g. "0644")
#                3. directory (e. g. "/boot/grub/")
#========================================================================
function set_permission_recursive {
    chown -R $1 $3
    chmod -R $2 $3
}

#===  FUNCTION  ==========================================================
#          NAME: install_packages
#   DESCRIPTION: Iterrate over passed packages and install them one by one
#    PARAMETERS: 1. packages: list of packages is passed for installation
#========================================================================
function install_packages() 
{
	IFS=' '
    packages="$@"
	for package in $packages; do
		log_info "Is going to install the package: ${COLOR_GREEN}"$package"${COLOR_DEFAULT}"
		yum install -y $package
	done
	IFS=''
}

#===  FUNCTION  ==========================================================
#          NAME: execute_full_update
#   DESCRIPTION: Execute full update
#     PARAMETER: ---
#========================================================================
function execute_full_update() {
	log_info "Is going to execute full update, please wait..."
	yum makecache
	yum update -y
}

#===  FUNCTION  ==========================================================
#          NAME: check_prerequisites
#   DESCRIPTION: Check prerequisites in order to continue the script execution
#     PARAMETER: ---
#========================================================================
function check_prerequisites()
{
	if [ $EUID -ne 0 ]; then
		log_error "This script must be run with root privileges."
		_exit
	fi
	log_info "Script stared with root privileges"
	
	# test an internet connection
	curl 1.1.1.1 2> /dev/null 1>&2
	if [ ${UID} -ne 0 ]; then
		log_error "No internet connection found!"
		_exit
	fi
	log_info "Internet connection found"

	if ! cat /etc/centos-release | grep 'CentOS' | grep '8' 2> /dev/null 1>&2; then
		log_error "Unsupported Linux distribution. Only CentOS 8 Supported"
		_exit
	fi
	log_info "Centos 8 OS found"

	if ! bash --version | grep -i 'bash' 2> /dev/null 1>&2; then
		log_error "Please install bash to continue.."
		_exit
	fi
	log_info "Bash found"

	if ! [ -x "$(which systemctl)" ]; then
		log_error "systemctl required. Unsupported setup.."
		_exit
	fi
	log_info "Systemctl found"
	
	execute_full_update
	
	if ! test -f "$HTTPD_CONF"; then
		log_info "$HTTPD_CONF apache config file not found."
		log_info "Is going to install apache, please wait..."
		yum install httpd
		service httpd start
		chkconfig httpd on
		touch $HTTPD_HTML
		index_page=$(cat <<EOF
<!DOCTYPE html>
<html>
	<head>
		<title>Centos 8 Apache Hardening Script</title>
	</head>
	<body>
		<h1>Centos 8 Apache Hardening Script</h1>
		<p>It works!</p>
	</body>
</html>
EOF
)
		append_config "$index_page" $HTTPD_HTML
	fi
	log_info "Apache Web Server found"

	if ! test -f "$IPTABLES_CONFIG"; then
		log_info "$IPTABLES_CONFIG firewall config file not found."
		log_info "Is going to install iptables package, please wait..."
		systemctl stop firewalld
		systemctl disable firewalld
		systemctl mask --now firewalld
		install_packages $IPTABLES_PACKAGE
		systemctl start iptables
		systemctl enable iptables
		systemctl status iptables --no-pager
	fi
	log_info "IPtables found"
	
	# Install some prerequisites packages
	install_packages $PREREQUISITES_PACKAGES
}

#===  FUNCTION  ==========================================================
#          NAME: iptables_hardening
#   DESCRIPTION: Apply iptable hardening rules as part of security hardening process
#     PARAMETER: ---
#========================================================================
function iptables_hardening ()
{
	if test -f "$IPTABLES_CONFIG"; then
		log_info "Is going to apply iptables hardening rules, please wait..."
		# source: https://raiyanlive.wordpress.com/2016/09/02/hardening-server-security-using-iptables/
		# Modify this file accordingly for your specific requirement.
		# 1. Delete all existing rules
		log_info "Deleting all existing rules"
		iptables -F

		# 2. Set default chain policies
		# iptables -P INPUT DROP
		# iptables -P FORWARD DROP
		# iptables -P OUTPUT DROP

		# 3. Block a specific ip-address
		BLOCK_THIS_IP="192.168.1.254"
		log_info "Blocking a specific ip-address: $BLOCK_THIS_IP"
		iptables -A INPUT -s "$BLOCK_THIS_IP" -j DROP
		
		INTERFACE_NAME='eth1'

		# 4. Allow ALL incoming SSH
		log_info "Allowing ALL incoming SSH"
		iptables -I INPUT -i $INTERFACE_NAME -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

		# 5. Allow incoming SSH only from a sepcific network
		# EXTERNAL_NET=`ip  -f inet a show eth0 | grep inet| awk '{print $2}'`	# e.g. inet address of eht1 network 172.28.128.20/24
		EXTERNAL_NET='192.168.1.0/24'
		log_info "Allowing incoming SSH only from a sepcific network: $EXTERNAL_NET"
		iptables -I INPUT -i $INTERFACE_NAME -p tcp -s $EXTERNAL_NET --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

		# 6. Allow incoming HTTP
		log_info "Allowing incoming HTTP"
		iptables -I INPUT -i $INTERFACE_NAME -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

		# Allow incoming HTTPS
		log_info "Allowing incoming HTTPS"
		iptables -I INPUT -i $INTERFACE_NAME -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

		# 7. MultiPorts (Allow incoming SSH, HTTP, and HTTPS)
		# iptables -I INPUT -i $INTERFACE_NAME -p tcp -m multiport --dports 22,80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
		# iptables -I OUTPUT -o $INTERFACE_NAME -p tcp -m multiport --sports 22,80,443 -m state --state ESTABLISHED -j ACCEPT

		# 8. Allow outgoing SSH
		log_info "Allowing outgoing SSH"
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I INPUT -i $INTERFACE_NAME -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

		# 9. Allow outgoing SSH only to a specific network
		log_info "Allowing outgoing SSH only to a specific network"
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp -d $EXTERNAL_NET --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I INPUT -i $INTERFACE_NAME -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

		# 10. Allow outgoing HTTPS
		log_info "Allowing outgoing HTTPS"
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I INPUT -i $INTERFACE_NAME -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

		# 12. Ping from inside to outside
		log_info "Ping from inside to outside"
		iptables -I OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
		iptables -I INPUT -p icmp --icmp-type echo-reply -j ACCEPT

		# 13. Ping from outside to inside
		log_info "Ping from outside to inside"
		iptables -I INPUT -p icmp --icmp-type echo-request -j ACCEPT
		iptables -I OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

		# 14. Allow loopback access
		log_info "Allowing loopback access"
		iptables -I INPUT -i lo -j ACCEPT
		iptables -I OUTPUT -o lo -j ACCEPT

		# 15. Allow packets from internal network to reach external network.
		# if eth1 is connected to external network (internet)
		# if eth0 is connected to internal network (192.168.1.x)
		# iptables -I FORWARD -i $INTERFACE_NAME -o eth0 -j ACCEPT

		# 16. Allow outbound DNS
		log_info "Allowing outbound DNS"
		iptables -I OUTPUT -p udp -o $INTERFACE_NAME --dport 53 -j ACCEPT
		iptables -I INPUT -p udp -i $INTERFACE_NAME --sport 53 -j ACCEPT

		# 18. Allow rsync from a specific network
		log_info "Allowing rsync from a specific network"
		iptables -I INPUT -i $INTERFACE_NAME -p tcp -s $EXTERNAL_NET --dport 873 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 873 -m state --state ESTABLISHED -j ACCEPT

		# 19. Allow MySQL connection only from a specific network
		log_info "Allowing MySQL connection only from a specific network"
		iptables -I INPUT -i $INTERFACE_NAME -p tcp -s $EXTERNAL_NET --dport 3306 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 3306 -m state --state ESTABLISHED -j ACCEPT

		# 20. Allow Sendmail or Postfix
		log_info "Allowing Sendmail or Postfix"
		iptables -I INPUT -i $INTERFACE_NAME -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT

		# 21. Allow IMAP and IMAPS
		log_info "Allowing IMAP and IMAPS"
		iptables -I INPUT -i $INTERFACE_NAME -p tcp --dport 143 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 143 -m state --state ESTABLISHED -j ACCEPT

		iptables -I INPUT -i $INTERFACE_NAME -p tcp --dport 993 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 993 -m state --state ESTABLISHED -j ACCEPT

		# 22. Allow POP3 and POP3S
		log_info "Allowing POP3 and POP3S"
		iptables -I INPUT -i $INTERFACE_NAME -p tcp --dport 110 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 110 -m state --state ESTABLISHED -j ACCEPT

		iptables -I INPUT -i $INTERFACE_NAME -p tcp --dport 995 -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -I OUTPUT -o $INTERFACE_NAME -p tcp --sport 995 -m state --state ESTABLISHED -j ACCEPT

		# 23. Prevent DoS attack
		log_info "Preventing DoS attack"
		iptables -I INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

		# 24. Port forwarding 80 to 8080
		# iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080 # Can not access from outside
				
		# iptables-save > /etc/sysconfig/iptables
		# log_info "Saved iptables into /etc/sysconfig/iptables"
		service iptables save
		log_info "Saved iptables successfully!"
		iptables -nvL
		systemctl restart iptables
		iptables-restore < /etc/sysconfig/iptables
		log_info "Restored iptables successfully!"
		# systemctl start firewalld
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: ssh_hardening
#   DESCRIPTION: Install and harden ssh server.
#     PARAMETER: ---
#========================================================================
function ssh_hardening ()
{
    log_info "Installing ssh server."
    install_packages 'openssh-server'

    log_info "Backing up ssh configuration files."
    backup_file ${SSHD_CONFIG}
    backup_file ${SSHD_PAM}
	
	log_info "Stopping ssh server."
    systemctl stop sshd

    log_info "Changing ssh port from input."
	SSH_PORT="22"
    log_info "Configuring ssh port to ${SSH_PORT}."
    set_parameter "Port" ${SSH_PORT} ${SSHD_CONFIG}

    log_info "Disabling the banner message from motd."
    comment_parameter "^session[ ]*optional[ ]*pam_motd.so[ ]*motd=\/run\/motd.dynamic" ${SSHD_PAM}
    comment_parameter "^session[ ]*optional[ ]*pam_motd.so[ ]*noupdate" ${SSHD_PAM}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.15
    log_info "Configuring the text, that is shown before the authorization when an ssh session is connected."
    backup_file ${ISSUE_NET}
    echo "********************************************************************" > ${ISSUE_NET}
    echo "*                                                                  *" >> ${ISSUE_NET}
    echo "* This system is for the use of authorized users only.  Usage of   *" >> ${ISSUE_NET}
    echo "* this system may be monitored and recorded by system personnel.   *" >> ${ISSUE_NET}
    echo "*                                                                  *" >> ${ISSUE_NET}
    echo "* Anyone using this system expressly consents to such monitoring   *" >> ${ISSUE_NET}
    echo "* and is advised that if such monitoring reveals possible          *" >> ${ISSUE_NET}
    echo "* evidence of criminal activity, system personnel may provide the  *" >> ${ISSUE_NET}
    echo "* evidence from such monitoring to law enforcement officials.      *" >> ${ISSUE_NET}
    echo "*                                                                  *" >> ${ISSUE_NET}
    echo "********************************************************************" >> ${ISSUE_NET}
    set_parameter "Banner" "/etc/issue.net" ${SSHD_CONFIG}

    # log_info "Disabling password authentication."
    # set_parameter "PasswordAuthentication" "no" ${SSHD_CONFIG}

    log_info "Enabling public key authentication."
    set_parameter "PubkeyAuthentication" "yes" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.7
    log_info "Disabling the authentication of throughtrusted hosts via the user."
    set_parameter "HostbasedAuthentication" "no" ${SSHD_CONFIG}
    set_parameter "RhostsRSAAuthentication" "no" ${SSHD_CONFIG}

    log_info "Disabling challenge-response authentication."
    set_parameter "ChallengeResponseAuthentication" "no" ${SSHD_CONFIG}

    log_info "Disabling GSSAPI authentication."
    set_parameter "GSSAPIAuthentication" "no" ${SSHD_CONFIG}

    log_info "Disabling RSA authentication."
    set_parameter "RSAAuthentication" "no" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.6
    log_info "Disabling .rhosts and .shosts files in RhostsRSAAuthentication or HostbasedAuthentication."
    set_parameter "IgnoreRhosts" "yes" ${SSHD_CONFIG}

    log_info "Disabling the use of DNS in SSH."
    set_parameter "UseDNS" "no" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    log_info "Disabling TCP forwarding."
    set_parameter "AllowTcpForwarding" "no" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    log_info "Disabling sending TCP keepalive messages to the other side."
    set_parameter "TCPKeepAlive" "no" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    log_info "Disabling compression."
    set_parameter "Compression" "no" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    log_info "Separating privileges by creating an unprivileged child process to deal with incoming network traffic to SANDBOX."
    set_parameter "UsePrivilegeSeparation" "SANDBOX" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    log_info "Disabling ssh-agent forwarding."
    set_parameter "AllowAgentForwarding" "no" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.2
    log_info "Configuring protocol to version 2."
    set_parameter "Protocol" "2" ${SSHD_CONFIG}

    log_info "Configuring logging levels to verbose."
    set_parameter "LogLevel" "VERBOSE" ${SSHD_CONFIG}

    log_info "Disabling X11 forwarding."
    set_parameter "X11Forwarding" "no" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.5
    # Lynis recommendation [test:SSH-7408]
    log_info "Configuring the maximum number of authentication attempts permitted per connection to 2."
    set_parameter "MaxAuthTries" "2" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    log_info "Configuring the maximum number of open shell, login or subsystem (e.g. sftp) sessions permitted per network connection to 2."
    set_parameter "MaxSessions" "2" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.8
    log_info "Disabling root logins."
    set_parameter "PermitRootLogin" "no" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.11
    log_info "Configuring ciphers and algorithms."
    set_parameter "KexAlgorithms" "curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" ${SSHD_CONFIG}
    set_parameter "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" ${SSHD_CONFIG}
    set_parameter "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" ${SSHD_CONFIG}
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp && mv /etc/ssh/moduli.tmp /etc/ssh/moduli

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.12
    log_info "Configuring the idle timeout interval to 300 seconds ${DECORATION_DIM_ON}(5 minutes)${DECORATION_DIM_OFF}."
    set_parameter "ClientAliveInterval" "300" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.13
    log_info "Configuring the time allowed for successful authentication to the SSH server to 60 seconds ${DECORATION_DIM_ON}(1 minute)${DECORATION_DIM_OFF}."
    set_parameter "LoginGraceTime" "60" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.14
    log_info "Adding current user to ssh group."
	groupadd ssh
    usermod -a -G ssh ${CURRENT_USER}
    log_info "Configuring SSH access only to ${DECORATION_BOLD_ON}\"ssh\"${DECORATION_BOLD_OFF} group."
    set_parameter "AllowGroups" "ssh" ${SSHD_CONFIG}

    log_info "Starting shh service."
    systemctl start sshd
}

#===  FUNCTION  ==========================================================
#          NAME: apache_restart
#   DESCRIPTION: Restart apache web server
#     PARAMETER: ---
#========================================================================
function apache_restart()
{
	sleep 2
	log_info "Apache restart is being executed, please wait..."
	apachectl restart
	if ! apachectl status | grep 'active (running)' 2> /dev/null 1>&2; then
		log_error "Restart apache has failed!"
		# log_error "For more information, please use: sudo journalctl -xe"
		# systemctl status httpd.service
		# journalctl -xe
		_exit
	else
		log_info "Restart apache OK!"
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: append_config
#   DESCRIPTION: Append configs to destination file
#     PARAMETER: 1. config: configuration that is going to append to destination file
#				 2. destination_file: the file that is going to append the configs
#========================================================================
function append_config()
{
	config=$1
	destination_file=$2
	[[ -z "$config" ]] && { log_error "First parameter (config) is empty in function append_config"; _exit; }
	[[ -z "$destination_file" ]] && { log_error "Second parameter (destination_file) is empty in function append_config"; _exit; }
	echo $config >> $destination_file
}

#===  FUNCTION  ==========================================================
#          NAME: replace_configs
#   DESCRIPTION: Replace configs based on passing directory and destination file
#     PARAMETER: 1. directory: Specify the directory of the apache config file
#				 2. destination_file: The file that is going to be applied the configs
#========================================================================
function replace_configs()
{
	directory=$1
	[[ -z "$directory" ]] && { log_error "First parameter (directory) is empty in function replace_configs"; _exit; }
	destination_file=$2
	[[ -z "$destination_file" ]] && { log_error "Second parameter (destination_file) is empty in function replace_configs"; _exit; }
	
	if [ "$directory" == "html" ]; then
		sed -i '/<Directory "\/var\/www\/html">/,/<\/Directory>/ s/Options Indexes FollowSymLinks/Options -Indexes -FollowSymLinks -ExecCGI -Includes/' $destination_file
		sed -i '/<Directory "\/var\/www\/html">/,/<\/Directory>/ s/Require all granted/Require all granted\n\n\t<LimitExcept GET POST HEAD>\n\t\tdeny from all\n\t<\/LimitExcept>\n/' $destination_file
	elif [ "$directory" == "root" ]; then
		sed -i '/<Directory \/>/,/<\/Directory>/ s/AllowOverride none/\tOptions None\n\tOrder Deny,Allow\n\t#Deny from all/' $destination_file
		sed -i '/<Directory \/>/,/<\/Directory>/ s/Require all denied/\tAllowOverride None/' $destination_file
	elif [ "$directory" == "mod_evasive" ]; then
		sed -i '/<IfModule mod_evasive24.c>/,/<\/IfModule>/ s/#DOSEmailNotify      you@yourdomain.com/DOSEmailNotify      labis.papadopoulos@gmail.com/' $destination_file
		dir='/var/www/html/logs'
		[ ! -d "$dir" ] && mkdir -p "$dir"
		sed -i '/<IfModule mod_evasive24.c>/,/<\/IfModule>/ s/#DOSLogDir           "\/var\/lock\/mod_evasive"/DOSLogDir           "\/var\/www\/html\/logs"/' $destination_file
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: mod_security
#   DESCRIPTION: Execute Mod_Security installation and configuration
#     PARAMETER: ---
#========================================================================
function mod_security()
{
	# source: https://devops.ionos.com/tutorials/how-to-configure-modsecurity-and-mod_evasive-for-apache-on-centos-7/,
	# https://artsysops.com/2019/12/17/how-to-harden-apache-web-server-on-centos-7/
	log_info "Is going to install Mod_Security, please wait..."
	install_packages $MOD_SECURITY
	
	apache_restart
	
	backup_file $MOD_SECURITY_CONF
	
	# Installing A Core Rule Set and Configuring Mod_Security
	log_info "Installing A Core Rule Set and Configuring Mod_Security."
	mkdir /etc/httpd/crs-rules
	cd /etc/httpd/crs-rules
	wget --no-check-certificate -c https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/v3.2.0.tar.gz -O master
	tar xzf master
	mv owasp-modsecurity-crs-3.2.0 owasp-modsecurity-crs
	cd owasp-modsecurity-crs/
	cp crs-setup.conf.example crs-setup.conf
	# Enable the below setting in case that is not included all *.conf files in apache httpd.conf config file
#	mod_security_config=$(cat <<EOF
#<IfModule security2_module>
#	Include /etc/httpd/crs-rules/owasp-modsecurity-crs/crs-setup.conf
#	Include /etc/httpd/crs-rules/owasp-modsecurity-crs/rules/*.conf
#</IfModule>	
#EOF
#)
	# append_config "$mod_security_config" $HTTPD_CONF
	append_config $NEW_LINE $HTTPD_CONF	# add new line in httpd.conf file
	
	# We will place our customized directives and we create our own configuration file within the /etc/httpd/modsecurity.d directory
	log_info "We will place our customized directives and we create our own configuration file within the $CUSTOM_CRS_CONF directory."
	cd /etc/httpd/modsecurity.d
	touch custom-crs.conf
	custom_crs_configs=$(cat <<EOF
<IfModule mod_security2.c>
	SecRuleEngine On
	SecRequestBodyAccess On
	SecResponseBodyAccess On 
	SecResponseBodyMimeType text/plain text/html text/xml application/octet-stream 
	SecDataDir /tmp
</IfModule>
EOF
)
	append_config "$custom_crs_configs" $CUSTOM_CRS_CONF
	append_config $NEW_LINE $CUSTOM_CRS_CONF
	cd $PWD
	
	# perform test to mod_security
	log_info "Is going to perform test to Mod_Security."
	mod_security_status_code=`curl -s -o /dev/null -w "%{http_code}" http://localhost -A Nessus`
	if [ "$mod_security_status_code" == "403" ]; then	# 403 Forbidden
		log_info "${COLOR_GREEN}Mod security test passed successfully!${COLOR_DEFAULT}"
	else
		curl -i http://localhost -A Nessus
		log_info "${COLOR_RED}Mod_security test failed! ${COLOR_DEFAULT}"
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: mod_evasive
#   DESCRIPTION: Execute Mod_Evasive installation and configuration
#     PARAMETER: ---
#========================================================================
function mod_evasive()
{
	# source: https://phoenixnap.com/kb/apache-mod-evasive,
	# https://www.tecmint.com/protect-apache-using-mod_security-and-mod_evasive-on-rhel-centos-fedora/
	log_info "Is going to install Mod_Evasive"
	# dnf install -y https://pkgs.dyn.su/el8/base/x86_64/raven-release-1.0-1.el8.noarch.rpm
	# dnf --enablerepo=raven-extras install -y mod_evasive
	
	# wget --no-check-certificate https://pkgs.dyn.su/el8/extras/x86_64/mod_evasive-0:1.10.1-33.el8.x86_64.rpm
	wget --no-check-certificate -O mod_evasive-0_1.10.1-33.el8.x86_64.rpm https://www.dropbox.com/s/8wufr6qz9oud1ys/mod_evasive-0_1.10.1-33.el8.x86_64.rpm?dl=1
	dnf install -y mod_evasive-0_1.10.1-33.el8.x86_64.rpm
	rm -rf mod_evasive-0_1.10.1-33.el8.x86_64.rpm
	
	apache_restart
	
	backup_file	$MOD_EVASIVE_CONF
	# Remove the # sign, then replace you@yourdomain.com with your actual email address
	replace_configs "mod_evasive" $MOD_EVASIVE_CONF
	
	apache_restart
	
	backup_file $MOD_EVASIVE_TEST_SCRIPT
	
	# Apply bug fix to mod_evasive_test_script in order to retrieve 403 Forbidden error
	log_info "Is going to apply a bug fix to mod_evasive test.pl script in order to retrieve 403 Forbidden error"
	sed -i 's/HTTP\/1.0\\n\\n/HTTP\/1.0\\r\\n\\r\\n/g' $MOD_EVASIVE_TEST_SCRIPT
	
	# perform some tests:
	# testing: perl /usr/share/doc/mod_evasive/test.pl
	log_info "Is going to execute Mod_Evasive test.pl script to test Mod_Evasive module"
	forbidden_count=`perl $MOD_EVASIVE_TEST_SCRIPT | grep 'HTTP/1.1 403 Forbidden' | wc -l`
	log_info "Retrieved forbidden_count: $forbidden_count"
	if [ "$forbidden_count" -gt "80" ]; then
		log_info "${COLOR_GREEN}Mod Evasive test passed successfully! ${COLOR_DEFAULT}"
	else
		log_info "${COLOR_RED}Mod_evasive test failed! ${COLOR_DEFAULT}"
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: apache_hardening
#   DESCRIPTION: Execute Apache hardening processes
#     PARAMETER: ---
#========================================================================
function apache_hardening()
{
	# Apache hardening source: https://devops.ionos.com/tutorials/how-to-harden-the-apache-web-server-on-centos-7/
	backup_file $HTTPD_CONF
	
	#Keep Apache Up To Date
	log_info "Keeping Apache Up To Date"
	yum update httpd -y
	
	# Hide The Apache Version
	log_info "Is going to hide the apache version"
	append_config "ServerSignature Off" $HTTPD_CONF
	append_config "ServerTokens Prod" $HTTPD_CONF
	
	# Secure Apache From Clickjacking Attacks
	log_info "Securing Apache From Clickjacking Attacks"
	append_config "Header append X-FRAME-OPTIONS \"SAMEORIGIN\"" $HTTPD_CONF
	
	# Disable ETag
	log_info "Disabling ETag"
	append_config "FileETag None" $HTTPD_CONF
	
	# Disable TRACE and TRACK methods
	log_info "Disabling TRACE and TRACK methods"
	append_config "TraceEnable Off" $HTTPD_CONF
	append_config $NEW_LINE $HTTPD_CONF	# add new line in httpd.conf file
	
	# Turn Off Directory Listing (add: -Indexes in Options)
	log_info "Turning Off Directory Listing"
	# Disable Apache's FollowSymLinks (add: -FollowSymLinks in Options)
	log_info "Disabling Apache's FollowSymLinks"
	# Turn Off Server-Side Includes (SSI) And CGI Execution (add: -ExecCGI -Includes in Options)
	log_info "Turning Off Server-Side Includes (SSI) And CGI Execution"
	replace_configs "html" $HTTPD_CONF

	# Turn Off Server-Side Includes (SSI) And CGI Execution for specific web directory and also Limit Request Size
	log_info "Turning Off Server-Side Includes (SSI) And CGI Execution for specific web directory and also Limit Request Size"
	configs=$(cat <<EOF
<Directory "/var/www/example.com/">
	Options -Includes -ExecCGI
	LimitRequestBody 204800
</Directory>
EOF
)
	# append_config "$configs" $HTTPD_CONF # TODO check
	append_config $NEW_LINE $HTTPD_CONF # add new line in httpd.conf file
	
	# Disable Unnecessary Modules
	log_info "Disabling Unnecessary Modules"
	backup_file $BASE_MODULES
	comment_parameter "LoadModule info_module modules\/mod_info.so" $BASE_MODULES
	comment_parameter "LoadModule userdir_module modules\/mod_userdir.so" $BASE_MODULES
	
	# Disallow Browsing Outside The Document Root
	log_info "Disallowing Browsing Outside The Document Root"
	replace_configs "root" $HTTPD_CONF
	
	# Secure Apache From XSS Attacks (add in IfModule mod_headers.c: Header set X-XSS-Protection "1; mode=block")
	log_info "Securing Apache From XSS Attacks"
	# Protect Cookies With HTTPOnly Flag (add in IfModule mod_headers.c: Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure)
	log_info "Protecting Cookies With HTTPOnly Flag"
	mod_headers_conf=$(cat <<EOF
<IfModule mod_headers.c>
	Header set X-XSS-Protection "1; mode=block"
	Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
</IfModule>
EOF
)
	append_config "$mod_headers_conf" $HTTPD_CONF
	append_config $NEW_LINE $HTTPD_CONF # add new line in httpd.conf file
}

#===  FUNCTION  ==========================================================
#          NAME: expect_script
#   DESCRIPTION: Used in secure_bootloader for password creation
#     PARAMETER: ---
#========================================================================
function expect_script(){
    cat <<EOF
    log_user 0
    spawn  ${MKPASSWD}
    sleep 0.33
    expect  "Enter password: " {
        send "$GRUB_PASSPHRASE"
        send "\n"
    }
    sleep 0.33
    expect "Reenter password: " {
        send "$GRUB_PASSPHRASE"
        send "\n"
    }
    sleep 0.33
    expect eof {
        puts "\$expect_out(buffer)"
    }
    exit 0
EOF
}

#===  FUNCTION  ==========================================================
#          NAME: secure_bootloader
#   DESCRIPTION: Enable superuser and create password on bootloader
#     PARAMETER: ---
#========================================================================
function secure_bootloader()
{
	backup_file $DEFAULTGRUB
	backup_file $GRUB_40_CUSTOM
	log_info "Securing bootloader"
	if [ -n "$GRUB_PASSPHRASE" ]; then
		sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="--users $GRUB_SUPERUSER"/' "$DEFAULTGRUB"
		echo "set superusers=$GRUB_SUPERUSER" >> $GRUB_40_CUSTOM
		GRUB_PASS=$(expect_script "$1" | $EXPECT | sed -e "/^\r$/d" -e "/^$/d" -e "s/.* \(.*\)/\1/")
		echo "password_pbkdf2 $GRUB_SUPERUSER $GRUB_PASS" >> $GRUB_40_CUSTOM
		echo 'export superusers' >> $GRUB_40_CUSTOM
		log_info "Secure Bootloader finished successfully!"
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: disable_unneeded_modules
#   DESCRIPTION: Disable unneeded kernel and file systems modules, 
#				 disable also unwanted services and protocols
#     PARAMETER: ---
#========================================================================
function disable_unneeded_modules()
{
	# ok
	# Disable unwanted services
	log_info "Is going to disable unwanted services"
	for disable in $UNW_SERVICES; do
		systemctl disable $disable
	done
	
	# ok
	# Disable unneeded kernel modules
	log_info "Is going to disable unneeded kernel modules"
	for disable in $MOD; do
		if ! grep -q "$disable" "$DISABLEMOD" 2> /dev/null; then
			echo "install $disable /bin/true" >> "$DISABLEMOD"
		fi
	done
	
	# ok
	# Disable unneeded file systems
	log_info "Is going to disable unneeded file systems"
	for disable in $UNW_FS; do
		if ! grep -q "$disable" "$DISABLEFS" 2> /dev/null; then
			echo "install $disable /bin/true" >> "$DISABLEFS"
		fi
	done
	
	# ok
	# Disabling unwanded protocols
	log_info "Is going to disable unwanded protocols"
	for disable in $UNW_PROT; do
	 	if ! grep -q "$disable" "$DISABLENET" 2> /dev/null; then
	 		echo "install $disable /bin/true" >> "$DISABLENET"
	 	fi
	done
	
	# Disable core dumps
	#log_info "Is going to disabling coredump" # Causes error on mod_evasive and mod_security testing
	#backup_file $SYSTEMCONF
	#sed -i 's/^#DumpCore=.*/DumpCore=no/' "$SYSTEMCONF"
	#sed -i 's/^#CrashShell=.*/CrashShell=no/' "$SYSTEMCONF"
	#sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$SYSTEMCONF"
	#sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=100/' "$SYSTEMCONF"
	#sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=100/' "$SYSTEMCONF"
	backup_file $USERCONF
	sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$USERCONF"
	sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=100/' "$USERCONF"
	sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=100/' "$USERCONF"

	systemctl daemon-reload

	if test -f "$COREDUMPCONF"; then
		backup_file $COREDUMPCONF
		log_info "Fixing Systemd/coredump.conf"
		sed -i 's/^#Storage=.*/Storage=none/' "$COREDUMPCONF"

		systemctl restart systemd-journald
		log_info "systemd-journald restarted successfully!"
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: secure_mounts
#   DESCRIPTION: Disable the execution rights in shared memory in files /tmp, /var/tmp and /dev/shm
#     PARAMETER: ---
#========================================================================
function secure_mounts()
{
	log_info "Is going to secure mounts"

cat > /etc/systemd/system/tmp.mount <<EOF
# /etc/systemd/system/default.target.wants/tmp.mount -> ../tmp.mount

[Unit]
Description=Temporary Directory
Documentation=man:hier(7)
Before=local-fs.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nosuid,nodev
EOF

	sed -i '/floppy/d' /etc/fstab

	if [ -e   ]; then
		sed -i '/^\/tmp/d' /etc/fstab

		for t in $(mount | grep -e " /tmp " -e " /var/tmp " -e " /dev/shm " | awk '{print $3}'); do
			umount $t
		done

		mkdir /etc/systemd/system/default.target.wants

		sed -i '/[[:space:]]\/tmp[[:space:]]/d' /etc/fstab

		ln -s /etc/systemd/system/tmp.mount /etc/systemd/system/default.target.wants/tmp.mount
		sed -i 's/Options=.*/Options=mode=1777,strictatime,nodev,nosuid/' /etc/systemd/system/tmp.mount

		cp /etc/systemd/system/tmp.mount /etc/systemd/system/var-tmp.mount
		sed -i 's/\/tmp/\/var\/tmp/g' /etc/systemd/system/var-tmp.mount
		ln -s /etc/systemd/system/var-tmp.mount /etc/systemd/system/default.target.wants/var-tmp.mount

		cp /etc/systemd/system/tmp.mount /etc/systemd/system/dev-shm.mount
		sed -i 's/\/tmp/\/dev\/shm/g' /etc/systemd/system/dev-shm.mount
		ln -s /etc/systemd/system/dev-shm.mount /etc/systemd/system/default.target.wants/dev-shm.mount
		sed -i 's/Options=.*/Options=mode=1777,strictatime,noexec,nosuid/' /etc/systemd/system/dev-shm.mount

		chmod 0644 /etc/systemd/system/tmp.mount
		chmod 0644 /etc/systemd/system/var-tmp.mount
		chmod 0644 /etc/systemd/system/dev-shm.mount

		systemctl daemon-reload
	else
		log_error '/etc/systemd/system/tmp.mount was not found.'
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: configure_sysctl_params
#   DESCRIPTION: Security configurations in sysctl params
#     PARAMETER: ---
#========================================================================
function configure_sysctl_params()
{
	log_info "Is going to configure sysctl parameters"
	IFS='
'
	backup_file $SYSCTL
	
	append_config "fs.protected_hardlinks = 1" $SYSCTL
	append_config "fs.protected_symlinks = 1" $SYSCTL
	append_config "fs.suid_dumpable = 0" $SYSCTL
	append_config "kernel.core_uses_pid = 1" $SYSCTL
	append_config "kernel.kptr_restrict = 2" $SYSCTL
	append_config "kernel.panic = 60" $SYSCTL
	append_config "kernel.panic_on_oops = 60" $SYSCTL
	append_config "kernel.perf_event_paranoid = 2" $SYSCTL
	append_config "kernel.randomize_va_space = 2" $SYSCTL
	append_config "kernel.sysrq = 0" $SYSCTL
	append_config "kernel.yama.ptrace_scope = 1" $SYSCTL
	append_config "net.ipv4.conf.all.accept_redirects = 0" $SYSCTL
	append_config "net.ipv4.conf.all.accept_source_route = 0" $SYSCTL
	append_config "net.ipv4.conf.all.log_martians = 1" $SYSCTL
	append_config "net.ipv4.conf.all.rp_filter = 1" $SYSCTL
	append_config "net.ipv4.conf.all.secure_redirects = 0" $SYSCTL
	append_config "net.ipv4.conf.all.send_redirects = 0" $SYSCTL
	append_config "net.ipv4.conf.default.accept_redirects = 0" $SYSCTL
	append_config "net.ipv4.conf.default.accept_source_route = 0" $SYSCTL
	append_config "net.ipv4.conf.default.log_martians = 1" $SYSCTL
	append_config "net.ipv4.conf.default.rp_filter= 1" $SYSCTL
	append_config "net.ipv4.conf.default.secure_redirects = 0" $SYSCTL
	append_config "net.ipv4.conf.default.send_redirects = 0" $SYSCTL
	append_config "net.ipv4.icmp_echo_ignore_all = 1" $SYSCTL
	append_config "net.ipv4.icmp_echo_ignore_broadcasts = 1" $SYSCTL
	append_config "net.ipv4.icmp_ignore_bogus_error_responses = 1" $SYSCTL
	append_config "net.ipv4.ip_forward = 0" $SYSCTL
	append_config "net.ipv4.tcp_max_syn_backlog = 2048" $SYSCTL
	append_config "net.ipv4.tcp_rfc1337 = 1" $SYSCTL
	append_config "net.ipv4.tcp_synack_retries = 2" $SYSCTL
	append_config "net.ipv4.tcp_syncookies = 1" $SYSCTL
	append_config "net.ipv4.tcp_syn_retries = 5" $SYSCTL
	append_config "net.ipv4.tcp_timestamps = 0" $SYSCTL
	append_config "net.ipv4.conf.all.forwarding = 0" $SYSCTL
	append_config "net.ipv6.conf.all.disable_ipv6 = 1" $SYSCTL
	append_config "net.ipv6.conf.default.disable_ipv6 = 1" $SYSCTL
	append_config "net.ipv6.conf.lo.disable_ipv6 = 1" $SYSCTL
	append_config "net.ipv6.conf.all.use_tempaddr = 2" $SYSCTL
	append_config "net.ipv6.conf.all.accept_ra = 0" $SYSCTL
	append_config "net.ipv6.conf.all.accept_redirects = 0" $SYSCTL
	append_config "net.ipv6.conf.default.accept_ra = 0" $SYSCTL
	append_config "net.ipv6.conf.default.accept_ra_defrtr = 0" $SYSCTL
	append_config "net.ipv6.conf.default.accept_ra_pinfo = 0" $SYSCTL
	append_config "net.ipv6.conf.default.accept_redirects = 0" $SYSCTL
	append_config "net.ipv6.conf.default.autoconf = 0" $SYSCTL
	append_config "net.ipv6.conf.default.dad_transmits = 0" $SYSCTL
	append_config "net.ipv6.conf.default.max_addresses = 1" $SYSCTL
	append_config "net.ipv6.conf.default.router_solicitations = 0" $SYSCTL
	append_config "net.ipv6.conf.default.use_tempaddr = 2" $SYSCTL
	append_config "net.ipv6.conf.all.forwarding = 0" $SYSCTL
	append_config "net.netfilter.nf_conntrack_max = 2000000" $SYSCTL
	append_config "net.netfilter.nf_conntrack_tcp_loose = 0" $SYSCTL

	# sed -i '/net.ipv6.conf.eth0.accept_ra_rtr_pref/d' "$SYSCTL"

	for i in $(arp -n -a | awk '{print $NF}' | sort | uniq); do
		# echo "net.ipv6.conf."$i".accept_ra_rtr_pref = 0"
		append_config "net.ipv6.conf.$i.accept_ra_rtr_pref = 0" $SYSCTL
	done

	echo 1048576 > /sys/module/nf_conntrack/parameters/hashsize

	chmod 0600 "$SYSCTL"
	IFS=''
	systemctl restart systemd-sysctl
}

#===  FUNCTION  ==========================================================
#          NAME: configure_user_limits
#   DESCRIPTION: Configuring user access limits in production apache web servers
#     PARAMETER: ---
#========================================================================
function configure_user_limits()
{
	# Configure user security limits
	log_info "Is going to configure user security limits"
	backup_file $LIMITSCONF
	
	sed -i 's/^# End of file*//' "$LIMITSCONF"
	append_config "* hard maxlogins 10" $LIMITSCONF
	append_config "* hard core 0" $LIMITSCONF
	append_config "* soft nproc 100" $LIMITSCONF
	append_config "* hard nproc 150" $LIMITSCONF
	append_config "# End of file" $LIMITSCONF
}

#===  FUNCTION  ==========================================================
#          NAME: remove_suid_bits
#   DESCRIPTION: Remove suid bits in some files to avoid root execution of these files
#     PARAMETER: ---
#========================================================================
function remove_suid_bits()
{
	# Remove suid bits
	log_info "Is going to remove suid bits"

	for p in /bin/fusermount /bin/mount /bin/ping /bin/ping6 /bin/su /bin/umount \
			 /usr/bin/bsd-write /usr/bin/chage /usr/bin/chfn /usr/bin/chsh \
			 /usr/bin/mlocate /usr/bin/mtr /usr/bin/newgrp /usr/bin/pkexec \
			 /usr/bin/traceroute6.iputils /usr/bin/wall /usr/sbin/pppd;
	do
		if [ -e "$p" ]; then
			oct=$(stat -c "%a" $p |sed 's/^4/0/')	# 0755
			ug=$(stat -c "%U:%G" $p)				# root:root
			chmod $oct $p
			chown $ug $p
			chmod -s $p	# clear the bits with symbolic modes like
		fi
	done

	for SHELL in $(cat /etc/shells); do
		if [ -x "$SHELL" ]; then
			chmod -s "$SHELL"
		fi
	done
}

#===  FUNCTION  ==========================================================
#          NAME: configure_umask
#   DESCRIPTION: Apply strict permissions on files and folders by configuring system umask to '027'
#     PARAMETER: ---
#========================================================================
function configure_umask()
{
	# Set umask
	log_info "Is going to set umask to 027"
	
	if ! grep -q -i "umask" "/etc/profile" 2> /dev/null; then
		backup_file $ETC_PROFILE
		append_config "umask 027" $ETC_PROFILE
	fi

	if ! grep -q -i "umask" "/etc/bashrc" 2> /dev/null; then
		backup_file $ETC_BASHRC
		append_config "umask 027" $ETC_BASHRC
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: secure_rhosts_hosts_equiv
#   DESCRIPTION: Delete configs for possible remote access to apache web server
#     PARAMETER: ---
#========================================================================
function secure_rhosts_hosts_equiv()
{
	# Secure user and services host files
	log_info "Is going to secure .rhosts and hosts.equiv"

	for dir in $(awk -F ":" '{print $6}' /etc/passwd); do
		find "$dir" \( -name "hosts.equiv" -o -name ".rhosts" \) -exec rm -f {} \; 2> /dev/null
	done
		
	if [[ -f /etc/hosts.equiv ]]; then
		rm /etc/hosts.equiv
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: configure_tcp_wrappers
#   DESCRIPTION: Configuring TCP wrappers for Centos services access control
#     PARAMETER: ---
#========================================================================
function configure_tcp_wrappers()
{
	# Configure TCP Wrappers
	log_info "Is going to configure TCP Wrappers"

	append_config "ALL: LOCAL, 127.0.0.1" $HOSTS_ALLOW
	append_config "ALL: PARANOID" $HOSTS_DENY
	chmod 644 $HOSTS_ALLOW
	chmod 644 $HOSTS_DENY
}

#===  FUNCTION  ==========================================================
#          NAME: configure_logindefs
#   DESCRIPTION: Configuring accounts termination policy
#     PARAMETER: ---
#========================================================================
function configure_logindefs()
{
	# Configure logindefs
	log_info "Is going to configure accounts termination policy"

	sed -i 's/^.*LOG_OK_LOGINS.*/LOG_OK_LOGINS\t\tyes/' "$LOGINDEFS"
	sed -i 's/^UMASK.*/UMASK\t\t077/' "$LOGINDEFS"
	sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t\t7/' "$LOGINDEFS"
	sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t\t30/' "$LOGINDEFS"
	sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' "$LOGINDEFS"
	sed -i 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' "$LOGINDEFS"
	sed -i 's/^# SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS\t\t10000/' "$LOGINDEFS"
}

#===  FUNCTION  ==========================================================
#          NAME: configure_loginconf
#   DESCRIPTION: Configuring lock sessions and automatic users logout
#     PARAMETER: ---
#========================================================================
function configure_loginconf()
{
	# Configure loginconf
	log_info "Is going to configure lock sessions and automatic users logout"

	sed -i 's/^#KillUserProcesses=no/KillUserProcesses=1/' "$LOGINDCONF"
	sed -i 's/^#KillExcludeUsers=root/KillExcludeUsers=root/' "$LOGINDCONF"
	sed -i 's/^#IdleAction=ignore/IdleAction=lock/' "$LOGINDCONF"
	sed -i 's/^#IdleActionSec=30min/IdleActionSec=15min/' "$LOGINDCONF"
	sed -i 's/^#RemoveIPC=yes/RemoveIPC=yes/' "$LOGINDCONF"

	systemctl daemon-reload
}

#===  FUNCTION  ==========================================================
#          NAME: locking_new_users
#   DESCRIPTION: Lock new users
#     PARAMETER: ---
#========================================================================
function locking_new_users()
{
	# Locking new user shell by default
	log_info "Is going to lock new users"
	sed -i 's/SHELL=.*/SHELL=\/bin\/false/' "$USERADD"
	sed -i 's/^# INACTIVE=.*/INACTIVE=35/' "$USERADD"
}

#===  FUNCTION  ==========================================================
#          NAME: remove_unneeded_users
#   DESCRIPTION: Delete unnecessary users
#     PARAMETER: ---
#========================================================================
function remove_unneeded_users()
{
	# Remove unneeded users
	log_info "Is going to remove unwanted users"

	for users in games gnats irc list news uucp; do
		userdel -r "$users" 2> /dev/null
	done
}

#===  FUNCTION  ==========================================================
#          NAME: disable_ipv6
#   DESCRIPTION: Disable IPv6 protocol in case that is not used for security reasons
#     PARAMETER: ---
#========================================================================
function disable_ipv6()
{
	log_info "Is going to disable ipv6"
	backup_file $NETCONFIG
	sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ipv6.disable=1"/' "$DEFAULTGRUB"
	sed '/udp6/d' $NETCONFIG
	sed '/tcp6/d' $NETCONFIG
}

#===  FUNCTION  ==========================================================
#          NAME: configure_dns_resovlers
#   DESCRIPTION: Configure secure DNS resolvers to avoid man-in-the-middle attacks
#     PARAMETER: ---
#========================================================================
function configure_dns_resovlers()
{
	# Configure DNS resolvers
	log_info "Is going to confugure secure DNS resolvers"

	dnsarray=( $(grep nameserver /etc/resolv.conf | sed 's/nameserver//g') )
	dnslist=${dnsarray[@]}

	backup_file $RESOLVEDCONF
	backup_file $NSSWITCH
	sed -i "s/^#DNS=.*/DNS=$dnslist/" "$RESOLVEDCONF"
	sed -i "s/^#FallbackDNS=.*/FallbackDNS=8.8.8.8 8.8.4.4/" "$RESOLVEDCONF"
	sed -i "s/^#DNSSEC=.*/DNSSEC=allow-downgrade/" "$RESOLVEDCONF"
	sed -i '/^hosts:/ s/files dns/files resolve dns/' $NSSWITCH

	systemctl daemon-reload
}

#===  FUNCTION  ==========================================================
#          NAME: lock_cronjobs
#   DESCRIPTION: Disable cron jobs for users
#     PARAMETER: ---
#========================================================================
function lock_cronjobs()
{
	# Lock up cronjobs
	log_info "Is going to locking up cronjobs for users"

	rm /etc/cron.deny 2> /dev/null
	rm /etc/at.deny 2> /dev/null

	echo 'root' > /etc/cron.allow
	echo 'root' > /etc/at.allow

	chown root:root /etc/cron*
	chmod og-rwx /etc/cron*

	chown root:root /etc/at*
	chmod og-rwx /etc/at*

	systemctl mask atd.service
	systemctl stop atd.service
	systemctl daemon-reload
}

#===  FUNCTION  ==========================================================
#          NAME: configure_logrotate
#   DESCRIPTION: Configure logrotate to avoid system corruption from log files
#     PARAMETER: ---
#========================================================================
function configure_logrotate()
{
	log_info "Is going to configure logrotate"
	backup_file $LOGROTATE
	echo '' > $LOGROTATE

	log_rotate_configs=$(cat <<EOF
# see "man logrotate" for details
# rotate log files daily
daily

# use the syslog group by default, since this is the owning group
# of /var/log/syslog.
su root syslog

# keep 7 days worth of backlogs
rotate 7

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
dateext

# compressed log files
compress

# use xz to compress
compresscmd /usr/bin/xz
uncompresscmd /usr/bin/unxz
compressext .xz

# packages drop log rotation information into this directory
include /etc/logrotate.d

# no packages own wtmp and btmp -- we will rotate them here
/var/log/wtmp {
    monthly
    create 0664 root utmp
    minsize 1M
    rotate 1
}

/var/log/btmp {
    missingok
    monthly
    create 0600 root utmp
    rotate 1
}

# system-specific logs may be also be configured here.
EOF
)
	append_config "$log_rotate_configs" $LOGROTATE

	backup_file $JOURNALDCONF
	sed -i 's/^#Storage=.*/Storage=persistent/' "$JOURNALDCONF"
	sed -i 's/^#ForwardToSyslog=.*/ForwardToSyslog=yes/' "$JOURNALDCONF"
	sed -i 's/^#Compress=.*/Compress=yes/' "$JOURNALDCONF"

	systemctl restart systemd-journald
}


# Malware Scanners
#===  FUNCTION  ==========================================================
#          NAME: enable_rkhunter
#   DESCRIPTION: Install, configure and enable rkhunter scanner
#     PARAMETER: ---
#========================================================================
function enable_rkhunter()
{
	log_info "Installation of Rkhunter in progress. Please wait..."
	install_packages $RKHUNTER_PACKAGE
	
	# Enable RKHUNTER (source: https://www.theurbanpenguin.com/install-rkhunter-on-centos-7/)
	log_info "Is going to configure and enable rkhunter scanner"

	# sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="yes"/' "$RKHUNTERCONF"
	# sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="yes"/' "$RKHUNTERCONF"
	sed -i 's/ALLOW_SSH_ROOT_USER=.*/ALLOW_SSH_ROOT_USER=no/g' $RKHUNTERCONF
	append_config "CRON_DAILY_RUN=\"yes\"" $RKHUNTERCONF
	append_config "APT_AUTOGEN=\"yes\"" $RKHUNTERCONF

	rkhunter --propupd
}

#===  FUNCTION  ==========================================================
#          NAME: enable_clamav
#   DESCRIPTION: Install, configure and enable clamav antivirus
#     PARAMETER: ---
#========================================================================
function enable_clamav()
{
	log_info "Installation of Clamav antivirus in progress. Please wait..."
	install_packages $CLAMAV_PACKAGES
	
	log_info "Is going to configure and enable CLAMAV"
	setsebool -P antivirus_can_scan_system 1
	backup_file $CLAMAVCONF
	backup_file $CLAMAVSERVICE
	sed -i 's/#LocalSocket \/run/LocalSocket \/run/g' $CLAMAVCONF
	sed -i 's/scanner (%i) daemon/scanner daemon/g' $CLAMAVSERVICE
	sed -i 's/\/etc\/clamd.d\/%i.conf/\/etc\/clamd.d\/scan.conf/g' $CLAMAVSERVICE
	freshclam

	systemctl enable clamav-freshclam.service
	systemctl start clamav-freshclam.service
	
	mkdir /var/log/clamav/
	touch /var/log/clamav/user_clamscan.log
	cron_clamscan=$(cat <<EOF
#!/bin/bash
# SCAN_DIR="/home"
# LOG_FILE="/var/log/clamav/user_clamscan.log"
/usr/bin/clamscan -i -r /home >> /var/log/clamav/user_clamscan.log
EOF
)
	append_config "$cron_clamscan" $CRON_DAILY_CLAMSCAN
	chmod +x $CRON_DAILY_CLAMSCAN
}

#===  FUNCTION  ==========================================================
#          NAME: aide_ids
#   DESCRIPTION: Install, configure and enable aide IDS
#     PARAMETER: ---
#========================================================================
function aide_ids()
{
	log_info "Installation of Aide IDS in progress. Please wait..."
	install_packages $AIDE_PACKAGE
	
	log_info "Is going to secure Aide"
	backup_file $AIDECONFIG
	sed -i 's/^Checksums =.*/Checksums = sha512/' $AIDECONFIG
	
	log_info "Is going to set Aide postinstall"
	aide --init
	log_info "Building AIDE initial db, please wait..."
	cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2> /dev/null 1>&2
	
	log_info "Enabling AIDE check daily"
	
	aide_check_service=$(cat <<EOF
[Unit]
Description=Aide Check

[Service]
Type=simple
ExecStart=/usr/sbin/aide --check

[Install]
WantedBy=multi-user.target
EOF
)
	append_config "$aide_check_service" $AIDE_CHECK_SERVICE
	
	aide_check_timer=$(cat <<EOF
[Unit]
Description=Aide check every day at midnight

[Timer]
OnCalendar=*-*-* 00:00:00
Unit=/etc/systemd/system/aidecheck.service

[Install]
WantedBy=multi-user.target
EOF
)
	append_config "$aide_check_timer" $AIDE_CHECK_TIMER
	
	chmod 0644 /etc/systemd/system/aidecheck.*

	systemctl reenable aidecheck.timer
	systemctl start aidecheck.timer
	systemctl daemon-reload
}

#===  FUNCTION  ==========================================================
#          NAME: enable_fail2Ban
#   DESCRIPTION: Install, configure and enable Fail2Ban IDS
#     PARAMETER: ---
#========================================================================
function enable_fail2Ban()
{
	log_info "Installation of Fail2Ban IDS in progress. Please wait..."
	install_packages $FAIL2BAN_PACKAGE
	
	log_info "Is going to configure and enable Fail2Ban"
	systemctl enable fail2ban
	systemctl start fail2ban
	
	jail_local=$(cat <<EOF
[ssh]

enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
)
	touch /var/log/auth.log
	append_config "$jail_local" $FAIL2BAN_CONFIG
	systemctl restart fail2ban
	systemctl status fail2ban --no-pager
}

#===  FUNCTION  ==========================================================
#          NAME: check_for_restart
#   DESCRIPTION: Check if reboot needed after system update
#     PARAMETER: ---
#========================================================================
function check_for_restart()
{
	log_info "Is going to check if restart needed"
	restart=`needs-restarting -r >/dev/null && echo $?`
	if [[ ${restart} -ne 0 ]]; then
		log_info "Reboot $HOSTNAME to install kernel or core libs."
	else
		LAST_KERNEL=$(rpm -q --last kernel | perl -pe 's/^kernel-(\S+).*/$1/' | head -1)
		CURRENT_KERNEL=$(uname -r)

		if [[ "${LAST_KERNEL}" != "${CURRENT_KERNEL}" ]]; then
			log_info "Reboot $HOSTNAME to install kernel or core libs."
		else
			log_info "No restart needed!"
		fi
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: auto_cleanup
#   DESCRIPTION: Execute system cleanup of unused libraries
#     PARAMETER: ---
#========================================================================
function auto_cleanup() {
	log_info "Is going to auto cleanup the system from unnecessary packages, please wait..."
	yum autoremove -y
}

#===  FUNCTION  ==========================================================
#          NAME: execute_hardening_process
#   DESCRIPTION: Execute hardening process from step 0 to 27
#     PARAMETER: ---
#========================================================================
function execute_hardening_process()
{
	while true; do
		case $step in
			'0')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				check_prerequisites
				increase_step $step
				save_step $step
			;;
			'1')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				ssh_hardening
				increase_step $step
				save_step $step
			;;
			'2')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				secure_bootloader
				increase_step $step
				save_step $step
			;;
			'3')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				disable_unneeded_modules
				increase_step $step
				save_step $step
			;;
			'4')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				secure_mounts
				increase_step $step
				save_step $step
			;;
			'5')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				configure_sysctl_params
				increase_step $step
				save_step $step
			;;
			'6')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				configure_user_limits
				increase_step $step
				save_step $step
			;;
			'7')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				remove_suid_bits
				increase_step $step
				save_step $step
			;;
			'8')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				secure_rhosts_hosts_equiv
				increase_step $step
				save_step $step
			;;
			'9')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				configure_tcp_wrappers
				increase_step $step
				save_step $step
			;;
			'10')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				configure_logindefs
				increase_step $step
				save_step $step
			;;
			'11')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				configure_loginconf
				increase_step $step
				save_step $step
			;;
			'12')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				locking_new_users
				increase_step $step
				save_step $step
			;;
			'13')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				remove_unneeded_users
				increase_step $step
				save_step $step
			;;
			'14')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				disable_ipv6
				increase_step $step
				save_step $step
			;;
			'15')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				configure_dns_resovlers
				increase_step $step
				save_step $step
			;;
			'16')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				lock_cronjobs
				increase_step $step
				save_step $step
			;;
			'17')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				configure_logrotate
				increase_step $step
				save_step $step
			;;
			'18')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				enable_rkhunter
				increase_step $step
				save_step $step
			;;
			'19')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				enable_clamav
				increase_step $step
				save_step $step
			;;
			'20')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				aide_ids
				increase_step $step
				save_step $step
			;;
			'21')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				enable_fail2Ban
				increase_step $step
				save_step $step
			;;
			'22')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				iptables_hardening
				increase_step $step
				save_step $step
			;;
			'23')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				apache_hardening
				increase_step $step
				save_step $step
			;;
			'24')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				mod_security
				increase_step $step
				save_step $step
			;;
			'25')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				mod_evasive
				increase_step $step
				save_step $step
			;;
			'26')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				auto_cleanup
				increase_step $step
				save_step $step
			;;
			'27')
				state=$(get_value $step)
				log_info "${COLOR_GREEN}Process $step/$max_processes_num, executing state: $state${COLOR_DEFAULT}"
				check_for_restart
				increase_step $step
				save_step $step
			;;
			*)
				log_info "${COLOR_GREEN}End of Apache Hardening Process on Centos8!${COLOR_DEFAULT}"
				_exit
			;;
		esac
	done
}

#===  FUNCTION  ==========================================================
#          NAME: no_check_ssl_certificate
#   DESCRIPTION: Apply no ssl check upon package downloading
#     PARAMETER: ---
#========================================================================
function no_check_ssl_certificate()
{
	# echo insecure >> ~/.curlrc
	if ! cat /etc/yum.conf | grep -i 'sslverify=false' 2> /dev/null 1>&2; then
		append_config "sslverify=false" "/etc/yum.conf"
	fi
}

#===  FUNCTION  ==========================================================
#          NAME: main
#   DESCRIPTION: Main method of centos8-apache-hardening script
#     PARAMETER: ---
#========================================================================
function main()
{
	no_check_ssl_certificate
	script_logo
	# Apache installation source: https://www.linode.com/docs/guides/how-to-install-apache-web-server-centos-8/
	if [ $DEV -eq 1 ]; then # make clean up
		log_info "Stared script in DEV mode"
		rm -rf $FILE
		rm -rf /tmp/centos8-apache-hardening.lok
		rm -rf /etc/httpd/crs-rules
		rm -rf $CUSTOM_CRS_CONF
		rm -rf $DISABLEMOD
		rm -rf $DISABLEFS
		rm -rf $DISABLENET
		rm -rf /etc/systemd/system/tmp.mount
		rm -rf /etc/systemd/system/var-tmp.mount
		rm -rf /etc/systemd/system/dev-shm.mount
		rm -rf /etc/systemd/system/default.target.wants/
		rm -rf $CRON_DAILY_CLAMSCAN
		rm -rf /var/log/clamav/
		rm -rf $AIDE_CHECK_SERVICE
		rm -rf $AIDE_CHECK_TIMER
		rm -rf $FAIL2BAN_CONFIG
		rm -rf $FAIL2BAN_SERVICE_SYMLINK
		cp $HTTPD_CONF.bak $HTTPD_CONF 2> /dev/null 1>&2 && rm -rf $HTTPD_CONF.bak
		cp $BASE_MODULES.bak $BASE_MODULES 2> /dev/null 1>&2 && rm -rf $BASE_MODULES.bak
		cp $MOD_EVASIVE_CONF.bak $MOD_EVASIVE_CONF 2> /dev/null 1>&2 && rm -rf $MOD_EVASIVE_CONF.bak
		cp $MOD_SECURITY_CONF.bak $MOD_SECURITY_CONF 2> /dev/null 1>&2 && rm -rf $MOD_SECURITY_CONF.bak
		cp $SSHD_CONFIG.bak $SSHD_CONFIG 2> /dev/null 1>&2 && rm -rf $SSHD_CONFIG.bak
		cp $SSHD_PAM.bak $SSHD_PAM 2> /dev/null 1>&2 && rm -rf $SSHD_PAM.bak
		cp $ISSUE_NET.bak $ISSUE_NET 2> /dev/null 1>&2 && rm -rf $ISSUE_NET.bak
		cp $DEFAULTGRUB.bak $DEFAULTGRUB 2> /dev/null 1>&2 && rm -rf $DEFAULTGRUB.bak
		cp $GRUB_40_CUSTOM.bak $GRUB_40_CUSTOM 2> /dev/null 1>&2 && rm -rf $GRUB_40_CUSTOM.bak
		cp $SYSTEMCONF.bak $SYSTEMCONF 2> /dev/null 1>&2 && rm -rf $SYSTEMCONF.bak
		cp $USERCONF.bak $USERCONF 2> /dev/null 1>&2 && rm -rf $USERCONF.bak
		cp $COREDUMPCONF.bak $COREDUMPCONF 2> /dev/null 1>&2 && rm -rf $COREDUMPCONF.bak
		cp $SYSCTL.bak $SYSCTL 2> /dev/null 1>&2 && rm -rf $SYSCTL.bak
		cp $LIMITSCONF.bak $LIMITSCONF 2> /dev/null 1>&2 && rm -rf $LIMITSCONF.bak
		cp $ETC_PROFILE.bak $ETC_PROFILE 2> /dev/null 1>&2 && rm -rf $ETC_PROFILE.bak
		cp $ETC_BASHRC.bak $ETC_BASHRC 2> /dev/null 1>&2 && rm -rf $ETC_BASHRC.bak
		cp $NETCONFIG.bak $NETCONFIG 2> /dev/null 1>&2 && rm -rf $NETCONFIG.bak
		cp $RESOLVEDCONF.bak $RESOLVEDCONF 2> /dev/null 1>&2 && rm -rf $RESOLVEDCONF.bak
		cp $NSSWITCH.bak $NSSWITCH 2> /dev/null 1>&2 && rm -rf $NSSWITCH.bak
		cp $CLAMAVCONF.bak $CLAMAVCONF 2> /dev/null 1>&2 && rm -rf $CLAMAVCONF.bak
		cp $CLAMAVSERVICE.bak $CLAMAVSERVICE 2> /dev/null 1>&2 && rm -rf $CLAMAVSERVICE.bak
		cp $AIDECONFIG.bak $AIDECONFIG 2> /dev/null 1>&2 && rm -rf $AIDECONFIG.bak
		cp $LOGROTATE.bak $LOGROTATE 2> /dev/null 1>&2 && rm -rf $LOGROTATE.bak
		cp $JOURNALDCONF.bak $JOURNALDCONF 2> /dev/null 1>&2 && rm -rf $JOURNALDCONF.bak
	fi
	acquire_lock
	retrieve_step
	execute_hardening_process
}

main "$@"
