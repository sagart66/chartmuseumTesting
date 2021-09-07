#!/bin/bash
set -x 
#1.1.2 Ensure /tmp is configured
systemctl unmask tmp.mount; 
systemctl enable tmp.mount;
echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime" >>/etc/fstab;

echo "[Mount] " >>/etc/systemd/system/local-fs.target.wants/tmp.mount;
echo "What=tmpfs " >>/etc/systemd/system/local-fs.target.wants/tmp.mount;
echo "Where=/tmp " >>/etc/systemd/system/local-fs.target.wants/tmp.mount;
echo "Type=tmpfs " >>/etc/systemd/system/local-fs.target.wants/tmp.mount;
echo "Options=mode=1777,strictatime,noexec,nodev,nosuid " >>/etc/systemd/system/local-fs.target.wants/tmp.mount;

#systemctl enable tmp.mount;



#1.1.17 Ensure noexec option set on /dev/shm partition
mount -o remount,noexec /dev/shm;
echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab;

#1.7.1.1 Ensure message of the day is configured properly
echo "Authorized uses only. All activity may be monitored and reported." >/etc/motd;
echo "Authorized uses only. All activity may be monitored and reported." >/etc/issue;
echo "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net;


#2.2.4 Ensure telnet client is not installed
yum -y remove telnet ;

sed -i -r 's/0net.ipv4.conf.default.send_redirects/net.ipv4.conf.default.send_redirects/' /etc/sysctl.conf;

echo "net.ipv4.conf.all.rp_filter = 1 " >>/etc/sysctl.conf;
echo "net.ipv4.conf.default.rp_filter = 1 " >>/etc/sysctl.conf;
sysctl -w net.ipv4.conf.all.rp_filter=1 ;
sysctl -w net.ipv4.conf.default.rp_filter=1 ;

cp /etc/group /etc/group_cp;
#5.6 Ensure access to the su command is restricted
echo "auth required pam_wheel.so use_uid" >>/etc/pam.d/su;
echo "wheel:x:10:root,ec2-user" >>/etc/group

#5.2.13 Ensure only strong ciphers are used
echo "Ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com" >>/etc/ssh/sshd_config;
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >>/etc/ssh/sshd_config;
echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchangesha256" >>/etc/ssh/sshd_config;

echo "AllowUsers ec2-user">>/etc/ssh/sshd_config;
echo "AllowGroups ec2-user">>/etc/ssh/sshd_config;
echo "DenyUsers test" >>/etc/ssh/sshd_config;
echo "DenyGroups test" >>/etc/ssh/sshd_config;

#echo "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900 " >> /etc/pam.d/password-auth;
#echo "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900 " >> /etc/pam.d/password-auth;
#echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900 " >> /etc/pam.d/password-auth;

#echo "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900 " >>/etc/pam.d/system-auth;
#echo "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900 " >>/etc/pam.d/system-auth;
#echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900 " >>/etc/pam.d/system-auth;


#5.4.4 Ensure default user umask is 027 or more restrictive
sed -i -r 's/umask 002/umask 077/' /etc/bashrc;
sed -i -r 's/umask 002/umask 077/' /etc/profile;
sed -i -r 's/umask 027/umask 077/' /etc/bashrc;
sed -i -r 's/umask 027/umask 077/' /etc/profile;

#sed -i -r 's/umask 022/umask 027/' /etc/profile.d/bash_completion.sh;
#sed -i -r 's/umask 022/umask 027/' /etc/profile.d/colorgrep.sh;
#sed -i -r 's/umask 022/umask 027/' /etc/profile.d/less.sh;
#sed -i -r 's/umask 022/umask 027/' /etc/profile.d/which2.sh;
#sed -i -r 's/umask 022/umask 027/' /etc/profile.d/vim.sh;
#sed -i -r 's/umask 022/umask 027/' /etc/profile.d/lang.sh;
#sed -i -r 's/umask 022/umask 027/' /etc/profile.d/256term.sh;
#sed -i -r 's/umask 022/umask 027/' /etc/profile.d/colorls.sh;

#Ensure password expiration is 365 days or less
#echo "PASS_MAX_DAYS 90" >>/etc/login.defs;
#chage --maxdays 90 ec2-user;
chage --maxdays 90 root;

#Ensure minimum days between password changes is 7 or more
echo "PASS_MIN_DAYS 7 " >>/etc/login.defs;
chage --mindays 7 ec2-user;
chage --mindays 7 root;

#Ensure password expiration warning days is 7 or more
echo "PASS_WARN_AGE 7" >>/etc/login.defs;
chage --warndays 7 ec2-user;
chage --warndays 7 root;

#Ensure inactive password lock is 30 days or less
useradd -D -f 30;
#chage --inactive 30 test;

#Ensure the SELinux state is enforcing
#echo "SELINUX=enforcing" >>/etc/selinux/config;

#Ensure no unconfined daemons exist
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' >>damon_backgroup_running

#3.6 Disable IPv6
cp  /etc/default/grub_cp  /etc/default/grub;
echo "" >>/etc/default/grub; echo  'GRUB_CMDLINE_LINUX="ipv6.disable=1"' >>/etc/default/grub;
grub2-mkconfig -o /boot/grub2/grub.cfg;



# Ensure IP forwarding is disabled
#cp /etc/sysctl.conf /etc/sysctl.conf_cp;
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf ;
echo "net.ipv6.conf.all.forwarding = 0" >>/etc/sysctl.conf ;
sysctl -w net.ipv4.ip_forward=0;
sysctl -w net.ipv6.conf.all.forwarding=0;


 

 sysctl -w net.ipv4.conf.all.send_redirects=0
 sysctl -w net.ipv4.conf.default.send_redirects=0 
 

#Ensure packet redirect sending is disabled
echo "net.ipv4.conf.all.send_redirects = 0 " >> /etc/sysctl.conf ;
echo "net.ipv4.conf.default.send_redirects = 0 " >> /etc/sysctl.conf ;
sysctl -w net.ipv4.conf.all.send_redirects=0 ;
sysctl -w net.ipv4.conf.default.send_redirects=0 ;


#Ensure source routed packets are not accepted
echo "net.ipv4.conf.all.accept_source_route = 0 " >>/etc/sysctl.conf ;
echo "net.ipv4.conf.default.accept_source_route = 0 " >>/etc/sysctl.conf ;
sysctl -w net.ipv4.conf.all.accept_source_route=0 ;
sysctl -w net.ipv4.conf.default.accept_source_route=0 ;


#3.2.1 Ensure source routed packets are not accepted
echo "net.ipv4.conf.all.accept_source_route = 0" >>/etc/sysctl.conf ;
echo "net.ipv4.conf.default.accept_source_route = 0" >>/etc/sysctl.conf ;
echo "net.ipv6.conf.all.accept_source_route = 0" >>/etc/sysctl.conf ;
echo "net.ipv6.conf.default.accept_source_route = 0 ">>/etc/sysctl.conf ;
sysctl -w net.ipv4.conf.all.accept_source_route=0;
sysctl -w net.ipv4.conf.default.accept_source_route=0;
sysctl -w net.ipv6.conf.all.accept_source_route=0;
sysctl -w net.ipv6.conf.default.accept_source_route=0;


#3.2.2 Ensure ICMP redirects are not accepted
echo "net.ipv4.conf.all.accept_redirects = 0 " >>/etc/sysctl.conf ;
echo "net.ipv4.conf.default.accept_redirects = 0" >>/etc/sysctl.conf ;
echo "net.ipv6.conf.all.accept_redirects = 0 "  >>/etc/sysctl.conf ;
echo "net.ipv6.conf.default.accept_redirects = 0"  >>/etc/sysctl.conf ;
sysctl -w net.ipv4.conf.all.accept_redirects=0; 
sysctl -w net.ipv4.conf.default.accept_redirects=0;
sysctl -w net.ipv6.conf.all.accept_redirects=0;
sysctl -w net.ipv6.conf.default.accept_redirects=0;



#3.2.3 Ensure secure ICMP redirects are not accepted
echo "net.ipv4.conf.all.secure_redirects = 0 ">>/etc/sysctl.conf ;
echo "net.ipv4.conf.default.secure_redirects = 0" >>/etc/sysctl.conf ;
sysctl -w net.ipv4.conf.all.secure_redirects=0;
sysctl -w net.ipv4.conf.default.secure_redirects=0;



#Ensure Reverse Path Filtering is enabled
echo "net.ipv4.conf.all.rp_filter = 1 ">>/etc/sysctl.conf ;
echo "net.ipv4.conf.default.rp_filter = 1 ">>/etc/sysctl.conf ;
sysctl -w net.ipv4.conf.all.rp_filter=1 ;
sysctl -w net.ipv4.conf.default.rp_filter=1 ;


#3.2.8 Ensure TCP SYN Cookies is enabled
echo " net.ipv4.tcp_syncookies = 1" >>/etc/sysctl.conf ;
sysctl -w net.ipv4.tcp_syncookies=1;


#3.2.9 Ensure IPv6 router advertisements are not accepted
echo "net.ipv6.conf.all.accept_ra = 0"  >>/etc/sysctl.conf ;
echo "net.ipv6.conf.default.accept_ra = 0" >>/etc/sysctl.conf ;
sysctl -w net.ipv6.conf.all.accept_ra=0;
sysctl -w net.ipv6.conf.default.accept_ra=0;

sysctl -w net.ipv4.route.flush=1;
sysctl -w net.ipv6.route.flush=1;


cat audit.rules >/etc/audit/audit.rules;
cat audit.rules > /etc/audit/rules.d/audit.rules;


#Ensure SSH X11 forwarding is disabled
echo "X11Forwarding no" >>/etc/ssh/sshd_config;

#service sshd restart;

#Ensure system accounts are non-login
#for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd` ;
#do 
#if [ $user != "root" ]; then
#usermod -L $user 
#if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user !="halt" ]; then 
#usermod -s /sbin/nologin $user 
#fi 
#fi
#done










