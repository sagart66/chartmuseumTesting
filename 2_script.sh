sed -i -r 's/wheel:x:10:ec2-user//' /etc/group;
echo "TMOUT=600" >>/etc/bashrc;
echo "TMOUT=600" >>/etc/profile;
sed -i -r 's/GRUB_CMDLINE_LINUX="ipv6.disable=1"//' /etc/group;
echo " "

echo 'GRUB_CMDLINE_LINUX="audit=1"' >>/etc/default/grub;
grub2-mkconfig -o /boot/grub2/grub.cfg;

yum install aide  -y;
aide --init &
sleep 10;
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz;
