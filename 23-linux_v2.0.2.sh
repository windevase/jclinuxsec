#!/bin/sh
LANG=ko_KR.UTF-8

alias ls=ls
alias grep=/bin/grep

echo "※ 서버 부하 체크"
uptime
echo " "

## 관리자(root) 권한으로 실행했는지 확인하는 부분.
if [ `id | grep "uid=0" | wc -l ` -eq 0 ]
then
        echo " "
        echo " "
        echo 'This script must be run as administrator(ex: ROOT) !!!'
        echo '본 진단 스크립트는 관리자(ROOT) 권한으로 실행해야 합니다 !!!'
        echo " "
        echo " "
        exit
fi

## 진단 스크립트 본문
LANG=C
export LANG

alias ls=ls


CREATE_FILE=`hostname`"_ini_error".log

echo > $CREATE_FILE 2>&1
chmod 700 $CREATE_FILE

if [ -d ./backup ]
 then
   echo "  " >> $CREATE_FILE 2>&1
 else
echo "########################   BACKUP START !!!   ################################################"
mkdir ./backup 
mkdir ./backup/dev/
mkdir ./backup/hidden/
mkdir ./backup/etc
mkdir ./backup/etc/default/

echo "############################  1.계정관리  ####################################################"
cp -p /etc/passwd ./backup/etc/ 
cp -p /etc/group ./backup/etc/
cp -p /etc/login.defs ./backup/etc/
cp -p /etc/shadow ./backup/etc/
cp -p /etc/profile ./backup/etc/
cp -p /etc/hosts ./backup/etc/
cp -p /etc/*ftpusers* ./backup/etc/
cp -p /etc/ftpd/ftpusers ./backup/etc/
cp -p /etc/*ftpd.conf /inetsec/backup/etc/
cp -p /etc/dfs/dfstab ./backup/etc/
cp -p /etc/services ./backup/etc/
cp -p /etc/inittab ./backup/etc/
cp -p /etc/syslog.conf ./backup/etc/


mkdir -p ./backup/etc/pam.d/
cp -p /etc/pam.d/su ./backup/etc/pam.d/
cp -p /etc/pam.d/login ./backup/etc/pam.d

mkdir -p ./backup/sbin/
cp -p /sbin/dump ./backup/sbin/
cp -p /sbin/showfdmn ./backup/sbin/
cp -p /sbin/showfsets ./backup/sbin/

mkdir -p ./backup/usr/bin/
cp -p /usr/bin/at ./backup/usr/bin/
cp -p /usr/bin/lpq ./backup/usr/bin/
cp -p /usr/bin/lpq-lpd ./backup/usr/bin/
cp -p /usr/bin/lpr ./backup/usr/bin/
cp -p /usr/bin/lpr-lpd ./backup/usr/bin/
cp -p /usr/bin/lprm ./backup/usr/bin/
cp -p /usr/bin/lprm-lpd ./backup/usr/bin/
cp -p /usr/bin/newgrp ./backup/usr/bin/

mkdir -p ./backup/usr/sbin/
cp -p /usr/sbin/lpc ./backup/usr/sbin/
cp -p /usr/sbin/lpc-lpd ./backup/usr/sbin/
cp -p /usr/sbin/traceroute ./backup/usr/sbin/

mkdir -p ./backup/inetd.conf/
mkdir -p ./backup/etc/xinetd.conf
mkdir -p ./backup/etc/xinetd.d/*
cp -p /etc/inetd.conf ./backup/etc/
cp -p /etc/xintd.conf ./backup/etc/
cp -p /etc/xinetd.d/* ./backup/etc/xinetd.d/

mkdir -p ./backup/etc/rc0.d/
mkdir -p ./backup/etc/rc1.d/
mkdir -p ./backup/etc/rc2.d/
mkdir -p ./backup/etc/rc3.d/
mkdir -p ./backup/etc/rc4.d/
mkdir -p ./backup/etc/rc5.d/
mkdir -p ./backup/etc/rc6.d/
cp -p /etc/rc0.d/* ./backup/etc/rc0.d/
cp -p /etc/rc1.d/* ./backup/etc/rc1.d/
cp -p /etc/rc2.d/* ./backup/etc/rc2.d/
cp -p /etc/rc3.d/* ./backup/etc/rc3.d/
cp -p /etc/rc4.d/* ./backup/etc/rc4.d/
cp -p /etc/rc5.d/* ./backup/etc/rc5.d/
cp -p /etc/rc6.d/* ./backup/etc/rc6.d/

mkdir -p ./backup/etc/snmp/
cp -p /etc/snmp/snmpd.conf ./backup/etc/snmp/

mkdir -p ./backup/etc/cron.daily/
mkdir -p ./backup/etc/cron.hourly/
mkdir -p ./backup/etc/cron.monthly/
mkdir -p ./backup/etc/cron.weekly/
mkdir -p ./backup/var/spool/cron/crontabs/
cp -p /etc/crontab ./backup/etc/
cp -p /etc/cron.daily/* ./backup/etc/cron.daily/
cp -p /etc/cron.hourly/* ./backup/etc/cron.hourly/
cp -p /etc/cron.monthly/* ./backup/etc/cron.monthly/
cp -p /etc/cron.weekly/* ./backup/etc/cron.weekly/


echo "######################################  3.네트워크 서비스  #############################################"
cp -p /etc/hosts.equiv ./backup/etc/
cp -p /etc/named.conf ./backup/etc/
cp -p /etc/named.boot ./backup/etc/
cp -p /etc/issue ./backup/etc/

mkdir -p ./backup/etc/dfs/
cp -p /etc/dfs/dfstab ./backup/etc/dfs/

mkdir -p ./backup/etc/autofs/
cp -p /etc/rc2.d/S74autofs ./backup/etc/autofs/

mkdir -p ./backup/etc/mail
cp -p /etc/mail/sendmail.cf ./backup/etc/mail


echo "######################################  4.로그 관리  ###################################################"
cp -p /etc/login.defs ./backup/etc/
cp -p /etc/syslog.conf ./backup/etc/default/

echo "##########    egrep -i fail|err|panic /var/log/messages*   ########"
echo "##########    egrep -i fail|err|panic /var/log/messages*   ########" >> ./backup/4.4_log_check.log 2>&1
egrep -i "fail|err|panic" /var/log/messages* | tail				     >> ./backup/4.4_log_check.log 2>&1
echo " "								     >> ./backup/4.4_log_check.log 2>&1

echo "##########      egrep -i fail|err|panic /var/log/syslog*   ########"
echo "##########      egrep -i fail|err|panic /var/log/syslog*   ########" >> ./backup/4.4_log_check.log 2>&1
egrep -i "fail|err|panic" /var/log/syslog* | tail				     >> ./backup/4.4_log_check.log 2>&1
echo " " 								     >> ./backup/4.4_log_check.log 2>&1

echo "##########       egrep -i fail|err|panic /var/log/authlog   #######"
echo "##########       egrep -i fail|err|panic /var/log/authlog   #######" >> ./backup/4.4_log_check.log 2>&1
egrep -i "fail|err|panic" /var/log/authlog | tail				     >> ./backup/4.4_log_check.log 2>&1
echo " " 								     >> ./backup/4.4_log_check.log 2>&1

echo "###############         4.5 log file mode change    #################"
ls -alL /var/log/wtmp							>> ./backup/4.5_log_perm.log 2>&1
ls -alL /var/run/utmp							>> ./backup/4.5_log_perm.log 2>&1
ls -alL /var/log/btmp							>> ./backup/4.5_log_perm.log 2>&1
ls -alL /var/log/pacct						        >> ./backup/4.5_log_perm.log 2>&1
ls -alL /var/log/messages					        >> ./backup/4.5_log_perm.log 2>&1
ls -alL /var/log/lastlog							>> ./backup/4.5_log_perm.log 2>&1
ls -alL /var/log/secure* 					        >> ./backup/4.5_log_perm.log 2>&1


echo "######################################  5. 주요 응용 설정  #############################################"
cp -p /etc/ftpusers ./backup/etc/
mkdir -p ./backup/etc/ftpd/
cp -p /etc/ftpd/ftpusers ./backup/etc/ftpd/

cp -p /etc/rc3.d/S76snmpdx ./backup/etc/
cp -p /etc/snmp/conf/snmpd.conf ./backup/etc/
cp -p /etc/rc2.d/S88sendmail ./backup/etc/
cp -p /etc/mail/sendmail.cf ./backup/etc/
cp -p /etc/rc3.d/S90samba ./backup/etc/
cp -p /etc/ssh/sshd_config ./backup/etc/

echo "####################################   BACKUP END !!!   ################################################"

fi


#echo "INFO_CHKSTART"  >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1

echo " "
echo "★ Ⅱ. 전체 결과물 출력  ★ ****************************************************************************" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "############################### Start Time ###################################################"
date
echo " "
echo "############################### Start Time ###################################################" >> $CREATE_FILE 2>&1
date >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "========================= System Information Query Start ====================================="
echo "========================= System Information Query Start =====================================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "#############################   Kernel Information   #########################################"
echo "#############################   Kernel Information   #########################################" >> $CREATE_FILE 2>&1
uname -a                            >> $CREATE_FILE 2>&1
echo " "                            >> $CREATE_FILE 2>&1
echo "☞ /proc/version 파일 내용"   >> $CREATE_FILE 2>&1
cat /proc/version                   >> $CREATE_FILE 2>&1
echo " "                            >> $CREATE_FILE 2>&1
echo "☞ /etc/*-release  파일 내용" >> $CREATE_FILE 2>&1
cat /etc/*-release                  >> $CREATE_FILE 2>&1
echo " "                            >> $CREATE_FILE 2>&1
echo "* IP_Start "                  >> $CREATE_FILE 2>&1
echo "###############################   IP Information   ###########################################"
echo "###############################   IP Information   ###########################################" >> $CREATE_FILE 2>&1
ifconfig -a >> $CREATE_FILE 2>&1
echo "* IP_End " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "###############################   Network Status   ###########################################"
echo "###############################   Network Status   ###########################################" >> $CREATE_FILE 2>&1
netstat -anp | egrep -i "LISTEN|ESTABLISHED" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "#############################   Routing Information   ########################################"
echo "#############################   Routing Information   ########################################" >> $CREATE_FILE 2>&1
netstat -rn >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "################################   Process Status   ##########################################"
echo "################################   Process Status   ##########################################" >> $CREATE_FILE 2>&1
ps -ef >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "################################   User Env   ################################################"
echo "################################   User Env   ################################################" >> $CREATE_FILE 2>&1
env >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
echo "========================= System Information Query End ======================================="
echo "========================= System Information Query End =======================================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo >> $CREATE_FILE 2>&1
echo "***************************************** START **********************************************" >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1
echo
echo "***************************************** START **********************************************"
echo
echo >> $CREATE_FILE 2>&1

echo "==============================================================================================" >> $CREATE_FILE 2>&1
echo "==============================================================================================" >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1
echo "INFO_CHKEND"  >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1

echo "1.01 START" >> $CREATE_FILE 2>&1
echo "################## 1.계정관리 - 1.01 Default 계정 삭제 ########################################"
echo "################## 1.계정관리 - 1.01 Default 계정 삭제 ########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "Default 계정(lp,uucp,nuucp) 삭제" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① Default 계정 확인" >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | egrep "lp:|uucp:|nuucp:" | grep -v "lpd:" | wc -l` -eq 0 ]
  then
    echo "☞ lp, uucp, nuucp 계정이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  else
    cat /etc/passwd | egrep "lp:|uucp:|nuucp:" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
#echo "② UID 500 이상 계정 확인" >> $CREATE_FILE 2>&1
#if [ `cat /etc/passwd | egrep -v "^#|^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher|/nologin|/bin/false" |awk -F: '$3>=500{ print $1 " -> UID=" $3 }' | wc -l` -eq 0 ]
#  then
#    echo "☞ UID 500 이상 계정이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
#  else
#    cat /etc/passwd | egrep -v "^#|^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher|/nologin|/bin/false" |awk -F: '$3>=500{ print $1 " -> UID=" $3 }' >> $CREATE_FILE 2>&1
#fi

echo " " >> $CREATE_FILE 2>&1
# 조치방법
echo "※ /etc/passwd파일에 Default 계정(lp,uucp,nuucp) 및 퇴직, 계약 해지자 등 계정 삭제" >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1

#if [ \( `cat /etc/passwd | egrep -i "lp:|uucp:|nuucp:"| grep -v "lpd:" | wc -l` -gt 0 \) -o \( `cat /etc/passwd | egrep -v "^#|^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher|/nologin|/bin/false" |awk -F: '$3>=500{ print $1 " -> UID=" $3 }' | wc -l` -gt 0 \) ]
if [ `cat /etc/passwd | egrep -i "lp:|uucp:|nuucp:"| grep -v "lpd:" | wc -l` -gt 0 ]
    then
      echo "＠ 취약 1.01" >> $CREATE_FILE 2>&1
    else
      echo "＠ 양호 1.01" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.02 START" >> $CREATE_FILE 2>&1
echo "################## 1.계정관리 - 1.02 일반계정 root 권한 관리 ##################################"
echo "################## 1.계정관리 - 1.02 일반계정 root 권한 관리 ##################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "vi /etc/passwd 파일 실행하여 UID가 0인 일반계정의 UID를 100 이상으로 수정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "[ /etc/passwd 파일 내용 ]" >> $CREATE_FILE 2>&1
cat /etc/passwd >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
# 조치방법
echo "※ root 계정 및 그룹을 제외한 일반 계정의 UID 가 ‘100’ 이상으로 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `awk -F: '$3==0  { print $1 }' /etc/passwd | grep -v "root"| wc -l` -eq 0 ]
  then
    echo "＠ 양호 1.02" >> $CREATE_FILE 2>&1
  else
    echo "＠ 취약 1.02" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.03 START" >> $CREATE_FILE 2>&1
echo "################## 1.계정관리 - 1.03 /etc/passwd 파일 권한 설정 ###############################"
echo "################## 1.계정관리 - 1.03 /etc/passwd 파일 권한 설정 ###############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/passwd 파일의 권한을 root 소유의 ‘644’이하로 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[ /etc/passwd 파일의 권한 확인 ]" >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    ls -alL /etc/passwd >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
# 조치방법
echo "※ /etc/passwd 파일의 권한을 root 소유의 ‘644’ 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ls -alL /etc/passwd | awk '{print $1,$3}' | grep "root" | grep "...-.--.--" | wc -l` -eq 1 ]
  then
    echo "＠ 양호 1.03" >> $CREATE_FILE 2>&1
  else
    echo "＠ 취약 1.03" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.04 START" >> $CREATE_FILE 2>&1
echo "################## 1.계정관리 - 1.04 /etc/group 파일 권한 설정 ################################"
echo "################## 1.계정관리 - 1.04 /etc/group 파일 권한 설정 ################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/group 파일의 권한을 root(또는 bin) 소유의 644로 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -alL /etc/group >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
# 조치방법
echo "※ /etc/group 파일의 권한을 root(또는 bin) 소유의 ‘644’로 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ls -alL /etc/group |  awk '{print $1,$3}' | egrep "root|bin" | grep "...-.--.--" | wc -l` -eq 1 ]
      then
        echo "＠ 양호 1.04" >> $CREATE_FILE 2>&1
      else
        echo "＠ 취약 1.04" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.05 START" >> $CREATE_FILE 2>&1
echo "################## 1.계정관리 - 1.05 /etc/shadow 파일 권한 설정 ###############################"
echo "################## 1.계정관리 - 1.05 /etc/shadow 파일 권한 설정 ###############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. /etc/shadow 파일의 권한을 root 소유의 "400"으로 설정" >> $CREATE_FILE 2>&1
echo "나. /etc/passwd 파일 암호화 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① /etc/shadow 파일의 권한 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
  then
    ls -alL /etc/shadow >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/shadow 파일이 없습니다." >> $CREATE_FILE 2>&1
	
fi
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "② /etc/passwd 파일의 Shadow mode 설정 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
	then
		if [ `cat /etc/passwd | awk -F ':' '{print $1 ":" $2 ":"}' | egrep -v 'x|\*' |wc -l` -ge 1 ]
			then
				cat /etc/passwd | awk -F ':' '{print $1 ":" $2 ":"}' | egrep -v -w 'x|\*' >> $CREATE_FILE 2>&1
				echo "☞ 위 계정 Shadow 설정 되어 있지 않음(취약)" >> $CREATE_FILE 2>&1
			else
				echo "☞ 모든 계정 Shadow mode 설정 되어 있음" >> $CREATE_FILE 2>&1
		fi
	else
		echo "☞ /etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
# 조치방법
echo "※ /etc/shadow 파일의 권한을 root 소유의 "400"으로 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


if [ \( `ls -alL /etc/shadow | awk '{print $1,$3}' | grep "root" | grep "...-.--.--" | wc -l` -eq 1 \) -a \( `cat /etc/passwd | awk -F ':' '{print $1 ":" $2 ":"}' | grep -v -w 'x' |wc -l` -eq 0 \) ]
  then
    echo "＠ 양호 1.05" >> $CREATE_FILE 2>&1
  else
    echo "＠ 취약 1.05" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.06 START" >> $CREATE_FILE 2>&1
echo "################## 1.계정관리 - 1.06 패스워드 사용규칙 적용 ###################################"
echo "################## 1.계정관리 - 1.06 패스워드 사용규칙 적용 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. 패스워드 사용규칙, 계정 잠금 임계값 설정" >> $CREATE_FILE 2>&1
echo "나. AMS에 연동되어 있을 경우 예외(Control-SA 등)" >> $CREATE_FILE 2>&1
echo "다. 패스워드 저장시 일방향 암호 알고리즘 사용(SHA-256 이상)" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "① 계정관리시스템 구동 현황" >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep "JMC|p_ctsce|cmmd" | grep -v "grep" | wc -l` -eq 0 ]
 then
   echo "☞ 계정관리시스템(AMS) 비실행중 입니다." >> $CREATE_FILE 2>&1
 else
   ps -ef | egrep "JMC|p_ctsce|cmmd" | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "② 리눅스 종류 확인" >> $CREATE_FILE 2>&1
cat /etc/*-release >> $CREATE_FILE 2>&1
uname -r >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "③ /etc/login.defs 파일 내용" >> $CREATE_FILE 2>&1
grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_LEN" >> $CREATE_FILE 2>&1
grep -v '^ *#' /etc/login.defs | grep -i "PASS_MAX_DAYS" >> $CREATE_FILE 2>&1
grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_DAYS" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo " " > password.log 2>&1

  if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "^#" | awk '{print $2}' | wc -l` -eq 0 ]
    then
      echo "＠ 취약" >> password.log 2>&1
	  echo "☞ PASS_MIN_LEN 설정 없음(취약) " >> $CREATE_FILE 2>&1
    else
      if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN"| grep -v "^#" | awk '{print $2}'` -ge 9 ]
        then
          echo "＠ 양호" >> password.log 2>&1
        else
          echo "＠ 취약" >> password.log 2>&1
		  echo "☞ PASS_MIN_LEN 설정 취약(9자 이상) " >> $CREATE_FILE 2>&1
      fi
  fi


  if [ `cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "^#" | awk '{print $2}' | wc -l` -eq 0 ]
   then
     echo "＠ 취약" >> password.log 2>&1
	 echo "☞ PASS_MAX_DAYS 설정 없음(취약) " >> $CREATE_FILE 2>&1
   else
     if [ `cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "^#" | awk '{print $2}'` -gt 90 ]
      then
       echo "＠ 취약" >> password.log 2>&1
	   echo "☞ PASS_MAX_DAYS 설정 취약(90일 이하) " >> $CREATE_FILE 2>&1
      else
       echo "＠ 양호" >> password.log 2>&1
     fi
  fi


  if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "^#" |awk '{print $2}' | wc -l` -eq 0 ]
   then
     echo "＠ 취약" >> password.log 2>&1
	 echo "☞ PASS_MIN_DAYS 설정 없음(취약) " >> $CREATE_FILE 2>&1
   else
    if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "^#" | awk '{print $2}'` -eq 0 ]
		then
			echo "＠ 취약" >> password.log 2>&1
			echo "☞ PASS_MIN_DAYS 설정 취약(1일 이상) " >> $CREATE_FILE 2>&1
     else
		echo "＠ 양호" >> password.log 2>&1
    fi
  fi
echo " " >> $CREATE_FILE 2>&1


if [ `cat /etc/*-release | grep -i 'DISTRIB_DESCRIPTION' | grep -i 'ubuntu' | wc -l` -gt 0 ]
	then
		if [ `cat /etc/*-release | grep -i 'DISTRIB_DESCRIPTION' | grep -i 'ubuntu' | grep -i '22.' | wc -l` -gt 0 ]
			then
				echo "(4-1) Ubuntu: /etc/pam.d/common-auth 파일 내용(22버전)" >> $CREATE_FILE 2>&1
				if [ -f /etc/pam.d/common-auth ]
					then
						touch pam_tally.log
						cat /etc/pam.d/common-auth | grep -v '#' |grep -v -e '^$' >> $CREATE_FILE 2>&1
						if [ `cat /etc/pam.d/common-auth | grep -v "^#" | grep -i "pam_faillock" | egrep -i "auth" | grep -i "required" | wc -l` -gt 0 ]
							then
								cat /etc/pam.d/common-auth | grep -v "^#" | grep -i "pam_faillock" | egrep -i "auth" >> pam_tally.log
								#cat /etc/pam.d/common-auth | grep -v "^#" | grep -i "pam_faillock" | egrep -i "auth" | grep -i "required" >> pam_tally.log
								if [ `cat pam_tally.log | grep -i "required" | grep -i "silent" | grep -i "audit" | uniq | wc -l` -eq 0 ]
									then
										echo "＠ 취약" >> password.log 2>&1
										echo "☞ auth  required  pam_faillock.so silent audit 옵션 설정 취약" >> $CREATE_FILE 2>&1
								fi
								if [ `cat pam_tally.log | grep -i "required" | egrep -o "deny=[0-9]+" | awk -F "=" '{print $2}' | uniq` -gt 10 ]
									then
										echo "＠ 취약" >> password.log 2>&1
										echo "☞ auth  required  pam_faillock.so deny=10 이하 설정 취약" >> $CREATE_FILE 2>&1
								fi
								if [ `cat pam_tally.log | grep -i "required" | egrep -o "unlock_time=[0-9]+" | awk -F"=" '{print $2}'| uniq` -lt 600 ]
									then
										echo "＠ 취약" >> password.log 2>&1
										echo "☞ auth  required  pam_faillock.so unlock_time=600 이상 설정 취약" >> $CREATE_FILE 2>&1
								fi
								if [ `cat pam_tally.log | grep -i "default=die" | grep -i "pam_faillock" | grep -i "authfail" | grep -i "audit" | grep -i "deny=" | grep -i "unlock_time="| uniq | wc -l` -eq 0 ]
									then
										echo "＠ 취약" >> password.log 2>&1
										echo "☞ auth  [default=die]  pam_faillock.so authfail audit deny=10 unlock_time=600 설정 취약" >> $CREATE_FILE 2>&1
								fi
								if [ `cat pam_tally.log | grep -i "sufficient" | grep -i "pam_faillock" | grep -i "authsucc" | grep -i "audit" | grep -i "deny=" | grep -i "unlock_time="| uniq | wc -l` -eq 0 ]
									then
										echo "＠ 취약" >> password.log 2>&1
										echo "☞ auth  sufficient  pam_faillock.so authsucc audit deny=10 unlock_time=600 설정 취약" >> $CREATE_FILE 2>&1
								fi

						else
							echo "＠ 취약" >> password.log 2>&1
							echo "☞ auth  required  pam_faillock.so  preauth silent audit deny=10 unlock_time=600 미설정 취약 " >> $CREATE_FILE 2>&1
						fi
				else
						echo "☞ common-auth 파일 없음" >> $CREATE_FILE 2>&1
				fi
				echo " " >> $CREATE_FILE 2>&1
				echo "(4-2) Ubuntu: /etc/pam.d/common-account 파일 내용(22버전)" >> $CREATE_FILE 2>&1
				if [ -f /etc/pam.d/common-account ]
					then
						cat /etc/pam.d/common-account | grep -v '#' |grep -v -e '^$' >> $CREATE_FILE 2>&1
						if [ `cat /etc/pam.d/common-account | grep -v "^#" | grep -i "pam_faillock" | egrep -i "account" | grep -i "required" | wc -l` -gt 0 ]
							then
								echo "＠ 양호" >> password.log 2>&1
						else
							echo "＠ 취약" >> password.log 2>&1
							echo "☞ account required pam_faillock.so 미설정 취약 " >> $CREATE_FILE 2>&1
						fi
				else
					echo "☞ common-auth 파일 없음" >> $CREATE_FILE 2>&1
				fi
		else
		
		echo "(4-1) Ubuntu: /etc/pam.d/common-auth 파일 내용" >> $CREATE_FILE 2>&1
		if [ -f /etc/pam.d/common-auth ]
			then
				touch pam_tally.log
				cat /etc/pam.d/common-auth | grep -v '#' |grep -v -e '^$' >> $CREATE_FILE 2>&1
				if [ `cat /etc/pam.d/common-auth | grep -v "^#" | grep -i "pam_tally" | egrep -i "auth" | grep -i "required" | wc -l` -gt 0 ]
					then
						cat /etc/pam.d/common-auth | grep -v "^#" | grep -i "pam_tally" | egrep -i "auth" | grep -i "required" >> pam_tally.log
						if [ `cat pam_tally.log | egrep -o "deny=[0-9]+" | awk -F "=" '{print $2}' | uniq` -gt 10 ]
							then
								echo "＠ 취약" >> password.log 2>&1
								echo "☞ deny=10 이하 설정 취약" >> $CREATE_FILE 2>&1
						fi
						if [ `cat pam_tally.log | egrep -o "unlock_time=[0-9]+" | awk -F"=" '{print $2}'| uniq` -lt 600 ]
							then
								echo "＠ 취약" >> password.log 2>&1
								echo "☞ unlock_time=600 이상 설정 취약" >> $CREATE_FILE 2>&1
						fi
				else
					echo "＠ 취약" >> password.log 2>&1
					echo "☞ auth  required  pam_tally2.so  onerr=fail even_deny_root deny=10 unlock_time=600 미설정 취약 " >> $CREATE_FILE 2>&1
				fi
		else
				echo "☞ common-auth 파일 없음" >> $CREATE_FILE 2>&1
		fi
		echo " " >> $CREATE_FILE 2>&1
		echo "(4-2) Ubuntu: /etc/pam.d/common-account 파일 내용" >> $CREATE_FILE 2>&1
		if [ -f /etc/pam.d/common-account ]
			then
				cat /etc/pam.d/common-account | grep -v '#' |grep -v -e '^$' >> $CREATE_FILE 2>&1
				if [ `cat /etc/pam.d/common-account | grep -v "^#" | grep -i "pam_tally" | egrep -i "account" | grep -i "required" | wc -l` -gt 0 ]
					then
						echo "＠ 양호" >> password.log 2>&1
				else
					echo "＠ 취약" >> password.log 2>&1
					echo "☞ account required pam_tally2.so 미설정 취약 " >> $CREATE_FILE 2>&1
				fi
		else
				echo "☞ common-auth 파일 없음" >> $CREATE_FILE 2>&1
		fi		
	fi
else
    if [ `cat /etc/*-release | grep -i 'release'| awk -F"." '{print $1}' | egrep -o [8-9] | tail -1 |wc -l` -gt 0 ]
		then
			echo "(4-1) faillock module 활성화 확인(활성화 명령어: authselect enable-feature with-faillock)" >> $CREATE_FILE 2>&1
			authselect current	>> $CREATE_FILE 2>&1
			if [ `authselect current | grep faillock | wc -l` -gt 0 ]
				then
					echo " " >> $CREATE_FILE 2>&1
					echo "(4-2) /etc/security/faillock.conf 설정 확인" >> $CREATE_FILE 2>&1
					cat /etc/security/faillock.conf | grep -i 'silent' >> $CREATE_FILE 2>&1
					if [ `cat /etc/security/faillock.conf | grep -v "^#" | grep -i silent | wc -l` -eq 0 ]
						then
							echo "＠ 취약" >> password.log 2>&1
							echo "☞ silent 설정 취약" >> $CREATE_FILE 2>&1
					fi
					cat /etc/security/faillock.conf | grep -i 'deny =' >> $CREATE_FILE 2>&1
					if [ `cat /etc/security/faillock.conf | grep -v "^#" | grep -i "deny =" | wc -l` -gt 0 ]
						then
							if [ `cat /etc/security/faillock.conf | grep -v "^#" | grep -i "deny =" | awk -F"=" '{print $2}'` -gt 10 ]
								then
									echo "＠ 취약" >> password.log 2>&1
									echo "☞ deny=10 이하 설정 취약" >> $CREATE_FILE 2>&1
							fi
						else
							echo "☞ deny=10 이하 설정 취약" >> $CREATE_FILE 2>&1
					fi
					cat /etc/security/faillock.conf | grep -i 'unlock_time =' | grep -v 'root' >> $CREATE_FILE 2>&1
					if [ `cat /etc/security/faillock.conf | grep -v "^#" | grep -i "unlock_time =" | grep -v "root" | wc -l` -gt 0 ]
						then
							if [ `cat /etc/security/faillock.conf | grep -v "^#" | grep -i "unlock_time =" | grep -v "root" | awk -F"=" '{print $2}'` -lt 600 ]
								then
									echo "＠ 취약" >> password.log 2>&1
									echo "☞ unlock_time=600 이상 설정 취약" >> $CREATE_FILE 2>&1
							fi
						else
							echo "☞ unlock_time=600 이상 설정 취약" >> $CREATE_FILE 2>&1
					fi
			else
				echo "☞ faillock module 미사용으로 취약" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "(4-2) /etc/security/faillock.conf 설정 확인" >> $CREATE_FILE 2>&1
				cat /etc/security/faillock.conf | grep -E 'silent|deny =|unlock_time =' | grep -v 'root' >> $CREATE_FILE 2>&1
			fi
	else
	
	echo "(4) /etc/pam.d/password-auth 파일 내용" >> $CREATE_FILE 2>&1
	touch pam_tally.log
	cat /etc/pam.d/password-auth >> $CREATE_FILE 2>&1

	if [ `cat /etc/pam.d/password-auth | grep -v "^#" | grep -i "pam_tally" | egrep -i "auth|account" | grep -i "required" | wc -l` -ge 2 ]
		then
			cat /etc/pam.d/password-auth | grep -v "^#" | grep -i "pam_tally" | egrep -i "auth|account" | grep -i "required" >> pam_tally.log
			if [ `cat pam_tally.log | egrep -o "deny=[0-9]+" | awk -F "=" '{print $2}' | uniq` -gt 10 ]
				then
					echo "＠ 취약" >> password.log 2>&1
					echo "☞ deny=10 이하 설정 취약" >> $CREATE_FILE 2>&1
			fi
			if [ `cat pam_tally.log | egrep -o "unlock_time=[0-9]+" | awk -F"=" '{print $2}'| uniq` -lt 600 ]
				then
					echo "＠ 취약" >> password.log 2>&1
					echo "☞ unlock_time=600 이상 설정 취약" >> $CREATE_FILE 2>&1
			fi
	else
		echo "＠ 취약" >> password.log 2>&1
		echo "☞ auth  required  pam_tally2.so  deny=10 unlock_time=600 미설정 취약 " >> $CREATE_FILE 2>&1
		echo "☞ account  required  pam_tally2.so 미설정 취약 " >> $CREATE_FILE 2>&1
	fi
	fi
fi
echo " " >> $CREATE_FILE 2>&1
echo "(5) 패스워드 암호화 설정 확인" >> $CREATE_FILE 2>&1
#echo "[ 사용중인 암호 알고리즘 ]" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
if [ `cat /etc/login.defs | grep CRYPT | egrep -v '#' | egrep -i "sha256|sha512" | wc -l` -gt 0 ]
	then
		cat /etc/login.defs | grep CRYPT | egrep -v '#'>> $CREATE_FILE 2>&1
		echo "☞ 안전한 암호 알고리즘을 사용하고 있습니다." >> $CREATE_FILE 2>&1
else
		if [ `cat /etc/login.defs | grep CRYPT | egrep -v '#' | egrep -i "md5" | wc -l` -gt 0 ]
			then
				cat /etc/login.defs | grep CRYPT | egrep -v '#'>> $CREATE_FILE 2>&1
				echo "☞ 취약한 암호 알고리즘을 사용하고 있습니다." >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> password.log 2>&1
		else
			authconfig --test | grep password >> $CREATE_FILE 2>&1
			cryp=`authconfig --test | grep password | tail -1 | awk '{print $NF}'`
			if [ `authconfig --test | grep password | egrep -i "sha256|sha512" | wc -l` -gt 0 ]
				then
					echo "☞ 안전한 암호 알고리즘을 사용하고 있습니다." >> $CREATE_FILE 2>&1
			else
				echo "☞ 사용중인 암호 알고리즘을 확인할 수 없습니다." >> $CREATE_FILE 2>&1
			fi
		fi
fi

echo " " >> $CREATE_FILE 2>&1

#echo "(5) Ubuntu: /etc/pam.d/common-password 파일 내용" >> $CREATE_FILE 2>&1
#if [ -f /etc/pam.d/common-password ]
#	then
#		cat /etc/pam.d/common-password  >> $CREATE_FILE 2>&1
#	else
#		echo "☞ common-password 파일 없음" >> $CREATE_FILE 2>&1
#fi

#echo " " >> $CREATE_FILE 2>&1

#echo "(5) 패스워드 암호화 설정 확인" >> $CREATE_FILE 2>&1
#echo "[ 사용중인 암호 알고리즘 ]" >> $CREATE_FILE 2>&1
#authconfig --test | grep password >> $CREATE_FILE 2>&1
#cryp=`authconfig --test | grep password | tail -1 | awk '{print $NF}'`
#echo " " >> $CREATE_FILE 2>&1
#if [ `authconfig --test | grep password | egrep -i "sha256|sha512" | wc -l` -gt 0 ]
#	then
#		echo "☞ 안전한 암호 알고리즘을 사용하고 있습니다." >> $CREATE_FILE 2>&1
#	else
#		echo "☞ 취약한 암호 알고리즘을 사용하고 있습니다." >> $CREATE_FILE 2>&1
#		echo "＠ 취약" >> password.log 2>&1
#fi
#echo " " >> $CREATE_FILE 2>&1
#echo "[ 패스워드 암호화 적용 현황(passwd 파일 또는 shadow 파일) ]" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#accounts=`cat /etc/passwd | egrep -v "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher|/nologin|/bin/false" | awk '{print $1}' | awk -F":" '{print $1}'`
#if [ `cat /etc/passwd | egrep -i ':x:' | wc -l` -eq 0 ]
#	then
#		echo "☞ shadow mode 사용 안함" >> $CREATE_FILE 2>&1
#		realpath="/etc/passwd"
#	else
#		echo "☞ shadow mode 사용" >> $CREATE_FILE 2>&1
#		if [ -f /etc/shadow ]
#			then
#				realpath="/etc/shadow"
#			else
#				echo "☞ /etc/shadow 파일이 없습니다."
#		fi
#fi
#echo " " >> $CREATE_FILE 2>&1
#echo "파일 : $realpath" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#for _id in $accounts
#do
#acc=`cat $realpath | grep "^$_id" | awk '{print $1}'`
#_pw=`echo $acc | awk -F":" '{print $2}' | cut -c 1-7`
#if [ `cat /etc/passwd | grep "^$_id" | egrep -i "/nologin|/bin/false" | wc -l` -gt 0 ]
#	then
#		_ox="-> nologin"
#	elif [ `echo $acc | grep -i ':!!:' | wc -l` -gt 0 ]
#		then
#			_ox="-> Password has never been set"
#	elif [ `echo $acc | grep -i ':\*:' | wc -l` -gt 0 ]
#		then
#			_ox="-> Account is locked"
#	elif [ `echo $acc | grep -i ':\*LOCK\*:' | wc -l` -gt 0 ]
#		then
#			_ox="-> Account is locked"
#	elif [ `echo $acc | grep -i ':$[5-6]' | wc -l` -gt 0 ]
#		then
#			_ox="-> 양호"
#	else
#		_ox="-> 취약"
#		echo "＠ 취약" >> password.log 2>&1
#fi
#echo $_id":"$_pw" ...  "$_ox >> $CREATE_FILE 2>&1
#done
#echo " " >> $CREATE_FILE 2>&1
#tod=`date -d '90 day ago' +%Y%m%d`

#echo "(7) 마지막 패스워드 변경 확인" >> $CREATE_FILE 2>&1
#lt=`cat /etc/passwd | egrep -v "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher|/nologin|/bin/false|shutdown|sync|halt" | grep -i "bin" | awk -F":" '{print $1}'`
#for user in $lt
#do

#echo "Last password change					: "`date -d "$(chage -l $user | grep 'Last password change' | awk -F: '{print $2}')" +'%Y-%m-%d'` >> $CREATE_FILE 2>&1
#if [ `date -d "$(chage -l $user | grep 'Last password change' | awk -F: '{print $2}')" | grep -i "[0-9][0-9][0-9][0-9]" | wc -l` -gt 0 ]
#	then
#		hhh=`date -d "$(chage -l $user | grep 'Last password change' | awk -F: '{print $2}')" +'%Y-%m-%d'` >> $CREATE_FILE 2>&1
#		old=`date -d "$(chage -l $user | grep 'Last password change' | awk -F: '{print $2}')" +'%Y%m%d'`
#else
#	hhh=`password must be changed` >> $CREATE_FILE 2>&1
#	old="취약"
#fi
#echo "▷ User : "$user "=>" $hhh >> $CREATE_FILE 2>&1
#if [ `echo $old | grep -i "[0-9][0-9][0-9][0-9]" | wc -l` -gt 0 ]
#	then
#		if [ $tod -ge $old ]
#			then
#				echo "＠ 취약" >> password.log 2>&1
#				echo "☞ 패스워드 변경이 90일을 넘어 취약" >> $CREATE_FILE 2>&1
#		else
#			echo "☞ 패스워드 변경이 90일을 넘지 않아 양호" >> $CREATE_FILE 2>&1
#		fi
#else
#	echo "☞ 패스워드 변경 이력 없어 취약" >> $CREATE_FILE 2>&1
#	echo "＠ 취약" >> password.log 2>&1
#fi
#echo " " >> $CREATE_FILE 2>&1
#done

echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ /etc/login.defs 파일에 PASS_MIN_LEN 9이상, PASS_MAX_DAYS 90이하, PASS_MIN_DAYS 7이상으로 설정" >> $CREATE_FILE 2>&1
echo "   및 /etc/pam.d/system-auth에 계정잠금 임계값 설정 권고" >> $CREATE_FILE 2>&1
echo "   또한 패스워드 저장시 일방향 암호 알고리즘 사용(SHA-256 이상) 설정 권고" >> $CREATE_FILE 2>&1
          

echo " " >> $CREATE_FILE 2>&1

if [ `cat password.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 1.06" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 1.06" >> $CREATE_FILE 2>&1
fi
rm -f password.log
rm -f pam_tally.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.07 START" >> $CREATE_FILE 2>&1
echo "################## 1.계정관리 - 1.07 로그인 불필요한 계정 shell 제한 ##########################"
echo "################## 1.계정관리 - 1.07 로그인 불필요한 계정 shell 제한 ##########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "로그인이 불필요한 계정 shell 제한" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ 로그인이 불필요한 계정에 /bin/false 또는 /nologin 부여 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" | egrep -v 'false|nologin' | wc -l` -eq 0 ]
  then
    echo "＠ 양호 1.07" >> $CREATE_FILE 2>&1
  else
    echo "＠ 취약 1.07" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.08 START" >> $CREATE_FILE 2>&1
echo "################## 1.계정관리 - 1.08 SU(Select User) 사용 제한 ################################"
echo "################## 1.계정관리 - 1.08 SU(Select User) 사용 제한 ################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "권한 없는 사용자의 su 명령어 제한" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> pam.log

echo "① /etc/pam.d/su 파일 설정" >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
  then
	if [ `cat /etc/pam.d/su | grep '^auth' | grep required | grep -i 'pam_wheel.so' | grep -v '^#' | wc -l` -ge 1 ]
		then
			cat /etc/pam.d/su | grep '^auth' | grep required | grep -i 'pam_wheel.so' | grep -v '^#'  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "② /etc/group 파일에 wheel 그룹 존재 여부" >> $CREATE_FILE 2>&1
			if [ `cat /etc/group | grep -i '^wheel' | wc -l` -ge 1 ]
				then
					cat /etc/group | grep ^wheel >> $CREATE_FILE 2>&1
					echo "＠ 양호 1.08" >> pam.log
					echo " " >> $CREATE_FILE 2>&1
			else
				echo "☞ wheel 그룹이 없어 취약 합니다." >> $CREATE_FILE 2>&1
				echo "＠ 취약 1.08"  >> pam.log
				echo " " >> $CREATE_FILE 2>&1
			fi
	else
		echo "☞ auth required pam_wheel.so 설정이 없어 /bin/su, group 설정 확인 필요" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "② /etc/group 파일에 wheel 그룹 존재 여부" >> $CREATE_FILE 2>&1
		if [ `cat /etc/group | grep -i '^wheel' | wc -l` -ge 1 ]
			then
				cat /etc/group | grep ^wheel >> $CREATE_FILE 2>&1
				echo "＠ 양호 1.08"  >> pam.log
		else
			echo "☞ wheel 그룹이 없어 취약 합니다." >> $CREATE_FILE 2>&1
				echo "＠ 취약 1.08"  >> pam.log
		fi
		echo " " >> $CREATE_FILE 2>&1
		echo "③ /bin/su 파일 그룹 확인" >> $CREATE_FILE 2>&1
		if [ `ls -alL /bin/su | awk -F" " '{print $4}' | grep "wheel" | wc -l` -eq 1 ]
			then
				ls -alL /bin/su >> $CREATE_FILE 2>&1
				echo "＠ 양호 1.08"  >> pam.log
		else
			ls -alL /bin/su >> $CREATE_FILE 2>&1
			echo "☞ /bin/su 파일 그룹 wheel 그룹으로 변경 필요(취약)" >> $CREATE_FILE 2>&1
			echo "＠ 취약 1.08"  >> pam.log
		fi
		echo " " >> $CREATE_FILE 2>&1
		echo "④ /bin/su 파일 권한(4750) 확인" >> $CREATE_FILE 2>&1
		#if [ `ls -alL /bin/su | grep "...s.-.---" | grep "wheel" | wc -l` -eq 1 ]
		if [ `ls -alL /bin/su | grep "...s.-.---" | wc -l` -eq 1 ]
			then
				ls -alL /bin/su >> $CREATE_FILE 2>&1
				echo "＠ 양호 1.08"  >> pam.log
		else
			ls -alL /bin/su >> $CREATE_FILE 2>&1
			echo "☞ /bin/su 파일 권한이 취약 합니다." >> $CREATE_FILE 2>&1
			echo "＠ 취약 1.08"  >> pam.log
		fi
	fi
else
	echo "① /etc/group 파일에 wheel 그룹 존재 여부" >> $CREATE_FILE 2>&1
	if [ `cat /etc/group | grep -i '^wheel' | wc -l` -ge 1 ]
		then
			cat /etc/group | grep ^wheel >> $CREATE_FILE 2>&1
	else
		echo "☞ wheel 그룹이 없어 취약 합니다." >> $CREATE_FILE 2>&1
		echo "＠ 취약 1.08"  >> pam.log
	fi
	echo " " >> $CREATE_FILE 2>&1
	echo "② /bin/su 파일 그룹 확인" >> $CREATE_FILE 2>&1
	if [ `ls -alL /bin/su | awk -F" " '{print $4}' | grep "wheel" | wc -l` -eq 1 ]
		then
			ls -alL /bin/su >> $CREATE_FILE 2>&1
			echo "＠ 양호 1.08"  >> pam.log
	else
		ls -alL /bin/su >> $CREATE_FILE 2>&1
		echo "☞ /bin/su 파일 그룹 wheel 그룹으로 변경 필요(취약)" >> $CREATE_FILE 2>&1
		echo "＠ 취약 1.08"  >> pam.log
	fi
	echo " " >> $CREATE_FILE 2>&1
	echo "③ /bin/su 파일 권한(4750) 확인" >> $CREATE_FILE 2>&1
	#if [ `ls -alL /bin/su | grep "...s.-.---" | grep "wheel" | wc -l` -eq 1 ]
	if [ `ls -alL /bin/su | grep "...s.-.---" | wc -l` -eq 1 ]
		then
			ls -alL /bin/su >> $CREATE_FILE 2>&1
			echo "＠ 양호 1.08"  >> pam.log
	else
		ls -alL /bin/su >> $CREATE_FILE 2>&1
		echo "☞ /bin/su 파일 권한이 취약 합니다." >> $CREATE_FILE 2>&1
		echo "＠ 취약 1.08"  >> pam.log
	fi
	echo "☞ /etc/pam.d/su 파일이 없어 bin/su, group 설정만 확인" >> $CREATE_FILE 2>&1
fi


echo " " >> $CREATE_FILE 2>&1
	
# 조치방법
echo "※ su 명령어 사용 제한을 위한 wheel group 생성하고, su 명령어가 필요한 계정만 wheel 그룹에 추가 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat pam.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 1.08" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 1.08" >> $CREATE_FILE 2>&1
fi

rm -f pam.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.01 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.01 사용자 UMASK(User MASK) 설정 ###########################"
echo "################## 2.파일시스템 - 2.01 사용자 UMASK(User MASK) 설정 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/profile , /etc/bashrc 사용자 UMASK 022 설정" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
touch um.log

if [ `cat /etc/*-release | grep -i 'DISTRIB_DESCRIPTION' | grep -i 'ubuntu' | wc -l` -gt 0 ]
	then
		echo "① /etc/bash.bashrc 파일 UMASK 설정값" >> $CREATE_FILE 2>&1
		if [ -f /etc/bash.bashrc ]
			then
				if [ `cat /etc/bash.bashrc | grep -v "^#" |grep -i umask | tail -n 1 | wc -l` -eq 0 ] ;
					then
						echo "☞ UMASK 설정 없음(Default 022) = 양호" >> $CREATE_FILE 2>&1
						echo "＠ 양호 2.01" >> um.log
				else
					cat /etc/bash.bashrc | grep -v "^#" | grep -i umask >> $CREATE_FILE 2>&1
					if [ `cat /etc/bash.bashrc | grep -i "umask" | grep -v "^#" | tail -n 1 | grep -v '[237][237]' | wc -l` -gt 0 ]
						then
							echo "＠ 취약 2.01" >> um.log
					else
						echo "＠ 양호 2.01" >> um.log
					fi
				fi
		else
			echo "☞ /etc/bash.bashrc(Default 022) 파일 없음" >> $CREATE_FILE 2>&1
		fi
		
else	
echo "① /etc/bashrc 파일 UMASK 설정값" >> $CREATE_FILE 2>&1
if [ -f /etc/bashrc ]
	then
		if [ `cat /etc/bashrc | grep -v "^#" |grep -i umask | tail -n 1 | wc -l` -eq 0 ] ;
			then
				echo "☞ UMASK 설정이 없습니다." >> $CREATE_FILE 2>&1
				echo "＠ 취약 2.01" >> um.log
		else
			cat /etc/bashrc | grep -v "^#" | grep -i umask >> $CREATE_FILE 2>&1
			if [ `cat /etc/bashrc | grep -i "umask" | grep -v "^#" | tail -n 1 | grep -v '[237][237]' | wc -l` -gt 0 ]
				then
					echo "＠ 취약 2.01" >> um.log
			else
				echo "＠ 양호 2.01" >> um.log
			fi
		fi
else
	echo "☞ /etc/bashrc 파일이 없습니다." >> $CREATE_FILE 2>&1
	echo "＠ 취약 2.01" >> um.log
fi


echo "② /etc/profile 파일 UMASK 설정값" >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
	then
		if [ `cat /etc/profile | grep -v "^#" |grep -i umask | tail -n 1 | wc -l` -eq 0 ] ;
			then
				echo "☞ UMASK 설정이 없습니다." >> $CREATE_FILE 2>&1
				echo "＠ 취약 2.01" >> um.log
		else
			cat /etc/profile | grep -v "^#" | grep -i umask >> $CREATE_FILE 2>&1
			if [ `cat /etc/profile | grep -i "umask" | grep -v "^#" | tail -n 1 | grep -v '[237][237]' | wc -l` -gt 0 ]
				then
					echo "＠ 취약 2.01" >> um.log
			else
				echo "＠ 양호 2.01" >> um.log
			fi
		fi
else
	echo "☞ /etc/profile 파일이 없습니다." >> $CREATE_FILE 2>&1
	echo "＠ 취약 2.01" >> um.log
fi
fi
echo "  " >> $CREATE_FILE 2>&1

#echo "  " >> $CREATE_FILE 2>&1
#if [ `cat /etc/passwd | grep -i /csh | wc -l` -gt 0 ]
#	then
#		echo "③ /etc/csh.login 파일 UMASK 설정값" >> $CREATE_FILE 2>&1
#		if [ -f /etc/csh.login ]
#			then
#				if [ `cat /etc/csh.login | grep -v "^#" |grep -i umask | wc -l` -eq 0 ] ;
#					then
#						echo "☞ UMASK 설정이 없습니다." >> $CREATE_FILE 2>&1
#						echo "＠ 취약 2.01" >> um.log
#				else
#					cat /etc/csh.login | grep -v "^#" | grep -i umask >> $CREATE_FILE 2>&1
#					if [ `cat /etc/csh.login | grep -i "umask" | grep -v "^#" | grep -v '[237][237]' | wc -l` -gt 0 ]
#						then
#							echo "＠ 취약 2.01" >> um.log
#					fi
#				fi
#		else
#			echo "☞ /etc/csh.login 파일이 없습니다." >> $CREATE_FILE 2>&1
#			echo "＠ 취약 2.01" >> um.log
#		fi
#fi
echo "  " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ /etc/profile, /etc/bashrc 사용자 UMASK 022 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `cat um.log | grep -i "양호"| wc -l` -gt 0 ]
	then
		echo "＠ 양호 2.01" >> $CREATE_FILE 2>&1
else
	echo "＠ 취약 2.01" >> $CREATE_FILE 2>&1
fi
rm -f um.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.02 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.02 SUID, SGID 설정 ########################################"
echo "################## 2.파일시스템 - 2.02 SUID, SGID 설정 ########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "불필요한 root 소유의 SUID, SGID 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

for check_file in $FILES
  do
    if [ -f $check_file ]
      then
        if [ -g $check_file -o -u $check_file ]
          then
            ls -alL $check_file >> $CREATE_FILE 2>&1
        else
			ls -alL $check_file >> $CREATE_FILE 2>&1
        fi
      else
        echo $check_file "이 없습니다" >> $CREATE_FILE 2>&1
    fi
done
echo " " >> $CREATE_FILE 2>&1


echo "setuid " > set.log
FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

for check_file in $FILES
  do
     if [ -f $check_file ]
      then
       if [ `ls -alL $check_file | awk '{print $1}' | grep -i 's' | wc -l` -gt 0 ]
           then
              ls -alL $check_file |awk '{print $1}' | grep -i 's' >> set.log
           else
              echo " " >> set.log
       fi
     fi
done

# 조치방법
echo "※ 불필요한 root 소유의 SUID, SGID 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `cat set.log | awk '{print $1}' | grep -i 's' | wc -l` -gt 1 ]
    then
           echo "＠ 취약 2.02" >> $CREATE_FILE 2>&1
    else
           echo "＠ 양호 2.02" >> $CREATE_FILE 2>&1
fi
rm -f set.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.03 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.03 /etc/inetd.conf, /etc/xinetd.conf 파일 권한 설정 #######"
echo "################## 2.파일시스템 - 2.03 /etc/inetd.conf, /etc/xinetd.conf 파일 권한 설정 #######" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/inetd.conf or /etc/xinetd.conf , /etc/xinetd.d/* 파일의 권한이 root 소유이면서 타사용자 쓰기권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① /etc/xinetd.conf 파일 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/xinetd.conf ]
  then
    ls -alL /etc/xinetd.conf >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/xinetd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "② /etc/inetd.conf 파일 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
  then
    ls -alL /etc/inetd.conf >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/inetd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "② /etc/xinetd.d/* 파일 확인" >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d/ ]
  then
    if [ `ls /etc/xinetd.d/ | wc -l` -gt 0 ]
		then
			ls -l /etc/xinetd.d/ >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/xinetd.d/* 파일이 없습니다." >> $CREATE_FILE 2>&1
	fi
  else
    echo "☞ /etc/xinetd.d/ 디렉토리가 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ /etc/inetd.conf, /etc/xinetd.conf 파일 권한이 root 소유의 타 사용자 쓰기 권한 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " > inetd.log

if [ -f /etc/inetd.conf ]
	then
	if [ `ls -alL /etc/inetd.conf | awk '{print $1 $2 $3}' | grep '........w.'| grep -i 'root' | wc -l` -eq 0 ]
		then
			echo "＠ 양호" >> inetd.log
	else
		echo "＠ 취약" >> inetd.log
	fi
else
	echo "＠ 양호" >> inetd.log
fi


if [ -f /etc/xinetd.conf ]
 then
  if [ `ls -alL /etc/xinetd.conf | awk '{print $1,$3}' | grep '^........w.' | grep -i 'root' | wc -l` -eq 0 ]
   then
     echo "＠ 양호" >> inetd.log
   else
     echo "＠ 취약" >> inetd.log
  fi
 else
 echo "＠ 양호" >> inetd.log
fi

if [ -d /etc/xinetd.d/ ]
 then
    if [ `ls /etc/xinetd.d/ | wc -l` -gt 0 ]
		then
			if [ `ls -alL /etc/xinetd.d/ | awk '{print $1,$3}' | grep '^........w.' | grep -i 'root' | wc -l` -eq 0 ]
				then
					echo "＠ 양호" >> inetd.log
			else
				echo "＠ 취약" >> inetd.log
			fi
	else
		echo "＠ 양호" >> inetd.log
	fi
 else
 echo "＠ 양호" >> inetd.log
fi


if [ `cat inetd.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 2.03" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 2.03" >> $CREATE_FILE 2>&1
fi

rm -f inetd.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "2.04 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.04 history 파일 권한 설정 #################################"
echo "################## 2.파일시스템 - 2.04 history 파일 권한 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "모든 사용자의 history 관련파일 권한을 600으로 소유자는 자신으로 설정" >> $CREATE_FILE 2>&1
echo "※ 솔루션 운영상 조치가 불가능한 파일에 대해서는 예외" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "^#"`
FILES="/.sh_history /.bash_history /.history"
fileox="no"

for file in $FILES
  do
    FILE=$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
		fileox="yes"
    fi
  done

FILES2="/.sh_history /.bash_history /.history"
for dir in $HOMEDIRS
do
  for file in $FILES2
  do
    FILE=$dir$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
		fileox="yes"
    fi
  done
done

if [ $fileox = "no" ]
	then
		echo "☞ history 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " > homesh.log

# 조치방법
echo " " >> $CREATE_FILE 2>&1
echo "※ 모든 사용자의 history 관련파일 권한을 600으로 소유자는 자신으로 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "^#"`
FILES="/.sh_history /.bash_history /.history"

for file in $FILES
          do
            if [ -f $file ]
             then
             if [ `ls -alL $file | awk '{print $1}' | grep ".rw-------" | wc -l` -eq 1 ]
              then
                echo "＠ 양호" >> homesh.log
              else
                echo "＠ 취약" >> homesh.log
             fi
            else
              echo "＠ 양호" >> homesh.log
            fi
         done

FILES2=".sh_history .bash_history .history"
 for dir in $HOMEDIRS
    do
       for file in $FILES2
          do
            if [ -f $dir/$file ]
             then
             if [ `ls -dalL $dir/$file | awk '{print $1}' | grep ".rw-------" | wc -l` -eq 1 ]
              then
                echo "＠ 양호" >> homesh.log
              else
                echo "＠ 취약" >> homesh.log
             fi
            else
              echo "＠ 양호" >> homesh.log
            fi
         done
    done

if [ `cat homesh.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 2.04" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 2.04" >> $CREATE_FILE 2>&1
fi

rm -f homesh.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.05 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.05 Crontab 파일 권한 설정 및 관리 #########################"
echo "################## 2.파일시스템 - 2.05 Crontab 파일 권한 설정 및 관리 #########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. crontab 관련파일의 타사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo "나. crontab 파일 권한 744이하, 소유자 root 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① Crontab 관련 파일의 권한 현황" >> $CREATE_FILE 2>&1
cro="/etc/crontab /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* /var/spool/cron/*"
#echo " " > cron.txt
for check_dir in $cro
do
  ls -alL $check_dir 2>/dev/null >> $CREATE_FILE 2>&1
  if [ `ls -alL $check_dir 2>/dev/null | grep  '^........w.' | wc -l` -eq 0 ]
    then 
     echo "양호" >> crontab.log
    else
     echo "취약" >> crontab.log
	 echo "☞ Crontab 관련 파일 권한 취약" >> $CREATE_FILE 2>&1
  fi       
done 
echo " " >> $CREATE_FILE 2>&1


echo "② Crontab에 설정된 예약 파일 현황(파일권한 및 파일 존재 유무 확인)" >> $CREATE_FILE 2>&1

crontxt=`crontab -l 2>&1 | grep -v "^#" | grep -v 'no crontab for root' | wc -l`

if [ $crontxt  -gt 0 ]
	then
		crontab -l | grep -v "^#" | grep -v -e '^$' >> $CREATE_FILE 2>&1
		
echo " " >> $CREATE_FILE 2>&1

CRO=`crontab -l | grep -v "^#" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "^/" | sed 's/"//' | uniq | grep -v null | egrep -v "/sh$|/ksh$|/csh$|/tcsh$" | egrep -v "^./|ftp:|http:|https"`

if [ `echo $CRO | grep [0-9a-zA-Z] | wc -l` -gt 0 ]
 then
 for file in $CRO
   do
     if [ -f $file ]
       then
	     ls -alL $file >> $CREATE_FILE 2>&1
		 if [ `ls -alL $file | awk '{print $NF}' | egrep -v "^/usr/bin/|^/usr/sbin/|^/sbin|^/bin|^bin|^/usr/lib/" | wc -l` -gt 0 ]
		  then
           if [ `ls -alL $file | awk '{print $1 $2 $3}' | grep ".....--.--" | grep -i root | wc -l` -eq 1 ]
            then
             echo "● 양호 - 2.5 Crontab 관리" >> crontab.log
            else
             echo "● 취약 - 2.5 Crontab 관리" >> crontab.log
		     echo "☞ Crontab에 설정된 파일 권한 또는 소유자 설정이 취약" >> $CREATE_FILE 2>&1
           fi
		  else
			echo "☞ 시스템 명령어(파일 퍼미션 검사 제외)" >> $CREATE_FILE 2>&1
		 fi
       else
		 if [ -d $file ]
			then
				ls -aldL $file >> $CREATE_FILE 2>&1
			else
			    ls -alL $file >> $CREATE_FILE 2>&1
				echo "● 취약 - 2.5 Crontab 관리" >> crontab.log
				echo "☞ Crontab에 설정된 파일이 없음 (취약)" >> $CREATE_FILE 2>&1
		 fi
     fi
   done
 else
  echo "☞ Crontab 설정된 파일이 없습니다." >> $CREATE_FILE 2>&1
  echo "● 양호 - 2.6 Crontab 관리" >> crontab.log
fi
else
	echo "☞ Crontab 설정 내용 없음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "※ crontab 관련파일의 타사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo "   crontab내에 불필요한 예약 설정 삭제 및 설정된 파일 권한은 744로 변경를 권고함" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
if [ `cat crontab.log | grep "취약" | wc -l` -eq 0 ]
 then 
  echo "＠ 양호 2.05" >> $CREATE_FILE 2>&1
 else 
  echo "＠ 취약 2.05" >> $CREATE_FILE 2>&1
fi

rm -f crontab.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.06 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.06 /etc/profile 파일 권한 설정 ############################"
echo "################## 2.파일시스템 - 2.06 /etc/profile 파일 권한 설정 ############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/profile 파일의 권한을 root(또는 bin) 소유의 타 사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
  then
    ls -alL /etc/profile >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/profile 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ /etc/profile 파일의 권한을 root(또는 bin) 소유의 타 사용자 쓰기 권한 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/profile ]
then
if [ `ls -alL /etc/profile | awk '{print $1,$3}' | grep -i '........w.' | egrep -i 'root|bin' | wc -l` -eq 0 ]
  then
     echo "＠ 양호 2.06" >> $CREATE_FILE 2>&1
  else
     echo "＠ 취약 2.06" >> $CREATE_FILE 2>&1
fi
else
 echo "＠ 양호 2.06" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "#########################################################################################################" >> $CREATE_FILE 2>&1
echo "=========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.07 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.07 /etc/hosts 파일 권한 설정 ##############################"
echo "################## 2.파일시스템 - 2.07 /etc/hosts 파일 권한 설정 ##############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/hosts 파일의 권한을 root(또는 bin) 소유의 타사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/hosts ]
  then
    ls -alL /etc/hosts >> $CREATE_FILE 2>&1
  else
    echo "/etc/hosts 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ /etc/hosts 파일의 권한을 root(또는 bin) 소유의 타사용자 쓰기 권한 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/hosts ]
then
if [ `ls -alL /etc/hosts | awk '{print $1,$3}' | grep -i '........w.' | egrep -i 'root|bin' | wc -l` -eq 0 ]
  then
    echo "＠ 양호 2.07" >> $CREATE_FILE 2>&1
  else
    echo "＠ 취약 2.07" >> $CREATE_FILE 2>&1
fi
else
 echo "＠ 양호 2.07" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "#########################################################################################################" >> $CREATE_FILE 2>&1
echo "=========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "2.08 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.08 /etc/issue 파일권한 설정 ###############################"
echo "################## 2.파일시스템 - 2.08 /etc/issue 파일권한 설정 ###############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/issue 파일의 권한을 root (또는 bin) 소유의 타사용자의 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/issue ]
  then
    ls -alL /etc/issue >> $CREATE_FILE 2>&1
   else
    echo "☞ /etc/issue 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ /etc/issue 파일의 권한을 root (또는 bin) 소유의 타사용자의 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo "   crontab내에 불필요한 예약 설정 삭제 및 설정된 파일 권한은 744로 변경를 권고함" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/issue ]
then
if [ `ls -alL /etc/issue | awk '{print $1,$3}' | grep -i '........w.' | egrep -i 'root|bin' | wc -l` -eq 0 ]
  then
    echo "＠ 양호 2.08" >> $CREATE_FILE 2>&1
  else
    echo "＠ 취약 2.08" >> $CREATE_FILE 2>&1
fi
else
 echo "＠ 양호 2.08" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.09 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.09 사용자 홈디렉토리 및 파일 관리 #########################"
echo "################## 2.파일시스템 - 2.09 사용자 홈디렉토리 및 파일 관리 #########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "사용자 홈디렉터리 및 환경변수 파일 타사용자 쓰기권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① 사용자 홈디렉토리 파일권한 현황" >> $CREATE_FILE 2>&1


echo " " > home.log
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "^#" | grep -v "/tmp" | grep -v "uucppublic" | grep -v "/dev/nul" | uniq`
         for dir in $HOMEDIRS
          do
               if [ -d $dir ]
			   ls -dalL $dir >> $CREATE_FILE 2>&1
               then
                if [ `ls -dalL $dir | awk '{print $1}' | grep "........w." | wc -l` -eq 0 ]
                then
                  echo "＠ 양호" >> home.log
                 else
                  echo "＠ 취약" >> home.log
                fi
              else
                echo "＠ 양호" >> home.log
              fi
         done


echo " " >> $CREATE_FILE 2>&1
echo "② 사용자 홈디렉토리 환경변수 파일의 권한 현황" >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "^#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for file in $FILES
  do
    FILE=$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
    fi
  done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    FILE=$dir/$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
    fi
  done
done
echo " " >> $CREATE_FILE 2>&1


HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "^#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for file in $FILES
          do
            if [ -f $file ]
             then
             if [ `ls -alL $file | awk '{print $1}' | grep "........w."| wc -l` -eq 0 ]
              then
                echo "＠ 양호" >> home.log
              else
                echo "＠ 취약" >> home.log
             fi
            else
              echo "＠ 양호" >> home.log
            fi
         done

 for dir in $HOMEDIRS
    do
         for file in $FILES
          do
            if [ -f $dir/$file ]
             then
             if [ `ls -dalL $dir/$file | awk '{print $1}' | grep "........w." | wc -l` -eq 0 ]
              then
                echo "＠ 양호" >> home.log
              else
                echo "＠ 취약" >> home.log
             fi
            else
              echo "＠ 양호"  >> home.log
            fi
         done
    done

# 조치방법
echo "※ 사용자 홈디렉토리 및 환경변수 파일 타사용자 쓰기권한 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat home.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 2.09" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 2.09" >> $CREATE_FILE 2>&1
fi
rm -f home.log
echo "END" >> $CREATE_FILE 2>&1
echo "#########################################################################################################" >> $CREATE_FILE 2>&1
echo "=========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.09 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.10 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.10 중요 디렉토리 권한 설정 ################################"
echo "################## 2.파일시스템 - 2.10 중요 디렉토리 권한 설정 ################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "중요 디렉터리(/sbin, /etc, /bin, /usr/bin, /usr/sbin, /usr/lbin) 권한을 root(또는 bin) 소유의 타사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS="/sbin /etc /bin /usr/bin /usr/sbin /usr/lbin"

         for dir in $HOMEDIRS
          do
            ls -dalL $dir 2>/dev/null | grep '\d.........' >> $CREATE_FILE 2>&1
         done
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ 중요 디렉토리의 권한을 root(또는 bin) 소유의 타사용자 쓰기 권한 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo " " > home.log
HOMEDIRS="/sbin /etc /bin /usr/bin /usr/sbin /usr/lbin"
         for dir in $HOMEDIRS
          do
               if [ -d $dir ]
               then
                if [ `ls -dalL $dir | awk '{print $1,$3}' | grep -i '........w.' | egrep -i 'root|bin' | wc -l` -eq 0 ]
                then
                  echo "＠ 양호" >> home.log
                 else
                  echo "＠ 취약" >> home.log
                fi
              else
                echo "＠ 양호" >> home.log
              fi
         done

if [ `cat home.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 2.10" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 2.10" >> $CREATE_FILE 2>&1
fi

rm -f home.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.10 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.11 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.11 PATH 환경변수 설정 #####################################"
echo "################## 2.파일시스템 - 2.11 PATH 환경변수 설정 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "root 계정 환경변수 설정 파일내 PATH 경로중 “.“ 없거나 맨뒤로 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo $PATH >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ root 계정 환경변수 설정 파일내 PATH 경로중 “.“ 제거하거나 맨뒤로 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
  then
    echo "＠ 양호 2.11" >> $CREATE_FILE 2>&1
  else
    echo "＠ 취약 2.11" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.11 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.12 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.12 FTP 접근제어 파일 권한설정 #############################"
echo "################## 2.파일시스템 - 2.12 FTP 접근제어 파일 권한설정 #############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/ftpusers, /etc/ftpd/ftpusers파일의 권한이 root소유의 타사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[ FTP 서비스 확인 ]" >> $CREATE_FILE 2>&1
netstat -anp | grep -i ftp | grep -v '/sftp' >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "  " > ftpusers.log
if [ `netstat -anp | grep -i vsftp | grep -i listen | grep -v grep | grep -v '/sftp'| wc -l` -gt 0 ]
	then
		#if [ -f /etc/vsftpd/vsftpd.conf ]
		if [ `ls -alL /etc/vsftpd/vsftpd.conf  | wc -l` -gt 0 ]
			then
				echo "[ VSFTP 서비스 사용중으로 파일 권한 확인 ]" >> $CREATE_FILE 2>&1
				
				if [ `cat /etc/vsftpd/vsftpd.conf | grep -i "userlist_enable" | grep -i "yes" | grep -v "^#" | wc -l` -gt 0 ]
					then
						cat /etc/vsftpd/vsftpd.conf | grep -i "userlist_enable" >> $CREATE_FILE 2>&1
						#if [ -f /etc/vsftpd/user_list ]
						if [ `ls -alL /etc/vsftpd/user_list | wc -l` -gt 0 ]
							then
								ls -alL /etc/vsftpd/user_list >> $CREATE_FILE 2>&1
								if [ `ls -alL /etc/vsftpd/user_list | awk '{print $1 $2 $3}' | grep -i 'root' |grep -v '........w.' | wc -l` -ge 1 ]
									then
										echo "● 2.12 결과 : 양호" >> ftpusers.log
								else
										echo "● 2.12 결과 : 취약" >> ftpusers.log
										echo "☞ user_list 파일 권한 취약"  >> $CREATE_FILE 2>&1
								fi
						else
							#if [ -f /etc/vsftpd.user_list ]
							if [ `ls -alL /etc/vsftpd.user_list | wc -l` -gt 0 ]
								then
									ls -alL /etc/vsftpd.user_list >> $CREATE_FILE 2>&1
									if [ `ls -alL /etc/vsftpd.user_list | awk '{print $1 $2 $3}' | grep -i 'root' |grep -v '........w.' | wc -l` -ge 1 ]
										then
											echo "● 2.12 결과 : 양호" >> ftpusers.log
									else
										echo "● 2.12 결과 : 취약" >> ftpusers.log
										echo "☞ user_list 파일 권한 취약"  >> $CREATE_FILE 2>&1
									fi
							else
								echo "● 2.12 결과 : 양호" >> ftpusers.log
								echo "☞ user_list 파일 없음"  >> $CREATE_FILE 2>&1
							fi
						fi
				else
					if [ `cat /etc/vsftpd/vsftpd.conf | grep -i "userlist_enable" | grep -i "no" | grep -v "^#" | wc -l` -gt 0 ]
						then
							cat /etc/vsftpd/vsftpd.conf | grep -i "userlist_enable" >> $CREATE_FILE 2>&1
							#if [ -f /etc/vsftpd/ftpusers ]
							if [ `ls -alL /etc/vsftpd/ftpusers | wc -l` -gt 0 ]
								then
									ls -alL /etc/vsftpd/ftpusers >> $CREATE_FILE 2>&1
									if [ `ls -alL /etc/vsftpd/ftpusers | awk '{print $1 $2 $3}' | grep -i 'root' |grep -v '........w.' | wc -l` -ge 1 ]
										then
											echo "● 2.12 결과 : 양호" >> ftpusers.log
									else
											echo "● 2.12 결과 : 취약" >> ftpusers.log
											echo "☞ ftpusers  파일 권한 취약"  >> $CREATE_FILE 2>&1
									fi
							else
								#if [ -f /etc/vsftpd.ftpusers ]
								if [ `ls -alL /etc/vsftpd.ftpusers | wc -l` -gt 0 ]
									then
										ls -alL /etc/vsftpd.ftpusers >> $CREATE_FILE 2>&1
										if [ `ls -alL /etc/vsftpd.ftpusers | awk '{print $1 $2 $3}' | grep -i 'root' |grep -v '........w.' | wc -l` -ge 1 ]
											then
												echo "● 2.12 결과 : 양호" >> ftpusers.log
										else
											echo "● 2.12 결과 : 취약" >> ftpusers.log
											echo "☞ ftpusers  파일 권한 취약"  >> $CREATE_FILE 2>&1
										fi
								else
									echo "● 2.12 결과 : 양호" >> ftpusers.log
									echo "☞ ftpusers 파일 없음"  >> $CREATE_FILE 2>&1
								fi
							fi
					fi
				fi
		fi
else
	if [ `netstat -anp | grep -i ftp | grep -i listen | grep -v grep | grep -v '/sftp'| wc -l` -gt 0 ]
		then
			echo "[ FTP 서비스 사용중으로 파일 권한 확인 ]" >> $CREATE_FILE 2>&1
			#if [ -f /etc/ftpusers ]
			if [ `ls -alL /etc/ftpusers | wc -l` -gt 0 ]
				then
					ls -alL /etc/ftpusers  >> $CREATE_FILE 2>&1
					if [ `ls -alL /etc/ftpusers | awk '{print $1 $2 $3}' | grep -i 'root' |grep -v '........w.' | wc -l` -ge 1 ]
						then
							echo "● 2.12 결과 : 양호" >> ftpusers.log
					else
							echo "● 2.12 결과 : 취약" >> ftpusers.log
							echo "☞ /etc/ftpusers 파일 권한 취약"  >> $CREATE_FILE 2>&1
					fi
			else
				echo "● 2.12 결과 : 양호" >> ftpusers.log
				#if [ -f /etc/ftpd/ftpusers ]
				if [ `ls -alL /etc/ftpd/ftpusers | wc -l` -gt 0 ]
					then
						ls -alL /etc/ftpd/ftpusers  >> $CREATE_FILE 2>&1
						if [ `ls -alL /etc/ftpd/ftpusers | awk '{print $1 $2 $3}' | grep -i 'root' |grep -v '........w.' | wc -l` -ge 1 ]
							then
								echo "● 2.12 결과 : 양호" >> ftpusers.log
						else
							echo "● 2.12 결과 : 취약" >> ftpusers.log
							echo "☞ /etc/ftpd/ftpusers 파일 권한 취약"  >> $CREATE_FILE 2>&1
						fi
				else
					echo "● 2.12 결과 : 양호" >> ftpusers.log
					echo "☞ /etc/ftpusers 파일 없음"  >> $CREATE_FILE 2>&1
					echo "☞ /etc/ftpd/ftpusers 파일 없음"  >> $CREATE_FILE 2>&1
				fi
			fi
	else
		echo "☞ FTP 서비스 미사용"  >> $CREATE_FILE 2>&1
	fi
fi
	
echo " " >> $CREATE_FILE 2>&1
echo "※ FTP 접근제어 파일의 권한을 root 소유의 타사용자 쓰기 권한 제거를 권고함" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat ftpusers.log | grep "취약" | wc -l` -gt 0 ]
 then
  echo "＠ 취약 2.12" >> $CREATE_FILE 2>&1
 else
  echo "＠ 양호 2.12" >> $CREATE_FILE 2>&1
fi
rm -f ftpusers.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.12 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.13 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.13 root 원격 접근제어 파일 권한 설정  #####################"
echo "################## 2.파일시스템 - 2.13 root 원격 접근제어 파일 권한 설정  #####################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/pam.d/login,/etc/securetty 권한을 root(또는 bin) 소유의 타사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "  " > LoginSecu.log
echo "① /etc/pam.d/login 파일 권한 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/login ]
  then
   ls -alL /etc/pam.d/login  >> $CREATE_FILE 2>&1
   if [ `ls -alL /etc/pam.d/login | awk '{print $1,$3}' | grep -i '........w.' | egrep -i 'root|bin' | wc -l` -gt 0 ]
       then
          echo "＠ 취약 2.13" >> LoginSecu.log 2>&1
    fi
else
   echo "☞ /etc/pam.d/login 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "② /etc/securetty 파일 권한 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/securetty ]
	then
		ls -alL /etc/securetty  >> $CREATE_FILE 2>&1
		if [ `ls -alL /etc/securetty | awk '{print $1,$3}' | grep -i '........w.' | egrep -i 'root|bin' | wc -l` -gt 0 ]
			then
				echo "＠ 취약 2.13" >> LoginSecu.log 2>&1
		fi
else
	echo "☞ /etc/securetty 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1


# 조치방법
echo "※ /etc/pam.d/login, /etc/securetty 권한을 root(또는 bin) 소유의 타사용자 쓰기 권한 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat LoginSecu.log | grep "취약" | wc -l` -gt 0 ]
 then
  echo "＠ 취약 2.12" >> $CREATE_FILE 2>&1
 else
  echo "＠ 양호 2.12" >> $CREATE_FILE 2>&1
fi
rm -f LoginSecu.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.13 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.14 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.14 NFS 접근제어 파일 권한 설정 ############################"
echo "################## 2.파일시스템 - 2.14 NFS 접근제어 파일 권한 설정 ############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/exports 파일의 권한이 root(또는 bin) 소유의 타사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f  /etc/exports ]
  then
   ls -alL /etc/exports  >> $CREATE_FILE 2>&1
  else
   echo "☞ /etc/exports 파일이 없습니다"  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ /etc/exports 파일의 권한이 root(또는 bin) 소유의 타사용자 쓰기 권한 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/exports ]
	then
		if [ `ls -alL /etc/exports | awk '{print $1,$3}' | grep -i '........w.' | egrep -i 'root|bin' | wc -l` -eq 0 ]
			then
				echo "＠ 양호 2.14" >> $CREATE_FILE 2>&1
		else
			echo "＠ 취약 2.14" >> $CREATE_FILE 2>&1
	fi
else
	echo "＠ 양호 2.14" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.14 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.15 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.15 /etc/services 파일 권한 설정 ###########################"
echo "################## 2.파일시스템 - 2.15 /etc/services 파일 권한 설정 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/services 파일의 권한이 root(또는 bin) 소유의 타사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/services ]
  then
   ls -alL /etc/services  >> $CREATE_FILE 2>&1
  else
   echo "☞ /etc/services 파일이 없습니다"  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ /etc/services 파일의 권한이 root(또는 bin) 소유의 타사용자 쓰기 권한 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/services ]
 then
  if [ `ls -alL /etc/services | awk '{print $1,$3}' | grep -i '........w.' | egrep -i 'root|bin' | wc -l` -eq 0 ]
      then
        echo "＠ 양호 2.15" >> $CREATE_FILE 2>&1
      else
        echo "＠ 취약 2.15" >> $CREATE_FILE 2>&1
  fi
 else
  echo "＠ 양호 2.15" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.15 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.16 START" >> $CREATE_FILE 2>&1
echo "################## 2.파일시스템 - 2.16 부팅 스크립트 파일 권한 설정 ###########################"
echo "################## 2.파일시스템 - 2.16 부팅 스크립트 파일 권한 설정 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "부팅 스크립트 파일(/etc/rc*.d/*, /etc/inittab 등) 권한 중 타사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

DIR744="/etc/rc*.d/* /etc/inittab"

echo "① /etc/rc*.d/* 파일 확인"   >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/rc*.d/* | grep  '^........w.' | wc -l` -gt 0 ]
	then
		ls -alL /etc/rc*.d/* | grep  '^........w.'  >> $CREATE_FILE 2>&1
else
	echo "☞ /etc/rc*.d/* 모든 파일 타사용자 쓰기 권한 없음(양호)"   >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "② /etc/inittab/* 파일 확인"   >> $CREATE_FILE 2>&1
if [ -d /etc/inittab ]
	then
		if [ `ls -alL /etc/inittab* | grep  '^........w.' | wc -l` -gt 0 ]
			then
				ls -alL /etc/inittab/* | grep  '^........w.'  >> $CREATE_FILE 2>&1
		else
			echo "☞ /etc/inittab/* 모든 파일 타사용자 쓰기 권한 없음(양호)"   >> $CREATE_FILE 2>&1
		fi
else
	echo "☞ /etc/inittab/* 디렉터리 없음"   >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

DIR744="/etc/rc*.d/* /etc/inittab"

echo " " >> etcfiles.log 2>&1

# 조치방법
echo "※ 부팅 스크립트 파일(/etc/rc*.d/*, /etc/inittab 등) 권한 중 타사용자 쓰기 권한 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

for check_dir in $DIR744
do
  if [ -f $check_dir ]
    then
    if [ `ls -alL $check_dir | awk '{print $1}' | grep  '........w.' | wc -l` -gt 0 ]
		then
			echo "＠ 취약" >> etcfiles.log 2>&1
	fi
  fi
  
done

if [ `cat etcfiles.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 2.16" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 2.16" >> $CREATE_FILE 2>&1
fi

rm -f etcfiles.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.16 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.01 START" >> $CREATE_FILE 2>&1
echo "################## 3.네트워크 서비스 - 3.01 RPC 서비스 제한 ###################################"
echo "################## 3.네트워크 서비스 - 3.01 RPC 서비스 제한 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "사용하지 않는 /etc/(x)inetd.conf에서 RPC관련 서비스 제거" >> $CREATE_FILE 2>&1
echo "※ 운영상 필요에 의하여 사용하는 RPC 서비스는 예외" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "① 실행중인 rpc 프로세스 확인"   >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep -i "rpc|portmap" | grep -v grep | grep -v "\[" |wc -l` -ge 1 ]
	then
	ps -ef | grep rpc | grep -v grep | grep -v "\["   >> $CREATE_FILE 2>&1
    echo "＠ 취약" >> rpc.log
else
	echo "☞ 실행중인 rpc 프로세스 존재하지 않습니다. " >> $CREATE_FILE 2>&1
	echo "＠ 양호" >> rpc.log
fi
echo " " >> $CREATE_FILE 2>&1

SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

echo "② /etc/xinetd.d 디렉터리에 rpc 서비스 설정 확인"   >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d ]
  then
    if [ `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | wc -l` -eq 0 ]
      then
        ls /etc/xinetd.d/	>> $CREATE_FILE 2>&1
		echo "☞ /etc/xinetd.d 디렉토리에 불필요한 서비스가 없습니다." >> $CREATE_FILE 2>&1
      else
        ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
    fi
  else
     echo "☞ /etc/xinetd.d 디렉토리가 존재하지 않습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo "③ /etc/inetd.conf 파일의 rpc 서비스 설정 확인"   >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
  then
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
else
    echo "☞ /etc/inetd.conf 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `cat /etc/*-release | grep -i 'DISTRIB_DESCRIPTION' | grep -i 'ubuntu' | wc -l` -gt 0 ]
	then
		echo "④ 부팅 스크립트 rpc 서비스 제거 확인"   >> $CREATE_FILE 2>&1
		echo "☞ Ubuntu Chkconfig 기능 없음 " >> $CREATE_FILE 2>&1
		echo "＠ 양호" >> rpc.log
else
	if [ `cat /etc/*-release | grep -i 'release'| awk -F"." '{print $1}' | egrep -o [7-9] | tail -1 |wc -l` -gt 0 ]
	#if [ `cat /etc/*-release | grep -i 'release'|egrep -o [7-9].[0-9] | tail -1 |wc -l` -gt 0 ]
		then
			echo "④ 부팅 스크립트 rpc 서비스 제거 확인"   >> $CREATE_FILE 2>&1
			if [ `systemctl list-unit-files --type service | egrep -i 'rpcbind|portmap|nfs|nfslock' | awk -F' ' '{print $2}' | egrep -i 'enabled' | wc -l` -eq 0 ]
				then
					systemctl list-unit-files --type service | egrep -i 'rpcbind|portmap|nfs|nfslock'  >> $CREATE_FILE 2>&1
					echo "＠ 양호" >> rpc.log
			else
				systemctl list-unit-files --type service | egrep -i 'rpcbind|portmap|nfs|nfslock'  >> $CREATE_FILE 2>&1
				echo "☞ 부팅 스크립트에 rpc 서비스가 있어 취약 합니다. " >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> rpc.log
			fi
	else
		echo "④ 부팅 스크립트 rpc 서비스 제거 확인"   >> $CREATE_FILE 2>&1
		if [ `chkconfig --list | egrep -i 'rpcbind|portmap|nfs|nfslock' | egrep -i ':on|:활성' | wc -l` -eq 0 ]
			then
				chkconfig --list | egrep -i 'rpcbind|portmap|nfs|nfslock'  >> $CREATE_FILE 2>&1
				echo "＠ 양호" >> rpc.log
		else
			chkconfig --list | egrep -i 'rpcbind|portmap|nfs|nfslock'  >> $CREATE_FILE 2>&1
			echo "☞ 부팅 스크립트에 rpc 서비스가 있어 취약 합니다. " >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> rpc.log
		fi
	fi
fi

echo " " >> $CREATE_FILE 2>&1
SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

if [ -d /etc/xinetd.d/ ]
	then
		if [ `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | wc -l` -gt 0 ]
			then
				for VVV in `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD| awk '{print $NF}'`
				do
					if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
						then
							echo "＠ 취약" >> rpc.log
					else
							echo "＠ 양호" >> rpc.log
					fi
				done
		else
			echo "＠ 양호" >> rpc.log
		fi
else
	if [ -f /etc/inetd.conf ]
		then
			if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l` -eq 0 ]
				then
					echo "＠ 양호" >> rpc.log
			else
				echo "＠ 취약" >> rpc.log
			fi
	fi
fi

# 조치방법
echo "※ 불필요한 경우 RPC 서비스를 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat rpc.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 3.01" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 3.01" >> $CREATE_FILE 2>&1
fi
rm -f rpc.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.02 START" >> $CREATE_FILE 2>&1
echo "################## 3.네트워크 서비스 - 3.02 NFS(Network File System) 제한 #####################"
echo "################## 3.네트워크 서비스 - 3.02 NFS(Network File System) 제한 #####################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. 서비스 필요시 인가되지 않는 시스템 mount 해제 및 everyone 으로 시스템 mount 제한" >> $CREATE_FILE 2>&1
echo "나. 서비스 불필요시 NFS데몬(nfsd, statd, lockd) 중지" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "① NFS 데몬(nfsd)확인" >> $CREATE_FILE 2>&1

if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ]
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"  >> $CREATE_FILE 2>&1
 else
   echo "☞ NFS 서비스가 비실행중입니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1


echo "② /etc/exports 파일 내용" >> $CREATE_FILE 2>&1
if [ -f /etc/exports ]
 then
   if [ `cat /etc/exports | grep -v "^#" | wc -l` -gt 0 ]
     then
	   cat /etc/exports | grep -v "^#"  >> $CREATE_FILE 2>&1
	 else
	   echo " ☞ /etc/exports 파일에 설정값이 없습니다.."  >> $CREATE_FILE 2>&1
   fi
 else
   echo "☞ /etc/exports 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1


echo "③ NFS를 원격에서 mount하고 있는 시스템을 확인 " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep nfsd | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ]
 then
   showmount  >> $CREATE_FILE 2>&1
 else
   echo "☞ NFS를 원격에서 mount하고 있는 시스템이 없습니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1


echo "④ NFS 데몬(statd,lockd)확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|rpc|statdaemon|emi|kblockd" | wc -l` -gt 0 ]
   then
       ps -ef | egrep "statd|lockd" | egrep -v "grep|rpc|statdaemon|emi|kblockd" >> $CREATE_FILE 2>&1
  else
    echo "☞ NFS 데몬(statd,lockd)이 비실행중입니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1


echo "⑤ NFS 서비스 시작 스크립트 확인" >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/rc*.d/* | egrep " S15nfs.sever| S73nfs.client" | wc -l` -eq 0 ]
 then
   echo "☞ NFS 시작 스크립트가 없습니다. " >> $CREATE_FILE 2>&1
 else
   ls -alL /etc/rc*.d/* | grep " S15nfs.sever| S73nfs.client" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ 불필요한 경우 NFS 서비스 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo " " > nfs.log 2>&1
if [ `ps -ef | egrep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "＠ 양호" >> nfs.log 2>&1
 else
   if [ -f /etc/exports ]
     then
       if [ `cat /etc/exports | grep -v "^#" | wc -l` -eq 0 ]
		  then
			  if [ `showmount | grep -v "^#" | wc -l` -eq 0 ]
  				 then
					 echo "＠ 취약 - 3.2 NFS 설정" >> nfs.log 2>&1
			  fi
		fi
	fi
fi


if [ `cat nfs.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 3.02" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 3.02" >> $CREATE_FILE 2>&1
fi
rm -f nfs.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.03 START" >> $CREATE_FILE 2>&1
echo "################## 3.네트워크 서비스 - 3.03 Automountd 서비스 제거 ############################"
echo "################## 3.네트워크 서비스 - 3.03 Automountd 서비스 제거 ############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "특별한 목적으로 사용하지 않는 Automount 서비스 제거" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "① Automount 데몬 확인 " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep automount | egrep -v "grep|rpc|statdaemon|emi" | wc -l` -gt 0 ]
  then
    ps -ef | grep automount | egrep -v "grep|rpc|statdaemon|emi" >> $CREATE_FILE 2>&1
  else
    echo "☞ Automount 서비스가 비실행중입니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "② Automount 부팅 스크립트 확인 " >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/rc*.d/* | grep -i autofs | grep "/S" | wc -l` -gt 0 ]
 then
   ls -alL /etc/rc*.d/* | grep -i autofs | grep "/S" | grep -v autoinstall  >> $CREATE_FILE 2>&1
 else
   echo "☞ Automount 부팅 스크립트가 존재하지 않습니다. "  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ 불필요한 경우 Automount 서비스 제거 및 부팅 스크립트에서 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep automount | egrep -v "grep|rpc|statdaemon|emi" | wc -l` -eq 0 ]
  then
     echo "＠ 양호" >> autof.log 2>&1
  else
     echo "＠ 취약" >> autof.log 2>&1
fi

if [ `ls -alL /etc/rc*.d/* | grep -i autofs | grep "/S" | wc -l` -eq 0 ]
  then
    echo "＠ 양호" >> autof.log 2>&1
  else
    echo "＠ 취약" >> autof.log 2>&1
fi


if [ `cat autof.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 3.03" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 3.03" >> $CREATE_FILE 2>&1
fi

rm -f autof.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.04 START" >> $CREATE_FILE 2>&1
echo "################## 3.네트워크 서비스 - 3.04 NIS(Network Information Service) 제한 #############"
echo "################## 3.네트워크 서비스 - 3.04 NIS(Network Information Service) 제한 #############" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "특별한 목적으로 사용하지 않는 NIS 서비스 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

echo "[ NIS 서비스 확인 ]" >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
   then
    echo "☞ NIS, NIS+ 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "[ NIS 시작 스크립트 파일 확인 ]" >> $CREATE_FILE 2>&1
		if [ `ls -alL /etc/rc*/* | grep -i ypserv | grep "/S" | wc -l` -gt 0 ]
			then
				ls -alL /etc/rc*.d/* | grep -i ypserv | grep "/S" >> $CREATE_FILE 2>&1
				echo "☞ NIS 시작 스크립트 파일 취약 " >> $CREATE_FILE 2>&1
		else
			echo "☞ NIS 시작 스크립트 파일 양호 " >> $CREATE_FILE 2>&1
		fi
		echo " " >> $CREATE_FILE 2>&1
	
else
    ps -ef | egrep $SERVICE | grep -v "grep" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ 불필요한 경우 NIS 서비스 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

if [ \( `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 \) -o \( `ls -alL /etc/rc*/* | grep -i 'ypserv' | grep "/S" | wc -l` -gt 0 \) ]
     then
        echo "＠ 양호 3.04" >> $CREATE_FILE 2>&1
     else
        echo "＠ 취약 3.04" >> $CREATE_FILE 2>&1
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "3.05 START" >> $CREATE_FILE 2>&1
echo "################## 3.네트워크 서비스 - 3.05 ‘r’ commands 서비스 제거 ##########################"
echo "################## 3.네트워크 서비스 - 3.05 ‘r’ commands 서비스 제거 ##########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. 서비스 필요시 /etc/hosts.equiv, /$HOME/.rhosts 파일의 권한을 400 root 소유로 설정" >> $CREATE_FILE 2>&1
echo "    /etc/hosts.equiv, /$HOME/.rhosts 설정에 접근가능 고정 IP 설정" >> $CREATE_FILE 2>&1
echo "나. 서비스 불필요시 rsh, rlogin, rexec 등 ‘r’ commands 서비스 제거" >> $CREATE_FILE 2>&1
echo "    /etc/hosts.equiv, /$HOME/.rhosts 파일의 권한을 root 소유의 000 으로 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " > rcmd.log
mand="no"

echo "[ r-command 서비스 확인 ]"	>> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d/ ]
	then
		RSERVICE=`ls -alL /etc/xinetd.d/ | egrep "rsh|rlogin|rexec" | egrep -v "grep|klogin|kshell|kexec" | wc -l`
else
	RSERVICE=0
fi

if [ `ps -ef | grep xinetd | grep -v 'grep' | wc -l` -eq 0 ]
	then
		echo "☞ r-command 서비스 미사용"	>> $CREATE_FILE 2>&1
else
	if [ $RSERVICE -eq 0 ]
		then
			ps -ef | grep xinetd | grep -v 'grep' >> $CREATE_FILE 2>&1
			echo "☞ rsh, rlogin, rexec 서비스 미사용"	>> $CREATE_FILE 2>&1
	else
		ps -ef | grep xinetd | grep -v 'grep' >> $CREATE_FILE 2>&1
		ls -alL /etc/xinetd.d/ | egrep "rsh|rlogin|rexec" | egrep -v "grep|klogin|kshell|kexec" >> $CREATE_FILE 2>&1
		echo "☞ rsh, rlogin, rexec 서비스 사용중"	>> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
echo "① /etc/xinetd.d에 r-command 설정 현황" >> $CREATE_FILE 2>&1
SERVICE_INETD="rsh|rlogin|rexec"
#SERVICE_INETD="rsh|rlogin|rexec|rstat"
if [ `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | wc -l` -gt 0 ]
  then
     for VVV in `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
         echo " $VVV 파일" >> $CREATE_FILE 2>&1
         cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
		 if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
			then
				mand="yes"
		fi
        done
  else
      echo "☞ 불필요 서비스 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1


echo "② /etc/inetd.conf에 r-command 설정 현황" >> $CREATE_FILE 2>&1
SERVICE_INETD="shell|login|exec"
if [ -f /etc/inetd.conf ]
  then
	if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -i "rsh|rlogin|rexec|rstat" | wc -l` -gt 0 ] 
		then
			cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -i "rsh|rlogin|rexec|rstat" >> $CREATE_FILE 2>&1
			echo "☞ 불필요 서비스가 존재 합니다. (취약)" >> $CREATE_FILE 2>&1
	else
		
		echo "☞ 불필요 서비스가 존재하지 않습니다. (양호)" >> $CREATE_FILE 2>&1
	fi
  else
    echo "☞ /etc/inetd.conf 파일이 존재하지 않습니다. (양호)" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -d /etc/xinetd.d/ ]
	then
		SERVICE_INETD="rsh|rlogin|rexec|rstat"
		if [ `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | wc -l` -gt 0 ]
			then
				for VVV in `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | awk '{print $9}'`
				do
					if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
						then
							echo "＠ 취약" >> rcmd.log
					else
						echo "＠ 양호" >> rcmd.log
					fi
				done
		else
			echo "＠ 양호" >> rcmd.log
		fi
elif [ -f /etc/inetd.conf ]
	then
		if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -i "rsh|rlogin|rexec|rstat" |wc -l` -eq 0 ]
			then
				echo "＠ 양호" >> rcmd.log
		else
			echo "＠ 취약" >> rcmd.log
		fi
else
	echo "＠ 양호" >> rcmd.log
fi

echo "③ /etc/hosts.equiv 파일권한 및 내용" >> $CREATE_FILE 2>&1

if [ -f /etc/hosts.equiv ]
	then
	if [ $mand == "yes" ]
		then
			if [ `ls -alL /etc/hosts.equiv | awk '{print $1 $2 $3}' | grep '..--------' | grep -i 'root' | wc -l` -gt 0 ]
				then
					if [ `cat /etc/hosts.equiv | grep "+" | grep -v "grep" | grep -v "^#" | wc -l ` -eq 0 ]
						then
							ls -alL /etc/hosts.equiv >> $CREATE_FILE 2>&1
							cat /etc/hosts.equiv >> $CREATE_FILE 2>&1
							echo "＠ 양호" >> rcmd.log
					else
						ls -alL /etc/hosts.equiv >> $CREATE_FILE 2>&1
						cat /etc/hosts.equiv >> $CREATE_FILE 2>&1
						echo "☞ /etc/hosts.equiv 파일내 '+' 설정 취약" >> $CREATE_FILE 2>&1
						echo "＠ 취약" >> rcmd.log
					fi
			else
				ls -alL /etc/hosts.equiv >> $CREATE_FILE 2>&1
				echo "☞ /etc/hosts.equiv 파일 권한 설정 취약(퍼미션 400 권고)" >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> rcmd.log
			fi
	else
			if [ `ls -alL /etc/hosts.equiv | awk '{print $1 $2 $3}' | grep '.---------' | grep -i 'root' | wc -l` -gt 0 ]
				then
					if [ `cat /etc/hosts.equiv | grep "+" | grep -v "grep" | grep -v "^#" | wc -l ` -eq 0 ]
						then
							ls -alL /etc/hosts.equiv >> $CREATE_FILE 2>&1
							cat /etc/hosts.equiv >> $CREATE_FILE 2>&1
							echo "＠ 양호" >> rcmd.log
					else
						ls -alL /etc/hosts.equiv >> $CREATE_FILE 2>&1
						cat /etc/hosts.equiv >> $CREATE_FILE 2>&1
						echo "☞ /etc/hosts.equiv 파일내 '+' 설정 취약" >> $CREATE_FILE 2>&1
						echo "＠ 취약" >> rcmd.log
					fi
			else
				ls -alL /etc/hosts.equiv >> $CREATE_FILE 2>&1
				echo "☞ /etc/hosts.equiv 파일 권한 설정 취약(퍼미션 000 권고)" >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> rcmd.log
			fi
	fi
else
    echo "☞ /etc/hosts.equiv 파일이 없습니다. (취약)" >> $CREATE_FILE 2>&1
	echo "＠ 취약" >> rcmd.log
fi
echo " " >> $CREATE_FILE 2>&1

rootDIRS=`cat /etc/passwd | grep -w 'root' | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
echo "④ /root/.rhosts 파일권한 및 내용 ($rootDIRS)" >> $CREATE_FILE 2>&1
if [ -f $rootDIRS/.rhosts ]
	then
		if [ $mand == "yes" ]
			then
				if [ `ls -alL $rootDIRS/.rhosts | awk '{print $1 $2 $3}' | grep '..--------' | grep -i 'root' | wc -l` -gt 0 ]
					then
						ls -alL $rootDIRS/.rhosts >> $CREATE_FILE 2>&1
						if [ `cat $rootDIRS/.rhosts | grep "+" | grep -v "grep" | grep -v "^#" | wc -l` -eq 0 ]
							then
								cat $rootDIRS/.rhosts >> $CREATE_FILE 2>&1
								echo "＠ 양호" >> rcmd.log
						else
							cat $rootDIRS/.rhosts | grep "+" | grep -v "grep" | grep -v "^#" >> $CREATE_FILE 2>&1
							echo "☞ $rootDIRS/.rhosts 파일내 '+' 설정 취약" >> $CREATE_FILE 2>&1
							echo "＠ 취약" >> rcmd.log
						fi
				else
					ls -alL $rootDIRS/.rhosts >> $CREATE_FILE 2>&1
					echo "☞ $rootDIRS/.rhosts 파일 권한 취약(퍼미션 400 권고)" >> $CREATE_FILE 2>&1
					echo "＠ 취약" >> rcmd.log
				fi
		else
				if [ `ls -alL $rootDIRS/.rhosts | awk '{print $1 $2 $3}' | grep '.---------' | grep -i 'root' | wc -l` -gt 0 ]
					then
						ls -alL $rootDIRS/.rhosts >> $CREATE_FILE 2>&1
						if [ `cat $rootDIRS/.rhosts | grep "+" | grep -v "grep" | grep -v "^#" | wc -l` -eq 0 ]
							then
								cat $rootDIRS/.rhosts >> $CREATE_FILE 2>&1
								echo "＠ 양호" >> rcmd.log
						else
							cat $rootDIRS/.rhosts | grep "+" | grep -v "grep" | grep -v "^#" >> $CREATE_FILE 2>&1
							echo "☞ $rootDIRS/.rhosts 파일내 '+' 설정 취약(퍼미션 000 권고)" >> $CREATE_FILE 2>&1
							echo "＠ 취약" >> rcmd.log
						fi
				else
					ls -alL $rootDIRS/.rhosts >> $CREATE_FILE 2>&1
					echo "☞ $rootDIRS/.rhosts 파일 권한 취약" >> $CREATE_FILE 2>&1
					echo "＠ 취약" >> rcmd.log
				fi
		fi
else
	echo "☞ $rootDIRS/.rhosts 파일 없음 (취약)" >> $CREATE_FILE 2>&1
	   echo "＠ 취약" >> rcmd.log
fi        

echo " " >> $CREATE_FILE 2>&1

echo "⑤ /HOME/.rhosts 파일권한 및 내용 " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | grep -v 'root' | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
FILES="/.rhosts"
for dir in $HOMEDIRS
do
      for file in $FILES
      do
        if [ -f $dir$file ]
        then
          echo "☞ $dir$file 설정 내용" >> $CREATE_FILE 2>&1
			ls -alL $dir$file  >> $CREATE_FILE 2>&1
          cat $dir$file | grep -v "^#" >> $CREATE_FILE 2>&1
          echo " " >> $CREATE_FILE 2>&1
        else
echo "☞ $dir$file 파일이 없습니다." >> $CREATE_FILE 2>&1
        fi
      done
done

fi
fi

## /$HOME/.rhosts 파일에 + 존재 여부 점검
for dir in $HOMEDIRS
do
	  for file in $FILES
	  do
	    if [ -f $dir$file ]
	      then
	        if [ `cat $dir$file | grep "+" | grep -v "grep" | grep -v "^#" |wc -l ` -eq 0 ]
	         then
	          echo "＠ 양호" >> rcmd.log
	         else
	          echo "＠ 취약" >> rcmd.log
	        fi
	      else
	      echo "＠ 양호" >> rcmd.log
	    fi
	  done
done
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ 불필요한 경우 ‘r’ commands 서비스 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat rcmd.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 3.05" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 3.05" >> $CREATE_FILE 2>&1
fi

rm -f rcmd.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.06 START" >> $CREATE_FILE 2>&1
echo "################## 3.네트워크 서비스 - 3.06 불필요한 서비스 제거 ##############################"
echo "################## 3.네트워크 서비스 - 3.06 불필요한 서비스 제거 ##############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "서버의 정보 노출 하고 보안상 불필요한 서비스 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SERVICE_INETD="echo|discard|daytime|chargen|time|tftp|finger|sftp|uucp-path|nntp|ntp|netbios_ns|netbios_dgm|netbios_ssn|bftp|ldap|printer|talk|ntalk|uucp|pcserver|ldaps|ingreslock|www-ldap-gw|nfsd|dtspcd"

echo "① /etc/inetd.conf 기타 서비스 현황" >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
  then
    if cat /etc/inetd.conf | grep -v '^#' | egrep '^echo|^discard|^daytime|^chargen|^time|^tftp|^finger|^sftp|^uucp-path|^nntp|^ntp|^netbios_ns|^netbios_dgm|^netbios_ssn|^bftp|^ldap|^printer|^talk|^ntalk|^uucp|^pcserver|^ldaps|^ingreslock|^www-ldap-gw|^nfsd|^dtspcd' ; then
	   cat /etc/inetd.conf | grep -v '^#' | egrep '^echo|^discard|^daytime|^chargen|^time|^tftp|^finger|^sftp|^uucp-path|^nntp|^ntp|^netbios_ns|^netbios_dgm|^netbios_ssn|^bftp|^ldap|^printer|^talk|^ntalk|^uucp|^pcserver|^ldaps|^ingreslock|^www-ldap-gw|^nfsd|^dtspcd' >> $CREATE_FILE 2>&1
	else
		echo "☞ 불필요한 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
  else
    echo "☞ /etc/inetd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "② /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
#if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
if [ -d /etc/xinetd.d/ ]
  then
     if [ `ls /etc/xinetd.d/ | wc -l` -gt 0 ]
		then
			if [ `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'` -gt 0 ]
				then
					for VVV in `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
						do
						echo " $VVV 파일" >> $CREATE_FILE 2>&1
						cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
						echo "   " >> $CREATE_FILE 2>&1
						done
			else
				ls /etc/xinetd.d/	>> $CREATE_FILE 2>&1s
				echo "☞ /etc/xinetd.d/* 불필요한 서비스 없습니다." >> $CREATE_FILE 2>&1s
			fi
	  else
			echo "☞ /etc/xinetd.d/* 파일이 없습니다." >> $CREATE_FILE 2>&1
	  fi
  else
      echo "☞ /etc/xinetd.d/ 디렉토리 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


echo " " > service.log

# 조치방법
echo "※ 불필요한 서비스가 실행중인 경우 서비스 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/inetd.conf ]
 then
  if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
      then
       echo "＠ 양호" >> service.log
      else
       echo "＠ 취약" >> service.log
  fi
 else
  echo "＠ 양호" >> service.log
fi

if [ -d /etc/xinetd.d/ ]
  then
   if [ `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
        if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "＠ 취약" >> service.log
          else
           echo "＠ 양호" >> service.log
        fi
        done
    else
      echo "＠ 양호" >> service.log
    fi
  else
    echo "＠ 양호" >> service.log
fi

if [ `cat service.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 3.06" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 3.06" >> $CREATE_FILE 2>&1
fi

rm -f service.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.07 START" >> $CREATE_FILE 2>&1
echo "################## 3.네트워크 서비스 - 3.07 서비스 Banner 관리 ################################"
echo "################## 3.네트워크 서비스 - 3.07 서비스 Banner 관리 ################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "Telnet, FTP, SMTP, DNS 서비스 사용시 접속 배너에 경고문 표시 및 정보 노출 방지 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[ TELNET 배너 확인 ]" >> $CREATE_FILE 2>&1
if [ -f /etc/services ]
	then
	if [ `cat /etc/services | grep -w "telnet" | grep -i "tcp" | wc -l` -gt 0 ]
		then
			telnetp=`cat /etc/services | grep -w "telnet" | grep -v '#' | grep -i "tcp" | awk -F' ' '{print $2}' | awk -F'/' '{print $1}'`
	else
		telnetp=23
	fi
else
	telnetp=23
fi
echo "① TELNET Port 확인 " >> $CREATE_FILE 2>&1
echo "telnet "$telnetp"/tcp" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `netstat -an 2>&1 | grep -i ":$telnetp " | grep -i LISTEN | wc -l` -gt 0 ]
	then
		echo "② TELNET 서비스 확인 " >> $CREATE_FILE 2>&1
		netstat -an 2>&1 | grep -i ":$telnetp " | grep -i LISTEN >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "③ /etc/issue 파일 확인 -" >> $CREATE_FILE 2>&1
		if [ -f /etc/issue.net ]
			then
				cat /etc/issue.net >> $CREATE_FILE 2>&1
			else
				echo "☞ /etc/issue.net 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
		fi
	else
		echo "☞ telnet 서비스가 구동중이지 않습니다" >> $CREATE_FILE 2>&1
fi

echo "  " > banner.log
if [ `netstat -an 2>&1 | grep -i ":$telnetp " | grep -i LISTEN | wc -l` -gt 0 ]
 then
   if [ -f /etc/issue.net ]
     then
       if [ `cat /etc/issue.net | egrep -i "kernel|release" | wc -l` -eq 0 ]
         then
           echo "＠ 양호 - telnet" >> banner.log
         else
           echo "＠ 취약 - telnet" >> banner.log
		   echo "☞ Telnet banner 취약" >> $CREATE_FILE 2>&1
       fi
     else
       echo "＠ 취약 - telnet" >> banner.log
   fi
 else
   echo "＠ 양호 - telnet" >> banner.log
fi

echo " " >> $CREATE_FILE 2>&1

echo "[ FTP 배너 확인 ]" >> $CREATE_FILE 2>&1
echo "① FTP 서비스 확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep ftpd | grep -v grep | grep -v '^sftp' | wc -l` -eq 0 ]
	then
		echo "☞ FTP 서비스가 구동중이지 않습니다." >> $CREATE_FILE 2>&1
else
	ps -ef | grep ftpd | grep -v grep >> $CREATE_FILE 2>&1
	
	
if [ `ps -ef | grep -i "/ftpd" | grep -v grep | wc -l` -gt 0 ]
    then
		echo " " >> $CREATE_FILE 2>&1
		echo "[일반 FTP] /etc/welcome.msg 파일 확인" >> $CREATE_FILE 2>&1
		if [ -f /etc/welcome.msg ]
			then
				if [ `cat /etc/welcome.msg |egrep -i "welcome|ftp" | wc -l` -gt 0 ]
					then
						cat /etc/welcome.msg >> $CREATE_FILE 2>&1
						echo "＠ 취약 - ftp" >> banner.log
						echo "☞ banner 취약 합니다." >> $CREATE_FILE 2>&1
				else
					cat /etc/welcome.msg >> $CREATE_FILE 2>&1
					echo "＠ 양호 - ftp" >> banner.log
				fi
		else
			echo "☞ /etc/welcome.msg 파일이 없어 취약 합니다." >> $CREATE_FILE 2>&1
			echo "＠ 취약 - ftp" >> banner.log
		fi
else
	echo "＠ 양호 - ftp" >> banner.log		  
fi

if [ `ps -ef | egrep "/vsftpd" | grep -v grep | wc -l` -gt 0 ]
	then
		echo " " >> $CREATE_FILE 2>&1
		echo "[VSFTP] /etc/vsftpd/vsftpd.conf 파일 확인" >> $CREATE_FILE 2>&1
		if [ -f /etc/vsftpd/vsftpd.conf ]
			then
				cat /etc/vsftpd/vsftpd.conf | grep -i "ftpd_banner" >> $CREATE_FILE 2>&1
				if [ `cat /etc/vsftpd/vsftpd.conf |grep -v "^#" | grep -i "ftpd_banner" | awk -F"=" '{print $2}' | egrep -i "welcome|ftp" | wc -l` -gt 0 ]
					then
						echo "＠ 취약 - vsftp" >> banner.log
						echo "☞ banner 취약 합니다." >> $CREATE_FILE 2>&1
				else
					echo "＠ 양호 - vsftp" >> banner.log
				fi
		else
			echo "☞ /etc/vsftpd/vsftpd.conf 파일이 없어 취약 합니다." >> $CREATE_FILE 2>&1
			echo "＠ 취약 - ftp" >> banner.log
		fi
else
	echo "＠ 양호 - vsftp" >> banner.log		 
fi	  

if [ `ps -ef | egrep "/proftpd" | grep -v grep | wc -l` -gt 0 ]
	then
		echo " " >> $CREATE_FILE 2>&1
		echo "[PROFTP] proftpd.conf 파일(버전마다 위치가 다름)에 Serverldent 설정" >> $CREATE_FILE 2>&1
		cat /usr/local/proftpd/etc/proftpd.conf 2>/dev/null | grep -i "Serverldent" >> $CREATE_FILE 2>&1
		cat /usr/local/etc/proftpd.conf 2>/dev/null | grep -i "Serverldent" >> $CREATE_FILE 2>&1
		cat /etc/proftpd.conf 2>/dev/null | grep -i "Serverldent" >> $CREATE_FILE 2>&1
		cat /etc/proftpd/etc/proftpd.conf 2>/dev/null | grep -i "Serverldent" >> $CREATE_FILE 2>&1
		if [ `cat /usr/local/proftpd/etc/proftpd.conf /usr/local/etc/proftpd.conf /etc/proftpd.conf /etc/proftpd/etc/proftpd.conf | grep -i "ServerIdent" | grep -v "^#" | grep -i "off" | wc -l` -gt 0 ]
		    then
				echo "＠ 양호 - proftp" >> banner.log
        else
            echo "＠ 취약 - proftp" >> banner.log
			echo "☞ Serverldent 설정이 취약 합니다." >> $CREATE_FILE 2>&1
        fi
else
	echo "＠ 양호 - proftp" >> banner.log		  
fi
	  

if [ `ps -ef | egrep "/proftpd" | grep -v grep | wc -l` -gt 1 ]
	then
		echo " " >> $CREATE_FILE 2>&1
		echo "[WUFTP] /etc/ftpaccess 파일에 Greeting 설정" >> $CREATE_FILE 2>&1
		cat /etc/ftpaccess 2>/dev/null | grep -i "Greeting" >> $CREATE_FILE 2>&1
		if [ `cat /etc/ftpaccess | grep -i "greeting" | grep -v "^#" | grep -i "terse" | wc -l` -gt 0 ]
		    then
				echo "＠ 양호 - wuftp" >> banner.log
        else
            echo "＠ 취약 - wuftp" >> banner.log
			echo "☞ greeting 설정이 취약 합니다." >> $CREATE_FILE 2>&1
        fi
else
	echo "＠ 양호 - wuftp" >> banner.log
fi	  

fi

echo " " >> $CREATE_FILE 2>&1
echo "[ SMTP 배너 확인 ]" >> $CREATE_FILE 2>&1
echo "① SMTP 서비스 확인 " >> $CREATE_FILE 2>&1
if [ `netstat -anp | grep -i sendmail | grep -i tcp | wc -l` -gt 0 ]
  then
     netstat -anp | grep -i sendmail | grep -i tcp  >> $CREATE_FILE 2>&1
     echo " " >> $CREATE_FILE 2>&1
     
     #echo "☞ SMTP 배너 확인(SMTP 설정에 따라 sendmail.cf 파일 위치가 다를 수 있음)" >> $CREATE_FILE 2>&1
	 if [ -f /etc/postfix/main.cf ]
	   then
	     echo "② /etc/postfix/main.cf 파일 내용 " >> $CREATE_FILE 2>&1
         cat /etc/postfix/main.cf | grep -i "smtpd_banner" >> $CREATE_FILE 2>&1
         if [ `cat /etc/postfix/main.cf | grep -i "smtpd_banner" | grep -v '^#' | egrep -i '\$myhostname|\$main_name' | wc -l` -gt 0 ]
           then
             echo "● 3.07 결과 : 취약" >> banner.log
			 echo "☞ banner 취약 합니다." >> $CREATE_FILE 2>&1
		   else
			 echo "● 3.07 결과 : 양호" >> banner.log
         fi
       else
         if [ -f /etc/mail/sendmail.cf ]
           then
	         echo "② /etc/mail/sendmail.cf 파일 내용 " >> $CREATE_FILE 2>&1
             cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
             if [ `cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" | grep -v '^#' | egrep -i 'Sendmail|\$j|\$v|\$z|\$b' | wc -l` -eq 0 ]
               then
                 echo "● 3.07 결과 : 양호" >> banner.log
               else
                 echo "● 3.07 결과 : 취약" >> banner.log
				 echo "☞ banner 취약 합니다." >> $CREATE_FILE 2>&1
				 
             fi
           else
             echo "● 3.07 결과 : 취약" >> banner.log
             echo "☞ /etc/postfix/main.cf 파일이 존재하지 않아 취약 합니다." >> $CREATE_FILE 2>&1
			 echo "☞ /etc/mail/sendmail.cf 파일이 존재하지 않아 취약 합니다." >> $CREATE_FILE 2>&1
         fi
	 fi
  else
    echo "● 3.07 결과 : 양호" >> banner.log
    echo "☞ SMTP 서비스 구동중이지 않습니다." >> $CREATE_FILE 2>&1
fi

echo "  " >> $CREATE_FILE 2>&1
## conf
if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
	then
		if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 1 ]
			then
				if [ `ps -ef | grep named | grep -v grep | grep -i "\-c" | wc -l` -ge 2 ]
					then
						namec=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep -i "*.conf"`
				else
					if [ `ps -ef | grep named | grep -v grep | grep -i "\-c" | wc -l` -eq 1 ]
						then
							namec1=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep -i "*.conf"`
							if [ -f /etc/named.conf ]
								then
									namec2=`ls -alL /etc/named.conf | awk '{print $NF}'`
							else
								if [ -f /etc/named.caching-nameserver.conf ]
									then						
										namec2=`ls -alL /etc/named.caching-nameserver.conf | awk '{print $NF}'`  
								else
									namec2=`XXX`
								fi
							fi
					else
						if [ -f /etc/named.conf ]
							then
								namec=`ls -alL /etc/named.conf | awk '{print $NF}'`
						else
							if [ -f /etc/named.caching-nameserver.conf ]
								then						
									namec=`ls -alL /etc/named.caching-nameserver.conf | awk '{print $NF}'`  
							else
								namec=`XXX`
							fi
						fi
					fi
				fi
		else
			if [ `ps -ef | grep named | grep -v grep | grep -i "\-c" | wc -l` -eq 1 ]
				then
					namec=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep -i "*.conf"`
			else
				if [ -f /etc/named.conf ]
					then
						namec=`ls -alL /etc/named.conf | awk '{print $NF}'`
				else
					if [ -f /etc/named.caching-nameserver.conf ]
						then						
							namec=`ls -alL /etc/named.caching-nameserver.conf | awk '{print $NF}'`  
					else
						namec=`XXX`
					fi
				fi
			fi
		fi
fi

	
echo "[ DNS 배너 확인 ]" >> $CREATE_FILE 2>&1
echo "① DNS 서비스 확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
  then
    ps -ef | grep named | grep -v grep >> $CREATE_FILE 2>&1
    echo "  " >> $CREATE_FILE 2>&1

	echo "② conf 파일 확인" >> $CREATE_FILE 2>&1
	if [ `echo $namec | grep -i "conf" | wc -l` -gt 0 ]
		then
	for namedcf in $namec
		do
		echo "- $namedcf 파일 확인 -" >> $CREATE_FILE 2>&1
		if [ -f $namedcf ]
			then
				if [ `cat $namedcf | grep -i 'version "*"' | wc -l` -eq 0 ]
					then
						echo "● 3.07 결과 : 취약" >> banner.log
						echo "☞ $namedcf 파일 version 설정이 없습니다." >> $CREATE_FILE 2>&1
				else
					echo "● 3.07 결과 : 양호" >> banner.log
					cat $namedcf | grep -i "version" >> $CREATE_FILE 2>&1
					echo "☞ 배너 설정 양호" >> $CREATE_FILE 2>&1
				fi
		else
			echo "● 3.07 결과 : 취약" >> banner.log
			echo "☞ /etc/named.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
		fi
	done
	else
		echo "☞ named.conf 파일 확인 불가" >> $CREATE_FILE 2>&1
		echo "● 3.07 결과 : 취약" >> banner.log
	fi
else
	echo "● 3.07 결과 : 양호" >> banner.log
	echo "☞ DNS 서비스 구동중이지 않습니다." >> $CREATE_FILE 2>&1
fi	

echo " " >> $CREATE_FILE 2>&1

echo "※ Telnet, FTP, SMTP, DNS 서비스 사용시 접속 배너에 경고문 표시 및 정보 노출 방지 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat banner.log | grep "취약" | wc -l` -eq 0 ]
 then
   echo "＠ 양호 3.07" >> $CREATE_FILE 2>&1
 else
   echo "＠ 취약 3.07" >> $CREATE_FILE 2>&1
fi

rm -f banner.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.07 END" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1




echo "3.08 START" >> $CREATE_FILE 2>&1
echo "################## 3.네트워크 서비스 - 3.08 session timeout 설정 ##############################"
echo "################## 3.네트워크 서비스 - 3.08 session timeout 설정 ##############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "session timeout 10분 이내로 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

touch shelltype.log


if [ `cat /etc/*-release | grep -i 'DISTRIB_DESCRIPTION' | grep -i 'ubuntu' | wc -l` -gt 0 ]
	then
	echo "[ Ubuntu /etc/profile 설정 확인 ]" >> $CREATE_FILE 2>&1
	if [ -f /etc/profile ]
		then
		cat /etc/profile | grep -v "^#"| grep -i 'TMOUT'  >> $CREATE_FILE 2>&1
		if [ `cat /etc/profile | grep -v "^#"| grep -i 'TMOUT' | wc -l` -gt 0 ]
			then
			if [ `cat /etc/profile |  grep -v "^#" | grep -i 'TMOUT' | awk -F"=" '{print $2}'| head -1` -le 600 ]
				then
					echo "＠ 양호" >> shelltype.log
			else
				echo "☞ TMOUT 설정 값 취약" >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> shelltype.log
			fi
		else
			echo "☞ export TMOUT=600 설정 없음(취약)" >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> shelltype.log
		fi
	else
		echo "☞ /etc/profile 파일 없음 (취약)" >> $CREATE_FILE 2>&1
		echo "＠ 취약" >> shelltype.log
	fi
	echo " " >> $CREATE_FILE 2>&1

else

if [ `cat /etc/passwd | grep -v "^#" | egrep "/csh" | wc -l` -gt 0 ]
	then
	if [ -f /etc/csh.login ]
		then
		echo "[ csh 사용중으로 /etc/csh.login 설정 확인 ]" >> $CREATE_FILE 2>&1
		if [ `cat /etc/csh.login | grep -i 'set autologout' | grep -v '^#'| wc -l` -gt 0 ]
			then
			if [ `cat /etc/csh.login | grep -i 'set autologout' | grep -v '^#'| awk -F"=" '{print $2}'| wc -l` -le 10 ]
				then
					cat /etc/csh.login | grep -i 'set autologout' | grep -v "^#" >> $CREATE_FILE 2>&1
					echo "＠ 양호" >> shelltype.log
					echo " " >> $CREATE_FILE 2>&1
			else
				cat /etc/csh.login | grep -i 'set autologout' | grep -v "^#" >> $CREATE_FILE 2>&1
				echo "☞ set autologout 설정 취약" >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> shelltype.log
				echo " " >> $CREATE_FILE 2>&1
			fi
		else
			echo "☞ set autologout 설정 없음 (취약)" >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> shelltype.log	
			echo " " >> $CREATE_FILE 2>&1
		fi
	else
		if [ -f /etc/.login ]
			then
			echo "[ csh 사용중으로 /etc/.login 설정 확인 ]" >> $CREATE_FILE 2>&1
				if [ `cat /etc/.login | grep -i 'set autologout' | grep -v '^#'| wc -l` -gt 0 ]
					then
					if [ `cat /etc/.login | grep -i 'set autologout' | grep -v '^#'| awk -F"=" '{print $2}'| wc -l` -le 10 ]
						then
							cat cat /etc/.login | grep -i 'set autologout' | grep -v "^#"  >> $CREATE_FILE 2>&1
							echo "☞ /etc/csh.login 파일 없음" >> $CREATE_FILE 2>&1
							echo "＠ 양호" >> shelltype.log
							echo " " >> $CREATE_FILE 2>&1
					else
						cat cat /etc/.login | grep -i 'set autologout' | grep -v "^#" >> $CREATE_FILE 2>&1
						echo "☞ set autologout 설정 취약" >> $CREATE_FILE 2>&1
						echo "☞ /etc/csh.login 파일 없음" >> $CREATE_FILE 2>&1
						echo "＠ 취약" >> shelltype.log
						echo " " >> $CREATE_FILE 2>&1
					fi
				else
					echo "☞ set autologout 설정 없음 (취약)" >> $CREATE_FILE 2>&1
					echo "☞ /etc/csh.login 파일 없음" >> $CREATE_FILE 2>&1
					echo "＠ 취약" >> shelltype.log
					echo " " >> $CREATE_FILE 2>&1
				fi
		else
			echo "☞ /etc/.login 파일 없음 (취약)" >> $CREATE_FILE 2>&1
			echo "☞ /etc/csh.login 파일 없음 (취약)" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
	fi
fi
			
if [ `cat /etc/passwd | grep -v "^#" | egrep "/tcsh" | wc -l` -gt 0 ]
	then
	if [ -f /etc/.login ]
		then
		echo "[ tcsh 사용중으로 /etc/.login 설정 확인 ]" >> $CREATE_FILE 2>&1
		if [ `cat /etc/.login | grep -i 'set autologout' | grep -v '^#'| wc -l` -gt 0 ]
			then
			if [ `cat /etc/.login | grep -i 'set autologout' | grep -v '^#'| awk -F"=" '{print $2}'| wc -l` -le 10 ]
				then
					cat /etc/.login | grep -i 'set autologout' | grep -v "^#" >> $CREATE_FILE 2>&1
					echo "＠ 양호" >> shelltype.log
					echo " " >> $CREATE_FILE 2>&1
			else
				cat /etc/.login | grep -i 'set autologout' | grep -v "^#" >> $CREATE_FILE 2>&1
				echo "☞ set autologout 설정 취약" >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> shelltype.log
				echo " " >> $CREATE_FILE 2>&1
			fi
		else
			echo "☞ set autologout 설정 없음 (취약)" >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> shelltype.log	
			echo " " >> $CREATE_FILE 2>&1
		fi
	else
		echo "☞ /etc/.login 파일 없음 (취약)" >> $CREATE_FILE 2>&1
	fi
fi
	
if [ `cat /etc/passwd | egrep -v "^#|/csh|/tcsh" | grep "/*sh" | wc -l` -gt 0 ]
	then
	if [ -f /etc/profile ]
		then
		echo "[ bash 또는 ksh 사용중으로 /etc/profile 설정 확인 ]" >> $CREATE_FILE 2>&1
		if [ `cat /etc/profile | grep -v "^#"| grep -i 'TMOUT' | wc -l` -gt 0 ]
			then
			if [ `cat /etc/profile |  grep -v "^#" | grep -i 'TMOUT' | awk -F"=" '{print $2}'| head -1` -le 600 ]
				then
					cat /etc/profile  | grep -i 'TMOUT' | grep -v "^#"  >> $CREATE_FILE 2>&1
					echo "＠ 양호" >> shelltype.log
					echo " " >> $CREATE_FILE 2>&1
			else
				cat /etc/profile  | grep -i 'TMOUT' | grep -v "^#"  >> $CREATE_FILE 2>&1
				echo "☞ TMOUT 설정 취약" >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> shelltype.log
				echo " " >> $CREATE_FILE 2>&1
			fi
		else
			echo "☞ TMOUT 설정 없음 (취약)" >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> shelltype.log
			echo " " >> $CREATE_FILE 2>&1
		fi
	else
		echo "☞ /etc/profile 파일 없음 (취약)" >> $CREATE_FILE 2>&1
	fi
fi
fi


# 조치방법
echo "※ /etc/profile 파일 내 session timeout 600초 설정 권고" >> $CREATE_FILE 2>&1
echo "   csh 및 tcsh 쉘을 사용할 경우 set autologout=10 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat shelltype.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 3.08" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 3.08" >> $CREATE_FILE 2>&1
fi

rm -f shelltype.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "3.09 START" >> $CREATE_FILE 2>&1
echo "################## 3.네트워크 서비스 - 3.09 root 계정 telnet, ssh 접근 제한 ###################"
echo "################## 3.네트워크 서비스 - 3.09 root 계정 telnet, ssh 접근 제한 ###################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. Telnet 및 SSH 접속 시 root 계정으로의 접속 제한" >> $CREATE_FILE 2>&1
echo "나. SSH 사용시 암호가 없는 계정 로그인 허용 금지"      >> $CREATE_FILE 2>&1
echo "※ SSH 사용을 권장함(단, 대외서비스 Telnet 사용 금지)"      >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/services ]
	then
	if [ `cat /etc/services | grep -w "telnet" | grep -v "#" | grep -i "tcp" | wc -l` -gt 0 ]
		then
			telnetp=`cat /etc/services | grep -w "telnet" | grep -v "#"| grep -i "tcp" | awk -F' ' '{print $2}' | awk -F'/' '{print $1}'`
	else
		telnetp=23
	fi
else
	telnetp=23
fi

echo "  " > telnet.log
echo "① TELNET Port 확인 " >> $CREATE_FILE 2>&1
echo "telnet "$telnetp"/tcp" >> $CREATE_FILE 2>&1
if [ `netstat -an 2>&1 | grep -i ":$telnetp " | grep -i LISTEN | wc -l` -gt 0 ]
	then
		echo " " >> $CREATE_FILE 2>&1
		echo "② TELNET 서비스 확인 " >> $CREATE_FILE 2>&1
		netstat -an 2>&1 | grep -i ":$telnetp " | grep -i LISTEN >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
#		echo "③ /etc/issue 파일 확인 -" >> $CREATE_FILE 2>&1
#		if [ -f /etc/issue.net ]
#			then
#				cat /etc/issue.net >> $CREATE_FILE 2>&1
#			else
#				echo "☞ /etc/issue.net 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
#		fi
		echo "①-① Telnet : /etc/pam.d/login 설정 확인 " >> $CREATE_FILE 2>&1
		if [ `cat /etc/pam.d/login | grep "pam_securetty.so" | grep -v "^#" | wc -l` -gt 0 ]
			then
				cat /etc/pam.d/login | grep "pam_securetty.so" | grep -v "^#" >> $CREATE_FILE 2>&1
		else
			cat /etc/pam.d/login | grep "pam_securetty.so" >> $CREATE_FILE 2>&1
			echo "☞ /etc/pam.d/login 파일에 설정 취약" >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> telnet.log
		fi
		echo " " >> $CREATE_FILE 2>&1

		echo "①-② Telnet : /etc/securetty 파일 유무 확인 " >> $CREATE_FILE 2>&1
		if [ -f /etc/securetty ]
#		if [ `ls -alL /etc/ | grep -w "securetty" | wc -l` -eq 0 ]
			then
				ls -alL /etc/ | grep -w "securetty" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "①-③ Telnet : /etc/securetty 설정 확인 " >> $CREATE_FILE 2>&1
				if [ `cat /etc/securetty | grep "pts" | grep -v "#" | wc -l` -eq 0 ]
					then
						echo "☞ /etc/securetty 파일에 pts 설정 값이 없어 양호 합니다." >> $CREATE_FILE 2>&1 
				else
					cat /etc/securetty | grep "pts" | grep -v "#"  >> $CREATE_FILE 2>&1
					echo "☞ /etc/securetty 파일에 pts 설정 값이 있어 취약 합니다." >> $CREATE_FILE 2>&1 
				fi
		else
			echo "☞ /etc/securetty 파일이 없어 취약" >> $CREATE_FILE 2>&1 
			echo "＠ 취약" >> telnet.log
		fi

		echo " " >> $CREATE_FILE 2>&1
else
	echo "☞ telnet 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
fi


echo " " >> $CREATE_FILE 2>&1
echo "②-① SSH 구동 여부 확인 " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "☞ SSH 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
else
	ps -ef | grep sshd | grep -v grep >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "②-② /etc/ssh/sshd_config 파일 설정 현황" >> $CREATE_FILE 2>&1
	if [ -f /etc/ssh/sshd_config ]
		then
			if [ `cat /etc/ssh/sshd_config | grep -i PermitRootLogin | grep -i no | grep -v '^#' | wc -l ` -gt 0 ]
				then
					cat /etc/ssh/sshd_config | grep -i 'PermitRootLogin' | grep -v '#' >> $CREATE_FILE 2>&1
					echo "● 3.9 SSH 접근 제한 확인 결과 : 양호" >> telnet.log 2>&1
			else
				echo "● 3.9 SSH 접근 제한 확인 결과 : 취약" >> telnet.log 2>&1
				cat /etc/ssh/sshd_config | grep -i 'PermitRootLogin'  >> $CREATE_FILE 2>&1
				echo "☞ PermitRootLogin no 설정이 없어 취약" >> $CREATE_FILE 2>&1
			fi
			#if [ `cat /etc/ssh/sshd_config | grep -i AllowGroups | grep -i wheel | grep -v '^#' | wc -l ` -gt 0 ]
			#	then
			#		cat /etc/ssh/sshd_config | grep -i 'AllowGroups' >> $CREATE_FILE 2>&1
			#		echo "● 3.9 SSH 접근 제한 확인 결과 : 양호" >> telnet2.log 2>&1
			#else
			#	echo "● 3.9 SSH 접근 제한 확인 결과 : 취약" >> telnet2.log 2>&1
			#	echo "☞ AllowGroups wheel 설정이 없어 취약 합니다." >> $CREATE_FILE 2>&1
			#fi
			if [ `cat /etc/ssh/sshd_config | grep -i PermitEmptyPasswords | grep -i no | grep -v '^#' | wc -l ` -gt 0 ]
				then
					cat /etc/ssh/sshd_config | grep -i 'PermitEmptyPasswords' | grep -v '#' >> $CREATE_FILE 2>&1
					echo "● 3.9 SSH 접근 제한 확인 결과 : 양호" >> telnet.log 2>&1
			else
				echo "● 3.9 SSH 접근 제한 확인 결과 : 취약" >> telnet.log 2>&1
				cat /etc/ssh/sshd_config | grep -i 'PermitEmptyPasswords'  >> $CREATE_FILE 2>&1
				echo "☞ PermitEmptyPasswords no 설정이 없어 취약" >> $CREATE_FILE 2>&1
			fi
	else
		if [ -f /usr/local/etc/sshd_config ]
		then
			if [ `cat /usr/local/etc/sshd_config | grep -i PermitRootLogin | grep -i no | grep -v '^#' | wc -l ` -gt 0 ]
				then
					cat /usr/local/etc/sshd_config | grep -i 'PermitRootLogin' | grep -v '#' >> $CREATE_FILE 2>&1
					echo "● 3.9 SSH 접근 제한 확인 결과 : 양호" >> telnet.log 2>&1
			else
				echo "● 3.9 SSH 접근 제한 확인 결과 : 취약" >> telnet.log 2>&1
				cat /usr/local/etc/sshd_config | grep -i 'PermitRootLogin'  >> $CREATE_FILE 2>&1
				echo "☞ PermitRootLogin no 설정이 없어 취약" >> $CREATE_FILE 2>&1
			fi
			#if [ `cat /etc/ssh/sshd_config | grep -i AllowGroups | grep -i wheel | grep -v '^#' | wc -l ` -gt 0 ]
			#	then
			#		cat /etc/ssh/sshd_config | grep -i 'AllowGroups' >> $CREATE_FILE 2>&1
			#		echo "● 3.9 SSH 접근 제한 확인 결과 : 양호" >> telnet2.log 2>&1
			#else
			#	echo "● 3.9 SSH 접근 제한 확인 결과 : 취약" >> telnet2.log 2>&1
			#	echo "☞ AllowGroups wheel 설정이 없어 취약 합니다." >> $CREATE_FILE 2>&1
			#fi
			if [ `cat /usr/local/etc/sshd_config | grep -i PermitEmptyPasswords | grep -i no | grep -v '^#' | wc -l ` -gt 0 ]
				then
					cat /usr/local/etc/sshd_config | grep -i 'PermitEmptyPasswords' | grep -v '#' >> $CREATE_FILE 2>&1
					echo "● 3.9 SSH 접근 제한 확인 결과 : 양호" >> telnet.log 2>&1
			else
				echo "● 3.9 SSH 접근 제한 확인 결과 : 취약" >> telnet.log 2>&1
				cat /usr/local/etc/sshd_config | grep -i 'PermitEmptyPasswords'  >> $CREATE_FILE 2>&1
				echo "☞ PermitEmptyPasswords no 설정이 없어 취약" >> $CREATE_FILE 2>&1
			fi
		else
			echo "☞ /etc/ssh/sshd_config 파일이 없습니다." >> $CREATE_FILE 2>&1
			echo "● 3.9 SSH 접근 제한 확인 결과 : 취약" >> telnet.log 2>&1
		fi
	fi
fi


echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ telnet 및 ssh 접속 시 root 계정으로의 접속 제한 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat telnet.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 3.09" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 3.09" >> $CREATE_FILE 2>&1
fi

rm -f telnet.log
rm -f telnet2.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.09 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.10 START" >> $CREATE_FILE 2>&1
echo "################## 3.네트워크 서비스 - 3.10 방화벽 정책 적용 ##################################"
echo "################## 3.네트워크 서비스 - 3.10 방화벽 정책 적용 ##################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "명시적으로 허용되지 않는 접근은 모두 차단" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 방화벽 정책 담당자를 통해 접근이 필요한 대상 이외 모두 접근 차단" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "＠ 양호 3.10" >> $CREATE_FILE 2>&1
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.10 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "4.01 START" >> $CREATE_FILE 2>&1
echo "################## 4.로그관리 - 4.01 시스템 로그 설정 #########################################"
echo "################## 4.로그관리 - 4.01 시스템 로그 설정 #########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. su 로깅 기록 : /etc/login.defs 또는 /etc/syslog.conf 설정" >> $CREATE_FILE 2>&1
echo "나. /etc/syslog.conf(/etc/rsyslog.conf) 로그 설정 : *.notice, *.alert, *.emerg" >> $CREATE_FILE 2>&1
echo "다. 로그 파일 및 디렉터리에 대한 권한 설정 : root(또는 bin) 소유의 타사용자 쓰기 권한 제거" >> $CREATE_FILE 2>&1
echo "라. /etc/syslog.conf(/etc/rsyslog.conf) 파일의 권한을 root(또는 bin)소유의 ‘640’으로 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[ SU 로그 설정 현황 ]" >> $CREATE_FILE 2>&1
SULOG="0"
if [ `cat /etc/login.defs | grep SULOG_FILE | wc -l` -gt 0 ]
 then
   echo "① /etc/login.defs 설정" >> $CREATE_FILE 2>&1
   echo `cat /etc/login.defs | grep SULOG_FILE` >> $CREATE_FILE 2>&1
   echo " " >> $CREATE_FILE 2>&1
   SULOG="good"
 else
   echo "① /etc/login.defs 설정" >> $CREATE_FILE 2>&1
   echo "☞ 설정값이 없습니다." >> $CREATE_FILE 2>&1
   echo " " >> $CREATE_FILE 2>&1
   SULOG="bad"
fi

if [ `cat /etc/syslog.conf 2>/dev/null | grep authpriv.* | grep /var/log/secure | wc -l` -gt 0 ]
  then
   echo "② /etc/syslog.conf 설정" >> $CREATE_FILE 2>&1
   echo `cat /etc/syslog.conf 2>/dev/null | grep authpriv.* | grep /var/log/secure` >> $CREATE_FILE 2>&1
   AUTHP="good"
  else
   echo "② /etc/syslog.conf 설정" >> $CREATE_FILE 2>&1
   echo "☞ 설정값 없습니다." >> $CREATE_FILE 2>&1
   
   AUTHP="bad"
fi

echo " " > sulog.log

if [ $SULOG="good" -o $AUTHP="good" ]
  then
    echo "＠ 양호" >> sulog.log
	echo "" >> $CREATE_FILE 2>&1
	echo "☞ SU 로그 설정 양호" >> $CREATE_FILE 2>&1
  else
    echo "＠ 취약" >> sulog.log
	echo "" >> $CREATE_FILE 2>&1
	echo "☞ /etc/login.defs, /etc/syslog.conf 모두 SU 로그 설정이 없어 취약" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat /etc/*-release | grep -i 'DISTRIB_DESCRIPTION' | grep -i 'ubuntu' | wc -l` -gt 0 ]
	then
		echo "[ rsyslog 로그 설정 현황 ]" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "① rsyslog 프로세스" >> $CREATE_FILE 2>&1
		if [ `ps -ef | grep 'rsyslog' | grep -v grep | wc -l` -gt 0 ]
			then
				ps -ef | grep 'rsyslog' | grep -v grep >> $CREATE_FILE 2>&1
				if [ -f /etc/rsyslog.d/*default.conf ]
					then
						echo " " >> $CREATE_FILE 2>&1
						echo "② /etc/rsyslog.d/50-default.conf 시스템 로깅 설정" >> $CREATE_FILE 2>&1
						echo "# 파일명 확인: " `ls /etc/rsyslog.d/*default.conf` >> $CREATE_FILE 2>&1
						cat /etc/rsyslog.d/*default.conf | grep -v "^#" | grep -v -e '^$' >> $CREATE_FILE 2>&1
						if [ `cat /etc/rsyslog.d/*default.conf | grep -v "^#" | grep -i "*.notice" | wc -l` -gt 0 ]
							then
								echo "＠ 양호" >> sulog.log
						else
							echo "☞ *.notice  /var/log/messages 로그 설정 없음" >> $CREATE_FILE 2>&1
							echo "＠ 취약" >> sulog.log
						fi
						if [ `cat /etc/rsyslog.d/*default.conf| grep -v "^#" | grep -i "*.alert" | wc -l` -gt 0 ]
							then
								echo "＠ 양호" >> sulog.log
						else
							echo "☞ *.alert  /dev/console 로그 설정 없음" >> $CREATE_FILE 2>&1
							echo "＠ 취약" >> sulog.log
						fi
						if [ `cat /etc/rsyslog.d/*default.conf | grep -v "^#" | grep -i "*.emerg" | wc -l` -gt 0 ]
							then
								echo "＠ 양호" >> sulog.log
						else
							echo "☞ *.emerg  :omusrmsg:* 로그 설정 없음" >> $CREATE_FILE 2>&1
							echo "＠ 취약" >> sulog.log
						fi
				else
					echo "☞ /etc/rsyslog.d/50-default.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
					echo "＠ 취약" >> sulog.log
				fi
		else
			echo "☞ rsyslog 비실행중(취약)" >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> sulog.log
		fi
else
echo "[ Syslog(Rsyslog) 로그 설정 현황 ]" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep -i 'syslog' | grep -v grep | wc -l` -gt 0 ]
	then
		if [ -f /etc/syslog.conf ]
			then
				echo "① syslog 프로세스" >> $CREATE_FILE 2>&1
				ps -ef | grep 'syslog' | grep -v grep | grep -v -e '^$' >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "② /etc/syslog.conf 시스템 로깅 설정" >> $CREATE_FILE 2>&1
				cat /etc/syslog.conf | grep -v "^#" >> $CREATE_FILE 2>&1
				if [ `cat /etc/syslog.conf | grep -v "^#" | grep -i "\*.info" | wc -l` -gt 0 ]
					then
						if [ `cat /etc/syslog.conf | grep -v "^#" | grep -i "\*.emerg" | wc -l` -gt 0 ]
							then
								echo "＠ 양호" >> sulog.log
						else
							    echo "☞ *.emerg  * 로그 설정 없음" >> $CREATE_FILE 2>&1
								echo "＠ 취약" >> sulog.log
						fi
				else
						if [ `cat /etc/syslog.conf | grep -v "^#" | grep -i "\*.notice" | wc -l` -gt 0 ]
							then
								echo "＠ 양호" >> sulog.log
							else
								echo "☞ *.notice  /var/log/messages 로그 설정 없음" >> $CREATE_FILE 2>&1
							    echo "＠ 취약" >> sulog.log
						fi
						if [ `cat /etc/syslog.conf | grep -v "^#" | grep -i "\*.alert" | wc -l` -gt 0 ]
							then
								echo "＠ 양호" >> sulog.log
							else
								echo "☞ *.alert  /dev/console 로그 설정 없음" >> $CREATE_FILE 2>&1
								echo "＠ 취약" >> sulog.log
						fi
						if [ `cat /etc/syslog.conf | grep -v "^#" | grep -i "\*.emerg" | wc -l` -gt 0 ]
							then
								echo "＠ 양호" >> sulog.log
							else
							    echo "☞ *.emerg  * 로그 설정 없음" >> $CREATE_FILE 2>&1
								echo "＠ 취약" >> sulog.log
						fi
				fi
		else
			if [ -f /etc/rsyslog.conf ]
				then
					echo "① rsyslog 프로세스" >> $CREATE_FILE 2>&1
					ps -ef | grep 'rsyslog' | grep -v grep >> $CREATE_FILE 2>&1
					echo " " >> $CREATE_FILE 2>&1
					echo "② /etc/rsyslog.conf 시스템 로깅 설정" >> $CREATE_FILE 2>&1
					cat /etc/rsyslog.conf | grep -v "^#" | grep -v -e '^$' >> $CREATE_FILE 2>&1
					if [ `cat /etc/rsyslog.conf | grep -v "^#" | grep -i "*.info" | wc -l` -gt 0 ]
						then
							if [ `cat /etc/rsyslog.conf | grep -v "^#" | grep -i "*.emerg" | wc -l` -gt 0 ]
								then
									echo "＠ 양호" >> sulog.log
							else
									echo "☞ *.emerg  * 로그 설정 없음" >> $CREATE_FILE 2>&1
								echo "＠ 취약" >> sulog.log
							fi
					else
							if [ `cat /etc/rsyslog.conf | grep -v "^#" | grep -i "*.notice" | wc -l` -gt 0 ]
								then
									echo "＠ 양호" >> sulog.log
							else
									echo "☞ *.notice  /var/log/messages 로그 설정 없음" >> $CREATE_FILE 2>&1
									echo "＠ 취약" >> sulog.log
							fi
							if [ `cat /etc/rsyslog.conf | grep -v "^#" | grep -i "*.alert" | wc -l` -gt 0 ]
								then
									echo "＠ 양호" >> sulog.log
							else
									echo "☞ *.alert  /dev/console 로그 설정 없음" >> $CREATE_FILE 2>&1
									echo "＠ 취약" >> sulog.log
							fi
							if [ `cat /etc/rsyslog.conf | grep -v "^#" | grep -i "*.emerg" | wc -l` -gt 0 ]
								then
									echo "＠ 양호" >> sulog.log
							else
								echo "☞ *.emerg  * 로그 설정 없음" >> $CREATE_FILE 2>&1
								echo "＠ 취약" >> sulog.log
							fi
					fi
			else
				echo "☞ /etc/syslog.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
				echo "☞ /etc/rsyslog.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> sulog.log
			fi
				
		fi
else
		echo "☞ syslog 프로세스가 확인 되지 않습니다. (취약) " >> $CREATE_FILE 2>&1
		echo "＠ 취약" >> sulog.log
fi
fi


echo " " >> $CREATE_FILE 2>&1

echo "③ 로그 파일 및 디렉터리 권한 설정 현황" >> $CREATE_FILE 2>&1
FILES="/var/log/wtmp /var/wtmp /var/run/utmp /var/utmp /var/log/btmp /var/log/pacct /var/log/messages /var/log/lastlog /var/log/secure"


for file in $FILES
do
  if [ -f $file ]
    then
      ls -alL $file >> $CREATE_FILE 2>&1
	  if [ `ls -alL $file | awk '{print $1 $2 $3}' | egrep -i "root|bin|syslog" | grep "^........-." | wc -l` -eq 1 ]
	    then
          echo "＠ 양호" >> sulog.log
		else
		  echo "＠ 취약" >> sulog.log
		  echo "☞ 파일 권한(root 또는 bin 소유의 타사용자 쓰기 권한 제거) 설정 취약" >> $CREATE_FILE 2>&1
	  fi
  fi
done
echo " " >> $CREATE_FILE 2>&1


echo "④ /etc/syslog.conf /etc/rsyslog.conf 파일 권한 설정 현황" >> $CREATE_FILE 2>&1
FILES="/etc/syslog.conf /etc/rsyslog.conf"


for file in $FILES
do
  if [ -f $file ]
    then
      ls -alL $file >> $CREATE_FILE 2>&1
	  if [ `ls -alL $file | awk '{print $1 $2 $3}' | egrep -i "root|bin" | grep "^-..-.-----." | wc -l` -eq 1 ]
		then
          echo "＠ 양호" >> sulog.log
		else
		  echo "＠ 취약" >> sulog.log
		  echo "☞ 파일 권한(root 또는 bin 소유의 640 권고) 설정 취약" >> $CREATE_FILE 2>&1
		  
	  fi
  fi
done
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


# 조치방법
echo "※ su 로그 및 syslog의 설정과 로그 파일과 디렉토리의 권한을 적절히 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat sulog.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 4.01" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 4.01" >> $CREATE_FILE 2>&1
fi


rm -f sulog.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "4.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "4.02 START" >> $CREATE_FILE 2>&1
echo "################## 4.로그관리 - 4.02 로그 저장주기 ############################################"
echo "################## 4.로그관리 - 4.02 로그 저장주기 ############################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. 법에 정해진 로그 저장 기간 적용" >> $CREATE_FILE 2>&1
echo "나. 로그 기록을 정기적으로 확인 감독" >> $CREATE_FILE 2>&1
echo "다. 로그 파일을 별도 저장 장치에 백업 보관 및 쓰기 권한 제한" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 별도 로그 서버를 통해 저장 및 정기적 검토 진행" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "＠ 양호 4.02" >> $CREATE_FILE 2>&1
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "4.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "5.01 START" >> $CREATE_FILE 2>&1
echo "################## 5.주요 응용 설정 - 5.01 FTP 서비스 사용자 제한 #############################"
echo "################## 5.주요 응용 설정 - 5.01 FTP 서비스 사용자 제한 #############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. 서비스 필요 시 root 및 불필요한 계정의 FTP 서비스 제한, FTP UMASK ‘077’, Anonymous FTP 제한 설정" >> $CREATE_FILE 2>&1
echo "나. 서비스 불필요 시 서비스 중지 및 시스템 재시작시 서비스가 실행되지 않도록 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "[FTP 서비스 현황]" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep ftpd | grep -v grep | wc -l` -eq 0 ]
	then
		echo "☞ FTP 서비스가 구동중이지 않습니다." >> $CREATE_FILE 2>&1
		echo "＠ 양호" >> ftp.log
	else
		ps -ef | grep ftpd | grep -v grep >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
echo "[ root 및 불필요한 계정의 접속 제한 설정 현황 ]" >> $CREATE_FILE 2>&1
echo " " > ftp.log

#ftpd root 접속 제한
if [ `ps -ef | grep /ftpd | grep -v grep | wc -l` -gt 0 ]
	then
		echo "- FTP -" >> $CREATE_FILE 2>&1
		#if [ -f /etc/ftpusers ]
		if [ `ls -alL /etc/ftpusers | wc -l` -gt 0 ]
			then
				echo "① /etc/ftpusers 파일 내용" >> $CREATE_FILE 2>&1
				if [ `cat /etc/ftpusers | grep root | grep -v '^#' | wc -l` -gt 0 ]
					then
						cat /etc/ftpusers | grep root | grep -v '^#' >> $CREATE_FILE 2>&1
						echo "＠ 양호" >> ftp.log
						echo " " >> $CREATE_FILE 2>&1
				else
					echo "☞ /etc/ftpusers 파일에 root 없음.(취약)" >> $CREATE_FILE 2>&1
					echo "＠ 취약" >> ftp.log
					echo " " >> $CREATE_FILE 2>&1
				fi
		else
			#if [ -f /etc/ftpd/ftpusers ]
			if [ `ls -alL /etc/ftpd/ftpusers | wc -l` -gt 0 ]
				then
					echo "① /etc/ftpd/ftpusers 파일 내용" >> $CREATE_FILE 2>&1
					if [ `cat /etc/ftpd/ftpusers | grep root | grep -v '^#' | wc -l` -gt 0 ]
						then
							cat /etc/ftpd/ftpusers | grep root | grep -v '^#' >> $CREATE_FILE 2>&1
							echo "＠ 양호" >> ftp.log
							echo " " >> $CREATE_FILE 2>&1
					else
						echo "☞ /etc/ftpd/ftpusers 파일에 root 없음.(취약)" >> $CREATE_FILE 2>&1
						echo "＠ 취약" >> ftp.log
						echo " " >> $CREATE_FILE 2>&1
					fi
			else
				echo "☞ /etc/ftpusers 파일에 root 없음.(취약)" >> $CREATE_FILE 2>&1
				echo "☞ /etc/ftpd/ftpusers 파일에 root 없음.(취약)" >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> ftp.log
				echo " " >> $CREATE_FILE 2>&1
			fi
		fi
fi

#vsftpd root 접속 제한
if [ `ps -ef | grep /vsftpd | grep -v grep | wc -l` -gt 0 ]
	then
	echo "- vsftpd -" >> $CREATE_FILE 2>&1
	echo "① /etc/vsftpd/vsftpd.conf 파일 내용" >> $CREATE_FILE 2>&1
	#if [ -f /etc/vsftpd/vsftpd.conf ]
	if [ `ls -alL /etc/vsftpd/vsftpd.conf | wc -l` -gt 0 ]
		then
		if [ `cat /etc/vsftpd/vsftpd.conf | grep -i "userlist_enable" | grep -i "yes" |wc -l` -gt 0 ]
			then
			cat /etc/vsftpd/vsftpd.conf | grep -i "userlist_enable" >> $CREATE_FILE 2>&1
			#if [ -f /etc/vsftpd/user_list ]
			if [ `ls -alL /etc/vsftpd/user_list | wc -l` -gt 0 ]
				then
				echo " " >> $CREATE_FILE 2>&1
				echo "② /etc/vsftpd/user_list 파일 내용" >> $CREATE_FILE 2>&1
				if [ `cat /etc/vsftpd/user_list | grep root | grep -v '^#'| wc -l` -gt 0 ]
					then
						cat /etc/vsftpd/user_list | grep root | grep -v '^#' >> $CREATE_FILE 2>&1
						echo "＠ 양호" >> ftp.log
					else
						echo "☞ /etc/vsftpd/user_list 파일에 root 없음.(취약)" >> $CREATE_FILE 2>&1
						echo "＠ 취약" >> ftp.log
				fi
			else
				#if [ -f /etc/vsftpd.user_list ]
				if [ `ls -alL /etc/vsftpd.user_list | wc -l` -gt 0 ]
					then
						echo " " >> $CREATE_FILE 2>&1
						echo "② /etc/vsftpd.user_list 파일 내용" >> $CREATE_FILE 2>&1
						if [ `cat /etc/vsftpd.user_list | grep root | grep -v '^#'| wc -l` -gt 0 ]
							then
								cat /etc/vsftpd.user_list | grep root | grep -v '^#' >> $CREATE_FILE 2>&1
								echo "＠ 양호" >> ftp.log
							else
								echo "☞ /etc/vsftpd.user_list 파일에 root 없음.(취약)" >> $CREATE_FILE 2>&1
								echo "＠ 취약" >> ftp.log
						fi
				else
					echo "☞ /etc/vsftpd/user_list 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
					echo "☞ /etc/vsftpd.user_list 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
				fi
			fi
		else
			#if [ -f /etc/vsftpd/ftpusers ]
			if [ `ls -alL /etc/vsftpd/ftpusers | wc -l` -gt 0 ]
				then
					echo " " >> $CREATE_FILE 2>&1
					echo "② /etc/vsftpd/ftpusers 파일 내용" >> $CREATE_FILE 2>&1
					if [ `cat /etc/vsftpd/ftpusers | grep root | grep -v '^#'| wc -l` -gt 0 ]
						then
							cat /etc/vsftpd/ftpusers | grep -i root	>> $CREATE_FILE 2>&1
							echo "＠ 양호" >> ftp.log
					else
							cat /etc/vsftpd/ftpusers | grep -i root	>> $CREATE_FILE 2>&1
							echo "☞ /etc/vsftpd/ftpusers 파일에 root 없음.(취약)"	>> $CREATE_FILE 2>&1
							echo "＠ 취약" >> ftp.log
					fi
				else
					#if [ -f /etc/vsftpd.ftpusers ]
					if [ `ls -alL /etc/vsftpd.ftpusers | wc -l` -gt 0 ]
						then
							echo " " >> $CREATE_FILE 2>&1
							echo "② /etc/vsftpd.ftpusers 파일 내용" >> $CREATE_FILE 2>&1
							if [ `cat /etc/vsftpd.ftpusers | grep root | grep -v '^#'| wc -l` -gt 0 ]
								then
									cat /etc/vsftpd.ftpusers | grep root  >> $CREATE_FILE 2>&1
									echo "＠ 양호" >> ftp.log
							else
								cat /etc/vsftpd.ftpusers | grep root  >> $CREATE_FILE 2>&1
								echo "☞ /etc/vsftpd.ftpusers 파일에 root 없음.(취약)"	>> $CREATE_FILE 2>&1
								echo "＠ 취약" >> ftp.log
							fi
					else
						echo "☞ /etc/vsftpd/ftpusers 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
						echo "☞ /etc/vsftpd.ftpusers 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
						echo "＠ 취약" >> ftp.log
					fi
				fi
		fi
	else
		echo "☞ /etc/vsftpd/vsftpd.conf 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
		echo "＠ 취약" >> ftp.log
	fi
fi

#proftpd root 접속 제한
if [ `ps -ef | grep /proftpd | grep -v grep | wc -l` -gt 0 ]
	then
		echo " " >> $CREATE_FILE 2>&1
		echo "- PROFTP -" >> $CREATE_FILE 2>&1
		if [ -f /etc/proftpd.conf ]
			then
				echo "① /etc/proftpd.conf 파일 내용" >> $CREATE_FILE 2>&1
				if [ `cat /etc/proftpd.conf | grep -i 'RootLogin'| grep -i 'off' | grep -v '^#' | wc -l` -gt 0 ]
					then
						cat /etc/proftpd.conf | grep -i 'RootLogin'| grep -i 'off' | grep -v '^#' >> $CREATE_FILE 2>&1
						echo "＠ 양호" >> ftp.log
				else
						echo "☞ /etc/proftpd.conf 파일에 RootLogin off 설정 없음.(취약)"  >> $CREATE_FILE 2>&1
						echo "＠ 취약" >> ftp.log
				fi
		else
			echo "☞ /etc/proftpd.conf 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> ftp.log
		fi
fi


#ftpd umaks
echo " " >> $CREATE_FILE 2>&1
echo "[ FTP UMASK 제한 설정 현황 ]" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep /ftpd | grep -v grep | wc -l` -gt 0 ]
	then
		echo "- ftpd - " >> $CREATE_FILE 2>&1
		if [ -f /etc/ftpd.conf ]
			then
				echo "① /etc/ftpd.conf 파일 " >> $CREATE_FILE 2>&1
				if [ `cat /etc/ftpd.conf | grep -i "umask" | grep -i '077' | grep -v '^#' | wc -l` -gt 0 ]
					then
						cat /etc/ftpd.conf | grep -i "umask" | grep -v '^#' >> $CREATE_FILE 2>&1
						echo " " >> $CREATE_FILE 2>&1
						echo "＠ 양호" >> ftp.log
				else
					cat /etc/ftpd.conf | grep -i "umask" | grep -v '^#' >> $CREATE_FILE 2>&1
					echo "☞ /etc/ftpd.conf 파일에 umask=077 설정 없음.(취약)"  >> $CREATE_FILE 2>&1
					echo "＠ 취약" >> ftp.log
				fi
		else
			echo "☞ /etc/ftpd.conf 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> ftp.log
		fi
fi
 
#vsftpd umaks
if [ `ps -ef | grep /vsftpd | grep -v grep | wc -l` -gt 0 ]
	then
		echo "- vsftpd - " >> $CREATE_FILE 2>&1
		if [ -f /etc/vsftpd/vsftpd.conf ]
			then
				echo "① /etc/vsftpd/vsftpd.conf 파일 " >> $CREATE_FILE 2>&1
				if [ `cat /etc/vsftpd/vsftpd.conf | grep -i "umask" | grep -i "077" | grep -v '^#' | wc -l` -gt 0 ]
					then
						cat /etc/vsftpd/vsftpd.conf | grep -i "umask" | grep -v '^#'  >> $CREATE_FILE 2>&1
						echo " " >> $CREATE_FILE 2>&1
						echo "＠ 양호" >> ftp.log
				else
					cat /etc/vsftpd/vsftpd.conf | grep -i "umask" | grep -v '^#'  >> $CREATE_FILE 2>&1
					echo "☞ /etc/vsftpd/vsftpd.conf 파일에 umask=077 설정 없음.(취약)"  >> $CREATE_FILE 2>&1
					echo "＠ 취약" >> ftp.log
					echo " " >> $CREATE_FILE 2>&1
				fi
		else
			if [ -f /etc/vsftpd.conf ]
				then
					echo "① /etc/vsftpd.conf 파일 " >> $CREATE_FILE 2>&1
					if [ `cat /etc/vsftpd.conf | grep -i "umask" | grep -i "077" | grep -v '^#' | wc -l` -gt 0 ]
						then
							cat /etc/vsftpd.conf | grep -i "umask" | grep -v '^#'  >> $CREATE_FILE 2>&1
							echo " " >> $CREATE_FILE 2>&1
							echo "＠ 양호" >> ftp.log
					else
						cat /etc/vsftpd.conf | grep -i "umask" | grep -v '^#'  >> $CREATE_FILE 2>&1
						echo "☞ /etc/vsftpd.conf 파일에 umask=077 설정 없음.(취약)"  >> $CREATE_FILE 2>&1
						echo "＠ 취약" >> ftp.log
						echo " " >> $CREATE_FILE 2>&1
					fi
			else
				echo "☞ /etc/vsftpd/vsftpd.conf 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
				echo "☞ /etc/vsftpd.conf 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> ftp.log
			fi
		fi
fi

#proftpd umaks
if [ `ps -ef | grep /proftpd | grep -v grep | wc -l` -gt 0 ]
	then
		echo "- proftpd - " >> $CREATE_FILE 2>&1
		if [ -f /etc/proftpd.conf ]
			then
				echo "① /etc/proftpd.conf 파일 " >> $CREATE_FILE 2>&1
				if [ `cat /etc/proftpd.conf | grep -i "umask" | grep -i '077' | grep -v '^#' | wc -l` -gt 0 ]
					then
						cat /etc/proftpd.conf | grep -i "umask" | grep -v '^#' >> $CREATE_FILE 2>&1
						echo " " >> $CREATE_FILE 2>&1
						echo "＠ 양호" >> ftp.log
				else
					cat /etc/proftpd.conf | grep -i "umask" | grep -v '^#' >> $CREATE_FILE 2>&1
					echo "☞ /etc/proftpd.conf 파일에 umask 077 설정 없음.(취약)"  >> $CREATE_FILE 2>&1
					echo "＠ 취약" >> ftp.log
				fi
		else
			echo "☞ /etc/proftpd.conf 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> ftp.log
		fi
fi


echo "[ Anonymous FTP 제한 설정 현황 ]" >> $CREATE_FILE 2>&1

echo "- Default ftp 계정 확인 -" >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
	then
		echo "① /etc/passwd 파일 확인" >> $CREATE_FILE 2>&1
		if [ `cat /etc/passwd | grep -w 'ftp:' | grep -v 'tftp:' | grep -v '^#' | grep -v 'nologin' | grep -v '/bin/false' | wc -l` -gt 0 ]
			then
				cat /etc/passwd | grep -w 'ftp:' | grep -v 'tftp:'| grep -v '^#' | grep -v 'nologin' | grep -v '/bin/false'  >> $CREATE_FILE 2>&1
				echo "☞ ftp 계정 존재하여 취약 합니다." >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> ftp.log
		else
			echo "☞ Default ftp 계정이 없습니다." >> $CREATE_FILE 2>&1
			echo "＠ 양호" >> ftp.log
			echo " " >> $CREATE_FILE 2>&1
		fi
else
			echo "☞ /etc/passwd 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
fi

if [ `ps -ef | grep /vsftpd | grep -v grep | wc -l` -gt 0 ]
	then
		echo "- vsftpd -" >> $CREATE_FILE 2>&1
		if [ -f /etc/vsftpd/vsftpd.conf ]
			then
				echo "① /etc/vsftpd/vsftpd.conf 파일 " >> $CREATE_FILE 2>&1
				if [ `cat /etc/vsftpd/vsftpd.conf | grep -i 'anonymous_enable' | grep -i '=no' | grep -v '^#' | wc -l` -gt 0 ]
					then
						cat /etc/vsftpd/vsftpd.conf | grep -i 'anonymous_enable' >> $CREATE_FILE 2>&1
						echo " " >> $CREATE_FILE 2>&1
						echo "＠ 양호" >> ftp.log
				else
					cat /etc/vsftpd/vsftpd.conf | grep -i 'anonymous_enable' >> $CREATE_FILE 2>&1
					echo "☞ anonymous_enable=NO 설정 없음.(취약)" >> $CREATE_FILE 2>&1
					echo " " >> $CREATE_FILE 2>&1
					echo "＠ 취약" >> ftp.log
				fi
		else
			if [ -f /etc/vsftpd.conf ]
				then
					echo "① /etc/vsftpd.conf 파일 " >> $CREATE_FILE 2>&1
					if [`cat /etc/vsftpd.conf | grep -i 'anonymous_enable' | grep -i '=no' | grep -v '^#' | wc -l` -gt 0 ]
						then
							cat /etc/vsftpd.conf | grep -i 'anonymous_enable' >> $CREATE_FILE 2>&1
							echo " " >> $CREATE_FILE 2>&1
							echo "＠ 양호" >> ftp.log
					else
						cat /etc/vsftpd.conf | grep -i 'anonymous_enable' >> $CREATE_FILE 2>&1
						echo "☞ anonymous_enable=NO 설정 없음.(취약)" >> $CREATE_FILE 2>&1
						echo " " >> $CREATE_FILE 2>&1
						echo "＠ 취약" >> ftp.log
					fi
			else
				echo "☞ /etc/vsftpd/vsftpd.conf 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
				echo "☞ /etc/vsftpd.conf 파일이 없습니다.(취약)" >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> ftp.log
			fi
		fi
fi
fi

echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ root 및 불필요한 계정의 FTP 사용 제한하고, FTP UMASK 077, Anonymous FTP 제한 설정 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat ftp.log | grep "취약" | wc -l` -eq 0 ]
 then
  echo "＠ 양호 5.01" >> $CREATE_FILE 2>&1
 else
  echo "＠ 취약 5.01" >> $CREATE_FILE 2>&1
fi
rm -f ftp.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.02 START" >> $CREATE_FILE 2>&1
echo "################## 5.주요 응용 설정 - 5.02 SNMP 서비스 설정 ###################################"
echo "################## 5.주요 응용 설정 - 5.02 SNMP 서비스 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "서비스 필요 시 SNMP의 Community String 을 default 값인 public 또는 private 사용 제한" >> $CREATE_FILE 2>&1
echo "서비스 불필요 시 서비스 중지 및 시스템 재시작시 서비스가 실행되지 않도록 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " > snmpp.log
echo "① SNMP 서비스 여부 " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep snmp | egrep -v "dmi|osnmp" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "☞ SNMP가 비실행중입니다."  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "② SNMP 시작 스크립트 파일 확인 " >> $CREATE_FILE 2>&1
		if [ `ls -alL /etc/rc*.d/* | grep -i snmp | grep "/S" | wc -l` -gt 0 ]
			then
				ls -alL /etc/rc*.d/* | grep -i snmp | grep "/S" >> $CREATE_FILE 2>&1
				echo "☞ SNMP 시작 스크립트 파일 취약 " >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> snmpp.log 2>&1
		else
			echo "☞ SNMP 시작 스크립트 파일 양호 " >> $CREATE_FILE 2>&1
			echo "＠ 양호" >> snmpp.log 2>&1
		fi
		echo " " >> $CREATE_FILE 2>&1
		echo "＠ 양호" >> snmpp.log 2>&1
	else
		ps -ef | grep snmp | egrep -v "dmi|osnmp" | grep -v "grep"  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "② /etc/snmp/snmpd.conf 파일 " >> $CREATE_FILE 2>&1
		if [ -f /etc/snmp/snmpd.conf ]
			then
				grep -v '^ *#' /etc/snmp/snmpd.conf | grep -i "com2sec" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				string=`grep -v '^ *#' /etc/snmp/snmpd.conf | grep -i "com2sec" | awk '{print $NF}'`
				for one in $string
				do
				echo " " > snmp.log
				#if [ `echo $one | grep [0-9] | wc -l` -gt 0 ]
				#	then
				#		echo "good" >> snmp.log
				#fi
				#if [ `echo $one | grep [a-z] | wc -l` -gt 0 ]
				#	then
				#		echo "good" >> snmp.log
				#fi
				#if [ `echo $one | grep [A-Z] | wc -l` -gt 0 ]
				#	then
				#		echo "good" >> snmp.log
				#fi
				#if [ `echo $one | grep [\~\!\@\#\$%\^\&\*\(\)\-\_\+\=\?] | wc -l` -gt 0 ]
				#	then
				#		echo "good" >> snmp.log
				#fi	
				#if [ \( `echo $one | wc -c` -lt 10 \) -o  \( `cat snmp.log | grep good | wc -l` -lt 3 \) ]
				if [ `echo $one | grep -i public | wc -l` -gt 0 ]
					then
						echo "☞ $one : 취약한 community sting " >> $CREATE_FILE 2>&1
						echo "＠ 취약 - 5.02 SNMP 서비스 설정" >> snmpp.log
					else
						echo "☞ $one : 안전한 community sting " >> $CREATE_FILE 2>&1
				fi
				done
			else
				echo " ☞ /etc/snmp/snmpd.conf 파일이 존재하지 않음 " >> $CREATE_FILE 2>&1
		fi		
	fi

echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ 불필요한 경우 SNMP 서비스 제거, SNMP 서비스 필요한 경우 Community String 값 9자리 이상 숫자, 기호 혼합하여 사용 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat snmpp.log | grep "취약" | wc -l` -eq 0 ]
	then
		echo "＠ 양호 5.02" >> $CREATE_FILE 2>&1
else
	echo "＠ 취약 5.02" >> $CREATE_FILE 2>&1
fi

rm -f snmpp.log
rm -f snmp.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1






echo "5.03 START" >> $CREATE_FILE 2>&1
echo "################## 5.주요 응용 설정 - 5.03 SMTP 서비스 설정 ###################################"
echo "################## 5.주요 응용 설정 - 5.03 SMTP 서비스 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. 서비스 필요 시 Sendmail Abuse 방지 및 일반 사용자 q옵션 사용제한, Sendmail 8.15.2 이상의 버전 사용 " >> $CREATE_FILE 2>&1
echo "나. 서비스 불필요 시 서비스 중지 및 시스템 재시작시 서비스가 실행되지 않도록 설정 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
touch smtp.log
echo "① Sendmail 사용 여부 확인" >> $CREATE_FILE 2>&1
if [ `netstat -anp | grep 'sendmail' | grep -i 'listen' | wc -l` -eq 0 ]
	then
		echo "☞ Sendmail 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "② sendmail 시작 스크립트 파일 확인" >> $CREATE_FILE 2>&1
		if [ `ls -alL /etc/rc*.d/* | grep -i sendmail | grep "/S" | wc -l` -gt 0 ]
			then
				ls -alL /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1
				echo "☞ sendmail 시작 스크립트 파일 취약 " >> $CREATE_FILE 2>&1
				echo "＠ 취약" >> smtp.log 2>&1
		else
			echo "☞ sendmail 시작 스크립트 파일 양호 " >> $CREATE_FILE 2>&1
			echo "＠ 양호" >> smtp.log 2>&1
		fi
		echo " " >> $CREATE_FILE 2>&1
		echo "＠ 양호" >> smtp.log 2>&1
else
	netstat -anp | grep 'sendmail' | grep -i 'listen'  >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1

echo "② sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
	then
		echo "-/etc/mail/sendmail.cf 파일 확인- " >> $CREATE_FILE 2>&1
		if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "noexpn" | grep -i "novrfy" | grep -i "restrictqrun" | grep -v "^#" | wc -l` -gt 0 ]
			then
				cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -v '^#' >> $CREATE_FILE 2>&1
				echo "＠ 양호" >> smtp.log 2>&1
				echo " " >> $CREATE_FILE 2>&1
		else
			cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -v '^#' >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> smtp.log 2>&1
			echo "☞ O PrivacyOptions 옵션 취약" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
else
	if [ `find /etc -name 'sendmail.cf' | wc -l` -gt 0 ]
		then
		sendmailc=`find /etc -name 'sendmail.cf'`
		echo "-" $sendmailc "파일 확인- " >> $CREATE_FILE 2>&1
		if [ `echo $sendmailc | grep -i "O PrivacyOptions" | grep -i "noexpn" | grep -i "novrfy" | grep -i "restrictqrun" | grep -v "^#" | wc -l` -gt 0 ]
			then
				echo $sendmailc | grep -i "O PrivacyOptions" | grep -v '^#' >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "＠ 양호" >> smtp.log 2>&1
				
		else
			cat $sendmailc | grep -i "O PrivacyOptions" | grep -v '^#' >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> smtp.log 2>&1
			echo "☞ O PrivacyOptions 옵션 취약" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
	else
		echo "☞ sendmail.cf 파일이 존재하지 않습니다.(취약) " >> $CREATE_FILE 2>&1
		echo "＠ 취약" >> smtp.log 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
fi


echo "③ sendmail 버전확인" >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
	then
		echo "-/etc/mail/sendmail.cf 파일 확인- " >> $CREATE_FILE 2>&1
		if [ `cat /etc/mail/sendmail.cf | egrep "DZ8.15.2|DZ8.15.3|DZ8.15.4|DZ8.15.5|DZ8.15.6|DZ8.15.7|DZ8.15.8|DZ8.15.9" | wc -l` -gt 0 ]
			then
				cat /etc/mail/sendmail.cf | grep "DZ" | grep -v '^#' >> $CREATE_FILE 2>&1
				echo "＠ 양호" >> smtp.log 2>&1
				echo " " >> $CREATE_FILE 2>&1
		else
			cat /etc/mail/sendmail.cf | grep "DZ" | grep -v '^#' >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> smtp.log 2>&1
			echo "☞ sendmail 버전 취약" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
else
	if [ `find /etc -name 'sendmail.cf' | wc -l` -gt 0 ]
		then
		sendmailc=`find /etc -name 'sendmail.cf'`
		echo "-" $sendmailc "파일 확인- " >> $CREATE_FILE 2>&1
		if [ `echo $sendmailc | egrep "DZ8.15.2|DZ8.15.3|DZ8.15.4|DZ8.15.5|DZ8.15.6|DZ8.15.7|DZ8.15.8|DZ8.15.9" | wc -l` -gt 0 ]
			then
				echo $sendmailc | grep "DZ" | grep -v '^#' >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "＠ 양호" >> smtp.log 2>&1
				echo " " >> $CREATE_FILE 2>&1
		else
			cat $sendmailc | grep "DZ" | grep -v '^#' >> $CREATE_FILE 2>&1
			echo "＠ 취약" >> smtp.log 2>&1
			echo "☞ sendmail 버전 취약" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
	else
		echo "☞ sendmail.cf 파일이 존재하지 않습니다.(취약) " >> $CREATE_FILE 2>&1
		echo "＠ 취약" >> smtp.log 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
fi
fi


# 조치방법
echo "※ 불필요한 경우 SMTP 서비스 제거, 필요한 경우 Sendmail 8.15.2 이상 버전 사용 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat smtp.log | grep "취약" | wc -l` -eq 0 ]
	then
		echo "＠ 양호 5.03" >> $CREATE_FILE 2>&1
else
	echo "＠ 취약 5.03" >> $CREATE_FILE 2>&1
fi

rm -f smtp.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1







echo "5.04 START" >> $CREATE_FILE 2>&1
echo "################## 5.주요 응용 설정 - 5.04 DNS 보안 설정 ######################################"
echo "################## 5.주요 응용 설정 - 5.04 DNS 보안 설정 ######################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "가. 서비스 필요 시" >> $CREATE_FILE 2>&1
echo "-  BIND 9.9.8-P2 이상의 최신 버전 업데이트 권고" >> $CREATE_FILE 2>&1
echo "-  DNS 서버 정보 노출 제한 설정" >> $CREATE_FILE 2>&1
echo "-  DNS 쿼리 보안 설정" >> $CREATE_FILE 2>&1
echo "-  DNS zone transfer 보안 설정" >> $CREATE_FILE 2>&1
echo "-  RRL(Response Rate Limit) 설정" >> $CREATE_FILE 2>&1
echo "-  chroot /setuid 옵션 설정" >> $CREATE_FILE 2>&1
echo "-  OpeenSSL 버전확인" >> $CREATE_FILE 2>&1
echo "나. 서비스 불필요 시" >> $CREATE_FILE 2>&1
echo "-  서비스 중지 및 시스템 재 시작 시 서비스 시작되지 않도록 설정" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
result_504="양호"
echo "[ DNS 프로세스 확인 ]" >> $CREATE_FILE 2>&1
ps -ef | grep named | grep -v "grep" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1 
if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
then 
#서비스 불필요시
echo "☞ DNS 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① /etc/rc.tcpip 설정 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/rc.tcpip ]
	then
		cat /etc/rc.tcpip | grep -i start | grep -i named | grep -i "$src_running"
		echo " " >> $CREATE_FILE 2>&1
		if [ `cat /etc/rc.tcpip | grep "#" | grep -i start | grep -i named | grep -i "$src_running" | wc -l` -eq 0 ]
			then
				echo "☞ DNS Server 시작 방지 설정 없음(취약)" >> $CREATE_FILE 2>&1
			else
				result_504="취약"
		fi
	else
		echo "☞ /etc/rc.tcpip DNS 서비스 시작 설정 파일 없음(양호)" >> $CREATE_FILE 2>&1
fi

else
if [ `echo $namedc | wc -l` -lt 0 ]
	then
		result_504="취약"
fi
echo "[ BIND 최신 버전 확인 ]" >> $CREATE_FILE 2>&1
dns=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep -i "bin" | grep "/*named"`

for dnsfl in $dns
do
$dnsfl -v > dnsv.log

if [ -f $dnsfl ]
	then
		cat dnsv.log | grep -i "BIND" >> $CREATE_FILE 2>&1
		if [ `cat dnsv.log | grep -i "BIND 9\.11\.[0-9]" | wc -l` -eq 1 ]
			then
				result_504="양호"
		else
			if [ `cat dnsv.log | grep -i "BIND 9\.10\.[0-9]" | wc -l` -eq 0 ]
				then
					if [ `cat dnsv.log | grep -i "BIND 9\.9\.11-P[1-9]" | wc -l` -eq 0 ]
						then
							echo "☞ 취약한 버전 사용(BIND 9.9.11-P1 이상 권고)" >> $CREATE_FILE 2>&1
							result_504="취약"
					fi
			else
				if [ `cat dnsv.log | grep -i "BIND 9\.10\.6-P[1-9]" | wc -l` -eq 0 ]
					then
						echo "☞ 취약한 버전 사용(BIND 9.10.6-P1 이상 권고)" >> $CREATE_FILE 2>&1
						result_504="취약"
				fi
			fi
		fi
else
	echo "named 설치 경로를 찾을 수 없습니다." >> $CREATE_FILE 2>&1
	result_504="취약"
fi
echo " " >> $CREATE_FILE 2>&1
done

for namedcf in $namec
do
echo "[ $namedcf 파일 확인 ]" >> $CREATE_FILE 2>&1
echo "① DNS 서버 정보 노출 제한 방법" >> $CREATE_FILE 2>&1
if [ -f $namedcf ]
	then
		cat $namedcf | grep -i version >> $CREATE_FILE 2>&1
		if [ `cat $namedcf | egrep -v "^/|^#" | grep -i 'version "*"' | wc -l` -eq 0 ]
			then
				echo "☞ DNS 서버 정보 노출 제한 설정 없어 취약" >> $CREATE_FILE 2>&1
				result_504="취약"
		fi
else
	echo "☞ named.conf 파일 확인이 불가 합니다." >> $CREATE_FILE 2>&1
	result_504="취약"
fi
echo " " >> $CREATE_FILE 2>&1

echo "② DNS 쿼리 보안 설정(용도에 맞는 설정 권고)" >> $CREATE_FILE 2>&1
if [ -f $namedcf ]
	then
		echo "- Authority 용도 -" >> $CREATE_FILE 2>&1
		cat $namedcf | grep -v "/" | grep -i "allow-query" | egrep -v "cache|allow-r" >> $CREATE_FILE 2>&1
		if [ `cat $namedcf | grep -v "/" | grep -i "allow-query" | egrep -v "cache|allow-r" | egrep -i "any;" | wc -l` -eq 0 ]
			then
				echo "☞ allow-query { any; }; 설정 없습니다." >> $CREATE_FILE 2>&1
		fi
		cat $namedcf | grep -v "/" | grep -i "recursion" | egrep -v "cache|allow-r" >> $CREATE_FILE 2>&1
		if [ `cat $namedcf | grep -v "/" | grep -i "recursion" | egrep -v "cache|allow-r" | egrep -i "no;" | wc -l` -eq 0 ]
			then
				echo "☞ recursion no; 설정 없습니다." >> $CREATE_FILE 2>&1
		fi
		echo " " >> $CREATE_FILE 2>&1
		echo "- Cache 용도 -" >> $CREATE_FILE 2>&1
		cat $namedcf | grep -v "/" | grep -i "allow-query" | grep -v "cache" >> $CREATE_FILE 2>&1
		if [ `cat $namedcf | grep -v "/" | grep -i "allow-query" | grep -v "cache" | grep -w -i "any" | wc -l` -eq 0 ]
			then
				echo "☞ allow-query { any; }; 설정 없습니다." >> $CREATE_FILE 2>&1
		fi
		cat $namedcf | grep -v "/" | grep -i "allow-recursion" | grep -v "cache" >> $CREATE_FILE 2>&1
		if [ `cat $namedcf | grep -v "/" | grep -i "allow-recursion" | grep -v "cache" | grep -w -i "any" | wc -l` -eq 0 ]
			then
				echo "☞ allow-recursion { any; }; 설정 없습니다." >> $CREATE_FILE 2>&1
		fi 
 
		if [ \( `cat $namedcf | grep -v "/" | egrep -i "allow-query|recursion" | egrep -v "cache|allow-r" | egrep -i "any;|no;" | wc -l` -lt 2 \) -a  \( `cat $namedcf | grep -v "/" | egrep -i "allow-query|allow-recursion" | grep -v "cache" | grep -i "any;" | wc -l` -lt 2 \) ]
			then
				echo "☞ DNS 쿼리 보안 설정이 없거나 잘못되었습니다" >> $CREATE_FILE 2>&1
				result_504="취약"
		fi
else
	echo "☞ named.conf 파일 확인이 불가 합니다." >> $CREATE_FILE 2>&1
	result_504="취약"
fi
echo " " >> $CREATE_FILE 2>&1

echo "③ DNS zone transfer 보안 설정" >> $CREATE_FILE 2>&1
if [ -f $namedcf ]
	then
		cat $namedcf | egrep -i "allow-transfer" >> $CREATE_FILE 2>&1
		if [ `cat $namedcf | grep -i "allow-transfer" | grep -v "any" | grep -v "/" | wc -l` -eq 0 ]
			then
				echo "☞ allow-transfer 설정이 없거나 잘못되어 취약" >> $CREATE_FILE 2>&1
				result_504="취약"
		fi
		cat $namedcf | egrep -i "allow-notify" >> $CREATE_FILE 2>&1
		if [ `cat $namedcf | egrep -i "allow-notify { [0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}; };" | grep -v "/" | wc -l` -eq 0 ]
			then
				echo "☞ allow-notify 설정이 없거나 잘못되어 취약" >> $CREATE_FILE 2>&1
				result_504="취약"
		fi
else
	echo "☞ named.conf 파일 확인이 불가 합니다." >> $CREATE_FILE 2>&1
	result_504="취약"
fi
echo " " >> $CREATE_FILE 2>&1

echo "④ RRL(Response Rate Limit) 설정(정확한 진단 기준이 없음으로 제외)" >> $CREATE_FILE 2>&1
if [ -f $namedcf ]
	then
		if [ `cat $namedcf | grep -i "rate-limit" | wc -l` -gt 0 ]
			then
				cat $namedcf | egrep -i "slip [0-9]|window [0-9]|responses-per-second [0-9]|referrals-per-second [0-9]|nodata-per-second [0-9]|nxdomains-per-second [0-9]|errors-per-second [0-9]|all-per-second [0-9]|log-only no|qps-scale [0-9]|exempt-clients {|ipv4-prefix-length [0-9]|ipv6-prefix-length [0-9]|max-table-size [0-9]|min-table-size [0-9]" >> $CREATE_FILE 2>&1
			else
				echo "☞ RRL(Response Rate Limit) 설정 없습니다" >> $CREATE_FILE 2>&1
		fi
else
	echo "☞ named.conf 파일 확인이 불가 합니다." >> $CREATE_FILE 2>&1
	result_504="취약"
fi
echo " " >> $CREATE_FILE 2>&1

echo "⑤ chrootdir/setuid 옵션 설정" >> $CREATE_FILE 2>&1
ps -ef | grep named | grep -v "grep" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep named | grep -v "grep" | grep "\-t" | wc -l` -eq 0 ]
	then
		echo "☞ -t chrootdir 옵션 설정 없어 취약" >> $CREATE_FILE 2>&1
		result_504="취약"
fi
if [ `ps -ef | grep named | grep -v "grep" | grep "\-u" | wc -l` -eq 0 ]
	then
		echo "☞ -u username 옵션 설정 없어 취약" >> $CREATE_FILE 2>&1
		result_504="취약"
fi
echo " " >> $CREATE_FILE 2>&1

echo "⑥ OpenSSL 버전확인" >> $CREATE_FILE 2>&1
touch sslv.log
touch sslvd.log

openssl version > sslv.log
if [ `cat sslv.log | grep -i "openssl" | wc -l` -gt 0 ]
	then
		if [ `cat sslv.log | grep [0-9]\.[0-9]\.[0-9] | wc -l` -eq 0 ]
			then
			echo "☞ OpenSSL 버전 확인 불가" >> $CREATE_FILE 2>&1
			result_504="취약"	
		else
			cat sslv.log >> $CREATE_FILE 2>&1
			sslver=`cat sslv.log`
			if [ `echo $sslver 2>/dev/null | egrep -i "1.0.1[s-z]|1.0.2[g-z]" | wc -l` -eq 0 ]
				then
					echo "☞ 취약한 버전 사용(1.0.1s, 1.0.2g 이상 버전 권고)" >> $CREATE_FILE 2>&1
					result_504="취약"
			fi
		fi
else
	if [ -f /etc/bin/openssl ]
		then
			/etc/bin/openssl version > sslvd.log
			if [ `cat sslvd.log 2>/dev/null| grep [0-9]\.[0-9]\.[0-9] | wc -l` -eq 0 ]
				then
					echo "☞ OpenSSL 버전 확인 불가" >> $CREATE_FILE 2>&1
			else
				cat sslvd.log >> $CREATE_FILE 2>&1
				sslver=`cat sslvd.log`
				if [ `echo $sslver 2>/dev/null | egrep -i "1.0.1[s-z]|1.0.2[g-z]" | wc -l` -eq 0 ]
					then
						echo "☞ 취약한 버전 사용(1.0.1s, 1.0.2g 이상 버전 권고)" >> $CREATE_FILE 2>&1
					result_504="취약"
				fi
			fi
	else
		echo "☞ OpenSSL 서비스 확인 불가" >> $CREATE_FILE 2>&1
	fi
fi
echo " " >> $CREATE_FILE 2>&1
done
fi
echo " " >> $CREATE_FILE 2>&1
echo "※ 불필요한 경우 DNS 서비스 제거, 필요한 경우 전송 IP 제한 및 최신 버전 업데이트 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ $result_504 = "취약" ]
	then
		echo "＠ 취약 5.04" >> $CREATE_FILE 2>&1
	else
		echo "＠ 양호 5.04" >> $CREATE_FILE 2>&1
fi
rm -f dnsv.log
rm -f sslv.log
rm -f sslvd.log
echo "END" >> $CREATE_FILE 2>&1
echo "##############################################################################################" >> $CREATE_FILE 2>&1
echo "==============================================================================================" >> $CREATE_FILE 2>&1
echo "5.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1






echo "5.05 START" >> $CREATE_FILE 2>&1
echo "################## 5.주요 응용 설정 - 5.05 SWAT 보안 설정 #####################################"
echo "################## 5.주요 응용 설정 - 5.05 SWAT 보안 설정 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "/etc/inetd.conf 파일에 SWAT 서비스 제거" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[ /etc/inetd.conf 파일 확인 ]" >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
  then
    cat /etc/inetd.conf | grep -i swat >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/inetd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ 불필요한 경우 SWAT 서비스 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep swat | grep -v "grep"| wc -l` -eq 0 ]
  then
    if [ `cat /etc/inetd.conf 2>/dev/null | grep -i swat | grep -v '^#' | grep -v "grep" | wc -l` -eq 1 ]
      then
        echo "＠ 취약 5.05" >> $CREATE_FILE 2>&1
      else
        echo "＠ 양호 5.05" >> $CREATE_FILE 2>&1
    fi
else
    if [ `cat /etc/inetd.conf 2>/dev/null | grep -i swat | grep -v '^#' |grep -v "grep" | wc -l` -eq 1 ]
      then
        echo "＠ 취약 5.05" >> $CREATE_FILE 2>&1
      else
        echo "＠ 양호 5.05" >> $CREATE_FILE 2>&1
    fi
fi
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.06 START" >> $CREATE_FILE 2>&1
echo "################## 5.주요 응용 설정 - 5.06 Samba 버전 취약성 ##################################"
echo "################## 5.주요 응용 설정 - 5.06 Samba 버전 취약성 ##################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "Samba 서비스를 사용하지 않거나, 업무상 필요 시 Version 4.7.4 이상 버전인 경우 양호" >> $CREATE_FILE 2>&1
echo "(기타 버전) 4.2.14 이상, 4.3.13 이상, 4.4.16 이상, 4.5.15 이상, 4.6.12 이상 양호" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
#기존 스크립트
#SMBPR=`ps -ef | grep smb | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`
touch smbdv.log

echo "① Samba 서비스 사용유무 확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep smbd | grep -v grep | wc -l` -gt 0 ]
	then
	ps -ef | grep smbd | grep -v "grep" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "② Samba 서비스 버전 확인" >> $CREATE_FILE 2>&1
	smbd --version  >> $CREATE_FILE 2>&1
	smbd --version  >> sambaver.log 2>&1
	#$SMBPR -version  >> $CREATE_FILE 2>&1
		if [ `cat sambaver.log | grep -i "4\.7\.[0-3]" | wc -l` -eq 1 ]
			then
				echo "＠ 양호" >> smbdv.log 2>&1
		else
			if [ `cat sambaver.log | grep -i "4\.6\.1[2-9]" | wc -l` -eq 1 ]
				then
					echo "＠ 양호" >> smbdv.log 2>&1
			else
				if [ `cat sambaver.log | grep -i "4\.5\.1[5-9]" | wc -l` -eq 1 ]
					then
						echo "＠ 양호" >> smbdv.log 2>&1
				else
					if [ `cat sambaver.log | grep -i "4\.4\.1[6-9]" | wc -l` -eq 1 ]
						then
							echo "＠ 양호" >> smbdv.log 2>&1
					else
						if [ `cat sambaver.log | grep -i "4\.3\.3[3-9]" | wc -l` -eq 1 ]
							then
								echo "＠ 양호" >> smbdv.log 2>&1
						else
							if [ `cat sambaver.log | grep -i "4\.2\.3[4-9]" | wc -l` -eq 1 ]
								then
									echo "＠ 양호" >> smbdv.log 2>&1
							else
								echo "＠ 취약" >> smbdv.log 2>&1
							fi
						fi
					fi
				fi
			fi
		fi

else
	echo "☞ Samba 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "[ Samba 시작 스크립트 파일 확인 ]" >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/rc*.d/* | grep -i samba | grep "/S" | wc -l` -gt 0 ]
	then
		ls -alL /etc/rc*.d/* | grep -i samba | grep "/S" >> $CREATE_FILE 2>&1
		echo "☞ samba 시작 스크립트 파일 취약 " >> $CREATE_FILE 2>&1
		echo "＠ 취약" >> smbdv.log 2>&1
	else
		echo "☞ samba 시작 스크립트 파일 양호 " >> $CREATE_FILE 2>&1
		echo "＠ 양호" >> smbdv.log 2>&1
		
fi
echo " " >> $CREATE_FILE 2>&1
# 조치방법
echo "※ 불필요한 경우 Samba 서비스 제거, 필요한 경우 Samba 4.7.4 버전 이상 사용 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat smbdv.log | grep -i "취약" | wc -l` -eq 0 ]
  then
    echo "＠ 양호 5.06" >> $CREATE_FILE 2>&1
  else
    echo "＠ 취약 5.06" >> $CREATE_FILE 2>&1
fi
rm -f smbdv.log
rm -f sambaver.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.07 START" >> $CREATE_FILE 2>&1
echo "################## 5.주요 응용 설정 - 5.07 SSH 버전 취약성 ####################################"
echo "################## 5.주요 응용 설정 - 5.07 SSH 버전 취약성 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "불필요한 경우 OpenSSH 서비스를 사용하지 않거나 최신 버전을 사용" >> $CREATE_FILE 2>&1
echo "- OpenSSH 7.6p1 버전 이상 권고" >> $CREATE_FILE 2>&1
echo "- RHEL 4.X (Red Hat Enterprise Linux 4.X) --> openssh-3.9p1 버전 이상 권고" >> $CREATE_FILE 2>&1
echo "- RHEL 5.X (Red Hat Enterprise Linux 5.X) --> openssh-4.3p2 버전 이상 권고" >> $CREATE_FILE 2>&1
echo "- RHEL 6.X (Red Hat Enterprise Linux 6.X) --> openssh-5.3p1 버전 이상 권고" >> $CREATE_FILE 2>&1
echo "- RHEL 7.X (Red Hat Enterprise Linux 7.X) --> openssh-6.6.1p1 버전 이상 권고" >> $CREATE_FILE 2>&1
echo "- 일반적으로 OpenSSH 7.6p1 이상의 버전의 SSH 설치 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SSHPR=`ps -ef | grep sshd | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/sshd" | uniq`

echo "[ SSH 구동 여부 확인 ]" >> $CREATE_FILE 2>&1
if [ `echo $SSHPR | grep -i "ssh" | wc -l` -gt 0 ]
	then
		ps -ef | grep sshd | grep -v "grep" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "① 리눅스 종류 확인" >> $CREATE_FILE 2>&1
		uname -a >> $CREATE_FILE 2>&1
		cat /etc/*-release >> $CREATE_FILE 2>&1
		#RELE=`uname -a | awk -F" " '{print $3'} | awk -F"el" '{print $2'} | awk -F"." '{print $1'}`
		echo " " >> $CREATE_FILE 2>&1
		echo "② SSH 버전 확인 " >> $CREATE_FILE 2>&1
		#rpm -qa openssh-server > sshver1.log 2>&1
		#rpm -qa openssh-server >> $CREATE_FILE  2>&1
		ssh -V >> $CREATE_FILE 2>&1
		ssh -V > sshver.log 2>&1
		SSHV=`cat sshver.log | awk -F"OpenSSH_" '{print $2}' | awk -F"," '{print $1}' | awk -F" " '{print $1'}`
		echo $SSHV >> $CREATE_FILE 2>&1
		if [ `cat sshver.log | wc -l` -eq 0 ]
			then
				echo "☞ SSH 버전 확인 불가(취약)" >> $CREATE_FILE 2>&1
				echo "취약" >> sshresult.log 2>&1
		else
			if [ `echo $SSHV | grep -i "[8-9].[0-9]" | wc -l` -gt 0 ]
				then
					echo "양호" >> sshresult.log 2>&1
			else
				if [ `echo $SSHV | grep -i "7.[6-9]p" | wc -l` -gt 0 ]
					then
						echo "양호" >> sshresult.log 2>&1
				else
					if [ `echo $SSHV | grep -i "6.[6-9].[1-9]p[1-9]" | wc -l` -gt 0 ]
						then
							echo "양호" >> sshresult.log 2>&1
					else
						if [ `echo $SSHV | grep -i "6.[7-9]p[1-9]" | wc -l` -gt 0 ]
							then
								echo "양호" >> sshresult.log 2>&1
						else
							if [ `echo $SSHV | grep -i "5.[3-9]p[1-9]" | wc -l` -gt 0 ]
								then
									echo "양호" >> sshresult.log 2>&1
							else
								if [ `echo $SSHV | grep -i "4.[3-9]p[2-9]" | wc -l` -gt 0 ]
									then
										echo "양호" >> sshresult.log 2>&1
								else
									if [ `echo $SSHV | grep -i "3.9p[1-9]-" | wc -l` -gt 0 ]
										then
											echo "양호" >> sshresult.log 2>&1
									else
										echo "취약" >> sshresult.log 2>&1
									fi
								fi
							fi
						fi
					fi
				fi
			fi
		fi
else
	echo "☞ SSH 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "※ 불필요한 경우 SSH 서비스 제거, 필요한 경우 최신 버전의 SSH 사용 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "＠ 양호 5.07" >> $CREATE_FILE 2>&1
else
	if [ `cat sshresult.log | grep -i "취약" | wc -l` -eq 0 ]
		then
			echo "＠ 양호 5.07" >> $CREATE_FILE 2>&1
	else
		echo "＠ 취약 5.07" >> $CREATE_FILE 2>&1
	fi
fi

# 조치방법

rm -f sshver.log
rm -f sshver1.log
rm -f sshver2.log
rm -f sshresult.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "5.08 START" >> $CREATE_FILE 2>&1
echo "################## 5.주요 응용 설정 - 5.8 x-server 접속 제한 설정 #############################"
echo "################## 5.주요 응용 설정 - 5.8 x-server 접속 제한 설정 #############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "모든 사용자의 자동 실행파일 에서 ‘xhost +’ 와 같은 x-server 접속 설정 제거" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "◇ 취약한 자동 실행 파일 List" >> $CREATE_FILE 2>&1
echo "------------------------------" >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u| grep -vw "/"`
FILES="/.profile /.cshrc /.kshrc /.login /.bash_profile /.bashrc /.bash_login /.xinitrc /.xsession"

#for file in $FILES
#do
#    if [ -f $file ]
#    then
#        echo " " >> $CREATE_FILE 2>&1
#        echo " cat $file " >> $CREATE_FILE 2>&1
#        echo " ------------" >> $CREATE_FILE 2>&1
#        grep -v '^ *#' $file | grep "xhost +" >> $CREATE_FILE 2>&1
#        echo " " >> $CREATE_FILE 2>&1
#    else
#        echo $file " 파일이 없습니다." >> $CREATE_FILE 2>&1
#    fi
#done

#for dir in $HOMEDIRS
#do
#  for file in $FILES
#  do
#    if [ -f $dir$file ]
#    then
#        echo " " >> $CREATE_FILE 2>&1
#        echo " cat $dir$file " >> $CREATE_FILE 2>&1
#        echo "----------------" >> $CREATE_FILE 2>&1
#        grep -v '^ *#' $dir$file | grep "xhost +" >> $CREATE_FILE 2>&1
#        echo " " >> $CREATE_FILE 2>&1
#    else
#       echo $dir$file " 파일이 없습니다." >> $CREATE_FILE 2>&1
#    fi
#  done
#done

#echo " " >> $CREATE_FILE 2>&1

echo " " > xhost.log
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u| grep -vw "/"`
FILES="/.profile /.cshrc /.kshrc /.login /.bash_profile /.bashrc /.bash_login /.xinitrc /.xsession"

for file in $FILES
do
    if [ -f $file ]
    then
        if [ `cat $file | grep "xhost.*+" | wc -l` -eq 0 ]
        then
             echo "＠ 양호" >> xhost.log
        else
             echo "＠ 취약" >> xhost.log
			 echo "$file (xhost + 설정 존재)" >> $CREATE_FILE 2>&1
        fi
    else
        echo "  " >> xhost.log
        echo "＠ 양호" >> xhost.log
    fi
done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    if [ -f $dir$file ]
    then
        if [ `cat $dir$file | grep "xhost.*+" | wc -l` -eq 0 ]
        then
             echo "＠ 양호" >> xhost.log
        else
             
			 echo "＠ 취약" >> xhost.log
			 echo "$dir$file (xhost + 설정 존재)" >> $CREATE_FILE 2>&1
        fi
    else
        echo "＠ 양호" >> xhost.log
    fi
  done
done
if [ `cat xhost.log | grep "취약" | wc -l` -eq 0 ]
then
  echo "☞ 취약한 자동 실행파일 없음" >> $CREATE_FILE 2>&1
fi


echo " " >> $CREATE_FILE 2>&1

# 조치방법
echo "※ 모든 사용자의 자동 실행파일 에서 ‘xhost +’ 와 같은 x-server 접속 설정 제거 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat xhost.log | grep "취약" | wc -l` -eq 0 ]
then
  echo "＠ 양호 5.08" >> $CREATE_FILE 2>&1
else
  echo "＠ 취약 5.08" >> $CREATE_FILE 2>&1
fi
rm -f xhost.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "6.01 START" >> $CREATE_FILE 2>&1
echo "################## 6.보안패치 - 6.01 보안 패치 적용 ###########################################"
echo "################## 6.보안패치 - 6.01 보안 패치 적용 ###########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "START" >> $CREATE_FILE 2>&1
echo "■ 기준" >> $CREATE_FILE 2>&1
echo "서버 침해 방지를 위해 주기적으로 보안 패치 적용" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 현재 설치되어 있는 패치" >> $CREATE_FILE 2>&1
echo "--------------------------" >> $CREATE_FILE 2>&1

if [ `cat /etc/*-release | grep -i 'DISTRIB_DESCRIPTION' | grep -i 'ubuntu' | wc -l` -gt 0 ]
	then
		apt list > rpmlog.log 2>&1
		tail -20 rpmlog.log >> $CREATE_FILE 2>&1
		echo "..." >> $CREATE_FILE 2>&1
else
	rpm -qa > rpmlog.log 2>&1
	tail -20 rpmlog.log >> $CREATE_FILE 2>&1
	echo "..." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
# 조치방법

echo "※ 주기적인 보안 패치 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "＠ 양호 6.01" >> $CREATE_FILE 2>&1
rm -f rpmlog.log
echo "END" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "6.01 END" >> $CREATE_FILE 2>&1




unset HOMEDIRS
rm -f ftp_temp
rm -f ftp2_temp
rm -f log_temp
rm -f svc

echo "**************************************** END ***************************************************" >> $CREATE_FILE 2>&1
date >> $CREATE_FILE 2>&1
echo "**************************************** END ***************************************************"


echo "1.01 Default 계정 삭제" > list.log
echo "1.02 일반계정 root 권한 관리" >> list.log
echo "1.03 /etc/passwd 파일 권한 설정" >> list.log
echo "1.04 /etc/group 파일 권한 설정" >> list.log
echo "1.05 /etc/shadow 파일 권한 설정" >> list.log
echo "1.06 패스워드 사용규칙 적용" >> list.log
echo "1.07 로그인 불필요한 계정 shell 제한" >> list.log
echo "1.08 SU(Select User) 사용 제한" >> list.log
echo "2.01 사용자 UMASK(User MASK) 설정" >> list.log
echo "2.02 SUID, SGID 설정" >> list.log
echo "2.03 /etc/inetd.conf, /etc/xinetd.conf 파일 권한 설정" >> list.log
echo "2.04 history 파일 권한 설정" >> list.log
echo "2.05 Crontab 파일 권한 설정 및 관리" >> list.log
echo "2.06 /etc/profile 파일 권한 설정" >> list.log
echo "2.07 /etc/hosts 파일 권한 설정" >> list.log
echo "2.08 /etc/issue 파일권한 설정" >> list.log
echo "2.09 사용자 홈디렉토리 및 파일 관리" >> list.log
echo "2.10 중요 디렉토리 권한 설정" >> list.log
echo "2.11 PATH 환경변수 설정 " >> list.log
echo "2.12 FTP 접근제어 파일 권한설정" >> list.log
echo "2.13 root 원격 접근제어 파일 권한 설정" >> list.log
echo "2.14 NFS 접근제어 파일 권한 설정" >> list.log
echo "2.15 /etc/services 파일 권한 설정" >> list.log
echo "2.16 부팅 스크립트 파일 권한 설정" >> list.log
echo "3.01 RPC 서비스 제한" >> list.log
echo "3.02 NFS(Network File System) 제한" >> list.log
echo "3.03 Automountd 서비스 제거" >> list.log
echo "3.04 NIS(Network Information Service) 제한" >> list.log
echo "3.05 ‘r’ commands 서비스 제거" >> list.log
echo "3.06 불필요한 서비스 제거" >> list.log
echo "3.07 서비스 Banner 관리" >> list.log
echo "3.08 Session timeout 설정" >> list.log
echo "3.09 root 계정 telnet, ssh 접근 제한" >> list.log
echo "3.10 방화벽 정책 적용" >> list.log
echo "4.01 시스템 로그 설정" >> list.log
echo "4.02 로그 저장주기" >> list.log
echo "5.01 FTP 서비스 사용자 제한" >> list.log
echo "5.02 SNMP 서비스 설정" >> list.log
echo "5.03 SMTP 서비스 설정" >> list.log
echo "5.04 DNS 보안 설정" >> list.log
echo "5.05 SWAT 보안 설정" >> list.log
echo "5.06 Samba 버전 취약성" >> list.log
echo "5.07 SSH 버전 취약성" >> list.log
echo "5.08 x-server 접속 제한 설정" >> list.log
echo "6.01 보안 패치 적용" >> list.log




echo "*****************************  전체 결과물 파일 생성 시작  *************************************"
#CREATE_FILE=`hostname`"_"`date +%Y%m%d`"_linux("$bbb").log"
#echo > $CREATE_FILE

echo " "

awk '/INFO_CHKSTART/,/INFO_CHKEND/' $CREATE_FILE > result_temp.log 2>&1


echo " "  >> result_temp.log 2>&1
echo " "  >> result_temp.log 2>&1
echo "★ 전체 진단 결과"  >> result_temp.log 2>&1

cat $CREATE_FILE | grep "END" | awk '{print $1}' > VUL1.log

for vul in `uniq VUL1.log`
        do
           awk '/'"$vul"' START/,/'"$vul"' END/' $CREATE_FILE >> result_temp.log 2>&1
           echo >> result_temp.log 2>&1
        done

rm -f VUL1.log
#echo "******************************  전체 결과물 파일 생성 끝 ***********************************"
#echo "*****************************   취약한 항목 출력 시작 **************************************"
echo > vul5.log 2>&1
echo "########################################################################################################" >> vul5.log 2>&1
echo "#                         Copyright (c) 2022 JOYCITY Co. Ltd. All Rights Reserved.                     #" >> vul5.log 2>&1
echo "########################################################################################################" >> vul5.log 2>&1
echo "********************************************************************************************************" >> vul5.log 2>&1
echo "  ※  본 스크립트의 '기준'에 대한 내용은 보안가이드라인 문서에서 요약한 내용입니다.               " >> vul5.log 2>&1
echo "      진단항목별로 구체적인 진단 기준과 조치방법은 '보안가이드라인' 문서를 참고하시기 바랍니다.   " >> vul5.log 2>&1
echo "  ※  특이한 설정이나 정의되어 있지 않은 패턴에 대해서는 오탐이 있을 수 있으며,                   " >> vul5.log 2>&1
echo "      정확한 진단을 위해서는 실제 설정 현황과 보안가이드라인 문서를 바탕으로 판단하시기 바랍니다. " >> vul5.log 2>&1
echo "********************************************************************************************************" >> vul5.log 2>&1
echo "  ※  Version: 2023-001                                                                       " >> vul5.log 2>&1
echo "  ※  Script File: 23-linux_v2.0.1.sh                                                              " >> vul5.log 2>&1
echo "  ※  Launching Time: `date`                                                                      " >> vul5.log 2>&1
echo "  ※  Hostname: `hostname`                                                                        " >> vul5.log 2>&1

ipadd=`ifconfig -a | grep "inet " | awk -F":" '{i=1; while(i<=NF) {print $i; i++}}' | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep "^[1-9]" | egrep -v "^127|^255|255$"`
echo "  ※  ip address: `echo $ipadd`                                                                        " >> vul5.log 2>&1
echo "********************************************************************************************************" >> vul5.log 2>&1
uname -a                            >>  vul5.log 2>&1
echo "********************************************************************************************************" >>  vul5.log 2>&1
echo " " >> vul5.log 2>&1
echo "******************************  전체 결과물 파일 생성 끝 ***************************************"
echo "################################# Script Launching Time #######################################"
date
echo " "
echo " " >> vul5.log 2>&1
echo " " >> vul5.log 2>&1
echo "********************************  Ⅰ. 취약 & N/A 항목 출력   ****************************************" >> vul5.log 2>&1

cat result_temp.log | egrep "＠ 취약" | grep -v "컨설턴트" | awk '{print $3}' | egrep -o "[0-9].[0-9]+" > VUL1.log 2>&1
cat result_temp.log | egrep "＠ N/A" | grep -v "컨설턴트" | awk '{print $3}' | egrep -o "[0-9].[0-9]+" > VUL2.log 2>&1
touch vul9.log

echo " " >> vul5.log 2>&1
echo " " >> vul5.log 2>&1
#echo "* Vul_Start " >> vul5.log 2>&1
echo "===========================================" >> vul5.log 2>&1
echo "☞ 취약 항목" >> vul5.log 2>&1
echo "===========================================" >> vul5.log 2>&1

for LIST in `uniq VUL1.log`
 do
  cat list.log | grep -w $LIST  >> vul9.log 2>&1
  cat list.log | grep -w $LIST  >> vul5.log 2>&1
done
#echo "* Vul_End " >> vul5.log 2>&1
echo " " >> vul5.log 2>&1

#echo "* Nocheck_Start " >> vul5.log 2>&1
echo "===========================================" >> vul5.log 2>&1
echo "☞ N/A 항목" >> vul5.log 2>&1
echo "===========================================" >> vul5.log 2>&1
for LIST in `uniq VUL2.log`
 do
  cat list.log | grep -w $LIST  >> vul5.log 2>&1
done
#echo "* Nocheck_End " >> vul5.log 2>&1
echo " " >> vul5.log 2>&1
echo " " >> vul5.log 2>&1
#echo "===========================================" >> vul5.log 2>&1
#echo "☞ 취약 항목에 대한 세부내용" >> vul5.log 2>&1
#echo "===========================================" >> vul5.log 2>&1
#echo >> vul5.log 2>&1
#if [ ` cat result_temp.log | grep "취약" | wc -l` -eq 0 ]
#  then
#    echo >> vul5.log 2>&1
#  else
#      for vul in `uniq VUL1.log`
#        do
#           awk '/'"$vul"' START/,/'"$vul"' END/' $CREATE_FILE >> vul5.log 2>&1
#           echo >> vul5.log 2>&1
#           echo >> vul5.log 2>&1
#        done
#fi

# if [ ` cat result_temp.log | grep "미점검" | wc -l` -eq 0 ]
  # then
    # echo >> vul5.log 2>&1
  # else
      # for vul in `uniq VUL2.log`
        # do
           # awk '/'"$vul"' START/,/'"$vul"' END/' $CREATE_FILE >> vul5.log 2>&1
           # echo >> vul5.log 2>&1
           # echo >> vul5.log 2>&1
        # done
# fi
#echo "**********************************************************************************************" >> vul5.log 2>&1

echo "################################## 발견된 취약 항목 ###########################################"
echo ""
if [ `cat vul9.log | wc -l` -gt 0 ]
	then
		cat vul9.log
else
	echo "※ 발견된 취약 항목이 없습니다."
fi
echo ""
echo "###############################################################################################"
aaa=`cat vul9.log | wc -l`
#bbb=`echo "100-$aaa*2.3" | bc -l`
#ccc=`echo $bbb | awk -F "." '{print $1}'`
ccc=`echo $aaa | awk '{printf "%.0f", 100 - $aaa * 2.3}'`
#bbb=`echo "$aaa/(46-3)*100" | bc -l`
echo "※ 발견된 취약 항목 $aaa 개,  보안 준수율 $ccc  점"
echo "###############################################################################################"
#echo "##############################################################################################" >> vul5.log 2>&1
#aaaa=`cat vul9.log | wc -l`
#bbb=`echo "100-$aaa*2.3" | bc -l`
#ccc=`echo $bbb | awk -F "." '{print $1}'`
#cccc=`echo $aaaa | awk '{printf "%.0f", 100 - $aaaa * 2.3}'`
#echo "※ 발견된 취약 항목 $aaa 개,  보안 준수율 $ccc 점" >> vul5.log 2>&1
#eecho "##############################################################################################" >> vul5.log 2>&1


## APACHE/TOMCAT 확인 후 파일명 결정
alias ls=ls
alias grep=/bin/grep

echo ''
if [ `uname | grep -i 'hp-ux' | wc -l` -gt 0 ]
	then
		ppss='ps -efx'
		aaww='awk'
else
	if [ `uname | grep -i 'sun' | wc -l` -eq 0 ]
		then
			ppss='ps auxwww'
			aaww='awk'
	else
		ppss='/usr/ucb/ps auxww'
		aaww='nawk'
	fi
fi

if [ `$ppss | grep httpd | grep -v grep | wc -l` -ge 1 ]
	then
		if [ `$ppss |grep -i tomcat | grep -i java |grep -v grep | wc -l` -ge 1 ]
			then
				CREATE_FILE_RESULT=`hostname`"_"`date +%Y%m%d`"_linux-Apache-Tomcat-"$ccc"%.log"
				echo > $CREATE_FILE_RESULT
		else
				CREATE_FILE_RESULT=`hostname`"_"`date +%Y%m%d`"_linux-Apache-"$ccc"%.log"
				echo > $CREATE_FILE_RESULT
		fi
else
	if [ `$ppss | grep -i tomcat | grep -i java |grep -v grep | wc -l` -ge 1 ]
		then
			CREATE_FILE_RESULT=`hostname`"_"`date +%Y%m%d`"_linux-Tomcat-"$ccc"%.log"
			echo > $CREATE_FILE_RESULT
	else
		CREATE_FILE_RESULT=`hostname`"_"`date +%Y%m%d`"_linux-"$ccc"%.log"
		echo > $CREATE_FILE_RESULT
	fi
fi
		

cat vul5.log > result_temp2.log 2>&1
rm -f vul5.log
cat result_temp2.log >> $CREATE_FILE_RESULT 2>&1
cat result_temp.log >> $CREATE_FILE_RESULT 2>&1
echo "##############################################################################################" >> $CREATE_FILE_RESULT 2>&1
aaa=`cat vul9.log | wc -l`
#bbb=`echo "100-$aaa*2.3" | bc -l`
#ccc=`echo $bbb | awk -F "." '{print $1}'`
ccc=`echo $aaa | awk '{printf "%.0f", 100 - $aaa * 2.3}'`
#bbb=`echo "$aaa/(46-3)*100" | bc -l`
echo "※ OS(Linux) 발견된 취약 항목 $aaa 개,  보안 준수율 $ccc 점" >> $CREATE_FILE_RESULT 2>&1
echo "##############################################################################################" >> $CREATE_FILE_RESULT 2>&1

if [ `ps -ef | grep httpd | grep -v grep | wc -l` -eq 0 ]
	then
		echo " " >> $CREATE_FILE_RESULT 2>&1
		echo "END_RESULT" >> $CREATE_FILE_RESULT 2>&1
else
	if [ `ps -ef |grep -i tomcat | grep -i java |grep -v grep | wc -l` -eq 0 ]
		then
			echo " " >> $CREATE_FILE_RESULT 2>&1
			echo "END_RESULT" >> $CREATE_FILE_RESULT 2>&1
	fi
fi



rm -f result_temp.log
rm -f result_temp2.log
rm -f VUL.log
rm -f VUL1.log
rm -f VUL2.log
rm -f list.log
rm -f vul9.log

rm -f $CREATE_FILE 2>&1
chmod 777 $CREATE_FILE_RESULT 2>&1
#unix2dos $CREATE_FILE_RESULT 2>&1


############################################### APACHE #####################################################

echo ""
echo ""

APACHE_CREATE_FILE_RESULT="apache.log"

alias ls=ls
alias grep=/bin/grep

echo ''
if [ `uname | grep -i 'hp-ux' | wc -l` -gt 0 ]
	then
		ppss='ps -efx'
		aaww='awk'
else
	if [ `uname | grep -i 'sun' | wc -l` -eq 0 ]
		then
			ppss='ps auxwww'
			aaww='awk'
	else
		ppss='/usr/ucb/ps auxww'
		aaww='nawk'
	fi
fi

if [ `$ppss | grep httpd | grep -v grep | wc -l` -ge 1 ]
	then
		#echo "※ APACHE 구동중으로 진단을 수행하겠습니다."
		echo "########################### Apache 진단 스크립트를 실행하겠습니다 ###########################"
		echo ""
		echo ""

echo '[Apache 서비스 확인]'
$ppss | grep httpd | grep -v grep
#echo ''
#echo "※ 자동 진단을 진행하시려면 1 을 수동 진단을 진행하시려면 2 를 선택하여 주십시오 : "
#read abc
#echo ''
touch apachepaths.bak
touch apacheconfs.bak
#수동진단
#if [ $abc -eq 2 ]
#	then
#	echo '※ 현재 사용중인 httpd.conf 파일 갯수 입력 : '
#	read cu
#	echo ' '
#	if [ $cu -ge 1 ]
#		then
#			num=1
#			while [ $num -le $cu ]
#			do
#				while true
#				do
#				echo "$num번째 httpd.conf 경로 (ex. /usr/local/apache/conf/httpd.conf): "
#				read filepath
#				echo " "
#				if [ -f $filepath ]
#					then
#						echo $filepath >> apacheconfs.bak 2>&1
#						break
#					else
#						echo "   입력하신 파일이 존재하지 않습니다. 다시 입력하여 주십시오."
#						echo " "
#				fi
#				done
#			num=`expr $num + 1`
#			done
#
#			num=1
#			while [ $num -le $cu ]
#			do
#				while true
#				do
#				echo "$num번째 httpd 실행파일 경로 (ex. /usr/local/apache/bin/httpd): "
#				read filepath
#				echo " "
#				if [ -f $filepath ]
#					then
#						echo $filepath >> apachepaths.bak 2>&1
#						break
#					else
#						echo "   입력하신 파일이 존재하지 않습니다. 다시 입력하여 주십시오."
#						echo " "
#				fi
#				done
#			num=`expr $num + 1`
#			done
#	fi
#
#else

#자동진단
	if [ `$ppss | grep -i httpd | grep -v grep | wc -l` -ge 1 ]
	then

#default config 파일 사용하는 httpd 경로
	_onlyhttpd=`$ppss | grep httpd | egrep -v 'grep|\.conf' | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep '\/httpd$' | sort -u`
	echo ''
	for apa in $_onlyhttpd
	do
	if [ `ls -l $apa 2>&1 | egrep -i 'lrwxrwxrwx|ls:' |wc -l` -gt 0 ]
		then
			ls -l $apa
			echo ''
			while true
			do
			echo "※ 위 httpd 파일을 확인하시고 정확한 httpd 실행 파일 경로를 입력하십시오. "
			read realpath
			echo " "
			if [ -f $realpath ]
				then
					echo $realpath >> apachepaths.bak 2>&1
					break
				else
					echo "☞ 입력하신 파일이 존재하지 않습니다. 다시 입력하여 주십시오."
					echo " "
			fi
			done
		else
			echo $apa >> apachepaths.bak 2>&1
	fi

	done

	_httpds=`cat apachepaths.bak | sed 's/\/httpd$//' | sort -u`
	for binpath in $_httpds
	do
	if [ `$binpath/apachectl -V 2>&1 | grep -i "SERVER_CONFIG_FILE" | wc -l` -gt 0 ]
		then
			apahttpd="$binpath/apachectl"
		else
			apahttpd="$binpath/httpd"
	fi
	if [ `$apahttpd -V 2>&1 | grep -i "HTTPD_ROOT" | $aaww -F'"' '{print $2}' | grep "/" | wc -l` -gt 0 ]
		then
			apache=`$apahttpd -V 2>&1 | grep -i "HTTPD_ROOT" | $aaww -F'"' '{print $2}'`
			if [ `$apahttpd -V 2>&1 | grep -i "SERVER_CONFIG_FILE" | $aaww -F'"' '{print $2}' | grep "\.conf" | wc -l` -gt 0 ]
				then
					cfile=`$apahttpd -V 2>&1 | grep -i "SERVER_CONFIG_FILE" | $aaww -F'"' '{print $2}'`
					if [ `echo $cfile | grep "^/" | wc -l` -eq 0 ]
						then
							confile=$apache/$cfile
						else
							confile=$cfile
					fi
					if [ -f $confile ]
						then
							echo $confile >> apacheconfs.bak 2>&1
					fi
			fi
		else
			while true
			do
			echo "※ 선언되지 않은 httpd.conf 파일 경로를 입력하십시오. "
			read filepath
			echo " "
			if [ -f $filepath ]
				then
					echo $filepath >> apacheconfs.bak 2>&1
					break
				else
					echo "   입력하신 파일이 존재하지 않습니다. 다시 입력하여 주십시오."
					echo " "
			fi
			done
	fi
	done


#별도의 config 파일 사용하는 httpd 경로
	_withconf=`$ppss | grep httpd | grep -v grep | grep -i '\.conf' | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep '\/httpd$' | sort -u`
	_confs=`$ppss | grep httpd | grep -v grep | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep '\.conf$' | sort -u`
	for apa in $_withconf
	do
	if [ `ls -l $apa 2>&1 | egrep -i 'lrwxrwxrwx|ls:' |wc -l` -gt 0 ]
		then
			ls -l $apa
			echo ''
			while true
			do
			echo "※ 위 httpd 파일을 확인하시고 정확한 httpd 실행 파일 경로를 입력하십시오. "
			read realpath
			echo " "
			if [ -f $realpath ]
				then
					echo $realpath >> apachepaths.bak 2>&1
					break
				else
					echo "☞ 입력하신 파일이 존재하지 않습니다. 다시 입력하여 주십시오."
					echo " "
			fi
			done
		else
			echo $apa >> apachepaths.bak 2>&1
	fi
	done

	for cfile in $_confs
	do
	if [ -f $cfile ]
		then
			echo $cfile >> apacheconfs.bak 2>&1
		else
			while true
			do
			echo $cfile
			echo "※ 위 httpd.conf 파일을 확인하시고 정확한 httpd.conf 파일 경로를 입력하십시오. "
			read filepath
			echo " "
			if [ -f $filepath ]
				then
					echo $filepath >> apacheconfs.bak 2>&1
					break
				else
					echo "   입력하신 파일이 존재하지 않습니다. 다시 입력하여 주십시오."
					echo " "
			fi
			done
	fi
	done

	fi
#fi
echo " "
echo '[Apache httpd.conf 경로]'
cat apacheconfs.bak | grep "\.conf$" | sort -u
echo " "
echo '[Apache httpd 실행파일 경로]'
cat apachepaths.bak | grep '\/httpd$' | sort -u

_confiles=`cat apacheconfs.bak | grep "\.conf$" | sort -u`
_confolds=`cat apacheconfs.bak | grep "\.conf$" | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`
_httpdbins=`cat apachepaths.bak | grep '\/httpd$' | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`

if [ `$ppss | grep -i 'http' | grep -v "grep" | grep -v "root" | $aaww -F" " '{print $1}' | wc -l` -gt 0 ]
	then
		APSID=`$ppss | grep -i 'http' | grep -v "grep" | grep -v "root" | $aaww -F" " '{print $1}' | head -1`
else
	APSID='root'
fi



rm -f apachepaths.bak
rm -f apacheconfs.bak

#echo " "
echo " "

echo " "  >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " "  >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "[ APACHE 취약점 진단 결과 ]"  >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " "  >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " "  >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " "  >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "★ 전체 진단 결과"  >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "##############################################################################################"
echo " "
echo "1.01 START" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "################## 1.설정 - 1.01 데몬 관리"
echo "################## 1.설정 - 1.01 데몬 관리 #############################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'Apache 데몬이 root 권한으로 운영되지 않고 전용 데몬으로 구동중이면 양호' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1

echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result1='양호'
$ppss  |grep httpd |grep -v grep >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
httpdcon=`$ppss | grep httpd | egrep -v 'grep|rotatelogs' | $aaww -F"/" '{print $2 $3 $4 $5 $6 $7}' | sort -u | wc -l`
rootcon=`$ppss | grep httpd | egrep -v 'grep|rotatelogs' | $aaww '{print $1}' | grep root | wc -l`
notrootcon=`$ppss | grep httpd | egrep -v 'grep|rotatelogs' | $aaww '{print $1}' |grep -v "^root" | wc -l`
if [ $httpdcon -ne $rootcon ]
		then
			result1='취약'
			echo '☞ Web Server 전용 계정 사용 안함(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
	elif [ $notrootcon -eq 0 ]
		then
			result1='취약'
			echo '☞ Web Server 전용 계정 사용 안함(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

for confile in $_confiles
do
echo "◈ $confile 파일 확인 " >> $APACHE_CREATE_FILE_RESULT 2>&1
cat $confile |grep 'User ' |grep -v '#' >> $APACHE_CREATE_FILE_RESULT 2>&1
cat $confile |grep 'Group ' |grep -v '#' >> $APACHE_CREATE_FILE_RESULT 2>&1
cat $confile |grep '^Listen ' |grep -v '#' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ `cat $confile |grep '^Listen ' |grep -v '#' | $aaww '{print $2}' | grep ":" | wc -l` -gt 0 ]
	then
		portns=`cat $confile |grep '^Listen ' |grep -v '#' | $aaww '{print $2}' | $aaww -F":" '{print $2}'`
	else
		portns=`cat $confile |grep '^Listen ' |grep -v '#' | $aaww '{print $2}'`
fi

if [ `echo $portns | grep [0-9] | wc -l` -gt 0 ]
	then
		for portn in $portns
		do
		if [ `netstat -an | grep -i LISTEN | egrep "\.$portn |\:$portn " | wc -l` -gt 0 ]
			then
				netstat -an | grep -i LISTEN | egrep "\.$portn |\:$portn " >> $APACHE_CREATE_FILE_RESULT 2>&1
			else
				echo '☞ 설정된 $portn 포트 사용 안함' >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
		done
	else
		echo '☞ LISTEN PORT 설정 없음' >> $APACHE_CREATE_FILE_RESULT 2>&1
		netstat -an | grep -i LISTEN | egrep "\.80 |\:80 " >> $APACHE_CREATE_FILE_RESULT 2>&1
		portn=`echo 80`
fi

#Port 사용 확인
if [ `echo $portn` -gt 1024 ]
then
	if [ `uname | grep -i 'sun' | wc -l` -eq 0 ]
	then
			
#Unix(Linux) Port 사용 확인
pids=`netstat -anp | grep LISTEN | egrep "\.$portn |\:$portn " | $aaww '{print $7}' | $aaww -F"/" '{print $1}'`
for pid in $pids
do
if [ `pstree -p root | grep "$pid$" | wc -l` -gt 0 ]
	then
		echo "☞ $pid 포트 root 계정으로 구동중(취약)" >> $APACHE_CREATE_FILE_RESULT 2>&1
		result1='취약'
fi
done
			else
#Solaris Port 사용 확인
port=$portn
for proc in `ptree -a | grep -v ptree | $aaww '{print $1};'`
do
result=`pfiles $proc 2> /dev/null| grep "port: $port"`
if [ ! -z "$result" ]
	then
		program=`ps -fo comm -p $proc | /usr/bin/tail -1`
		if [ `ptree root | grep $proc | wc -l` -gt 0 ]
			then
				echo "☞ $pid 포트 root 계정으로 구동중(취약)" >> $APACHE_CREATE_FILE_RESULT 2>&1
				result1='취약'
		fi
fi
done
	fi
fi

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
done
echo '[Apache /etc/passwd]' >> $APACHE_CREATE_FILE_RESULT 2>&1
_apausers=`$ppss  |grep httpd | grep -v grep |$aaww '{print  $1}' | sort -u`
for user in $_apausers
do
cat /etc/passwd |grep "^$user": >> $APACHE_CREATE_FILE_RESULT 2>&1
done

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '※ Apache의 프로세스가 root 계정 외의 WEB 서버 전용 계정으로 구동할 것을 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ $result1 = '취약' ]
	then
		echo '＠ 취약 - 데몬 관리' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 양호 - 데몬 관리' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi

echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.01 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1


echo "1.02 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 1.설정 - 1.02 관리서버 디렉터리 권한 설정"
echo "################## 1.설정 - 1.02 관리서버 디렉터리 권한 설정 ##################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'Server Root는 전용 Web Server 계정 소유의 750이하 퍼미션이 부여되어있는지 확인' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result2='양호'
for confile in $_confiles
do
echo "◈ $confile 파일 확인" >> $APACHE_CREATE_FILE_RESULT 2>&1
cat $confile |grep ServerRoot |grep -v '#' >> $APACHE_CREATE_FILE_RESULT 2>&1
seroot=`cat $confile |grep ServerRoot |grep -v '#'|$aaww -F'"' '{print $2}'`
ls -alLd $seroot | head -1 >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ \( `ls -alLd $seroot | head -1 | grep -v 'root' | grep -v $APSID |wc -l` -gt 0 \) -o \( `ls -alLd $seroot | head -1 | grep -v '.....-.---' |wc -l` -gt 0 \) ]
	then
	result2='취약'
	echo '☞ 소유자가 root 또는 전용 Web Server 계정이 아니거나 퍼미션 취약' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
done
echo '※ 관리서버 디렉터리에 일반 사용자가 접근할 수 없도록 전용 Web Server 계정 소유의 750 이하 권한 설정 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ \( $result2 = '양호' \) ]
	then
		echo '＠ 양호 - 관리서버 디렉터리 권한 설정' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 취약 - 관리서버 디렉터리 권한 설정' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.02 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1


echo "1.03 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 1.설정 - 1.03 설정파일 권한 설정"
echo "################## 1.설정 - 1.03 설정파일 권한 설정  #######################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '설정파일은 전용 Web Server 계정 소유의 600 또는 700이하의 퍼미션이 부여되어있는지 확인' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result3='양호'

for confo in $_confolds
do
echo "[ conf 디렉터리 : $confo ]" >> $APACHE_CREATE_FILE_RESULT 2>&1
confo=`echo $confo | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }'`
echo $confo >> $APACHE_CREATE_FILE_RESULT 2>&1
ls -alL $confo | egrep -v '^d|total' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ \( `ls -alL $confo | grep '^-' | grep -v 'root' | grep -v $APSID | wc -l` -gt 0 \) -o \( `ls -alL $confo | grep '^-' | grep -v '....------' | wc -l` -gt 0 \) ]
	then
		result3='취약'
		echo '☞ 소유자가 전용 Web Server 계정이 아니거나 퍼미션 취약' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
done

for confile in $_confiles
do
echo "[ $confile - Include 설정파일 확인 ]" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ `cat $confile |grep -i "Include " |grep -v '#' | wc -l` -gt 0 ]
then
cat $confile |grep -i "Include " |grep -v '#' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
confinc=`cat $confile | grep -i "Include " | grep -v '#' | $aaww '{print $2}' | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`
seroot=`cat $confile |grep ServerRoot |grep -v '#'|$aaww -F'"' '{print $2}'`
for conlist in $confinc
	do
		if [ `echo $conlist | grep "^/" | wc -l` -eq 0 ]
			then
				if [ -d $seroot/$conlist ]
					then
						conpath=$seroot/$conlist
				fi
			else
				conpath=$conlist
		fi
		if [ -d $conpath ]
			then
				echo $conpath >> $APACHE_CREATE_FILE_RESULT 2>&1
				ls -alL $conpath | egrep -v '^d|total' >> $APACHE_CREATE_FILE_RESULT 2>&1
				if [ \( `ls -alL $conpath | grep '^-' | grep -v 'root' | grep -v $APSID | wc -l` -gt 0 \) -o \( `ls -alL $conpath | grep '^-' | grep -v '.....-----' | wc -l` -gt 0 \) ]
					then
						result3='취약'
						echo '☞ 소유자가 전용 Web Server 계정이 아니거나 퍼미션 취약' >> $APACHE_CREATE_FILE_RESULT 2>&1
				fi
			else
				echo "$conpath 파일이 존재하지 않습니다." >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
		echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
	done
else
	echo "☞ $confile 파일 내에 Include 설정 없음" >> $APACHE_CREATE_FILE_RESULT 2>&1
	echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
done

echo '※ 웹 서버의 설정 파일 권한을 전용 Web Server 계정 소유의 600 또는 700 이하로 설정 및 설정 파일의 Backup은 삭제 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ \( $result3 = '양호' \) ]
	then
		echo '＠ 양호 - 설정파일 권한 설정' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 취약 - 설정파일 권한 설정' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.03 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1


echo "1.04 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 1.설정 - 1.04 디렉터리 검색 기능 제거"
echo "################## 1.설정 - 1.04 디렉터리 검색 기능 제거  ###################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '<Directory>노드에 부여된 Indexes옵션을 삭제하도록 권고함' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result4='양호'
for confile in $_confiles
do
echo "◈ $confile 파일 확인 " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "[ httpd-autoindex.conf 파일 include 여부 ]" >> $APACHE_CREATE_FILE_RESULT 2>&1
confinc=`cat $confile | grep -i "Include " | grep -v '#' | $aaww '{print $2}' | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`
seroot=`cat $confile |grep ServerRoot |grep -v '#'|$aaww -F'"' '{print $2}'`
incOX="X"
priority='X'
for conlist in $confinc
	do
		if [ `echo $conlist | grep "^/" | wc -l` -eq 0 ]
			then
				if [ -d $seroot/$conlist ]
					then
						conpath=$seroot/$conlist
				fi
			else
				conpath=$conlist
		fi
		if [ `cat $confile | grep -i "Include " | grep -v '#' | egrep -i "\*|httpd-autoindex.conf" | wc -l` -gt 0 ]
		then
		if [ `find $conpath -name "*.conf" -exec ls -alL {} \; | grep -i 'httpd-autoindex.conf'|wc -l` -eq 1 ]
			then
				index=`find $conpath -name "*.conf" -exec ls -alL {} \; | grep -i 'httpd-autoindex.conf' | $aaww '{print $NF}'`
				incline=`cat $confile |grep -n " "|grep -v '#'| grep -i 'httpd-autoindex.conf' |$aaww -F":" '{print $1}'`
				incOX="O"
				echo 'Include '$conlist >> $APACHE_CREATE_FILE_RESULT 2>&1
				ls -alL $index >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
		fi
done

if [ \( $incOX = 'X' \) ]
	then
		echo "☞ httpd-autoindex.conf 파일이 include 되어 있지 않음" >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1


#Start
#Include
if [ \( $incOX = 'O' \) ]
	then
		echo '[ httpd-autoindex.conf - index 설정 확인 ]' >> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ -f $index ]
			then
				cat $index |grep -v '#'|egrep -i '<Directory| Options|</Directory'|egrep -i '<Directory| Indexes|</Directory' >> $APACHE_CREATE_FILE_RESULT 2>&1
				if [ `cat $index |grep -v '#'|grep -i ' Options' |grep -i ' Indexes'| wc -l` -eq 0 ]
					then
						echo '☞ Indexes 옵션 설정이 없음(양호)' >> $APACHE_CREATE_FILE_RESULT 2>&1
						echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
					else
						result4='취약'
						echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
				fi
		fi
fi

#httpd.conf
echo "[ $confile - index 설정 확인 ]" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ -f $confile ]
	then
		cat $confile |grep -v '#'|egrep -i '<Directory| Options|</Directory'|egrep -i '<Directory| Indexes|</Directory' >> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ `cat $confile |grep -v '#'|grep -i ' Options'|egrep -i ' Indexes' | wc -l` -eq 0 ]
			then
				echo '☞ Indexes 옵션 설정이 없음(양호)' >> $APACHE_CREATE_FILE_RESULT 2>&1
				echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
			else
				result4='취약'
				echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
fi
#End
done

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '※ 웹 서버의 설정 파일에서 디록토리 검색 기능 제거를 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ \( $result4 = '양호' \) ]
	then
		echo '＠ 양호 - 디렉터리 검색 기능 제거' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 취약 - 디렉터리 검색 기능 제거' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.04 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1




echo "1.05 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 1.설정 - 1.05 로그 디렉터리/파일 권한 설정"
echo "################## 1.설정 - 1.05 로그 디렉터리/파일 권한 설정  ################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'Log의 경로 확인하여 해당 Log디렉터리의 퍼미션이 전용 Web Server 계정 소유의 750이하이고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '로그파일 퍼미션이 전용 Web Server 계정 소유의 640이하인지 확인' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result5='양호'
for confile in $_confiles
do
echo "◈ $confile 파일 확인" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "[ $confile 파일 파일 include 설정 여부 ]" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ `cat $confile | grep -v '#' | grep -i "Include " | egrep -i "\/\*|vhost|ssl" | wc -l` -gt 0 ]
	then
		cat $confile | grep -v '#' | grep -i "Include " | egrep -i "\/\*|vhost|ssl" >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo "☞ vhost 또는 ssl 관련 파일 Include 되어 있지 않음" >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1

seroot=`cat $confile |grep ServerRoot |grep -v '#'|$aaww -F'"' '{print $2}'`
echo $confile > conflist.log
echo '' > logdir.log
if [ `cat $confile | grep -v '#' | grep -i "Include " | egrep -i "\/\*" | wc -l` -gt 0 ]
	then
		incpath=`cat $confile | grep -v '#' | grep -i "Include " | egrep -i "\/\*" | $aaww '{print $2}' | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`
		if [ `echo $incpath | grep "^/" | wc -l` -eq 0 ]
			then
				if [ -d $seroot/$incpath ]
					then
						conpath=$seroot/$incpath
				fi
			else
				conpath=$incpath
		fi
		confs=`ls -al $conpath | egrep -i "vhost|ssl" | $aaww '{print $NF}'`
		for conf in $confs
		do
		if [ -f $conpath/$conf ]
			then
				echo $conpath/ >> conflist.log
		fi
		done
fi
if [ `cat $confile | grep -v '#' | grep -i "Include " | egrep -i "vhost|ssl" | wc -l` -gt 0 ]
	then
		incpaths=`cat $confile | grep -v '#' | grep -i "Include " | egrep -i "vhost|ssl" | $aaww '{print $2}' | sort -u`
		for incpath in $incpaths
		do
		if [ `echo $incpath | grep "^/" | wc -l` -eq 0 ]
			then
				conf=`echo $seroot/$incpath`
			else
				conf=`echo $incpath`
		fi
		if [ -f $conf ]
			then
				echo $conf >> conflist.log
			else
				echo "☞ Include 설정된 $conf 파일 없음" >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
		done
		echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi

conflists=`cat conflist.log | grep -i conf | sed 's/\/\//\//' | grep "/" | sort -u`
for file in $conflists
do
if [ -f $file ]
	then
		echo "[ $file 로그 설정 확인 ]"  >> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ `cat $file |grep -v '#'|egrep -i 'ErrorLog|CustomLog'|wc -l` -eq 0 ]
			then
				echo 'ErrorLog, CustomLog 설정이 없음' >> $APACHE_CREATE_FILE_RESULT 2>&1
			else
				cat $file |grep -v '#'|egrep -i 'ErrorLog|CustomLog'| grep -v "#"  >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi

		if [ `cat $file |egrep -i 'ErrorLog|CustomLog'| grep -v "#" | wc -l` -gt 0 ]
			then
				if [ `cat $file |egrep -i 'ErrorLog|CustomLog'| grep -v "#" | $aaww -F" " '{print $2}' | grep -i '^"'| wc -l` -gt 0 ]
					then
						logpaths=`cat $file |egrep -i 'ErrorLog|CustomLog'| grep -v "#" |$aaww -F'"' '{print $2}' | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep "/" | grep -i -v "rotatelogs" | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`
					else
						logpaths=`cat $file |egrep -i 'ErrorLog|CustomLog'| grep -v "#" |$aaww -F" " '{print $2}' | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep "/" | grep -i -v "rotatelogs" | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`
				fi
				for log in $logpaths
					do
					if [ `echo $log | grep "^/" | wc -l` -eq 0 ]
						then
							echo $seroot/$log >> logdir.log
						else
							echo $log >> logdir.log
					fi
				done
		fi
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
done

echo '| Log 퍼미션 확인 |'  >> $APACHE_CREATE_FILE_RESULT 2>&1
logdir=`cat logdir.log | sed 's/\/\//\//' | grep "/" | sort -u`
for logd in $logdir
do
if [ -d $logd ]
	then
		echo "LOG 디렉터리 : $logd" >> $APACHE_CREATE_FILE_RESULT 2>&1
		ls -aldL $logd >> $APACHE_CREATE_FILE_RESULT 2>&1
		ls -alL $logd | egrep -i "error|access|log" | head -15 >> $APACHE_CREATE_FILE_RESULT 2>&1
		echo "..."	>> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ \( `ls -dlL $logd | $aaww '{print $1 $2 $3 $4}' | grep -v 'root' | grep -v $APSID | wc -l` -gt 0 \) -o \( `ls -dlL $logd | grep -v 'd....-.---' | wc -l` -gt 0 \) -o \( `ls -alL $logd | grep -i "log" | $aaww '{print $1 $2 $3 $4}' | grep -v 'root' | grep -v $APSID | wc -l` -gt 0 \) -o \( `ls -alL $logd | grep -i "log" | grep -v '^-..-.-----' | wc -l` -gt 0 \) ]
			then
				result5='취약'
				echo '☞ 소유자가 root 또는 전용 Web Server 계정이 아니거나 퍼미션 취약' >> $APACHE_CREATE_FILE_RESULT 2>&1
			else
				echo '☞ 취약한 디렉터리/파일이 없습니다.(양호)' >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
fi
echo "" >> $APACHE_CREATE_FILE_RESULT 2>&1
done
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
done

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '※ 로그 디렉터리는 전용 Web Server 계정 소유의 750이하 권한으로 파일은 전용 Web Server 계정 소유의 640이하 권한으로 설정 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ \( $result5 = '양호' \) ]
then
	echo '＠ 양호 - 로그 디렉터리/파일 권한 설정' >> $APACHE_CREATE_FILE_RESULT 2>&1
else
	echo '＠ 취약 - 로그 디렉터리/파일 권한 설정' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi

rm -f conflist.log
rm -f logdir.log
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.05 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1






echo "1.06 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 1.설정 - 1.06 로그 포맷 설정"
echo "################## 1.설정 - 1.06 로그 포맷 설정 ##########################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'LogFormat이 Combined형태보다 상세하게 설정되어있으면 양호' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result6='취약'
for confile in $_confiles
do
echo "◈ $confile 파일 확인" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "[ $confile 파일 설정 ]" >> $APACHE_CREATE_FILE_RESULT 2>&1
cat $confile | egrep -v '#|RewriteCond' | egrep -i 'Include*|SSLEngine|LogFormat|CustomLog|TransferLog|<VirtualHost|</VirtualHost>|%' | egrep -i '\/\*|vhost|ssl|SSLEngine|LogFormat|CustomLog|TransferLog|<VirtualHost|</VirtualHost>|%' >> $APACHE_CREATE_FILE_RESULT 2>&1

seroot=`cat $confile |grep ServerRoot |grep -v '#'|$aaww -F'"' '{print $2}'`
echo '' > conflist.log
if [ `cat $confile | grep -v '#' | grep -i "Include " | egrep -i "\/\*" | wc -l` -gt 0 ]
	then
		incpath=`cat $confile | grep -v '#' | grep -i "Include " | egrep -i "\/\*" | $aaww '{print $2}' | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`
		if [ `echo $incpath | grep "^/" | wc -l` -eq 0 ]
			then
				if [ -d $seroot/$incpath ]
					then
						conpath=$seroot/$incpath
				fi
			else
				conpath=$incpath
		fi
		confs=`ls -alL $conpath | egrep -i "vhost|ssl" | $aaww '{print $NF}'`
		if [ `ls -alL $conpath | egrep -i "vhost|ssl" | wc -l` -gt 0 ]
			then
				for conf in confs
				do
				if [ -f $conpath/$conf ]
					then
						echo $conpath/$conf >> conflist.log
				fi
				done
			else
				echo "☞ $incpath 폴더 내에 httpd-vhosts, httpd-ssl 관련 파일 없음" >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
fi
if [ `cat $confile | grep -v '#' | grep -i "Include " | egrep -i "vhost|ssl" | wc -l` -gt 0 ]
	then
		incpaths=`cat $confile | grep -v '#' | grep -i "Include " | egrep -i "vhost|ssl" | $aaww '{print $2}' | sort -u`
		for incpath in $incpaths
		do
		if [ `echo $incpath | grep "^/" | wc -l` -eq 0 ]
			then
				conf=`echo $seroot/$incpath`
			else
				conf=`echo $incpath`
		fi
		if [ -f $conf ]
			then
				echo $conf >> conflist.log
			else
				echo "☞ Include 설정된 $conf 파일 없음" >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
		done
	else
		echo '☞ httpd-vhosts, httpd-ssl 관련 Include 설정 없음' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
conflists=`cat conflist.log | grep -i conf | sed 's/\/\//\//' | grep "/" | sort -u`
for file in $conflists
do
if [ -f $file ]
	then
		echo "[ $file 로그 포맷 설정 확인 ]"  >> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ `cat $file |egrep -v '#|RewriteCond'|egrep -i 'SSLEngine|LogFormat|CustomLog|TransferLog|<VirtualHost|</VirtualHost>'|wc -l` -eq 0 ]
			then
				echo 'LogFormat, CustomLog 설정이 없음' >> $APACHE_CREATE_FILE_RESULT 2>&1
			else
				cat $file |egrep -v '#|ErrorLog|RewriteCond' | egrep -i 'SSLEngine|LogFormat|CustomLog|TransferLog|<VirtualHost|</VirtualHost>|%' >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
		echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '☞ Include 설정된 파일 없음' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
done
done

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '※ 아래 로그 포맷 설정 예시를 참고하여 설정할 것을 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '   CustomLog의 combined는 마지막에 선언된 combined의 LogFormat에 정의된 로그 형식을 사용' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '   combined를 사용하지 않고 별도의 로그 형식을 정의하여 사용 가능' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '==================================================================================' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '[ 일반적인 로그 포맷 예시 ]
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
CustomLog "logs/access_log" combined
[ SSL 로그 사용시 포맷 예시 ]
CustomLog "logs/ssl_request_log" "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b \"%{Referer}i\" \"%{User-Agent}i\""' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '==================================================================================' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

#※ 수동 진단
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '@ 수동 - 로그 포맷 설정' >> $APACHE_CREATE_FILE_RESULT 2>&1

rm -f conflist.log
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.06 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1




echo "1.07 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 1.설정 - 1.07 로그 저장 주기"
echo "################## 1.설정 - 1.07 로그 저장 주기  #########################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '정통망법 및 개인정보보호법, 사규에 정해진 로그 저장주기 설정 적용' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '로그 저장 기간, 정기적인 확인/감독, 별도 저장장치에 백업 등 상세 내용은 보안가이드라인 문서 참고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '☞ 인터뷰 필요' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '＠ N/A - 로그 저장 주기' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.07 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1


echo "1.08 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 1.설정 - 1.08 헤더 정보 노출 방지"
echo "################## 1.설정 - 1.08 헤더 정보 노출 방지 #######################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'ServerTokens값이 Prod로 설정되어 있는지 확인' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'ServerSignature이 Off로 설정되어 있는지 확인' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result8='양호'
for confile in $_confiles
do
echo "◈ $confile 파일 확인" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '[httpd-default.conf 파일 include 여부]' >> $APACHE_CREATE_FILE_RESULT 2>&1
confinc=`cat $confile | grep -i "Include " | grep -v '#' | $aaww '{print $2}' | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`
seroot=`cat $confile |grep ServerRoot |grep -v '#'|$aaww -F'"' '{print $2}'`
incOX="X"
priority='X'
for conlist in $confinc
	do
		if [ `echo $conlist | grep "^/" | wc -l` -eq 0 ]
			then
				if [ -d $seroot/$conlist ]
					then
						conpath=$seroot/$conlist
				fi
			else
				conpath=$conlist
		fi
		if [ `cat $confile | grep -i "Include " | grep -v '#' | egrep -i "\*|httpd-default.conf" | wc -l` -gt 0 ]
		then
		if [ `find $conpath -name "*.conf" -exec ls -alL {} \; | grep -i 'httpd-default.conf'|wc -l` -eq 1 ]
			then
				header=`find $conpath -name "*.conf" -exec ls -alL {} \; | grep -i 'httpd-default.conf' | $aaww '{print $NF}'`
				incline=`cat $confile |grep -n " "|grep -v '#'| grep -i 'httpd-default.conf' |$aaww -F":" '{print $1}'`
				incOX="O"
				echo 'Include '$conlist >> $APACHE_CREATE_FILE_RESULT 2>&1
				ls -alL $header >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
		fi
done
if [ \( $incOX = 'X' \) ]
	then
		echo "☞ httpd-default.conf 파일이 include 되어 있지 않음" >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

#우선순위 판별
if [ \( $incOX = 'O' \) ]
	then
		if [ `cat $confile |grep -v '#'|egrep -i 'ServerTokens|ServerSignature'| wc -l` -gt 0 ]
			then
				cfgline=`cat $confile |grep -n " "|grep -v '#'|egrep -i 'ServerTokens|ServerSignature'|tail -1 |$aaww -F":" '{print $1}'`
				if [ $incline -gt $cfgline ]
					then
						priority='O'
				fi
			else
				priority='O'
		fi
fi

#Start
if [ \( $priority = 'O' \) ]
then
#Include
		echo '[httpd-default.conf 파일 설정 확인]' >> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ -f $header ]
			then
				if [ `cat $header |egrep -i 'ServerTokens|ServerSignature'|grep -v '#'|wc -l` -eq 0 ]
					then
						echo 'ServerTokens, ServerSignature 설정이 없음(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
						echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
					else
						cat $header |egrep -i 'ServerTokens|ServerSignature'|grep -v '#' >> $APACHE_CREATE_FILE_RESULT 2>&1
						echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
				fi
			else
				echo 'httpd-default.conf 파일이 존재하지 않음(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
				echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi

		if [ \( $incOX = 'O' \) ]
			then
				if [ -f $header ]
					then
						if [ `cat $header |grep -v '#' | grep -i 'ServerTokens'| grep -i "prod" | wc -l` -eq 0 ]
							then
								result8='취약'
						fi
						if [ `cat $header |grep -v '#' | grep -i 'ServerSignature'| grep -i "off" | wc -l` -eq 0 ]
							then
								result8='취약'
						fi
				fi
		fi

else
#httpd.conf
echo "[$confile 파일 설정 확인]" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ -f $confile ]
	then
		if [ `cat $confile |egrep -i 'ServerTokens|ServerSignature'|grep -v '#'|wc -l` -eq 0 ]
			then
				echo 'ServerTokens, ServerSignature 설정이 없음' >> $APACHE_CREATE_FILE_RESULT 2>&1
				echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
			else
				cat $confile |egrep -i 'ServerTokens|ServerSignature'|grep -v '#' >> $APACHE_CREATE_FILE_RESULT 2>&1
				echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
fi

if [ -f $confile ]
	then
		if [ `cat $confile |grep -v '#' | grep -i 'ServerTokens'| grep -i "prod" | wc -l` -eq 0 ]
			then
				result8='취약'
		fi
		if [ `cat $confile |grep -v '#' | grep -i 'ServerSignature'| grep -i "off" | wc -l` -eq 0 ]
			then
				result8='취약'
		fi
fi
#End
fi
done

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '※ 웹 서버의 설정 파일에서 ServerTokens값은 Prod로 ServerSignature는 Off로 설정을 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ \( $result8 = '양호' \) ]
	then
		echo '＠ 양호 - 헤더 정보 노출 방지' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 취약 - 헤더 정보 노출 방지' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.08 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1


echo "1.09 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 1.설정 - 1.09 FollowSymLinks 옵션 비활성화"
echo "################## 1.설정 - 1.09 FollowSymLinks 옵션 비활성화 ############################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '<Directory>노드에 FollowSymLinks옵션이 부여되어있으면 취약' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result9='양호'
for confile in $_confiles
do
echo "◈ $confile 파일 확인" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '[httpd-autoindex.conf 파일 include 여부]' >> $APACHE_CREATE_FILE_RESULT 2>&1
confinc=`cat $confile | grep -i "Include " | grep -v '#' | $aaww '{print $2}' | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`
seroot=`cat $confile |grep ServerRoot |grep -v '#'|$aaww -F'"' '{print $2}'`
incOX="X"
priority='X'
for conlist in $confinc
	do
		if [ `echo $conlist | grep "^/" | wc -l` -eq 0 ]
			then
				if [ -d $seroot/$conlist ]
					then
						conpath=$seroot/$conlist
				fi
			else
				conpath=$conlist
		fi
		if [ `cat $confile | grep -i "Include " | grep -v '#' | egrep -i "\*|httpd-autoLinks.conf" | wc -l` -gt 0 ]
		then
		if [ `find $conpath -name "*.conf" -exec ls -alL {} \; | grep -i 'httpd-autoLinks.conf'|wc -l` -eq 1 ]
			then
				Links=`find $conpath -name "*.conf" -exec ls -alL {} \; | grep -i 'httpd-autoLinks.conf' | $aaww '{print $NF}'`
				incline=`cat $confile |grep -n " "|grep -v '#'| grep -i 'httpd-autoLinks.conf' |$aaww -F":" '{print $1}'`
				incOX="O"
				echo 'Include '$conlist >> $APACHE_CREATE_FILE_RESULT 2>&1
				ls -alL $Links >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
		fi
done
if [ \( $incOX = 'X' \) ]
	then
		echo "☞ httpd-autoLinks.conf 파일이 include 되어 있지 않음" >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1


#Start
#Include
if [ \( $incOX = 'O' \) ]
	then
		echo '[httpd-autoLinks.conf - FollowSymLinks 설정 확인]' >> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ -f $Links ]
			then
				cat $Links |grep -v '#'|egrep -i '<Directory| Options|</Directory'|egrep -i '<Directory| FollowSymLinks|</Directory' >> $APACHE_CREATE_FILE_RESULT 2>&1
				if [ `cat $Links |grep -v '#'|grep -i ' Options'|grep -i ' FollowSymLinks'|wc -l` -eq 0 ]
					then
						echo '☞ FollowSymLinks 옵션 설정이 없음(양호)' >> $APACHE_CREATE_FILE_RESULT 2>&1
						echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
					else
						echo '☞ FollowSymLinks 옵션 삭제 권고(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
						echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
						result9='취약'
				fi
			else
				echo 'httpd-autoLinks.conf 파일이 존재하지 않음' >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
fi

#httpd.conf
echo "[$confile 설정 확인]" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ -f $confile ]
	then
		cat $confile |grep -v '#'|egrep -i '<Directory| Options|</Directory'|egrep -i '<Directory| FollowSymLinks|</Directory' >> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ `cat $confile |grep -v '#'|grep -i ' Options'|grep -i ' FollowSymLinks'|wc -l` -eq 0 ]
			then
				echo '☞ FollowSymLinks 옵션 설정이 없음(양호)' >> $APACHE_CREATE_FILE_RESULT 2>&1
				echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
			else
				echo '☞ FollowSymLinks 옵션 삭제 권고(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
				echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
				result9='취약'
		fi
fi
#End
done

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '※ 웹 서버의 설정 파일에서 FollowSymLinks 옵션을 제거를 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ \( $result9 = '양호' \) ]
	then
		echo '＠ 양호 - FollowSymLinks 옵션 비활성화' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 취약 - FollowSymLinks 옵션 비활성화' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.09 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1


echo "1.10 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 1.설정 - 1.10 MultiViews 옵션 비활성화"
echo "################## 1.설정 - 1.10 MultiViews 옵션 비활성화 ################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '<Directory>노드에 MultiViews옵션이 부여되어있으면 취약' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result10='양호'
for confile in $_confiles
do
echo "◈ $confile 파일 확인" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '[httpd-autoindex.conf 파일 include 여부]' >> $APACHE_CREATE_FILE_RESULT 2>&1
confinc=`cat $confile | grep -i "Include " | grep -v '#' | $aaww '{print $2}' | $aaww -F"/" 'BEGIN{ OFS="/"}{ $NF=""; print }' | sort -u`
seroot=`cat $confile |grep ServerRoot |grep -v '#'|$aaww -F'"' '{print $2}'`
incOX="X"
priority='X'
for conlist in $confinc
	do
		if [ `echo $conlist | grep "^/" | wc -l` -eq 0 ]
			then
				if [ -d $seroot/$conlist ]
					then
						conpath=$seroot/$conlist
				fi
			else
				conpath=$conlist
		fi
		if [ `cat $confile | grep -i "Include " | grep -v '#' | egrep -i "\*|httpd-autoViews.conf" | wc -l` -gt 0 ]
		then
		if [ `find $conpath -name "*.conf" -exec ls -alL {} \; | grep -i 'httpd-autoViews.conf'|wc -l` -eq 1 ]
			then
				Views=`find $conpath -name "*.conf" -exec ls -alL {} \; | grep -i 'httpd-autoViews.conf' | $aaww '{print $NF}'`
				incline=`cat $confile |grep -n " "|grep -v '#'| grep -i 'httpd-autoViews.conf' |$aaww -F":" '{print $1}'`
				incOX="O"
				echo 'Include '$conlist >> $APACHE_CREATE_FILE_RESULT 2>&1
				ls -alL $Views >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
		fi
done
if [ \( $incOX = 'X' \) ]
	then
		echo "☞ httpd-autoViews.conf 파일이 include 되어 있지 않음" >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1


#Start
#Include
if [ \( $incOX = 'O' \) ]
	then
		echo '[httpd-autoViews.conf - MultiViews 설정 확인]' >> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ -f $Views ]
			then
				cat $Views |grep -v '#'|egrep -i '<Directory| Options|</Directory'|egrep -i '<Directory| MultiViews|</Directory' >> $APACHE_CREATE_FILE_RESULT 2>&1
				if [ `cat $Views |grep -v '#'|grep -i ' Options'|grep -i ' MultiViews'|wc -l` -eq 0 ]
					then
					echo '☞ MultiViews 옵션 설정이 없음(양호)' >> $APACHE_CREATE_FILE_RESULT 2>&1
					echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
				else
					echo '☞ MultiViews 옵션 삭제 권고(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
					echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
					result10='취약'
				fi
			else
				echo 'httpd-autoViews.conf 파일이 존재하지 않음' >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
fi

#httpd.conf
echo "[$confile 설정 확인]" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ -f $confile ]
	then
		cat $confile |grep -v '#'|egrep -i '<Directory| Options|</Directory'|egrep -i '<Directory| MultiViews|</Directory' >> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ `cat $confile |grep -v '#'|grep -i ' Options'|grep -i ' MultiViews'|wc -l` -eq 0 ]
			then
			echo '☞ MultiViews 옵션 설정이 없음(양호)' >> $APACHE_CREATE_FILE_RESULT 2>&1
			echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
		else
			echo '☞ MultiViews 옵션 삭제 권고(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
			echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
			result10='취약'
		fi
fi
#End
done

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '※ 웹 서버의 설정 파일에서 MultiViews 옵션 제거를 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ \( $result10 = '양호' \) ]
	then
		echo '＠ 양호 - MultiViews 옵션 비활성화' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 취약 - MultiViews 옵션 비활성화' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.10 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1



echo "1.11 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 1.설정 - 1.11 HTTP Method 제한"
echo "################## 1.설정 - 1.11 HTTP Method 제한 #####################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '불필요한 Method(PUT, DELETE, OPTIONS, TRACE) 제한 설정이 되어 있는지 확인' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'Apache 1.3.33 / 2.0.54 버전 사용시 mod_rewrite 를 사용하여 TRACE Method 제한' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result11='양호'
vercheck='no'
methodcheck='no'
#버전체크
echo '[ Apache 버전 확인 ] ' >> $APACHE_CREATE_FILE_RESULT 2>&1
for binpath in $_httpdbins
do
if [ `$binpath/apachectl -V 2>&1 | grep -i "SERVER_CONFIG_FILE" | wc -l` -gt 0 ]
	then
		apahttpd="$binpath/apachectl"
	else
		apahttpd="$binpath/httpd"
fi
if [ `$apahttpd -V 2>&1 | grep -i 'Server version' | wc -l` -gt 0 ]
	then
		$apahttpd -V 2>&1 | grep -i 'Server version' >> $APACHE_CREATE_FILE_RESULT 2>&1
		if [ `$apahttpd -V 2>&1 | grep -i 'Server version' | egrep -i "1\.3\.33|2\.0\.54" | wc -l` -gt 0 ]
			then
				vercheck='yes'
		fi
		if [ `$apahttpd -V 2>&1 | grep -i 'Server version' | egrep -i "\/1\.3\.|\/2\.0\.|\/2\.2\." | wc -l` -gt 0 ]
			then
				methodcheck='yes'
		fi
fi
done
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1

for confile in $_confiles
do
echo "◈ $confile 파일 확인" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '[ Trace Method 제한 ]' >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ `cat $confile | grep -i TraceEnable | grep -v "\#" |wc -l` -eq 0 ]
then
	echo '☞ TraceEnable On/Off 설정이 존재하지 않음(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
else
	cat $confile | grep -i TraceEnable >> $APACHE_CREATE_FILE_RESULT 2>&1
fi

if [ `cat $confile | grep -i TraceEnable | grep -i off | grep -v '#' |wc -l` -eq 0 ]
then
	result11='취약'
fi

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ $vercheck = 'yes' ]
then
echo '[ Apache 1.3.33 or 2.0.54 버전 사용 : mod_rewrite 모듈 및 TRACE Method 제한 확인 ]' >> $APACHE_CREATE_FILE_RESULT 2>&1
cat $confile | grep -i LoadModule | grep -i mod_rewrite >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ `cat $confile | grep -i LoadModule | grep -i "rewrite_module" | grep -i "mod_rewrite\.so" | grep -v "\#" | wc -l` -eq 0 ]
	then
		echo '☞ mod_rewrite 모듈을 Load하고 있지 않음(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
		result11='취약'
fi
echo '[ TRACE Method 제한 설정 확인 ]' >> $APACHE_CREATE_FILE_RESULT 2>&1
cat $confile | grep -i "rewriteengine" | grep -v "\#" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ `cat $confile | grep -v '#' | grep -i RewriteEngine | grep -i On | wc -l` -eq 0 ]
	then
		echo '☞ RewriteEngine On 설정 없음(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
		result11='취약'
fi
cat $confile | egrep -i "rewritecond|rewriterule" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ `cat $confile | egrep -i "rewritecond|rewriterule" | grep -v '#' | egrep -i "\ ^TRACE|\[F\]|\[R\=405\,L\]" | wc -l` -lt 2 ]
	then
		echo '☞ TRACE Method 제한 설정 없음(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
		result11='취약'
fi
fi

echo '[ Rewrite Module 로드 여부 확인 ]' >> $APACHE_CREATE_FILE_RESULT 2>&1
cat $confile | grep -i LoadModule | grep -i mod_rewrite | grep -v "\#" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ `cat $confile | grep -i LoadModule | grep -i "rewrite_module" | grep -i "mod_rewrite\.so" | grep -v "\#" | wc -l` -eq 0 ]
	then
		echo '☞ mod_rewrite 모듈을 Load하고 있지 않음(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
		result11='취약'
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '[ PUT, DELETE, OPTIONS Method 제한 설정 확인 ]' >> $APACHE_CREATE_FILE_RESULT 2>&1
cat $confile | grep -i "rewriteengine" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ `cat $confile | grep -v '#' | grep -i RewriteEngine | grep -i On | wc -l` -eq 0 ]
	then
		echo '☞ RewriteEngine On 설정 없음(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
		result11='취약'
fi
cat $confile | egrep -i "RewriteCond|RewriteRule" | grep -v "\#" >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ `cat $confile | grep -v '#' | grep -i "RewriteRule" | egrep "\[F\]|\[R\=405\,L\]" | wc -l` -eq 0 ]
	then
		echo '☞ Method 제한 설정 없음(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
		result11='취약'
	else
		if [ `cat $confile | grep -v '#' | grep -i "RewriteCond" | grep -i "REQUEST_METHOD" | grep -i " \!\^" | egrep "PUT|DELETE|OPTIONS|TRACE" | wc -l` -gt 0 ]
			then
				echo '☞ Method 제한 설정 미흡(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
				result11='취약'
		fi
		if [ `cat $confile | grep -v '#' | grep -i "RewriteCond" | grep -i "REQUEST_METHOD" | grep -i " \^" | wc -l` -gt 0 ]
			then
				if [ $methodcheck = 'yes' ]
					then
						if [ `cat $confile | grep -v '#' | grep -i "RewriteCond" | grep -i "REQUEST_METHOD" | grep -i " \^" | grep -v "\^TRACK" | grep "PUT" | grep "DELETE" | grep "OPTIONS" | wc -l` -eq 0 ]
							then
								echo '☞ Method 제한 설정 미흡(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
								result11='취약'
						fi
					else
						if [ `cat $confile | grep -v '#' | grep -i "RewriteCond" | grep -i "REQUEST_METHOD" | grep -i " \^" | grep -v "\^TRACK" | grep "OPTIONS" | wc -l` -eq 0 ]
							then
								echo '☞ Method 제한 설정 미흡(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
								result11='취약'
						fi
				fi
		fi
fi

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
done


echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '※ HTTP Method 중 GET, POST, HEAD 만 허용하도록 PUT, DELETE, OPTIONS, TRACE 제한 설정을 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ $result11 = '취약' ]
	then
		echo '＠ 취약 - HTTP Method 제한' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 양호 - HTTP Method 제한' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "1.11 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1






echo "2.01 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 2.솔루션 취약점 - 2.01 불필요한 디렉터리 삭제"
echo "################## 2.솔루션 취약점 - 2.01 불필요한 디렉터리 삭제 ###############################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '불필요한 Manual 디렉터리 및 CGI스크립트를 삭제하도록 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result21_1='양호'
result21_2='양호'
_apahs=`cat $_confiles | grep -v "#" | grep ServerRoot | $aaww -F'"' '{print $2}' | sort -u`
man_dirs=`cat $_confiles | grep -v "#" | grep -i '^Alias' | grep -i manual | $aaww -F'"' '{print $2}'`
cgi_dirs=`cat $_confiles | grep -v "#" | grep -i '^ScriptAlias' | grep -i "cgi-bin" | $aaww -F'"' '{print $2}'`

echo '| Manual 디렉터리 확인 |' >> $APACHE_CREATE_FILE_RESULT 2>&1
for apache in $_apahs
do
if [ -d $apache/manual ]
	then
		ls -aldL $apache/manual >> $APACHE_CREATE_FILE_RESULT 2>&1
		result21_1='취약'
		echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
done
if [ `echo $man_dirs | grep -i manual | wc -l` -gt 0 ]
	then
		for man in $man_dirs
		do
		if [ -d $man ]
			then
				ls -aldL $man >> $APACHE_CREATE_FILE_RESULT 2>&1
				result21_1='취약'
		fi
		done
fi
if [ $result21_1 = '양호' ]
	then
		echo 'manual 디렉터리가 존재하지 않음' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1

echo '| CGI 스크립트 확인 | ' >> $APACHE_CREATE_FILE_RESULT 2>&1
for apache in $_apahs
do
if [ -d $apache/cgi-bin ]
	then
		if [ \( `ls -alL $apache/cgi-bin/ | grep -i printenv|wc -l` -gt 0 \) -o \( `ls -alL $apache/cgi-bin/ | grep -i test-cgi|wc -l` -gt 0 \) ]
			then
				echo "$apache/cgi-bin/" >> $APACHE_CREATE_FILE_RESULT 2>&1
				ls -alL $apache/cgi-bin/ | egrep -i "printenv|test-cgi" >> $APACHE_CREATE_FILE_RESULT 2>&1
				result21_2='취약'
				echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
		fi
fi
done
if [ `echo $cgi_dirs | grep -i "cgi-bin" | wc -l` -gt 0 ]
	then
		for cgi in $cgi_dirs
		do
		if [ -d $cgi ]
			then
				if [ \( `ls -alL $cgi | grep -i printenv|wc -l` -gt 0 \) -o \( `ls -alL $cgi | grep -i test-cgi|wc -l` -gt 0 \) ]
					then
						echo $cgi >> $APACHE_CREATE_FILE_RESULT 2>&1
						ls -alL $cgi | egrep -i "printenv|test-cgi" >> $APACHE_CREATE_FILE_RESULT 2>&1
						result21_2='취약'
				fi
		fi
		done
fi
if [ $result21_2 = '양호' ]
	then
		echo 'cgi-bin 디렉터리가 존재하지 않음' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1

echo '※ Manual 디렉터리 및 기본 CGI 스크립트 삭제를 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ \( $result21_1 = '양호' \) -a \( $result21_2 = '양호' \) ]
	then
		echo '＠ 양호 - 불필요한 디렉터리 삭제' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 취약 - 불필요한 디렉터리 삭제' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "2.01 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1





echo "2.02 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 2.솔루션 취약점 - 2.02 WebDAV 설정 제한"
echo "################## 2.솔루션 취약점 - 2.02 WebDAV 설정 제한 #################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'WebDAV 제한 설정이 되어 있으면 양호' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
result22='양호'
for confile in $_confiles
do
echo "◈ $confile 파일 확인" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '| Dav 모듈 사용 제한 : 모듈 Load 확인 |' >> $APACHE_CREATE_FILE_RESULT 2>&1
if [ `cat $confile | grep -i LoadModule | grep -i dav | grep -v "\#" | wc -l` -eq 0 ]
then
	echo 'Dav 모듈을 Load하고 있지 않음(양호)' >> $APACHE_CREATE_FILE_RESULT 2>&1
else
	cat $confile | grep -i LoadModule | grep -i Dav  >> $APACHE_CREATE_FILE_RESULT 2>&1
	echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
	echo '| Dav 모듈 사용 제한 : Dav on 설정 확인 |' >> $APACHE_CREATE_FILE_RESULT 2>&1
	if [ `cat $confile | grep -i "Dav " | grep -v '#' | egrep -i "On|Off" | wc -l` -gt 0 ]
		then
			cat $confile | grep -i "Dav " | grep -v '#' | egrep "on|off" >> $APACHE_CREATE_FILE_RESULT 2>&1
		else
			echo 'Dav On/Off 설정이 존재하지 않음(양호)' >> $APACHE_CREATE_FILE_RESULT 2>&1
	fi
fi

if [ `cat $confile | grep -i LoadModule | grep -i dav | grep -v "\#" | wc -l` -gt 0 ]
	then
		if [ `cat $confile | grep -i dav | grep -i on | grep -v '#' |wc -l` -gt 0 ]
			then
				echo 'Dav On 삭제 또는 Dav Off 설정 권고(취약)' >> $APACHE_CREATE_FILE_RESULT 2>&1
				result22='취약'
		fi
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
done

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '※ Dav 모듈을 Load할 경우 Dav Off 설정을 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ $result22 = '취약' ]
	then
		echo '＠ 취약 - WebDAV 설정 제한' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 양호 - WebDAV 설정 제한' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "2.02 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1





echo "3.01 START" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "################## 3.설정 - 3.01 보안 패치 적용"
echo "################## 3.설정 - 3.01 보안 패치 적용 ####################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WSTART" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '해당 버전보다 상위버전이면 양호' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '| Apache 버전 확인 | ' >> $APACHE_CREATE_FILE_RESULT 2>&1
result31='양호'
for binpath in $_httpdbins
do
if [ `$binpath/apachectl -V 2>&1 | grep -i "SERVER_CONFIG_FILE" | wc -l` -gt 0 ]
	then
		apahttpd="$binpath/apachectl"
	else
		apahttpd="$binpath/httpd"
fi
if [ `$apahttpd -V 2>&1 | grep -i 'Server version' | wc -l` -eq 0 ]
	then
		echo '버전 정보를 찾을 수 없음(수동 확인 필요)' >> $APACHE_CREATE_FILE_RESULT 2>&1
		result31='취약'
	else
		echo $apahttpd >> $APACHE_CREATE_FILE_RESULT 2>&1
		$apahttpd -V 2>&1 | grep -i 'Server version' >> $APACHE_CREATE_FILE_RESULT 2>&1
		apaver=`$apahttpd -V 2>&1 | grep -i 'Server version' | $aaww '{print $3}' | $aaww -F"/" '{print $2}'`
		if [ `echo $apaver | egrep '1\.[0-3]\.' | wc -l` -gt 0 ]
			then
				echo 'Apache 1.3 버전은 서비스 종료이므로 취약합니다.' >> $APACHE_CREATE_FILE_RESULT 2>&1
				result31='취약'
		fi
		if [ `echo $apaver | egrep '2\.0\.' | wc -l` -gt 0 ]
			then
				if [ `echo $apaver | $aaww -F"." '{print $3}'` -lt 65 ]
					then
						echo '취약한 버전을 사용하고 있습니다.' >> $APACHE_CREATE_FILE_RESULT 2>&1
						result31='취약'
				fi
		fi
		if [ `echo $apaver | egrep '2\.2\.' | wc -l` -gt 0 ]
			then
				if [ `echo $apaver | $aaww -F"." '{print $3}'` -lt 20 ]
					then
						echo '취약한 버전을 사용하고 있습니다.' >> $APACHE_CREATE_FILE_RESULT 2>&1
						result31='취약'
				fi
		fi
		if [ `echo $apaver | egrep '2\.4\.' | wc -l` -gt 0 ]
			then
				if [ `echo $apaver | $aaww -F"." '{print $3}'` -lt 13 ]
					then
						echo '취약한 버전을 사용하고 있습니다.' >> $APACHE_CREATE_FILE_RESULT 2>&1
						result31='취약'
				fi
		fi
fi
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
done

echo '※ 아래 사이트 및 최신 버전을 참고하여 서비스 영향도 평가 후 패치를 권고' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1

if [ $result31 = '취약' ]
	then
		echo '＠ 취약 - 보안 패치 적용' >> $APACHE_CREATE_FILE_RESULT 2>&1
	else
		echo '＠ 양호 - 보안 패치 적용' >> $APACHE_CREATE_FILE_RESULT 2>&1
fi

echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '※ Apache Securty Update:' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'http://httpd.apache.org/security_report.html' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' ' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo '[최신 버전]' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'Apache 2.4.13' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'Apache 2.2.20' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'Apache 2.0.65' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo 'Apache 1.3.X - 사용금지' >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "WEND" >> $APACHE_CREATE_FILE_RESULT	2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "==============================================================================================" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "3.01 END" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1
echo " " >> $APACHE_CREATE_FILE_RESULT 2>&1

echo "END_RESULT" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo ' '

#end script
echo "##############################################################################################"
fff=`cat $APACHE_CREATE_FILE_RESULT | grep '＠ 취약' | wc -l`
ggg=`echo "(14-$fff)/14*100" | bc -l`
hhh=`echo $ggg | $aaww -F"." '{print $1}'`
echo "※ 발견된 취약 항목 $fff 개,  보안 준수율 $hhh 점"
echo "##############################################################################################"

echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "※ WEB(Apache) 발견된 취약 항목 $fff 개,  보안 준수율 $hhh 점" >> $APACHE_CREATE_FILE_RESULT 2>&1
echo "##############################################################################################" >> $APACHE_CREATE_FILE_RESULT 2>&1

cat $APACHE_CREATE_FILE_RESULT >> $CREATE_FILE_RESULT 2>&1
rm -f apache.log

else
	echo " "
	break
fi


############################################### TOMCAT #####################################################

echo ""
echo ""

TOMCAT_CREATE_FILE_RESULT="tomcat.log"

alias ls=ls
alias grep=/bin/grep

if [ `uname | grep -i 'hp-ux' | wc -l` -gt 0 ]
	then
		ppss='ps -efx'
		aaww='awk'
else
	if [ `uname | grep -i 'sun' | wc -l` -eq 0 ]
		then
			ppss='ps auxwww'
			aaww='awk'
	else
		ppss='/usr/ucb/ps auxww'
		aaww='nawk'
	fi
fi


if [ `$ppss |grep -i tomcat | grep -i java |grep -v grep | wc -l` -ge 1 ]
	then
		#echo "※ TOMCAT 구동중으로 진단을 수행하겠습니다."
		echo "########################### TOMCAT 진단 스크립트를 실행하겠습니다 ###########################"
		echo ""
		echo ""


echo '[Tomcat 서비스 확인]'
echo ''
$ppss |grep -i tomcat | grep -i java |grep -v grep
echo ''

#bcount=`$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep / |wc -l`
bcount=`$ppss |grep -i tomcat | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep "Dcatalina.base=" | $aaww -F"=" '{print $2}' | wc -l`

#verconf=`$ppss |grep -i tomcat |$aaww -F'bootstrap.jar:' '{print $2}' |$aaww '{print $1}' |$aaww -F'bin/' '{print $1}'| grep / | head -1`

echo '[현재 구동중인 Tomcat 프로세스 ]'
echo "☞  $bcount 개 " 
echo ''

echo '[현재 구동중인 Tomcat 설치 경로]'
#$ppss |grep -i tomcat | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep "base=" | $aaww -F"=" '{print $2}'
bbb=`$ppss |grep -i tomcat | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | $aaww -F"=" '{print $2}' | uniq`
for der in $bbb
	do
		echo ''
		if [ `ls -ld $der | grep 'lrwxrwxrwx' |wc -l` -gt 0 ]
			then
				echo $der
				echo "*위 basesdir는 링크 파일로 아래 절대 경로를 참조해 주세요."
				ls -dl $der
				datalin=`ls -dl $der`
		else
			echo $der
		fi
done
echo ''

#echo ''
#echo -n "※ 자동 진단 1번, 수동 진단 2번 (1 or 2) : "
#read abc
#echo ''

#if [ $abc -eq 2 ]
#        then
#        echo -n  '※ 현재 구동중인 Tomcat 프로세스 갯수 입력(10개 이하) : '
#        read cu
#        echo ' '
#        if [ $cu -ge 1 ]
#   then
#      num=1
#      while [ $num -le $cu ]
#      do 
#        echo "$num번 경로: "
#                read conf$num
#                echo " "
#                num=`expr $num + 1`
#      done
#fi
#echo " "

#echo [ 입력 디렉터리 확인 ]
#conftest=`echo $conf1 $conf2 $conf3 $conf4 $conf5 $conf6 $conf7 $conf8 $conf9 $conf10`
#echo ' ' >  conftest.log
#for folder in $conftest
#                do
#                        if [ -d $folder ]
#                                then
#                                        echo $folder
#                        else
#                                echo $folder '폴더가 없음'
#                                echo exit >> conftest.log
#                        fi
#done

#if [ `cat conftest.log | grep exit | wc -l` -gt 0 ]
#        then
#                echo " "
#                echo "☞  Tomcat 설치 디렉터리 확인후 재실행 해주세요!!"
#                echo " "
#                exit
#else
#        echo " "
#        echo "☞ 입력한 디렉터리가 모두 존재 합니다!!"
#        echo " "
#fi
#rm -f conftest.log
#
#else

echo ''

#Dcatalina.Base
bcount=`$ppss |grep -i tomcat | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | $aaww -F"=" '{print $2}' | uniq |wc -l`

#Dcatalina.Base 경로
if [ $bcount -gt 11 ]
        then
        echo 'Dcatalina.Base가 너무 많음 수동진단하시기 바랍니다.'
        bcount=11
else
		if [ $bcount -eq 10 ]
                then
                #$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep /
				conf1=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 1:|$aaww -F':' '{print $2}'`
                conf2=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 2:|$aaww -F':' '{print $2}'`
                conf3=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 3:|$aaww -F':' '{print $2}'`
                conf4=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 4:|$aaww -F':' '{print $2}'`
                conf5=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 5:|$aaww -F':' '{print $2}'`
                conf6=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 6:|$aaww -F':' '{print $2}'`
				conf7=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 7:|$aaww -F':' '{print $2}'`
				conf8=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 8:|$aaww -F':' '{print $2}'`
				conf9=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 9:|$aaww -F':' '{print $2}'`
				conf10=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 10:|$aaww -F':' '{print $2}'`
        fi
		if [ $bcount -eq 9 ]
                then
                #$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep /
				conf1=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 1:|$aaww -F':' '{print $2}'`
                conf2=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 2:|$aaww -F':' '{print $2}'`
                conf3=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 3:|$aaww -F':' '{print $2}'`
                conf4=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 4:|$aaww -F':' '{print $2}'`
                conf5=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 5:|$aaww -F':' '{print $2}'`
                conf6=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 6:|$aaww -F':' '{print $2}'`
				conf7=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 7:|$aaww -F':' '{print $2}'`
				conf8=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 8:|$aaww -F':' '{print $2}'`
				conf9=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 9:|$aaww -F':' '{print $2}'`
        fi
		if [ $bcount -eq 8 ]
                then
                #$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep /
				conf1=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 1:|$aaww -F':' '{print $2}'`
                conf2=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 2:|$aaww -F':' '{print $2}'`
                conf3=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 3:|$aaww -F':' '{print $2}'`
                conf4=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 4:|$aaww -F':' '{print $2}'`
                conf5=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 5:|$aaww -F':' '{print $2}'`
                conf6=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 6:|$aaww -F':' '{print $2}'`
				conf7=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 7:|$aaww -F':' '{print $2}'`
				conf8=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 8:|$aaww -F':' '{print $2}'`
        fi
		if [ $bcount -eq 7 ]
                then
                #$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep /
				conf1=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 1:|$aaww -F':' '{print $2}'`
                conf2=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 2:|$aaww -F':' '{print $2}'`
                conf3=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 3:|$aaww -F':' '{print $2}'`
                conf4=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 4:|$aaww -F':' '{print $2}'`
                conf5=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 5:|$aaww -F':' '{print $2}'`
                conf6=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 6:|$aaww -F':' '{print $2}'`
				conf7=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 7:|$aaww -F':' '{print $2}'`
        fi
        if [ $bcount -eq 6 ]
                then
                #$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep /
				conf1=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 1:|$aaww -F':' '{print $2}'`
                conf2=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 2:|$aaww -F':' '{print $2}'`
                conf3=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 3:|$aaww -F':' '{print $2}'`
                conf4=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 4:|$aaww -F':' '{print $2}'`
                conf5=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 5:|$aaww -F':' '{print $2}'`
                conf6=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 6:|$aaww -F':' '{print $2}'`
        fi
        if [ $bcount -eq 5 ]
                then
                #$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep /
                conf1=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 1:|$aaww -F':' '{print $2}'`
                conf2=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 2:|$aaww -F':' '{print $2}'`
                conf3=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 3:|$aaww -F':' '{print $2}'`
                conf4=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 4:|$aaww -F':' '{print $2}'`
                conf5=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 5:|$aaww -F':' '{print $2}'`
        fi
        if [ $bcount -eq 4 ]
                then
                #$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep / 
				conf1=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 1:|$aaww -F':' '{print $2}'`
                conf2=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 2:|$aaww -F':' '{print $2}'`
                conf3=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 3:|$aaww -F':' '{print $2}'`
                conf4=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 4:|$aaww -F':' '{print $2}'`
        fi
        if [ $bcount -eq 3 ]
                then
                #$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep /
                conf1=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 1:|$aaww -F':' '{print $2}'`
                conf2=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 2:|$aaww -F':' '{print $2}'`
                conf3=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 3:|$aaww -F':' '{print $2}'`
        fi
        if [ $bcount -eq 2 ]
                then
                #$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep / 
                conf1=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 1:|$aaww -F':' '{print $2}'`
                conf2=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 2:|$aaww -F':' '{print $2}'`
        fi
        if [ $bcount -eq 1 ]
                then
                #$ppss |grep -i tomcat |$aaww -F'base' '{print $2}'|$aaww '{print $1}'|$aaww -F'=' '{print $2}'|grep /
                conf1=`$ppss |grep -i tomcat |$aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | egrep -i "Dcatalina.base=|CATALINA_HOME=" | grep -v "|" | uniq | $aaww -F"=" '{print $2}'|grep / |grep -n '/'|grep 1:|$aaww -F':' '{print $2}'`
        #else
        #       echo 'Dcatalina.Base가 없음' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
        fi

confall=`echo $conf1 $conf2 $conf3 $conf4 $conf5 $conf6 $conf7 $conf8 $conf9 $conf10`
fi

#fi
echo " "

echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1 
echo "#################### Script Launching Time ##########################"
date
echo " "
echo '[ 구동중인 Tomcat 디렉터리 ]' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
confall=`echo $conf1 $conf2 $conf3 $conf4 $conf5 $conf6 $conf7 $conf8 $conf9 $conf10`
echo $confall | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo " " >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "********************************************************************************************************" >>  $TOMCAT_CREATE_FILE_RESULT 2>&1
for folder in $confall
	do
		if [ -d $folder ]
			then
				bind=`find $folder/ -name "version.sh" | tail -1`
				if [ `echo $bind | grep -i "/" | wc -l` -gt 0 ]
					then
						if [ `sh $bind 2>/dev/null | grep -i 'version' | grep -i 'tomcat' | grep -i [0-9].[0-9].[0-9] | wc -l` -gt 0 ]
							then
								vvv=`sh $bind 2>/dev/null | grep -i 'version' | grep -i 'tomcat'`
								echo "※ Tomcat Version : $vvv / Tomcat 경로 : $folder" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						else
							notes=`find $folder/ -name "*NOTES*" | tail -1`
							if [ -f $notes ]
								then
									if [ `cat $notes | grep -i "Tomcat Version" | wc -l` -gt 0 ]
										then
											vv=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}'`
											echo "※ Tomcat Version : $vv / Tomcat 경로 : $folder" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									else
										echo "※ Tomcat Version : 확인 불가! / Tomcat 경로 : $folder" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									fi
							else
								echo "※ Tomcat Version : 확인 불가! / Tomcat 경로 : $folder" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							fi
						fi
				else
					notes=`find $folder/ -name "*NOTES*" | tail -1`
					if [ `echo $notes | grep -i "/"| wc -l` -gt 0 ]
						then
							if [ -f $notes ]
								then
									if [ `cat $notes | grep -i "Tomcat Version" | wc -l` -gt 0 ]
										then
											vv=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}'`
											echo "※ Tomcat Version : $vv / Tomcat 경로 : $folder" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									else
										echo "※ Tomcat Version : 확인 불가! / Tomcat 경로 : $folder" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									fi
							else
								echo "※ Tomcat Version : 확인 불가! / Tomcat 경로 : $folder" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							fi
					else
						echo "※ Tomcat Version : 확인 불가! / Tomcat 경로 : $folder" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					fi
				fi
		else
			echo "※ Tomcat Version : 확인 불가! / Tomcat 경로 : 디렉터리 없음" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		fi
done
echo "********************************************************************************************************" >>  $TOMCAT_CREATE_FILE_RESULT 2>&1

echo "#############################   Kernel Information   #########################################" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
uname -a                            >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo " "                            >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "☞ /etc/*-release  파일 내용" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
cat /etc/*-release                  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo " "                            >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "* IP_Start "                  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "###############################################################################################" >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "****************************** Start *********************************" 

echo "★ 전체 진단 결과" >> $TOMCAT_CREATE_FILE_RESULT 2>&1

echo "1.01 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 1.01 =================================='
echo '======================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1.설정 - 1.01 데몬 관리'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '======================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'Tomcat의 데몬이 root 계정 외의 WAS 전용 계정으로 구동중이면 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
touch ptr.log
echo '1) Tomcat 데몬 구동 계정 확인' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
if [ `$ppss | grep -i 'tomcat' | grep -i 'java' | grep -v "16-Tomcat" | grep -v "grep" | wc -l` -gt 0 ]
	then
		$ppss | grep -i 'tomcat' | grep -i 'java' | grep -v "16-Tomcat" | grep -v "grep" >> $TOMCAT_CREATE_FILE_RESULT 2>&1

for folder in $confall
	do
		if [ -d $folder ]
			then
				port=`cat $folder/conf/server.xml 2>/dev/null| egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'|grep 'Connector'| $aaww -F"port=" '{print $2}' | $aaww -F"\"" '{print $2}'`
		fi
done
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '2) Tomcat 데몬 구동 Port 확인' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
for folder in $port
	do
		if [ `netstat -an | egrep -i "\.$folder |:$folder " | grep -i LISTEN | wc -l` -gt 0 ]
			then
				netstat -an | egrep -i "\.$folder |:$folder " | grep -i LISTEN >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				if [ `echo $folder` -lt 1024 ]
					then
						echo good >> ptr.log
				else
					echo bad >> ptr.log
				fi
		fi
done


# Tomcat ID
PSID=`$ppss | grep -i 'tomcat' | grep -i 'java' | grep -v "16-Tomcat" | grep -v "grep"| $aaww -F" " '{print $1}' | head -1`


if [ `cat ptr.log | grep -i good | wc -l` -gt 0 ]
	then
		result1_1='＠ 양호'
		echo '☞ 1024 이하 Port 사용으로 root 실행(양호)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
else
	if [ `$ppss | grep -i 'tomcat' | grep -i 'java' | grep -v "16-Tomcat" | grep -v "grep" | grep -i "root" | wc -l` -gt 0 ]
		then
			result1_1='＠ 취약'
	else
		result1_1='＠ 양호'
	fi
fi

else
	echo '☞ Tomcat의 데몬 구동중이지 않으며, 설치 및 설정 파일만 존재' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	result1_1='＠ N/A'
fi

echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '※ Tomcat의 데몬을 root 계정 외의 WAS 전용 계정으로 변경하여 구동 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $result1_1  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "1.01 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1

echo "1.02 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 1.02 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1.설정 - 1.02 관리서버 디렉터리 권한 설정'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '관리 서버 홈디렉터리 퍼미션이 750이하 양호(WAS 전용 계정)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
touch manager.log 2>&1
touch managerdir.log 2>&1
touch manadir.log 2>&1
for folder in $confall
	do
		if [ -d $folder ]
			then
				if [ `find $folder/ -name 'webapps' | wc -l` -gt 0 ]
					then
						find $folder/ -name 'webapps' >> manadir.log
						base=`find $folder/ -name 'webapps'`
						for fo in $base
							do
								if [ `ls -l $base | egrep -i 'manager|admin' | grep -v 'host-'| grep -i 'd..........' | wc -l` -gt 0 ]
									then
										echo '='$folder >> managerdir.log
								fi
						done
				fi
		fi
done
manadir=`cat manadir.log | sort -u`
	
echo '### Manager.xml/admin.xml 파일 확인 ###' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
for folder in $confall
		do
			if [ -d $folder ]
				then
					if [ `ls -alL $folder/conf/*/*/*.xml 2>/dev/null | egrep -i "admin.xml|manager.xml" |grep -v 'host-'| wc -l` -gt 0 ]
						then
							xml=`ls -alL $folder/conf/*/*/*.xml 2>/dev/null | egrep -i "admin.xml|manager.xml" |grep -v 'host-' | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep '^/'`
							for fd in $xml
								do
									echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									echo '▷' $folder '디렉터리내 manager.xml 파일 확인' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									ls -alL $fd >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									if [ `cat $fd | grep -i "docbase" | grep -i "docbase=" | $aaww -F'"' '{print $2}' | wc -l` -gt 0 ]
										then
											xm=`cat $fd | grep -i "docbase" | grep -i "docbase=" | $aaww -F'"' '{print $2}'`
											echo '1) manager 지정 폴더 : ' $xm >> $TOMCAT_CREATE_FILE_RESULT 2>&1
											if [ `echo $xm | grep -i 'catalina.home' | wc -l` -gt 0 ]
												then
													xmlaa=`echo $xm | $aaww -F'}' '{print $2}'`
													xmla=`echo $folder$xmlaa`
											else
												xmla=`cat $fd | grep -i "docbase" | grep -i "docbase=" | $aaww -F'"' '{print $2}'`
											fi
											if [ `ls -ld $xmla 2>/dev/null | wc -l` -gt 0 ]
												then
													xmlls=`ls -ld $xmla`
													echo '2) Manager 디렉터리 권한 확인 ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
													echo $xmlls >> $TOMCAT_CREATE_FILE_RESULT 2>&1
													echo '='$folder >> managerdir.log
													echo $xmla >> managerdir.log
													if [ \( `echo $xmlls | grep -v '.r...-.---'|wc -l` -gt 0 \) -o \( `echo $xmlls | grep -v $PSID |wc -l` -gt 0 \) ]
														then
															echo '☞ Manager 디렉터리 권한이 취약 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
															echo "＠ 취약 - yes" >> manager.log
													else
														echo '☞ Manager 디렉터리 권한이 양호 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
														echo "＠ 양호 - yes" >> manager.log
													fi
											else
												echo '2) Manager 디렉터리 권한 확인 ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
												echo '☞ 지정된 Manager 디렉터리가 존재 하지 않습니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
												echo "＠ 양호 - no" >> manager.log
											fi
									else
										echo '☞ Manager 디렉터리가 지정 되어 있지 않습니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
										echo "＠ 양호 - no" >> manager.log
									fi
							done
					else
						echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '▷' $folder '디렉터리내 manager.xml 파일 확인' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '☞ 설정된 manager.xml 또는 admin.xml 파일이 없습니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo "＠ 양호 - no" >> manager.log
					fi
			fi
	done

echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '### Default manager/admin 디렉터리 확인 ###' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
if [ `cat manadir.log | wc -l` -gt 0 ]
	then
for folder in $manadir
		do
			if [ -d $folder ]
				then
					echo '▷ Tomcat webapps 경로 : '$folder >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					if [ `ls -l $folder | egrep -i 'manager|admin' | grep -v 'host-' | grep 'd.........' | wc -l` -gt 0 ]
						then
							ls -alL $folder | egrep -i 'manager|admin' | grep -v 'host-' | grep 'd.........' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							ls -d $folder/manager 2>/dev/null >> managerdir.log
							ls -d $folder/admin 2>/dev/null >> managerdir.log
							if [ \( `ls -alL $folder | egrep -i 'manager|admin' | grep -v 'host-' |grep -v '.r...-.---'|wc -l` -gt 0 \) -o \( `ls -alL $folder | egrep -i 'manager|admin' | grep -v 'host-' |grep -v $PSID |wc -l` -gt 0 \) ]
								then
									echo '☞ Manager 디렉터리 권한이 취약 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									echo "＠ 취약 - yes" >> manager.log 2>&1
							else
								echo "＠ 양호 - yes" >> manager.log 2>&1
							fi
					else
						echo '☞ manager 및 admin 디렉터리가 없어 양호 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo "＠ 양호 - no" >> manager.log 2>&1
					fi
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
			fi
	done
else
	echo '☞ Tomcat webapps 폴더 없음' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	echo "＠ 양호 - no" >> manager.log 2>&1
	echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
fi	

echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
if [ `cat manager.log | grep "취약" | wc -l` -eq 0 ]
        then
                sresult1_2='＠ 양호'
else
        sresult1_2='＠ 취약'
fi
echo '※ 관리 서버 홈디렉터리 퍼미션이 750이하로 설정 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $sresult1_2 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "1.02 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "1.03 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 1.03 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1.설정 - 1.03 설정파일 권한 설정'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'Tomcat conf 디렉터리 내부의 설정파일 퍼미션이 600 또는 700이하 양호(WAS 전용 계정)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
cresult2_32='＠ 양호'
for folder in $confall
	do
		if [ -d $folder ]
			then
				echo '▷ Tomcat 구동 디렉터리 :' $folder/conf/ >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				ls -alL $folder/conf/|egrep ".xml|.properties|.policy" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				if [ \( `ls -alL $folder/conf/|egrep ".xml|.properties|.policy"| $aaww -F' ' '{print $1 $9}'|grep -v 'd.........'|grep -v '....------'|wc -l` -gt 0 \) -o \( `ls -alL $folder/conf/|egrep ".xml|.properties|.policy"| $aaww -F' ' '{print $1 $2 $3 $4 $9}'|grep -v $PSID |wc -l` -gt 0 \) ]
				#if [ \( `ls -alL $folder/conf/|egrep ".xml|.properties|.policy"| $aaww -F' ' '{print $1 $9}'|grep -v 'd.........'|grep -v '....------'|wc -l` -gt 0 \) -o \( `ls -alL $folder/conf/|egrep ".xml|.properties|.policy"| $aaww -F' ' '{print $1 $2 $3 $4 $9}'|grep -w 'root'|grep -v 'root' |wc -l` -gt 0 \) ]
					then
						cresult2_32='＠ 취약'
						echo '☞ 내부 설정 파일 퍼미션이 취약 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				fi
				echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		fi
done

echo '※ Tomcat conf 디렉터리 내부의 설정파일 퍼미션을 600 또는 700이하로 설정 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $cresult2_32 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "1.03 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "1.04 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 1.04 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1.설정 - 1.04 로그 디렉터리/파일 권한 설정'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '로그 디렉터리 퍼미션 750 이하, 로그 파일 퍼미션 640이하 양호(WAS 전용 계정)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
result2_55='양호'
for folder in $confall
	do
		if [ -d $folder ]
			then
				if [ `cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v "\-\-" |grep -v '!--'|grep -n ' '|grep 'valves.AccessLog' | wc -l` -gt 0 ]
					then
						if [ `cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v "\-\-" |grep -v '!--'|grep -n ' '|grep 'directory=' | grep 'AccessLogValve'| wc -l` -gt 0 ]
							then
								logg=`cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v "\-\-" |grep -v '!--'|grep -n ' '|grep 'directory='|$aaww -F'"' '{print $4}'`
						else
							logg=`cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v "\-\-" |grep -v '!--'|grep -n ' '|grep 'directory='|$aaww -F'"' '{print $2}'`
						fi
						for log in $logg
							do
						if [ `echo $log | grep "^/" | wc -l` -eq 0 ]
							then
								if [ \( `ls -alL $folder|grep $log|grep -v '.....-.---'|grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) -o \( `ls -alL $folder|grep $log |grep -v $PSID |grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) ]
								#if [ \( `ls -alL $folder|grep $log|grep -v '.....-.---'|grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) -o \( `ls -alL $folder|grep $log |grep 'root' |grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) ]
									then
										result2_55='취약'
								fi
						else
							if [ \( `ls -alL $log 2>/dev/null |grep -v '.....-.---'|grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) -o \( `ls -alL $log 2>/dev/null |grep -v $PSID |grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) ]
							#if [ \( `ls -alL $log 2>/dev/null |grep -v '.....-.---'|grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) -o \( `ls -alL $log 2>/dev/null | grep 'root' |grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) ]
								then
									result2_55='취약'
							fi
						fi
						done
				else
					if [ \( `ls -alL $folder | grep logs |grep -v '.....-.---'|grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) -o \( `ls -alL $folder | grep logs |grep -v $PSID |grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) ]
					#if [ \( `ls -alL $folder | grep logs |grep -v '.....-.---'|grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) -o \( `ls -alL $folder | grep logs |grep 'root' |grep -v 'total' |grep -v '합계'|wc -l` -gt 0 \) ]
						then
							result2_55='취약'
					fi
				fi
		fi
done

result2_5='양호'
for folder in $confall
	do
		if [ -d $folder ]
			then
				if [ `cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v "\-\-" | grep -v '!--'|grep -n ' '|grep 'directory=' | wc -l` -gt 0 ]
					then
						if [ `cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v "\-\-" |grep -v '!--'|grep -n ' '|grep 'directory=' | grep 'AccessLogValve'| wc -l` -gt 0 ]
							then
								logg=`cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v "\-\-" |grep -v '!--'|grep -n ' '|grep 'directory='|$aaww -F'"' '{print $4}'`
						else
							logg=`cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v "\-\-" |grep -v '!--'|grep -n ' '|grep 'directory='|$aaww -F'"' '{print $2}'`
						fi
						for log in $logg
							do
						if [ `echo $log | grep "^/" | wc -l` -eq 0 ]
							then
								echo '▷ Tomcat Log 디렉터리 :' $folder/$log >> $TOMCAT_CREATE_FILE_RESULT 2>&1
								ls -alLd $folder/$log >> $TOMCAT_CREATE_FILE_RESULT 2>&1
								ls -alL $folder/$log | grep -v 'total' |grep -v '합계'| grep -v '^d.........'| egrep -i '.txt|.log|catalina.out.' | head -5	>> $TOMCAT_CREATE_FILE_RESULT 2>&1
								echo "..." >> $TOMCAT_CREATE_FILE_RESULT 2>&1
								if [ \( `ls -alL $folder/$log|grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v '...-.-----'|wc -l` -gt 0 \) -o \( `ls -alL $folder/$log|grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v $PSID |wc -l` -gt 0 \) ]
								#if [ \( `ls -alL $folder/$log|grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v '...-.-----'|wc -l` -gt 0 \) -o \( `ls -alL $folder/$log|grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep 'root' |wc -l` -gt 0 \) ]
									then
										echo "--- 취약 List ---" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
										ls -alL $folder/$log|grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v '...-.-----' | head -3	>> $TOMCAT_CREATE_FILE_RESULT 2>&1
										ls -alL $folder/$log|grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v $PSID | head -3	>> $TOMCAT_CREATE_FILE_RESULT 2>&1
										echo "..." >> $TOMCAT_CREATE_FILE_RESULT 2>&1
										result2_5='취약'
								fi
								echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						else
							echo '▷ Tomcat Log 디렉터리 :' $folder '=>' $log >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							ls -alLd $log >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							ls -alL $log | grep -v 'total' |grep -v '합계'| grep -v '^d.........'| egrep -i '.txt|.log|catalina.out.' | head -5	 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							echo "..." >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							if [ \( `ls -alL $log 2>/dev/null | grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v '...-.-----'|wc -l` -gt 0 \) -o \( `ls -alL $log 2>/dev/null | grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v $PSID |wc -l` -gt 0 \) ]
							#if [ \( `ls -alL $log 2>/dev/null | grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v '...-.-----'|wc -l` -gt 0 \) -o \( `ls -alL $log 2>/dev/null | grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep 'root' |wc -l` -gt 0 \) ]
								then
									echo "--- 취약 List ---" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									ls -alL $log 2>/dev/null | grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v '...-.-----' | head -3	>> $TOMCAT_CREATE_FILE_RESULT 2>&1
									ls -alL $log 2>/dev/null | grep -v '^d.........' |grep -v 'total' |grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v $PSID	| head -3	>> $TOMCAT_CREATE_FILE_RESULT 2>&1
									echo "..." >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									result2_5='취약'
							fi
							echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						fi
						done
				else
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					if [ `ls -alL $folder | grep logs | wc -l` -gt 0 ]
						then
							echo '▷ Tomcat Log 디렉터리 :' $folder/logs >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							echo '☞ server.xml 파일에 AccessLog 설정이 없어 Default Logs 폴더 확인'>> $TOMCAT_CREATE_FILE_RESULT 2>&1
							ls -alLd $folder/logs >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							ls -alL $folder/logs | grep -v 'total' | grep -v '합계' | grep -v '^d.........'| egrep -i '.txt|.log|catalina.out.' | head -5	>> $TOMCAT_CREATE_FILE_RESULT 2>&1
							echo "..." >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							if [ \( `ls -alL $folder/logs|grep -v '^d.........' |grep -v 'total' | grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v '...-.-----'|wc -l` -gt 0 \) -o \( `ls -alL $folder/logs|grep -v '^d.........' |grep -v 'total' | grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v $PSID |wc -l` -gt 0 \) ]
							#if [ \( `ls -alL $folder/logs|grep -v '^d.........' |grep -v 'total' | grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v '...-.-----'|wc -l` -gt 0 \) -o \( `ls -alL $folder/logs|grep -v '^d.........' |grep -v 'total' | grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep 'root' |wc -l` -gt 0 \) ]
								then
									echo "--- 취약 List ---" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									ls -alL $folder/logs|grep -v '^d.........' |grep -v 'total' | grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v '...-.-----'	| head -3	>> $TOMCAT_CREATE_FILE_RESULT 2>&1
									ls -alL $folder/logs|grep -v '^d.........' |grep -v 'total' | grep -v '합계'| egrep -i '.txt|.log|catalina.out.' |grep -v $PSID	| head -3	>> $TOMCAT_CREATE_FILE_RESULT 2>&1
									echo "..." >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									result2_5='취약'
							fi
							echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					else
						echo '☞ Default Logs 폴더 없음'>> $TOMCAT_CREATE_FILE_RESULT 2>&1
					fi
				fi
			fi
done
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
if [ \( $result2_55 = "취약" \) -o \( $result2_5 = "취약" \) ]
	then
		result2_555='＠ 취약'
else
	result2_555='＠ 양호'
fi

echo '※ 로그파일 퍼미션을 640이하, 디렉터리 750이하로 설정을 권고함.'>> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $result2_555 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "1.04 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "1.05 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 1.05 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1.설정 - 1.05 로그 포맷 설정 '  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '로그 포맷 설정이  combined로 되어 있으면 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
cresult1_5='＠ 양호'
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
for folder in $confall
	do
		if [ -d $folder ]
			then
				echo '▷ Tomcat 구동 디렉터리 :' $folder/conf/server.xml >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				if [ `cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'| grep -v '#' | grep 'pattern=' | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep '^pattern' |wc -l` -gt 0 ]
					then
						pattern=`cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'| grep -v '#' | grep 'pattern=' | $aaww -F"pattern=" '{print $2}' | $aaww -F"\"" '{print $2}'`
						echo "pattern=$pattern" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						if [ `cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'| grep -v '#' | grep 'pattern=' | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep -i 'combined'| wc -l` -eq 0 ]
							then
								cresult1_5='＠ 취약'
								echo '☞ 로그 포맷 설정이 취약 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						fi
						echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				else
					echo '☞ server.xml 파일에 Log pattern 설정이 없습니다.'>> $TOMCAT_CREATE_FILE_RESULT 2>&1
					cresult1_5='＠ 취약'
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				fi
		fi
done

echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '※ 로그 포맷을 combined로 설정 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $cresult1_5 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "1.05 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "1.06 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 1.06 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1.설정 - 1.06 로그 저장 주기 '  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '법에 정해진 최소 로그 저장 기간대로 백업 및 보관하고 있으면 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '＠ N/A' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "1.06 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "1.07 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 1.07 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1.설정 - 1.07 HTTP Method 제한'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'PUT, DELETE, TRACE Method 제한 설정이 되어 있으면 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> readonly.log 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
for folder in $confall
	do
	if [ -d $folder ]
		then
		echo '▷ Tomcat 구동 디렉터리 :' $folder/conf/web.xml >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		echo '1) Method 설정 확인' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		if [ `cat $folder/conf/web.xml | egrep -v '<!--.+-->'| sed '/<!--/,/-->/d' |grep -v '\-\-'|$aaww '/<security-constraint/,/<\/security-constraint>/'|grep -i 'http-method'|wc -l` -gt 0 ]
			then
				cat $folder/conf/web.xml | egrep -v '<!--.+-->'| sed '/<!--/,/-->/d' |grep -v '\-\-'| $aaww '/<security-constraint/,/<\/security-constraint>/'|grep -i 'http-method'| sed 's/^[[:space:]]*//g' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				if [ `cat $folder/conf/web.xml | egrep -v '<!--.+-->'| sed '/<!--/,/-->/d' |grep -v '\-\-'|$aaww '/<security-constraint/,/<\/security-constraint>/'|grep -i method | grep -i 'put'|wc -l` -gt 0 ]
					then
						if [ `cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' |grep -v '\-\-'|$aaww '/<security-constraint/,/<\/security-constraint>/'|grep -i method | grep -i 'delete'|wc -l` -gt 0 ]
							then
								if [ `cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' |grep -v '\!\-\-'|$aaww '/<security-constraint/,/<\/security-constraint>/'|grep -i method | grep -i 'trace'|wc -l` -gt 0 ]
									then
										if [ `cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' |grep -v '\!\-\-'|$aaww '/<security-constraint/,/<\/security-constraint>/'|grep -i method | grep -i 'options'|wc -l` -gt 0 ]
											then
												echo '양호' >> readonly.log
										else
											echo '취약' >> readonly.log
											echo '☞ 일부 method 제한 설정만 확인(취약)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
										fi
								else
									echo '취약' >> readonly.log
									echo '☞ 일부 method 제한 설정만 확인(취약)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
								fi
						else
							echo '취약' >> readonly.log
							echo '☞ 일부 method 제한 설정만 확인(취약)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						fi
				else
					echo '취약' >> readonly.log
					echo '☞ 일부 method 제한 설정만 확인(취약)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				fi
		else
			echo '☞ method 제한 설정 없음(취약)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
			echo '취약' >> readonly.log
		fi
		echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		echo '2) readonly 설정 확인' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		if [ `cat $folder/conf/web.xml | egrep -v '<!--.+-->'| sed '/<!--/,/-->/d' |grep -v '\-\-'| $aaww '/<init-param/,/<\/init-param>/'|grep -i 'readonly' | wc -l` -gt 0 ]
			then
				cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' |grep -v '\!\-\-'| $aaww '/<init-param/,/<\/init-param>/' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		else
			echo '☞ Readonly 설정 없음(Default : true)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		fi
	fi
	echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
done

echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1

if [ `cat readonly.log | grep -i '취약' | wc -l` -gt 0 ]
	then
		cresult1_7='＠ 취약'
else
	cresult1_7='＠ 양호'
fi

echo '※ web.xml 파일에서 PUT, DELETE, TRACE Method 설정을 제한' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $cresult1_7 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "1.07 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "1.08 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 1.08 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1.설정 - 1.08 디렉터리 검색 기능 제거'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'web.xml내부의 listing설정이 false로 설정되어있으면 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
cresult1_8='＠ 양호'
for folder in $confall
	do
		if [ -d $folder ]
			then
				echo '▷ Tomcat 구동 디렉터리 :' $folder/conf/web.xml >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				mcount=`cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'|grep -n ' '|grep listing|$aaww -F':' '{print $1}'`
				mcount=`expr $mcount + 1`
				cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'|grep -n ' '|grep listing|$aaww -F':' '{print $2}' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'|grep -n ' '|grep $mcount:|head -1|$aaww -F':' '{print $2}' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				if [ `cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-' | grep -n ' ' |grep $mcount:|head -1|$aaww -F':' '{print $2}'|$aaww -F'>' '{print $2}'| $aaww -F'<' '{print $1}'` = 'true' ]
					then
						cresult1_8='＠ 취약'
						echo '☞ listing 설정이 취약 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				fi
				echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		fi
done

echo '※ 디렉터리 구조 및 주요 설정파일의 내용을 노출 시킬 수 있는 listing 설정 값 false로 변경 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $cresult1_8 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "1.08 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1

echo "1.09 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 1.09 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1.설정 - 1.09 Session Timeout 설정'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'Session Timeout 60분 이내로 변경 (Default = 30) ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
cresult1_9='＠ 양호'
for folder in $confall
	do
		if [ -d $folder ]
			then
				echo '▷ Tomcat webapps 경로 : ' $folder/conf/web.xml >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				if [ `cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'|grep -n ' '|grep session-timeout | wc -l` -gt 0 ]
					then
						cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'|grep -n ' '|grep session-timeout|$aaww -F':' '{print $2}' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						if [ `cat $folder/conf/web.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'|grep session-timeout|$aaww -F">" '{print $2}'|$aaww -F"<" '{print $1}'` -gt 60 ]
							then
								cresult1_9='＠ 취약'
								echo '☞ Session Timeout 설정이 취약 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						fi
						echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				else
					echo '☞ Session Timeout 설정이 존재하지 않습니다.(취약)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				fi
		fi
done

echo '※ Session Timeout 60분 이내로 변경 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $cresult1_9 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "1.09 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "1.10 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 1.10 =================================='
echo '======================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1.설정 - 1.10 헤더 정보 노출 방지 '  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '======================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'HTTP Response Header에 Server 정보가 반환되지 않도록 설정' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
cresult1_10='＠ 양호'
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
for folder in $confall
	do
		if [ -d $folder ]
			then
				echo '▷ Tomcat 구동 디렉터리 :' $folder/conf/server.xml >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				if [ `cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'| grep -v '#' | $aaww '/<Connector /,/\/>/' |wc -l` -gt 0 ]
					then
						cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'| grep -v '#' | $aaww '/<Connector /,/\/>/'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						if [ `cat $folder/conf/server.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'| grep -v '#' | $aaww '/<Connector /,/\/>/' | $aaww 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}' | grep -i 'server="'| wc -l` -gt 0 ]
							then
								cresult1_10='＠ 양호'
								echo '☞ 헤더 정보 노출 방지 설정(server="xxx") 확인 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
								
						else
							cresult1_10='＠ 취약'
							echo '☞ 헤더 정보 노출 방지 설정(server="xxx") 없음 취약' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						fi
						echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				else
					echo '☞ server.xml 파일에 Connector 설정이 없습니다.'>> $TOMCAT_CREATE_FILE_RESULT 2>&1
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
				fi
		fi
done

echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '※ 헤더 정보 노출 방지 설정(server="xxx") 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $cresult1_10 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "1.10 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "2.01 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 2.01 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '2.솔루션 취약점 - 2.01 불필요한 디렉터리 삭제'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '운영상 불필요한 디렉터리가 제거 되어 있으면 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
result2_1='＠ 양호'
manadir=`cat manadir.log | sort -u`
if [ `cat manadir.log | wc -l` -gt 0 ]
	then
for folder in $manadir
		do
			if [ -d $folder ]
				then
					echo '▷ Tomcat webapps 경로 : '$folder >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					if [ `ls -l $folder | grep -w 'examples' | grep 'd.........' | wc -l` -gt 0 ]
						then
							ls -alL $folder | grep -w 'examples' | grep 'd.........' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							result2_1='＠ 취약'
							echo '☞ examples 디렉터리가 있어 취약 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					else
						echo '☞ examples 디렉터리가 없어 양호 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					fi
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
			fi
	done
else
	echo '☞ Tomcat webapps 폴더 없음' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
fi

echo '※ example 디렉터리는 불필요시 삭제 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $result2_1 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "2.01 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1

echo "2.02 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 2.02 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '2.솔루션 취약점 - 2.02 프로세스 관리기능 삭제'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '불필요한 프로세스 관리 디렉터리가 삭제 되어 있으면 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1

result3_2='＠ 양호'

manadir=`cat manadir.log | sort -u`
if [ `cat manadir.log | wc -l` -gt 0 ]
	then
for folder in $manadir
		do
			if [ -d $folder ]
				then
					jar=`find $folder/ -name 'catalina-manager.jar'`
					echo '▷ Tomcat webapps 경로 : '$folder >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					if [ `echo $jar | grep -i 'catalina-manager' | wc -l` -gt 0 ]
						then
							echo $jar >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							result3_2='＠ 취약'
							echo '☞ catalina-manager.jar 파일이 있어 취약 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					else
						echo '☞ catalina-manager.jar 파일이 없어 양호 합니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					fi
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
			fi
	done
else
	echo '☞ Tomcat webapps 폴더 없음' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
fi

echo '※ Tomcat 설치시 관리자 프로세스 관리 기능이 웹상에서 가능하므로 catalina-manager.jar 파일 삭제' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo  $result3_2 >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "2.02 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "3.01 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 3.01 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '3.보안 패치 - 3.01 보안 패치 적용'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '주기적으로 최신 패치 적용 작업이 진행되고 있으면 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' > version.log
for folder in $confall
	do
		if [ -d $folder ]
			then
				bind=`find $folder/ -name "version.sh" | tail -1`
				if [ `echo $bind | grep -i "/" | wc -l` -gt 0 ]
					then
					if [ `sh $bind 2>/dev/null | grep -i 'version' | grep -i 'tomcat' | grep -i [0-9].[0-9].[0-9] | wc -l` -gt 0 ]
						then
							echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							echo '▷ Tomcat base 경로 : '$folder >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							vvv=`sh $bind |grep version|$aaww -F':' '{print $2}'|$aaww -F'/' '{print $2}'`
							echo '- Tomcat Version : ' $vvv >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							ver=`sh $bind |grep version|$aaww -F':' '{print $2}'|$aaww -F'/' '{print $2}'`
							ver1=`sh $bind |grep version|$aaww -F':' '{print $2}'|$aaww -F'/' '{print $2}'|$aaww -F'.' '{print $1}'`
							ver2=`sh $bind |grep version|$aaww -F':' '{print $2}'|$aaww -F'/' '{print $2}'|$aaww -F'.' '{print $2}'`
							ver3=`sh $bind |grep version|$aaww -F':' '{print $2}'|$aaww -F'/' '{print $2}'|$aaww -F'.' '{print $3}'`
							if [ $ver1 -eq 9 -a $ver2 -eq 0 ]
								then
									if [ $ver3 -ge 5 ]
										then 
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $CREATE_FILE_RESULT 2>&1
									else
										echo '취약' >> version.log
										echo '☞ Tomcat 버전 취약!' >> $CREATE_FILE_RESULT 2>&1
									fi
							fi
							if [ $ver1 -eq 8 -a $ver2 -eq 5 ]
								then
									if [ $ver3 -ge 28 ]
										then 
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $CREATE_FILE_RESULT 2>&1
									else
										echo '취약' >> version.log
										echo '☞ Tomcat 버전 취약!' >> $CREATE_FILE_RESULT 2>&1
									fi
							fi
							if [ $ver1 -eq 8 -a $ver2 -eq 0 ]
								then
									if [ $ver3 -ge 50 ]
										then 
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									else
										echo '취약' >> version.log
										echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									fi
							fi
							if [ $ver1 -eq 7 -a $ver2 -eq 0 ]
								then
									if [ $ver3 -ge 85 ]
										then 
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									else
										echo '취약' >> version.log
										echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									fi
							fi
							if [ $ver1 -eq 6 -a $ver2 -eq 0 ]
								then
									if [ $ver3 -ge 53 ]
										then
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									else
										echo '취약' >> version.log
										echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									fi
							fi
							if [ $ver1 -eq 5 ]
								then
									echo '취약' >> version.log
									echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							fi
					else
						notes=`find $folder/ -name "*NOTES*" | tail -1`
						if [ `echo $notes | grep -i "/" | wc -l` -gt 0 ]
							then
						if [ `cat $notes | grep -i "Tomcat Version" | wc -l` -gt 0 ]
							then
								echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
								echo '▷ Tomcat base 경로 : '$folder >> $TOMCAT_CREATE_FILE_RESULT 2>&1
								vv=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}'`
								echo '- Tomcat Version : ' $vv >> $TOMCAT_CREATE_FILE_RESULT 2>&1
								ve=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}'`
								ve1=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}' | $aaww -F"." '{print $1}'`
								ve2=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}' | $aaww -F"." '{print $2}'`
								ve3=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}' | $aaww -F"." '{print $3}'`
								if [ $ve1 -eq 9 -a $ve2 -eq 0 ]
									then
										if [ $ve3 -ge 5 ]
											then 
												echo '양호' >> version.log
												echo '☞ Tomcat 버전 양호!' >> $CREATE_FILE_RESULT 2>&1
										else
											echo '취약' >> version.log
											echo '☞ Tomcat 버전 취약!' >> $CREATE_FILE_RESULT 2>&1
										fi
								fi
								if [ $ve1 -eq 8 -a $ve2 -eq 5 ]
									then
										if [ $ve3 -ge 28 ]
											then 
												echo '양호' >> version.log
												echo '☞ Tomcat 버전 양호!' >> $CREATE_FILE_RESULT 2>&1
										else
											echo '취약' >> version.log
											echo '☞ Tomcat 버전 취약!' >> $CREATE_FILE_RESULT 2>&1
										fi
								fi								
								if [ $ve1 -eq 8 -a $ve2 -eq 0 ]
									then
										if [ $ve3 -ge 50 ]
											then 
												echo '양호' >> version.log
												echo '☞ Tomcat 버전 양호!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
										else
											echo '취약' >> version.log
											echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
										fi
								fi
								if [ $ve1 -eq 7 -a $ve2 -eq 0 ]
									then
										if [ $ve3 -ge 85 ]
										then 
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									else
										echo '취약' >> version.log
										echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									fi
								fi
								if [ $ve1 -eq 6 -a $ve2 -eq 0 ]
									then
										if [ $ve3 -ge 53 ]
											then
												echo '양호' >> version.log
												echo '☞ Tomcat 버전 양호!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
										else
											echo '취약' >> version.log
											echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
										fi
								fi
								if [ $ve1 -eq 5 ]
									then
										echo '취약' >> version.log
										echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
								fi
						else
							echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							echo '▷ Tomcat base 경로 : '$folder >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							echo '☞ Tomcat 버전 확인 불가!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							echo '수동진단' >> version.log
						fi
					else
						echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '▷ Tomcat base 경로 : '$folder >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '☞ Tomcat 버전 확인 불가!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '수동진단' >> version.log
					fi
				fi
				else
					notes=`find $folder/ -name "*NOTES*" | tail -1`
					if [ `echo $notes | grep -i "/"| wc -l` -gt 0 ]
						then
					if [ `cat $notes | grep -i "Tomcat Version" | wc -l` -gt 0 ]
						then
							echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							echo '▷ Tomcat base 경로 : '$folder >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							vv=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}'`
							echo '- Tomcat Version : ' $vv >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							ve=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}'`
							ve1=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}' | $aaww -F"." '{print $1}'`
							ve2=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}' | $aaww -F"." '{print $2}'`
							ve3=`cat $notes | grep -i "Tomcat Version" |$aaww -F'Version' '{print $2}' | $aaww -F"." '{print $3}'`
							if [ $ve1 -eq 9 -a $ve2 -eq 0 ]
								then
									if [ $ve3 -ge 5 ]
										then 
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $CREATE_FILE_RESULT 2>&1
										else
											echo '취약' >> version.log
											echo '☞ Tomcat 버전 취약!' >> $CREATE_FILE_RESULT 2>&1
									fi
							fi
							if [ $ve1 -eq 8 -a $ve2 -eq 5 ]
								then
									if [ $ve3 -ge 28 ]
										then 
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $CREATE_FILE_RESULT 2>&1
										else
											echo '취약' >> version.log
											echo '☞ Tomcat 버전 취약!' >> $CREATE_FILE_RESULT 2>&1
									fi
							fi							
							if [ $ve1 -eq 8 -a $ve2 -eq 0 ]
								then
									if [ $ve3 -ge 50 ]
										then 
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
										else
											echo '취약' >> version.log
											echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									fi
							fi
							if [ $ve1 -eq 7 -a $ve2 -eq 0 ]
								then
									if [ $ve3 -ge 85 ]
										then 
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									else
										echo '취약' >> version.log
										echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									fi
							fi
							if [ $ve1 -eq 6 -a $ve2 -eq 0 ]
								then
									if [ $ve3 -ge 53 ]
										then
											echo '양호' >> version.log
											echo '☞ Tomcat 버전 양호!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
									else
										echo '취약' >> version.log
										echo '☞ Tomcat 버전 취약!' >> $TOCAT_CREATE_FILE_RESULT 2>&1
									fi
									fi
							if [ $ve1 -eq 5 ]
								then
									echo '취약' >> version.log
									echo '☞ Tomcat 버전 취약!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							fi
					else
						echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '▷ Tomcat base 경로 : '$folder >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '☞ Tomcat 버전 확인 불가!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '수동진단' >> version.log
					fi
					else
						echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '▷ Tomcat base 경로 : '$folder >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '☞ Tomcat 버전 확인 불가!' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '수동진단' >> version.log
					fi
				fi
		fi
done

if [ `cat version.log | grep '수동진단' | wc -l` -gt 0 ]
	then
		result4_11='＠ 수동'
else
	if [ `cat version.log | grep '취약' | wc -l` -gt 0 ]
		then
			result4_11='＠ 취약'
	else
		result4_11='＠ 양호'
	fi
fi
	
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '[최신 버전]' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'Tomcat 9.0.x      9.0.5  이상' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'Tomcat 8.5.x      8.5.28  이상' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'Tomcat 8.0.x      8.0.50  이상' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'Tomcat 7.0.x      7.0.85 이상' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'Tomcat 6.0.x      6.0.53 이상' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo 'Tomcat 5.5버전 미만은 기술지원 완료로 인해 패치 지원 안함' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '※ 영향도 평가 이후 최신 패치 수행 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo $result4_11  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "3.01 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "4.01 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 4.01 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '4.접근 제어 - 4.01 관리자 콘솔 접근통제'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '불필요한 경우, Tomcat 관리자 콘솔 사용 금지되어 있고, 필요한 경우 Default Port 변경해서 사용하는 경우 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1) Tomcat 관리자 콘솔 확인'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
cresult4_1_1='양호'
if [ `cat manager.log | grep "yes" | wc -l` -eq 0 ]
	then
		echo '☞ 관리자 콘솔(manager/admin) 미사용으로 양호 합니다. ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
else
	cresult4_1_1='취약'
	cat managerdir.log | grep -v "=" | sort -u >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	mg=`cat managerdir.log | grep "=" | $aaww -F'=' '{print $2}' | sort -u`
	echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	echo '2) Default 포트(8080) 확인'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	echo '[ LISTEN Port 확인 ]' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	if [ `netstat -an | egrep -i "\.8080 |:8080 " | grep -i "LISTEN" | wc -l` -gt 0 ]
		then
			netstat -an | egrep -i "\.8080 |:8080 " | grep -i "LISTEN" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	else
		#netstat -an | grep -i "LISTEN" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		echo '☞ LISTEN 되고 있는 8080 Port 없음' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	fi
	echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	cresult4_1_2='양호'
	for folder in $mg
		do
			if [ -d $folder ]
				then
					echo '▷ server.xml 경로 : ' $folder/conf/server.xml >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					port=`cat $folder/conf/server.xml 2>/dev/null| egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'|grep 'Connector'| $aaww -F"port=" '{print $2}' | $aaww -F"\"" '{print $2}'`
					echo '- 설정된 Port -' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					echo '  '$port  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					if [ `echo $port | wc -l` -gt 0 ]
						then
							if [ `cat $folder/conf/server.xml 2>/dev/null| egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-'|grep 'Connector'| $aaww -F"port=" '{print $2}' | $aaww -F"\"" '{print $2}' | grep -i '^8080' | wc -l` -gt 0 ]
								then
									cresult4_1_2='취약'
							fi
					else
						echo '☞ 설정된 Port 없음(확인 필요)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					fi
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
			fi
	done
fi

if [ $cresult4_1_1 = "취약" ]
        then
                if [ $cresult4_1_2 = "취약" ]
                        then
                                result44_1='＠ 취약'
                else
                        result44_1='＠ 양호'
                fi
else
        result44_1='＠ 양호'
fi

echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '※ 불필요한 경우, Tomcat 관리자 콘솔 사용 금지하고, 필요한 경우 Default Port 변경 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1

echo $result44_1  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "4.01 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "4.02 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 4.02 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '4.접근 제어 - 4.02 관리자 Default 계정명 변경'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '관리자 콘솔 Default 값으로 제공된 계정명이 변경 되어 있으면 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
result4_2='양호'
echo '1) Tomcat 관리자 콘솔 확인'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
if [ `cat manager.log | grep "yes" | wc -l` -eq 0 ]
	then
		echo '☞ 관리자 콘솔(manager/admin) 미사용으로 양호 합니다. ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		cresult4_2='양호'
else
	cresult4_2='취약'
	cat managerdir.log | grep -v "=" | sort -u >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	mg=`cat managerdir.log | grep "=" | $aaww -F'=' '{print $2}' | sort -u`
	echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	echo '2) 관리자 콘솔 default 계정 확인'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	for folder in $mg
		do
			if [ -d $folder ]
				then
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					echo '▷ Tomcat 구동 디렉터리 :' $folder/conf/tomcat-users.xml >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					if [ -f $folder/conf/tomcat-users.xml ]
						then
							cat $folder/conf/tomcat-users.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-' | $aaww '/tomcat-users/,/\/tomcat-users/' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							if [ `cat $folder/conf/tomcat-users.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-' | $aaww '/tomcat-users/,/\/tomcat-users/' | egrep -i 'username="tomcat"|username="both"|username="role1"|username="admin"' | wc -l` -gt 0 ]
								then
									result4_2='취약'
									echo '☞ Tomacat Default 계정이 존재하여 취약 합니다.'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							else
								cat $folder/conf/tomcat-users.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-' | $aaww '/tomcat-users/,/\/tomcat-users/' | egrep -i 'username="tomcat"'
							fi
					else
						echo '☞ tomcat-users.xml 파일이 없습니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					fi
			fi
	done
fi
if [ $cresult4_2 = '취약' ]
	then
		if [ $result4_2 = '취약' ]
			then
				result4_2='＠ 취약'
		else
			if [ $result4_2 = '양호' ]
				then
					result4_2='＠ 양호'
			else
				result4_2='＠ 수동'
			fi
		fi
else
	result4_2='＠ 양호'
fi
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '※ 관리자 콘솔 default 계정명을 유추 힘든 계정으로 변경 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo $result4_2  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "4.02 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1


echo "4.03 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 4.03 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '4.접근 제어 - 4.03 관리자 패스워드 암호정책'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '패스워드 보안 정책에 맞게 사용중이면 양호' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '1) Tomcat 관리자 콘솔 확인'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
result4_3='취약'
cresult4_3='수동진단'
if [ `cat manager.log | grep "yes" | wc -l` -eq 0 ]
	then
		echo '☞ 관리자 콘솔(manager/admin) 미사용으로 양호 합니다. ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
		result4_3='양호'
else
	cresult4_3='수동진단'
	cat managerdir.log | grep -v "=" | sort -u >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	mg=`cat managerdir.log | grep "=" | $aaww -F'=' '{print $2}' | sort -u`
	echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	echo '2) 관리자 콘솔 default 계정 확인'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	for folder in $mg
		do
			if [ -d $folder ]
				then
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					echo '▷ Tomcat 구동 디렉터리 :' $folder/conf/tomcat-users.xml >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					if [ -f $folder/conf/tomcat-users.xml ]
						then
							cat $folder/conf/tomcat-users.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-' | $aaww '/tomcat-users/,/\/tomcat-users/' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							if [ `cat $folder/conf/tomcat-users.xml | egrep -v '<!--.+-->' | sed '/<!--/,/-->/d' | grep -v '\-\-' | $aaww '/tomcat-users/,/\/tomcat-users/' | egrep -i 'password="tomcat"|password="admin"' | wc -l` -gt 0 ]
								then
									echo '취약' >>	cresult4_3.log
									echo '☞ Tomacat Default 패스워드가 존재하여 취약 합니다.'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							else
								echo '수동진단' >>	cresult4_3.log
							fi
					else
						echo '☞ tomcat-users.xml 파일이 없습니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
						echo '양호' >>	cresult4_3.log
					fi
			fi
	done
fi

if [ $result4_3 = '양호' ]
	then
		result4_3='＠ 양호'
else
	if [ `cat cresult4_3.log | grep -i '취약' | wc -l` -gt 0 ]
		then
			result4_3='＠ 취약'
	else
		if [ `cat cresult4_3.log | grep -i '수동진단' | wc -l` -gt 0 ]
			then
				result4_3='＠ 수동'
		else
			result4_3='＠ 양호'
		fi
	fi
fi	

echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '※ 패스워드 보안 정책에 맞게 영문/숫자/특수문자 등 3종류 이상 조합으로' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '   9자리 이상의 길이로 구성 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1

echo $result4_3  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "4.03 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
rm -f cresult4_3.log

echo "4.04 START" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '============================== 4.04 =================================='
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '4.접근 제어 - 4.04 tomcat-users.xml 파일 권한 설정'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TSTART" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '■ 기준' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '패스워드 파일 (tomcat-users.xml) 퍼미션이 600 또는 700이하 양호(WAS 전용 계정)' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '■ 현황' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
result4_4='＠ 양호'
echo '1) Tomcat 관리자 콘솔 확인'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
if [ `cat manager.log | grep "yes" | wc -l` -eq 0 ]
	then
		echo '☞ 관리자 콘솔(manager/admin) 미사용으로 양호 합니다. ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
else
	cat managerdir.log | grep -v "=" | sort -u >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	mg=`cat managerdir.log | grep "=" | $aaww -F'=' '{print $2}' | sort -u`
	echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	echo '2) tomcat-users.xml 파일 권한 설정 확인'  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
	for folder in $mg
		do
			if [ -d $folder ]
				then
					echo '▷ Tomcat 구동 디렉터리 :' $folder/conf/tomcat-users.xml >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					if [ -f $folder/conf/tomcat-users.xml ]
						then
							ls -alL $folder/conf|grep tomcat-users.xml | grep -v '.back' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
							if [ \( `ls -alL $folder/conf|grep -w 'tomcat-users.xml'|grep -v '....------'|wc -l` -ge 1 \) -o \( `ls -alL $folder/conf|grep -w 'tomcat-users.xml'|grep -v $PSID |wc -l` -ge 1 \) ]
							#if [ \( `ls -alL $folder/conf|grep -w 'tomcat-users.xml'|grep -v '....------'|wc -l` -ge 1 \) -o \( `ls -alL $folder/conf|grep -w 'tomcat-users.xml'|grep 'root' |wc -l` -ge 1 \) ]
								then
									result4_4='＠ 취약'
							fi
					else
						echo '☞ tomcat-users.xml 파일이 없습니다.' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
					fi
					echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
			fi
	done
fi
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '※ 패스워드 파일(tomcat-users.xml) 퍼미션 700으로 변경 권고' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo '' >> $TOMCAT_CREATE_FILE_RESULT 2>&1

echo $result4_4  >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "TEND" >> $TOMCAT_CREATE_FILE_RESULT	2>&1
echo '=====================================================================' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo "4.04 END" >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1
echo ' ' >> $TOMCAT_CREATE_FILE_RESULT 2>&1

echo "END_RESULT" >> $TOMCAT_CREATE_FILE_RESULT 2>&1

echo '****************************** End **************************************' 
rm -f manadir.log
rm -f manager.log
rm -f managerdir.log
rm -f readonly.log
rm -f version.log
rm -f ptr.log
chmod 777 $TOMCAT_CREATE_FILE_RESULT

#end script

#echo ""
#echo "######################################################################"
#aaa=`cat $TOMCAT_CREATE_FILE_RESULT | grep '＠ 취약' | wc -l`
#bbb=`echo "(16-$aaa)/16*100" | bc -l`
#ccc=`echo $bbb | $aaww -F"." '{print $1}'`
#echo "※ 발견된 취약 항목 $aaa 개,  보안 준수율 $ccc 점"
#echo "######################################################################"

cat $TOMCAT_CREATE_FILE_RESULT >> $CREATE_FILE_RESULT 2>&1
rm -f tomcat.log


chmod 777 $CREATE_FILE_RESULT 2>&1
#unix2dos $CREATE_FILE_RESULT 2>&1

echo " "
echo "☞ 진단작업이 완료되었습니다. 수고하셨습니다!"
echo " "


else
	echo " "
	echo "☞ 진단작업이 완료되었습니다. 수고하셨습니다!"
	echo " "
	echo " "
	break
fi

# 스크립트 종료 IF문

	echo " "
	echo "☞ 진단작업이 종료되었습니다."
	echo " "
	echo " "
	break

















