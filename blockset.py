#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import argparse
import re
import numpy as np
#import xml.etree.ElementTree as ET
from lxml import etree as ET
import subprocess
# logrottateのgzipファイルに対応するため
import gzip

from logging import getLogger, StreamHandler, DEBUG, INFO

loggerLevel = DEBUG

# for logger おまじない
logger = getLogger(__name__)
handler = StreamHandler()
handler.setLevel(loggerLevel)
logger.setLevel(loggerLevel)
logger.addHandler(handler)
logger.propagate = False

# logger.info("info test")
# logger.debug("debug test")

maillog_default = "/var/log/mail.log"

ipset_file = "blocklist.xml"
ipset_ufw = "/etc/ufw/before.rules"
ipset_start_line = "blacklist-ipset-S"
ipset_end_line = "blacklist-ipset-E"

#iptables_tmpl = "/etc/sysconfig/iptables.tmpl"
#iptables_file = "/etc/sysconfig/iptables"

# 関数定義
# リスト中の重複数を集計して、データと登場回数のタプルのリストを作成して返す
def array_count(array):
    dat = {}
    for i in array:
        dat[i] = dat[i] + 1 if i in dat.keys() else 1
    return dat

# IPV4形式のデータを扱うクラス、ネットマスクがあれば/ビット数で保管
class ipv4adrset:
    def __init__(self):
        self.ips = []
        self.msk = 32
    def __init__(self, line = None):
        self.set_line(line)

    def set_line(self, line):
        if line is None:
            self.ips = []
            self.msk = 32
        else:
            res = re.match('^([0-9\.]+)\/([0-9]+)$', line)
            (ip, msk0) = (res.group(1), res.group(2)) if res else (line, 32)
            self.ips = list(map(lambda n: int(n), ip.split('.')))
            self.msk = int(msk0)

    def set_mask(self, mask):
        if self.msk < mask:
            return self
        msks = list(map(lambda n: int('1'*n+'0'*(8-n), 2), [8 if (mask - i*8) >= 8 else (mask - i*8) if (mask - i*8) > 0 else 0 for i in range(4)]))
        rip = list(np.array(self.ips) & np.array(msks))
        ret = ipv4adrset()
        ret.ips = rip
        ret.msk = mask
        return ret

    def __eq__(self, other):
        smsks = list(map(lambda n: int('1'*n+'0'*(8-n), 2), [ 8 if (self.msk - i*8) >= 8 else (self.msk - i*8) if (self.msk - i*8) > 0 else 0 for i in range(4)]))
        omsks = list(map(lambda n: int('1'*n+'0'*(8-n), 2), [ 8 if (other.msk - i*8) >= 8 else (other.msk - i*8) if (other.msk - i*8) > 0 else 0 for i in range(4)]))
        sip = list(np.array(self.ips) & np.array(smsks) & np.array(omsks))
        oip = list(np.array(other.ips) & np.array(smsks) & np.array(omsks))
        return sip == oip

    def __str__(self):
        return '.'.join(map(lambda i: str(i), self.ips)) + ('/' + str(self.msk) if self.msk < 32 else '')

def int_tuple(str):
    t = tuple(map(lambda x: int(x), str.split(',')))
    return t

def ipv4adr(str):
    a = ipv4adrset(str)
    return a

# オプション解析
parser = argparse.ArgumentParser(description='blockset.py collection of unauthorized access list and restart firewall(ufw)')
parser.add_argument('logfile', nargs='?', help='input log file default:' + maillog_default, default='')
parser.add_argument('-n', '--none', action='store_true', help='Check only mode.')
parser.add_argument('-f', '--force', action='store_true', help='bloclist force update, unless new record.')
parser.add_argument('-d', '--debug', action='store_true', help='debug print mode')
parser.add_argument('-u', '--update', action='store_true', help='blocklist update and restart firewall(ufw)')
parser.add_argument('-o', '--orderck', type=int_tuple, metavar='MASK,COUNT', help='ipset order ckeck')
parser.add_argument('-c', '--count', type=int, help='abuse count', default = 5)
parser.add_argument('-a', '--address', type=ipv4adr, help='individually address entry to blacklist')

args = parser.parse_args()

# オプション分岐
if args.none:
    logger.info('Check only mode.')
if args.force:
    logger.info('firewalld(ipset) force update.')
if args.debug:
    logger.info('Debug print mode.')
if args.orderck:
    logger.info('ipset order mode.')
    logger.info('mask bits : ' + str(args.orderck[0])) 
    logger.info('count     : ' + str(args.orderck[1])) 

# 処理開始-解析ログファイルの選択
if len(args.logfile) == 0:
    logger.info('use defaule.')
    args.logfile = maillog_default

iplist = []

# メールログから不正アクセスに相当するIPアドレスを取り出してリスト化する(gzipファイルはgzipモジュールのOPENを使用する)
try:
    with open(args.logfile, 'r', encoding='utf-8') if not re.search('\.gz$', args.logfile) else gzip.open(args.logfile, 'rt') as fh:
        for line in fh:
            line = line.rstrip('\n')
            res = re.match('^.+\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\].+ SASL [A-Z]+ authentication failed.*$', line)
            if res:
                iplist.append(res.group(1))
            res = re.match('SSL_accept .+\[([0-9.]+)\]', line)
            if res:
                iplist.append(res.group(1))
except FileNotFoundError:
    logger.error('file not found! : %s' % (args.logfile))

# IPアドレス、登場回数のタプルリストにする
items = array_count(iplist)
if args.address:
    items[str(args.address)] = 100

iplist = []
alist = []
dlist = []

# 対象ログに登場したIPアドレス集計を表示する（Debug）
if args.debug:
    for k in items:
        logger.info('Redord : %s (%d)' % (k, items[k]))

#一定数(5)以上の出現回数の物のみの IPV4アドレスリストを作成する
iplist = list(map(lambda t: ipv4adrset(t[0]), filter(lambda t: t[1] >= args.count, items.items())))

# firewall ipsetsのblocklist.xmlを解析する
#tree = ET.parse(ipset_file)
#root = tree.getroot()

# 現在設定中のblocklistをリスト化
#blklst = [aip for aip in map(lambda ip: ipv4adrset(ip.text), root.iter('entry'))]
blklst = []
newips = []
try:
    with open(ipset_ufw, 'r', encoding='utf-8') as fi:
        for line in fi:
            if re.search(ipset_start_line, line):
                break
        for line in fi:
            res = re.match('^.+ ([0-9./]+) .*', line)
            if res:
                logger.debug(res[1])
                blklst.append(ipv4adrset(res[1]))
                newips.append(res[1])
            if re.search(ipset_end_line, line):
                break
except FileNotFoundError:
    logger.error('file not found! : %s' % (ipset_ufw))
    exit('file not found')
except PermissionError:
    logger.error('can\'t read %s, please run as superuser!' % (ipset_ufw))
    exit('permisson errro')

# 今回登場したblocklist候補を登録済でないものに絞る
iplist = list(filter(lambda ip: ip not in blklst, iplist))
iplist.sort(key = lambda x: x.ips)

# 新規分を表示
for k in iplist:
    s = '.'.join(map(lambda i: str(i), k.ips))
    if not args.orderck:
        logger.info('New record : %s (%d)' % (s, items[s]))

# 新規分がなければ終了
if len(iplist) == 0:
    if not (args.force or args.orderck):
        logger.info('no action')
        exit(0)

# ipset のIPアドレスリストに iplist を加える
#newips = [ip.text for ip in root.iter('entry')]
newips += map(lambda ip: str(ip), iplist)

# IPアドレスオーダーチェック
if args.orderck:
    checkmask = args.orderck[0]
    if checkmask < 1 or checkmask > 32:
        exit('mask number error')
    checkcount = args.orderck[1]
    if checkcount < 1:
        exit('count error')
    orderdict = {}
        
    for adr in map(lambda x: ipv4adrset(x), newips):
        hashadr = adr.set_mask(checkmask)   # マスクビットを設定する（対象の方が小さなマスクであれば無視）
        hashstr = str(hashadr)
        if args.debug:
            print(hashstr)
        if hashstr not in orderdict:
            orderdict[hashstr] = []
        orderdict[hashstr].append(adr)
                
    for key, itm in orderdict.items():
        #s = ':'.join(map(lambda x: str(x), itm))
        #print(str(key) + '  =>  ', s)
        if len(itm) >= checkcount:
            for i in itm:
                print(str(key), ' <= ', str(i))
            newips = list(map(lambda x: x[0] if len(x[1]) > 1 else str(x[1][0]), orderdict.items()))

    # order対象外の検出IPアドレスを除く
    newips = list(filter(lambda x: x not in map(lambda ip: str(ip), iplist), newips))

# IPアドレスソート：セグメント数値順
newips.sort(key=lambda x: ipv4adrset(x).ips)

# before.rules への追加行の作成
ipset_lines = '\n'.join(map(lambda x: '-A ufw-before-input -s ' + x + ' -j DROP' ,newips)) + '\n'

# アップデートフラグの場合は ipset/blocklist.xml を書き換えてサービス再起動
write_data = ''
try:
    with open(ipset_ufw, 'r', encoding='utf-8') as fi:
        for line in fi:
            write_data += line
            if re.search(ipset_start_line, line):
                write_data += ipset_lines
                break
        for line in fi:
            if re.search(ipset_end_line, line):
                write_data += line
                break
        for line in fi:
            write_data += line
except FileNotFoundError:
    logger.error('before.rules file not found!')
    exit(1)
except PermissionError:
    logger.error('can\'t write to before.rules please check permission!')
    exit(1)
if not args.update:
    # print(write_data)
    exit(0)
else:
    logger.info('update ufw before.rules')
    with open(ipset_ufw, 'w', encoding='utf-8') as fo:
        fo.write(write_data)
    subprocess.call(['/usr/sbin/ufw','reload'])

if args.none:
    exit(0)
