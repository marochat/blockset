#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys,os,glob
import argparse
import re
import numpy as np
#import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta, tzinfo
from lxml import etree as ET
import subprocess
# logrottateのgzipファイルに対応するため
import gzip

from logging import getLogger, StreamHandler, DEBUG, INFO

loggerLevel = INFO

# for logger おまじない
logger = getLogger(__name__)
handler = StreamHandler()
handler.setLevel(loggerLevel)
logger.setLevel(loggerLevel)
logger.addHandler(handler)
logger.propagate = False

maillog_default = "/var/log/mail.log"

ipset_file = "blocklist.xml"
ipset_ufw = "/etc/ufw/before.rules"
ipset_start_line = "blacklist-ipset-S"
ipset_end_line = "blacklist-ipset-E"

tz_jst = timezone(timedelta(hours=9), name='JST')

# 関数定義
def array_count(array):
    """リスト中の重複数を集計して、データと登場回数のタプルのリストを作成して返す
    """
    dat = {}
    for i in array:
        dat[i] = dat[i] + 1 if i in dat.keys() else 1
    return dat

# IPV4形式のデータを扱うクラス、ネットマスクがあれば/ビット数で保管
class ipv4adrset:
    """
    IPV4形式のデータを扱うクラス、xxx.xxx.xxx.xxx or xxx.xxx.xxx.xxx/m
    __eq__(): ネットマスクのビットのみで比較
            例) 192.168.0.5 と 192.168.0.0/24 は等しいとする
    """
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
            self.ips = [int(n) for n in ip.split('.')]
            self.msk = int(msk0)

    def set_mask(self, mask):
        if self.msk < mask:
            return self
        msks = [int('1'*n+'0'*(8-n), 2) for n in [8 if (mask - i*8) >= 8 else (mask - i*8) if (mask - i*8) > 0 else 0 for i in range(4)]]
        rip = list(np.array(self.ips) & np.array(msks))
        ret = ipv4adrset()
        ret.ips = rip
        ret.msk = mask
        return ret

    def __eq__(self, other):
        smsks = [int('1'*n+'0'*(8-n), 2) for n in [ 8 if (self.msk - i*8) >= 8 else (self.msk - i*8) if (self.msk - i*8) > 0 else 0 for i in range(4)]]
        omsks = [int('1'*n+'0'*(8-n), 2) for n in [ 8 if (other.msk - i*8) >= 8 else (other.msk - i*8) if (other.msk - i*8) > 0 else 0 for i in range(4)]]
        sip = list(np.array(self.ips) & np.array(smsks) & np.array(omsks))
        oip = list(np.array(other.ips) & np.array(smsks) & np.array(omsks))
        return sip == oip

    def __str__(self):
        return '.'.join(map(lambda i: str(i), self.ips)) + ('/' + str(self.msk) if self.msk < 32 else '')

    def __hash__(self):
        return self.ips[0] * 0x1000000 + self.ips[1] * 0x10000 + self.ips[2] * 0x100 + self.ips[3]

def int_tuple(str):
    """argparseで整数タプルの引数を読み取る関数"""
    t = tuple(map(lambda x: int(x), str.split(',')))
    return t

def ipv4adr(str):
    """ipv4adrset型の引数を読み取る関数"""
    a = ipv4adrset(str)
    return a

def readfile_info(readfunc):
    """読み出すファイル名をログ出力するデコレータ"""
    def wrapper(*arg):
        logger.info('use logfile : %s', arg[0])
        return readfunc(*arg)
    return wrapper

# mail.log から不正アクセスらしいIPアドレスを、リストに追加して返す
def pattern_func_maillog(lst, line):
    if res := re.match('^.+\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\].+ SASL [A-Z]+ authentication failed.*$', line):
        lst.append(res.group(1))
    if res := re.match('SSL_accept .+\[([0-9.]+)\]', line):
        lst.append(res.group(1))
    return lst

# ログファイルから不正アクセスらしいIPアドレスを取り出してリスト化する（gzipファイルはgzipモジュールのOPENを使用する）
# 切り出しパターンの分離バージョン
def get_iiplist(lfile, st, ed, pattern_func):
    mlogs = []
    if lfile is not None:
        mlogs = [lfile]
    else:
        mlogs = [x for x in glob.glob(maillog_default + '*') if re.match('.*(log|gz|[0-9])',x) and os.path.getmtime(x) > st.timestamp()]
        mlogs.sort(key=lambda x: os.path.getmtime(x))
    lst = []
    for logfile in mlogs:
        logger.info(logfile)
        try:
            with open(logfile, 'r', encoding='utf-8') if not re.search('\.gz$', logfile) else gzip.open(logfile, 'rt') as fh:
                for line in map(lambda ln: ln.rstrip('\n'), fh):
                    lst = pattern_func(lst, line)
        except FileNotFoundError:
            logger.error('file not found! : %s' % (logfile))
    return lst

# 現在設定中のblocklistをリスト化
#blklst = [aip for aip in map(lambda ip: ipv4adrset(ip.text), root.iter('entry'))]
def get_blocklist_ufw():
    blist = []
    try:
        with open(ipset_ufw, 'r', encoding='utf-8') as fi:
            for line in fi:
                if re.search(ipset_start_line, line):
                    break
            for line in fi:
                res = re.match('^-A ufw-before-input.+ ([0-9./]+) .*DROP.*', line)
                if res:
                    logger.debug(res[1])
                    blist.append(ipv4adrset(res[1]))
                    # newips.append(res[1])
                if re.search(ipset_end_line, line):
                    break
    except FileNotFoundError:
        logger.error('file not found! : %s' % (ipset_ufw))
        exit('file not found')
    except PermissionError:
        logger.error('can\'t read %s, please run as superuser!' % (ipset_ufw))
        exit('permisson errro')
    return blist

# IPアドレスオーダーチェック　変数チェック用デコレータ
def oderck_argck(orderck_func):
    def wrapper(*arg):
        checkmask = arg[2]
        checkcount = arg[3]
        if checkmask not in range(1,33):
            sys.exit('order mask error')
        if checkcount < 1:
            sys.exit('order check count error')
        return orderck_func(*arg)
    return wrapper

# IPアドレスオーダーチェック
@oderck_argck
def address_oder_check(newips, iplist, checkmask, checkcount, debug=False):
    orderdict = {}
    for adr in map(lambda x: ipv4adrset(x), newips):
        hashadr = adr.set_mask(checkmask)   # マスクビットを設定する（対象の方が小さなマスクであれば無視）
        hashstr = str(hashadr)
        if debug:
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
    return newips

# ブロックリストをアップデートする（ufw版）
def set_blocklist_ufw(newips):
    # before.rules への追加行の作成(ログ出力とDocker対応)
    ipset_lines = '\n'.join(map(lambda x: '-A ufw-before-input -s ' + x + ' -j LOG --log-prefix "[BLOCKLIST]"' ,newips)) + '\n'
    ipset_lines += '\n'.join(map(lambda x: '-A ufw-before-input -s ' + x + ' -j DROP' ,newips)) + '\n'
    ipset_lines += '\n'.join(map(lambda x: '-A DOCKER-USER -s ' + x + ' -j DROP' ,newips)) + '\n'
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
        logger.error('can\'t read before.rules please check permission!')
        exit(1)
    try:
        logger.info('update ufw before.rules')
        with open(ipset_ufw, 'w', encoding='utf-8') as fo:
            fo.write(write_data)
        subprocess.call(['/usr/sbin/ufw','reload'])
    except PermissionError:
        logger.error('can\'t write to before.rules please check permission!')
        exit(1)

def main():
    # オプション解析
    parser = argparse.ArgumentParser(description='blockset.py collection of unauthorized access list and restart firewall(ufw)')
    parser.add_argument('logfile', nargs='?', help='input log file default:' + maillog_default, default=None)
    parser.add_argument('-n', '--none', action='store_true', help='Check only mode.')
    parser.add_argument('-f', '--force', action='store_true', help='bloclist force update, unless new record.')
    parser.add_argument('-d', '--debug', action='store_true', help='debug print mode')
    parser.add_argument('-u', '--update', action='store_true', help='blocklist update and restart firewall(ufw)')
    parser.add_argument('-l', '--list', action='store_true', help='display blocklist')
    parser.add_argument('-o', '--orderck', type=int_tuple, metavar='MASK,COUNT', help='ipset order ckeck')
    parser.add_argument('-c', '--count', type=int, help='abuse count', default = 5)
    parser.add_argument('-a', '--address', type=ipv4adr, help='individually address entry to blacklist')
    parser.add_argument('-r', '--remove', type=ipv4adr, help='remove address entry from blacklist')
    parser.add_argument('-D', '--days', type=int, help='days of collection', default=1)

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
        logger.info('mask bits : %s' % str(args.orderck[0])) 
        logger.info('count     : %s' % str(args.orderck[1])) 

    now = datetime.now(tz_jst)
    st = (now - timedelta(days=args.days))
    ed = now

    siplist = get_iiplist(args.logfile, st, ed, pattern_func_maillog)

    if args.list:
        blklst = get_blocklist_ufw()
        logger.info("block list:")
        for ip in blklst:
            logger.info(ip)
        exit(0)

    # IPアドレス、登場回数のタプルリストにする
    items = array_count(siplist)
    if args.address:
        items[str(args.address)] = 100

    iplist = []

    # 対象ログに登場したIPアドレス集計を表示する（Debug）
    if args.debug:
        for k in items:
            logger.info('Redord : %s (%d)' % (k, items[k]))

    #一定数(5)以上の出現回数の物のみの IPV4アドレスリストを作成する
    iplist = list(map(lambda t: ipv4adrset(t[0]), filter(lambda t: t[1] >= args.count, items.items())))

    # firewall ipsetsのblocklist.xmlを解析する
    #tree = ET.parse(ipset_file)
    #root = tree.getroot()

    # 設定中のブロックリスト
    blklst = get_blocklist_ufw()
    newips = list(map(lambda x: str(x), blklst))

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
        if not (args.force or args.orderck or args.remove):
            logger.info('no action')
            exit(0)

    # ipset のIPアドレスリストに iplist を加える
    newips += map(lambda ip: str(ip), iplist)

    if args.remove:
        newips = [ip for ip in newips if ip != str(args.remove)]
        print('remove ip %s from blocklist' % str(args.remove))
        args.update = True
        #exit(0)

    # オーダーチェック(関数呼び出し後アドレスセグメントをキーにソート)
    if args.orderck:
        newips = sorted(address_oder_check(newips, iplist, args.orderck[0], args.orderck[1], args.debug), key=lambda x: ipv4adrset(x).ips)

    # ブロックリストの更新
    # アップデートフラグの場合は ipset/blocklist.xml を書き換えてサービス再起動
    if args.update:
        set_blocklist_ufw(newips)

if __name__ == '__main__':
    main()
