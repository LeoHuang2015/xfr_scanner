#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""a dns zone transfer vulnerability scanner"""

'''
Author: Leo Huang
Date: 15/7/30
Feedback: 452054281@qq.com

详细说明
DNS域传送漏洞：http://wiki.wooyun.org/server:zone-transfer
漏洞示例：
    淘宝网dns域传送泄露漏洞  http://www.wooyun.org/bugs/wooyun-2010-0776
实现：
    dnspython进行xfr查询
    xfr查询比较耗时，所以把NS查询和xfr分离，xfr使用多线程
'''

import threading
import Queue
import time
import random
import dns.resolver, dns.zone


class AxfrChecker(threading.Thread):
    '''
    multithreading checker
    '''
    def __init__(self, input_queue, output_queue):
        threading.Thread.__init__(self)
        self.input_queue = input_queue
        self.output_queue = output_queue

    def run(self):
        while True:
            try:
                domain, ns = self.input_queue.get()
                #print domain, ns
                check_result = axfr_check(domain, ns)
                self.input_queue.task_done()
                if check_result:
                    self.output_queue.put([domain, ns])

            except Exception, e:
                #print "[Exception]", e
                break

def get_ns_server(domain):
    """
    Get NS Server
    """
    ns_server = set()
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        # 使用阿里DNS服务器，效果不咋滴
        #resolver.nameservers = ["223.5.5.5", "223.6.6.6"]

        answers = resolver.query(domain, "NS")
        #answers = dns.resolver.query(domain, "NS")
        if answers:
            for answer in answers:
                #print answer
                ns_server.add(str(answer))
    except Exception, e:
        print "[-]get ns server error! try: dig %s NS +short" %(domain) , str(e)

    return ns_server

def axfr_check(domain, ns):
    '''
    try to get axfr info. the core function axfr check, the same as: dig @ns domain axfr
    :param domain: check domain
    :param ns: NS server
    :return:
    '''

    has_zone_transfer = False

    try:
        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain, timeout=5, lifetime=10))
        if zone:
            has_zone_transfer = True

            # get detail info
            #for name, node in zone.nodes.items():
            #    rdatasets = node.rdatasets
            #    for rdataset in rdatasets:
            #        print "\t", name, rdataset

    except Exception, e:
        #print "[get xfr error]", domain, "\t", ns, str(e)
        pass

    return has_zone_transfer

def test_process():
    '''
    a simple testing for scan process
    :return:
    '''
    domain = "sporx.com"
    domain = "turbobit.net"    # 获取数据不稳定

    ns_server = get_ns_server(domain)
    print "begin get axfr", len(ns_server), ns_server

    for ns in ns_server:
        result = axfr_check(domain, ns)
        if result:
            print "check: dig @%s %s axfr" %(ns, domain)


def multi_axfr_check(domain_list, threads_num):
    '''
    Workflow: multithreading check
    :param domain_list:
    :param thread_num:
    :return:
    '''

    work_queue = Queue.Queue()
    out_queue = Queue.Queue()
    rtn_list = []
    for target in domain_list:
        ns_server = get_ns_server(target)
        for ns in ns_server:
            work_queue.put([target, ns])

    threads = []
    for i in range(threads_num):
        t = AxfrChecker(work_queue, out_queue)
        threads.append(t)
        t.setDaemon(True)
        t.start()

    work_queue.join()
    while out_queue.qsize() > 0:
        rtn_list.append(out_queue.get())

    return rtn_list

def dns_zone_check(domain_file, threads_num):
    '''
    :param domain_file:
    :param threads_num:
    :return:
    '''

    check_result = []
    ct = 0
    vul_domain = set()

    chunk = 8192
    _ = open(domain_file, 'r')

    print "[+]BEGIN DNS ZONE TRANSFER CHECK"
    print "[-]domain file:%s | scan_thread:%s" %(domain_file, threads_num)

    while 1:
        lines = _.readlines(chunk)
        if not lines:
            break

        domain_list = [domain.strip() for domain in lines if domain.strip()]
        tmp_result = multi_axfr_check(domain_list, threads_num)
        check_result.extend(tmp_result)

    print "[-]check result:"
    for domain, ns in check_result:
        print "\tpoc: dig @%s %s axfr" %(ns, domain)
        ct += 1
        vul_domain.add(domain)

    print "[+]find %s vul, %s domain" %(ct, len(vul_domain))

if __name__ == '__main__':

    bg_time = time.time()

    #test_process()

    scan_threads_num = 100
    domain_list_file = "domain.list"

    dns_zone_check(domain_list_file, scan_threads_num)


    print "time:", time.time() - bg_time
