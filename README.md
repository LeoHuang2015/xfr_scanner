# xfr_scanner

a dns zone transfer vulnerability scanner

####漏洞说明  

DNS域传送漏洞参考：http://wiki.wooyun.org/server:zone-transfer  
 
漏洞示例:  
淘宝网dns域传送泄露漏洞: http://www.wooyun.org/bugs/wooyun-2010-0776  

实现:  
调用dnspython库进行xfr查询  
xfr查询比较耗时，把NS查询和xfr查询进行了分离，xfr使用多线程  


####运行效果展示
	
	[+]BEGIN DNS ZONE TRANSFER CHECK
	[-]domain file:domain.list | scan_thread:100
	[-]check result:
       		poc: dig @ns2.y8.com. y8.com axfr
	[+]find 1 vul, 1 domain
	time: 10.2813620567


####其他
bug反馈：452054281@qq.com
