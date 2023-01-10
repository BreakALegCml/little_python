# !/usr/bin/env python3
# _*_ coding:utf-8 _*_

import requests
import re
import json
import tldextract


requests.packages.urllib3.disable_warnings()

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0','Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8','Accept-Encoding': 'gzip, deflate','Upgrade-Insecure-Requests': '1'}
# 信息爬取模块''
def getInfo(ip):
    r = requests.get('http://api.webscan.cc/?action=query&ip=' +str(ip),headers=headers,timeout=60,verify=False)
    #ru = re.compile(r'{"domain":".*?","title":".*?"}')
    #res = ru.findall(r.text)
    res = r.text
    return res

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass
 
    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
 
    return False

def extract_domain(domain):
    suffix = {'.com','.la','.io', '.co', '.cn','.info', '.net', '.org','.me', '.mobi', '.us', '.biz', '.xxx', '.ca', '.co.jp', '.com.cn', '.net.cn', '.org.cn', '.mx','.tv', '.ws', '.ag', '.com.ag', '.net.ag', '.org.ag','.am','.asia', '.at', '.be', '.com.br', '.net.br', '.name', '.live', '.news', '.bz', '.tech', '.pub', '.wang', '.space', '.top', '.xin', '.social', '.date', '.site', '.red', '.studio', '.link', '.online', '.help', '.kr', '.club', '.com.bz', '.net.bz', '.cc', '.band', '.market', '.com.co', '.net.co', '.nom.co', '.lawyer', '.de', '.es', '.com.es', '.nom.es', '.org.es', '.eu', '.wiki', '.design', '.software', '.fm', '.fr', '.gs', '.in', '.co.in', '.firm.in', '.gen.in', '.ind.in', '.net.in', '.org.in', '.it', '.jobs', '.jp', '.ms', '.com.mx', '.nl','.nu','.co.nz','.net.nz', '.org.nz', '.se', '.tc', '.tk', '.tw', '.com.tw', '.idv.tw', '.org.tw', '.hk', '.co.uk', '.me.uk', '.org.uk', '.vg'}

    domain = domain.lower()
    names = domain.split(".")
    if len(names) >= 3:
        if ("."+".".join(names[-2:])) in suffix:
            return ".".join(names[-3:]), ".".join(names[:-3])
        elif ("."+names[-1]) in suffix:
            return ".".join(names[-2:]), ".".join(names[:-2])
    print ("New domain suffix found. Use tld extract domain...")

    pos = domain.rfind("/")
    if pos >= 0: # maybe subdomain contains /, for dns tunnel tool
        ext = tldextract.extract(domain[pos+1:])
        subdomain = domain[:pos+1] + ext.subdomain
    else:
        ext = tldextract.extract(domain)
        subdomain = ext.subdomain
    if ext.suffix:
        mdomain = ext.domain + "." + ext.suffix
    else:
        mdomain = ext.domain
    return mdomain[0]

def main():
    with open('./ip.txt',encoding='utf-8') as f:
        urltags=f.readlines()
        for urltag in urltags:
            urltag = urltag.split('\t')[-1]
            # print(urltag)
            full_urltag = urltag.strip()
            urltag = urltag.strip()
            urltag = urltag.replace('/n','')
            urltag = urltag.replace('https://','')
            urltag = urltag.replace('http://','')
            urltag = urltag.split(':')[0]

            print(urltag)
            # 判断是否是ip
            if is_number(urltag.split('.')[-1]):
                try:
                    res = getInfo(str(urltag))
                    if (res!='null'):
                        t=json.loads(res)
                        rjson=t[0]['domain']
                        Domain = extract_domain(rjson)[0]
                        if (len(Domain) == 1 and (not is_number(Domain))):
                            Domain = rjson

                        print("ip：" + full_urltag + '\t的全域名是：'+ '\t' + rjson + "\t根域名：\t" + Domain + '\n')
                        with open('./fanchaResult.txt','a') as f:
                            f.write("ip：" + full_urltag + '\t的全域名是：'+ '\t' + rjson + "\t根域名：\t" + Domain + '\n')
                            #f.write(rjson['domain']+'\n')
                except Exception as e:
                    print(e)
            # 域名直接输出根域名
            else:
                try:
                    Domain = extract_domain(urltag)
                    if (len(Domain) == 1 and (not is_number(Domain))):
                        Domain = rjson
                    print("ip：" + full_urltag + '\t的全域名是：' + '\t' + urltag + "\t根域名：\t" + Domain + '\n')
                    with open('./fanchaResult.txt','a') as f:
                        f.write("ip：" + full_urltag + '\t的全域名是：'+ '\t' + urltag + "\t根域名：\t" + Domain + '\n')   
                except:
                    pass
    # urltag='113.106.5.155'
    # res = getInfo(str(urltag))
    # print(res)
    # if (res!='null'):
    #     t=json.loads(res)
    #     rjson=t[0]
    #     print(rjson)
    # else:
    #     exit()



if __name__ == '__main__':
    main()
