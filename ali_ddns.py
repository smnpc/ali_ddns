#! /usr/bin/python

from locale import setlocale, LC_COLLATE
from secrets import token_hex
from urllib.request import urlopen
from urllib.parse import quote
from time import strftime ,gmtime ,localtime
from hmac import new as hmac_new
from base64 import b64encode
from json import loads as json_loads

# 使用前请修改相关的参数

user_settings = {
        'DomainName':'yourdomain.com',                    #您的顶级域名
        'update_hosts':['@','www'],                                 #需要更新记录的“RR”值
        'ip_get_url':'http://ip.cip.cc',                                #获取外网IP地址的网址，可以自行更换，并根据具体的返回类型更新get_current_ip函数
        'AccessKeyId':'',                                                           #阿里提供的AccessKeyId，可在控制台设置和查找
        'AccessKeySec':'',                                                      #阿里提供的AccessKeySec，可在控制台设置和查找
        'DNSServer':'dns9.hichina.com',
        'ALiServerAddr':'alidns.aliyuncs.com',
}

basic_settings = {
        'AccessKeyId':user_settings['AccessKeyId'],
        'Format':'JSON',
	    'Version':'2015-01-09',	
	    'SignatureMethod' : 'HMAC-SHA1',
	    'SignatureVersion' : '1.0',
	    'Timestamp': '',
        'SignatureNonce': '',        
}

load_settings = {
        'Action':'DescribeDomainRecords',
	    'DomainName':user_settings['DomainName'],
}

update_settings = {
        'Action':'UpdateDomainRecord',
        'Type':'A',
	    'RR':'',
	    'RecordId':'',
	    'Value':'',
}

# 获取当前IP地址：

def get_current_ip(url):
    with urlopen(url) as u:
        raw_html =bytes.decode(u.readline()).rstrip('\n')
        ip_sections = raw_html.split('.')        
    if len(ip_sections) == 4 :
        for item in ip_sections :
            try:
                item = int(item)
                if item < 0 or item > 255 :
                    return False
            except Exception as e:
                log_tofile(e)
                return False           
        return raw_html        
    else: return False

    #URL拼接和生成:

def url_maker(actions ,bacics):
    storted_key = []
    addup_settings ={}
    url = []
    encoded_url = ''
    raw_url = ''
    for item in actions:
        addup_settings[item] = actions[item]
        storted_key.append(item)
    for item in bacics:
        addup_settings[item] = bacics[item]
        storted_key.append(item)
    setlocale(LC_COLLATE, 'C')
    storted_key = sorted(storted_key)
    for item in storted_key:
        encoded_url += quote(item)+'='+quote(addup_settings[item])+'&'
        raw_url += item+'='+addup_settings[item]+'&'
    url.append(encoded_url)
    url.append(raw_url)
    return url

    #生成带加密验证信息的url

def ser_maker(actions,bacics,users):
    bacics['Timestamp'] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
    bacics['SignatureNonce'] = token_hex(16)
    url = url_maker(actions,bacics)
    f_string = "GET&%2F&"+quote(url[0].rstrip('&'))
    h = hmac_new((users['AccessKeySec']+'&').encode(), f_string.encode(), digestmod='SHA1')
    h1 = b64encode(h.digest()).decode()
    return [url[0] + quote('Signature') + '=' + quote(h1), url,h1]


    # 得到已有的记录列表

def get_records(loads,bacics,users):
    ser_url = ser_maker(loads,bacics,users)
    get_url = 'https://'+user_settings['ALiServerAddr']+'/?'+ser_url[0]
    records = []
    with urlopen(get_url) as u :
        htmls = u.read().decode()
        js = json_loads(htmls)
        try:
            for item in js['DomainRecords']['Record']:
                records.append(item)
        except Exception as e:
            log_tofile(e)
    return records

# 更新记录

def update_records(updates,loads,bacics,users):
    ip = get_current_ip(users['ip_get_url'])
    if ip:
        log_tofile('got current IP:'+ip)
    else: 
        log_tofile('get ip failed!')
        return False
    record_list = get_records(loads,bacics,users)
    log_tofile('got record_list!' + str(len(record_list))+ ' records inside.')
    RR_list = users['update_hosts']
    for item in record_list:
        if item['RR'] in RR_list and item['Type'] == 'A':
            if item['Value'] == ip:
                log_tofile('No update, IP of -' + item['RR'] + '- is ' + item['Value'])
            else: 
                updates['RR'] = item['RR']
                updates['RecordId'] = item['RecordId']
                updates['Value'] = ip
                ser_url = ser_maker(updates,bacics,users)
                get_url = 'https://'+user_settings['ALiServerAddr']+'/?'+ser_url[0]
                with urlopen(get_url) as u:
                    log_tofile('The record of RR='+item['RR']+' is updated to --'+ip+ '--and got response of: '+u.read().decode())
        else: log_tofile('Record: '+ item['RR'] + ' IP: '+ item['Value'] + ' Type: ' + item['Type'] + ' is not in update list!')

#日志记录

def log_tofile(text):
    print(text)
    with open('./ali_ddns.log','a+') as f:
        f.writelines(strftime("%Y-%m-%d-%H:%M:%S", localtime())+':')
        f.writelines(text+'\n')

update_records(update_settings,load_settings,basic_settings,user_settings)
