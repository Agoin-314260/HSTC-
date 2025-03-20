import os
import re
import sys
import uuid
import socket
import base64
import requests
import subprocess
import win10toast
from bs4 import BeautifulSoup
from urllib.parse import quote
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5



"""===========账号配置==========="""
#账号
USERNAME = ""
#密码
PASSWORD = ""

"""===========账号配置==========="""



def get_local_ip():
    """获取本机内网IPv4地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"  # 默认回退地址


def get_mac_address():
    """获取本机MAC地址（无符号小写）"""
    mac = uuid.getnode()
    return "{:012x}".format(mac)


def get_default_gateway_ip():
    """获取默认网关IP（假设为接入点IP）"""
    try:
        # Windows 通过路由表获取默认网关
        result = subprocess.check_output(["route", "print", "0.0.0.0"], text=True, encoding="cp936")
        lines = result.split('\n')
        for line in lines:
            if "0.0.0.0" in line and "在链路上" not in line:
                parts = line.split()
                return parts[2]  # 网关IP
        return "192.168.2.33"  # 默认回退
    except Exception:
        return "192.168.2.33"  # 其他系统或异常


def get_access_point_name(ac_ip):
    """通过网关IP解析接入点名称（需预设或网络探测）"""
    # 示例：根据网关IP映射到预设名称
    ap_mapping = {
        "192.168.2.33": "CORE-RG-N18012",
        "10.0.0.1": "CORE-ROUTER-2",
        "172.16.0.1": "BACKUP-AP"
    }
    return ap_mapping.get(ac_ip, "UNKNOWN-AP")


def generate_login_url():
    # 动态获取本机信息
    ip = get_local_ip()
    mac = get_mac_address()
    ac_ip = get_default_gateway_ip()
    ac_name = get_access_point_name(ac_ip)

    # URL模板（动态填充所有参数）
    template = (
        "https://hscas.hstc.edu.cn/cas/login?"
        "service=http%3A%2F%2F192.168.2.34%3A801%2Feportal%2F%3Fc%3DCustom%26a%3Dlogin%26"
        "login_method%3D1%26wlan_user_ip%3D{ip}%26wlan_user_ipv6%3D%26"
        "wlan_user_mac%3D{mac}%26wlan_ac_ip%3D{ac_ip}%26"
        "wlan_ac_name%3D{ac_name}%26mac_type%3D1%26type%3D1&loginType=1"
    )

    # 替换参数并URL编码
    return template.format(
        ip=quote(ip),
        mac=quote(mac),
        ac_ip=quote(ac_ip),
        ac_name=quote(ac_name)
    )







#===============================下面不需要修改====================================#
def login_execution(login_url):
    # 获取登录页面的会话标识符
    print("=== 开始获取会话标识符 ===")
    try:
        # 获取登录页面
        login_page = requests.get(login_url)
        login_page.raise_for_status()  # 检查 HTTP 响应状态码（4xx/5xx 会触发异常）
        soup = BeautifulSoup(login_page.text, "html.parser")
        execution = soup.find("input", {"name": "execution"}).get("value")
        print(f"成功获取 execution: {execution}")
        #返回标识符
        return execution
    except requests.exceptions.RequestException as e:
        print(f"请求登录页面失败，原因：{e}")  # 处理网络请求相关异常（如连接超时、DNS 错误等）
    except AttributeError as e:
        print(f"解析页面时未找到 execution 元素，原因：{e}")  # 处理页面结构变化、元素缺失的异常
    except Exception as e:
        print(f"发生其他异常：{e}")  # 兜底处理其他未知异常





def get_public_key():
    #获取RSA公钥并打印调试信息
    CAS_URL = "https://hscas.hstc.edu.cn/"
    print("=== 获取RSA公钥 ===")
    url = f"{CAS_URL}cas/jwt/publicKey"
    try:
        #请求
        response = requests.get(url, timeout=5)
        #判断异常
        response.raise_for_status()
        #处理
        public_key = response.text.strip()
        print("成功获取公钥:", public_key)
        #返回key
        return public_key
    except requests.exceptions.RequestException as e:
        print("获取公钥失败:", e)
        return None




# 使用公钥加密登录信息
def rsa_encrypt(password, public_key):
    #使用RSA公钥加密密码并打印调试信息
    print("=== RSA加密密码 ===")
    print("明文密码:", password)

    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(password.encode())
    encrypted_password = ("__RSA__" + base64.b64encode(encrypted).decode())

    print("加密后的密码:", encrypted_password)
    return encrypted_password




#登录系统通知
def resource_path(relative_path):
    """ 获取资源路径 """
    if getattr(sys, 'frozen', False):  # 是否打包运行
        base_path = sys._MEIPASS  # 打包后的临时目录
    else:
        base_path = os.path.abspath(".")  # 当前脚本所在目录
    return os.path.join(base_path, relative_path)

def notice(text):
    print(text)
    tn = win10toast.ToastNotifier()
    tn.show_toast("校园网状态",text,icon_path = resource_path("HSTC.ico") ,duration=5)






def login(username, password,):
    """登录函数，并打印调试信息"""
    print("=== 开始登录流程 ===")
    #获取RSA公钥和加密
    encrypted_password = rsa_encrypt(password, get_public_key())
    login_url = generate_login_url()

    #请求配置
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "username": username,
        "password": encrypted_password,
        "currentMenu": 1,
        "_eventId": "submit",
        "submit": "Login1",
        "failN": 0,
        "execution": login_execution(login_url),
    }
    print("开始登录")
    response = requests.post(login_url, headers=headers, data=data)
    # 检查响应状态码
    if response.status_code == 200:
        #利用正则表达式匹配看是否正常登录
        pattern = r'<title>(.*?)</title>'
        match = re.search(pattern, response.text)
        if match:
            title = match.group(1)
            print("匹配到的标题是:", title)
            if title == "信息页":
                print('\033[42m重复登陆\033[0m')
                notice("重复登陆")

            elif title == "认证成功页":
                print('\033[42m成功登录\033[0m')
                notice('成功登录')

            else:
                print(title)

        else:
            print('\033[41m未找到标题\033[0m')
            print(response.text)
    elif response.status_code == 401:
        print('\033[41m账号密码错误\033[0m')
        notice('账号密码错误')

    else:
        print("请求失败，状态码:", response.status_code)

#判断是否为校园网
def check_internal_resource():
    campus_only_urls = [
        'http://rz.hstc.edu.cn/'
    ]
    for url in campus_only_urls:
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                return True
        except:
            continue
    return False
if check_internal_resource():
    login(USERNAME, PASSWORD)
else:
    notice('非校园网，取消连接')
