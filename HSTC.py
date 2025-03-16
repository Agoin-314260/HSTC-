import requests
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
from bs4 import BeautifulSoup
import base64
import re
# 配置
CAS_URL = "https://hscas.hstc.edu.cn/"
login_URL = "自己电脑登录的网址"
USERNAME = "自己的账号"
PASSWORD = "自己的密码"

def login_execution():
    # 获取登录页面的会话标识符
    print("=== 开始获取会话标识符 ===")
    try:
        # 获取登录页面
        login_page = requests.get(login_URL)
        login_page.raise_for_status()  # 检查 HTTP 响应状态码（4xx/5xx 会触发异常）
        soup = BeautifulSoup(login_page.text, "html.parser")
        execution = soup.find("input", {"name": "execution"}).get("value")
        print(f"成功获取 execution: {execution}")
        return execution
    except requests.exceptions.RequestException as e:
        print(f"请求登录页面失败，原因：{e}")  # 处理网络请求相关异常（如连接超时、DNS 错误等）
    except AttributeError as e:
        print(f"解析页面时未找到 execution 元素，原因：{e}")  # 处理页面结构变化、元素缺失的异常
    except Exception as e:
        print(f"发生其他异常：{e}")  # 兜底处理其他未知异常

def get_public_key():
    """获取RSA公钥并打印调试信息"""
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
        return public_key
    except requests.exceptions.RequestException as e:
        print("获取公钥失败:", e)
        return None
# 使用公钥加密登录信息
def rsa_encrypt(password, public_key):
    """使用RSA公钥加密密码并打印调试信息"""
    print("=== RSA加密密码 ===")
    print("明文密码:", password)

    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(password.encode())
    encrypted_password = ("__RSA__" + base64.b64encode(encrypted).decode())

    print("加密后的密码:", encrypted_password)
    return encrypted_password


def login():
    """登录函数，并打印调试信息"""
    print("=== 开始登录流程 ===")
    #获取RSA公钥和加密
    encrypted_password = rsa_encrypt(PASSWORD, get_public_key())
    #请求配置
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "username": USERNAME,
        "password": encrypted_password,
        "currentMenu": 1,
        "_eventId": "submit",
        "submit": "Login1",
        "failN": 0,
        "execution": login_execution(),
    }
    print("开始登录")
    response = requests.post(login_URL, headers=headers, data=data)
    # 检查响应状态码
    if response.status_code == 200:
        #利用正则表达式匹配看是否正常登录
        pattern = r'<title>(.*?)</title>'
        match = re.search(pattern, response.text)

        if match:
            title = match.group(1)
            print("匹配到的标题是:", title)
            if title == "信息页" :
               print("重复登陆")
            elif title == "认证成功页":
                print("成功登录")
            else:
                print(title)
        else:
            print("未找到标题")
        print(response.text)
    else:
        print("请求失败，状态码:", response.status_code)

login()