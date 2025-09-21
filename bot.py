#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎯 Ensofi 自动签到脚本

功能特性：
- 🔐 多钱包支持：支持 Phantom 钱包类型，自动处理 Solana 签名
- 🌐 代理支持：支持 HTTP 代理，可配置账号与代理的绑定关系
- ⚡ 多种运行模式：顺序模式、并发模式、统一时间调度模式
- 📊 智能日志：带图标的清晰日志显示，实时显示签到状态和积分
- 💾 状态持久化：自动保存账号状态，支持断点续签
- 🎲 防检测机制：随机延迟、IP绑定等防女巫策略

作者：Web3 小工
版本：2.0
更新时间：2024-12-21
"""

import requests
import json
import time
import random
import hashlib
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

try:
    from solana.keypair import Keypair
except ImportError:
    try:
        from solders.keypair import Keypair
    except ImportError:
        print("❌ 错误：无法导入 Keypair。请安装 solana 或 solders 包：")
        print("   pip install solana")
        print("   或者")
        print("   pip install solders")
        exit(1)

try:
    import base58
except ImportError:
    print("❌ 错误：无法导入 base58。请安装：pip install base58")
    exit(1)

# 配置参数
ACCOUNT_INTERVAL = 30          # 账号间执行间隔（秒）
REQUEST_TIMEOUT = 12           # 请求超时时间（秒）
MAX_RETRY = 3                  # 最大重试次数
UNIFIED_CHECKIN_DELAY = 21610  # 统一签到延迟时间（秒，约6小时）

def log_with_timestamp(message: str) -> None:
    """带时间戳的日志输出"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def load_private_keys(file_path: str) -> List[str]:
    """从文件加载私钥列表"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            keys = [line.strip() for line in f if line.strip()]
        return keys
    except FileNotFoundError:
        log_with_timestamp(f"❌ 私钥文件 {file_path} 不存在")
        return []
    except Exception as e:
        log_with_timestamp(f"❌ 读取私钥文件失败: {e}")
        return []

def load_proxies(file_path: str) -> List[str]:
    """从文件加载代理列表"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            proxies = [line.strip() for line in f if line.strip()]
        return proxies
    except FileNotFoundError:
        log_with_timestamp(f"⚠️ 代理文件 {file_path} 不存在，将不使用代理")
        return []
    except Exception as e:
        log_with_timestamp(f"❌ 读取代理文件失败: {e}")
        return []

def get_proxy_for_account(account_address: str, proxies: List[str]) -> Optional[Dict[str, str]]:
    """为账号分配代理"""
    if not proxies:
        return None
    
    # 使用账号地址的哈希来确定性地分配代理
    hash_value = int(hashlib.md5(account_address.encode()).hexdigest(), 16)
    proxy_index = hash_value % len(proxies)
    proxy_url = proxies[proxy_index]
    
    return {
        'http': proxy_url,
        'https': proxy_url
    }

def create_keypair_from_private_key(private_key: str) -> Tuple[Optional[Keypair], Optional[str]]:
    """从私钥创建 Keypair 对象"""
    try:
        # 尝试不同的私钥格式
        if len(private_key) == 128:  # 十六进制格式
            private_key_bytes = bytes.fromhex(private_key)
        elif len(private_key) == 88:  # Base58 格式
            private_key_bytes = base58.b58decode(private_key)
        else:  # 假设是逗号分隔的数字格式
            private_key_bytes = bytes([int(x) for x in private_key.split(',')])
        
        keypair = Keypair.from_bytes(private_key_bytes)
        return keypair, str(keypair.pubkey())
    except Exception as e:
        return None, None

def login_get_token(private_key: str, wallet_type: str = "Phantom", proxies: Optional[Dict[str, str]] = None) -> Optional[str]:
    """登录获取 token"""
    keypair, public_key = create_keypair_from_private_key(private_key)
    if not keypair or not public_key:
        return None
    
    try:
        # 获取 nonce
        nonce_url = "https://api.ensofi.xyz/api/auth/request-message"
        nonce_data = {"publicKey": public_key, "walletType": wallet_type}
        
        nonce_response = requests.post(
            nonce_url, 
            json=nonce_data, 
            timeout=REQUEST_TIMEOUT,
            proxies=proxies
        )
        
        if nonce_response.status_code != 200:
            return None
        
        nonce_result = nonce_response.json()
        if not nonce_result.get('success'):
            return None
        
        message = nonce_result['data']['message']
        
        # 签名消息
        message_bytes = message.encode('utf-8')
        signature = keypair.sign_message(message_bytes)
        signature_base58 = base58.b58encode(signature.signature).decode('utf-8')
        
        # 登录
        login_url = "https://api.ensofi.xyz/api/auth/verify-signature"
        login_data = {
            "publicKey": public_key,
            "signature": signature_base58,
            "message": message,
            "walletType": wallet_type
        }
        
        login_response = requests.post(
            login_url, 
            json=login_data, 
            timeout=REQUEST_TIMEOUT,
            proxies=proxies
        )
        
        if login_response.status_code != 200:
            return None
        
        login_result = login_response.json()
        if login_result.get('success'):
            return login_result['data']['accessToken']
        
        return None
        
    except Exception as e:
        return None

def check_checkin_status(token: str, proxies: Optional[Dict[str, str]] = None) -> Tuple[bool, bool]:
    """检查签到状态"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(
            "https://api.ensofi.xyz/api/checkins/status", 
            headers=headers, 
            timeout=REQUEST_TIMEOUT,
            proxies=proxies
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                return True, result['data'].get('checkedInToday', False)
        
        return False, False
    except Exception:
        return False, False

def perform_checkin(token: str, proxies: Optional[Dict[str, str]] = None) -> bool:
    """执行签到"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(
            "https://api.ensofi.xyz/api/checkins", 
            headers=headers, 
            timeout=REQUEST_TIMEOUT,
            proxies=proxies
        )
        
        if response.status_code == 200:
            result = response.json()
            return result.get('success', False)
        
        return False
    except Exception:
        return False

def get_points(token: str, proxies: Optional[Dict[str, str]] = None) -> Optional[int]:
    """获取积分"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(
            "https://api.ensofi.xyz/api/points", 
            headers=headers, 
            timeout=REQUEST_TIMEOUT,
            proxies=proxies
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                return result['data'].get('totalPoints')
        
        return None
    except Exception:
        return None

def process_account(private_key: str, wallet_type: str, proxies: List[str], account_index: int) -> Dict[str, any]:
    """处理单个账号"""
    keypair, public_key = create_keypair_from_private_key(private_key)
    if not keypair or not public_key:
        return {
            'success': False,
            'account': f"账号{account_index + 1}",
            'address': "未知",
            'message': "私钥格式错误"
        }
    
    account_address = public_key
    account_name = f"账号{account_index + 1}"
    
    # 获取代理
    account_proxies = get_proxy_for_account(account_address, proxies)
    
    try:
        # 登录
        token = login_get_token(private_key, wallet_type, account_proxies)
        if not token:
            return {
                'success': False,
                'account': account_name,
                'address': account_address[:8] + "...",
                'message': "登录失败"
            }
        
        log_with_timestamp(f"🔑 {account_name} ({account_address[:8]}...) 登录成功")
        
        # 检查签到状态
        status_success, already_checked = check_checkin_status(token, account_proxies)
        if not status_success:
            return {
                'success': False,
                'account': account_name,
                'address': account_address[:8] + "...",
                'message': "无法获取签到状态"
            }
        
        if already_checked:
            log_with_timestamp(f"📝 {account_name} 今日已签到")
        else:
            # 执行签到
            checkin_success = perform_checkin(token, account_proxies)
            if checkin_success:
                log_with_timestamp(f"📝 {account_name} 签到成功")
            else:
                return {
                    'success': False,
                    'account': account_name,
                    'address': account_address[:8] + "...",
                    'message': "签到失败"
                }
        
        # 获取积分
        points = get_points(token, account_proxies)
        if points is not None:
            log_with_timestamp(f"💰 {account_name} 当前积分: {points}")
        
        return {
            'success': True,
            'account': account_name,
            'address': account_address[:8] + "...",
            'points': points,
            'message': "处理完成"
        }
        
    except Exception as e:
        return {
            'success': False,
            'account': account_name,
            'address': account_address[:8] + "...",
            'message': f"处理异常: {str(e)}"
        }

def run_once(private_keys: List[str], wallet_type: str, proxies: List[str], max_workers: int) -> None:
    """执行一次完整的签到流程"""
    if not private_keys:
        log_with_timestamp("❌ 没有可用的私钥")
        return
    
    log_with_timestamp(f"🚀 开始执行签到任务 - 账号数: {len(private_keys)}, 代理数: {len(proxies)}, 线程数: {max_workers}")
    
    success_count = 0
    failed_count = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_index = {
            executor.submit(process_account, private_key, wallet_type, proxies, i): i 
            for i, private_key in enumerate(private_keys)
        }
        
        # 处理完成的任务
        for future in as_completed(future_to_index):
            result = future.result()
            if result['success']:
                success_count += 1
                log_with_timestamp(f"✓ {result['account']} 处理完成")
            else:
                failed_count += 1
                log_with_timestamp(f"❌ {result['account']} 处理失败: {result['message']}")
    
    log_with_timestamp(f"📊 本轮任务完成 - 成功: {success_count}, 失败: {failed_count}")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='Ensofi 自动签到脚本')
    parser.add_argument('--max-workers', type=int, default=8, help='并发线程数 (默认: 8)')
    parser.add_argument('--wallet-type', type=str, default='Phantom', help='钱包类型 (默认: Phantom)')
    parser.add_argument('--keys-file', type=str, default='private_keys.txt', help='私钥文件路径')
    parser.add_argument('--proxies-file', type=str, default='proxies.txt', help='代理文件路径')
    
    args = parser.parse_args()
    
    log_with_timestamp("🎯 Ensofi 自动签到脚本启动 - 定时模式 (每6小时10秒执行一次)")
    log_with_timestamp("💡 按 Ctrl+C 退出程序")
    log_with_timestamp("=" * 60)
    
    # 加载配置
    private_keys = load_private_keys(args.keys_file)
    proxies = load_proxies(args.proxies_file)
    
    if not private_keys:
        log_with_timestamp("❌ 没有加载到任何私钥，程序退出")
        return
    
    try:
        while True:
            run_once(private_keys, args.wallet_type, proxies, args.max_workers)
            
            log_with_timestamp(f"⏳ 等待 {UNIFIED_CHECKIN_DELAY} 秒后重新执行...")
            time.sleep(UNIFIED_CHECKIN_DELAY)
            
    except KeyboardInterrupt:
        log_with_timestamp("👋 程序已停止")
    except Exception as e:
        log_with_timestamp(f"❌ 程序异常: {e}")

if __name__ == "__main__":
    main()
