
'''
1. 시스템 구조
1. Syslog 서버: 네트워크 장비나 시스템에서 발생하는 로그 메시지를 수집하는 서버입니다.
2. 데이터 파이프라인: 수집된 로그 데이터를 전처리하고, 분석을 위해 저장소로 전달합니다.
3. 데이터 저장소: 전처리된 데이터를 저장하는 데이터베이스나 파일 시스템입니다.
4. AI/ML 모델: 수집된 데이터를 학습하여 패턴을 인식하고, 이상 탐지나 예측 등을 수행하는 모델입니다.
5. 자동 설정 엔진: AI/ML 모델의 예측 결과를 바탕으로 시스템 설정을 자동으로 조정하는 엔진입니다.
'''

import socketserver
import pandas as pd
from datetime import datetime
import threading
import time
from netmiko import ConnectHandler

# 전역 리스트에 로그 데이터를 저장
log_data = []

# 네트워크 장비에 접속하여 CLI 명령을 실행하는 함수
def execute_cli_command(device_params, command):
    try:
        connection = ConnectHandler(**device_params)
        output = connection.send_command(command)
        connection.disconnect()
        return output
    except Exception as e:
        print(f"Error executing CLI command: {e}")

        return None

# syslog 메시지에서 "link up" 또는 "link down"을 감지하고 대응하는 함수
def handle_link_status(message, dev_ip_addr, interface):
    device_params = {
        'device_type': 'cisco_ios',
        'ip': dev_ip_addr,
        'username': 'root',
        'password': 'admin',
        'session_timeout': 120,
        'timeout': 120,
        'global_delay_factor': 2,
    }

    if "up" in message.lower():
        # 링크 업 이벤트 처리
        print(f"Link Up detected on interface {interface}, executing CLI command.")
        command = f'show interface status {interface}'  # CLI 명령
    elif "down" in message.lower():
        # 링크 다운 이벤트 처리
        print(f"Link Down detected on interface {interface}, executing CLI command.")
        command = f'show interface {interface}'  # CLI 명령
    else:
        print("No link status change detected.")
        return

    output = execute_cli_command(device_params, command)
    print(output)

# 로그 데이터 전처리 함수
def preprocess_log(log):
    try:
        pri = None
        if log.startswith('<'):
            parts = log.split('>', 1)
            pri = parts[0][1:]  # <PRI>에서 PRI 추출
            log = parts[1].strip()

        parts = log.split()

        # 전통적인 syslog 형식
        if len(parts) > 5 and ':' in parts[4]:
            timestamp = " ".join(parts[:3])
            host = parts[3]
            process = parts[4].split('[')[0]
            message = " ".join(parts[5:])
            timestamp = datetime.strptime(timestamp, "%b %d %H:%M:%S").replace(year=datetime.now().year)
            return {
                "pri": pri,
                "timestamp": timestamp,
                "host": host,
                "process": process,
                "message": message
            }
        # 날짜 형식이 포함된 로그 (예: RFC 5424 비슷한 형식)
        elif len(parts) > 6 and '-' in parts[0] and ':' in parts[1]:
            timestamp = " ".join(parts[:2])
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            host = parts[3]
            process = parts[4]
            message = " ".join(parts[5:])
            return {
                "pri": pri,
                "timestamp": timestamp,
                "host": host,
                "process": process,
                "message": message
            }
        # 기타 형식 (날짜가 포함되지 않은 경우)
        else:
            print(f"Skipping log due to missing timestamp: {log}")
            return None

    except Exception as e:
        print(f"Error processing log: {e}")
        return None

# CSV 파일로 저장하는 함수
def save_logs_to_csv():
    global log_data
    while True:
        if log_data:  # log_data 리스트에 로그가 있는 경우
            valid_logs = [log for log in log_data if preprocess_log(log['raw_message']) is not None]  # 리스트 컴프리헨션로 유효한 로그만 필터링
            if valid_logs:
                df = pd.DataFrame(valid_logs)
                df = df.apply(lambda row: preprocess_log(row['raw_message']), axis=1, result_type='expand')
                df.to_csv('syslog_data.csv', mode='a', header=False, index=False)
                print("Logs saved to syslog_data.csv")
            log_data = []  # csv 파일에 저장 후 리스트 초기화
        time.sleep(60)  # 60초마다 저장

# 메시지 분류 함수
def classify_message(message):
    words = message.split(". ")   # 공백과 '.' 제거
    interface = None
    for word in words:
        if 'up' in word.lower() or 'down' in word.lower():
            # 인터페이스 추출 (형식: "1/25")
            parts = message.split()
            for part in parts:
                if '/' in part:
                    interface = part
                    break
            return True, interface
    return False, None

# SyslogUDPHandler 클래스
class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        message = data.strip().decode('utf-8')
        print(f"Received syslog from {self.client_address[0]}: {message}")
        log_data.append({'raw_message': message})
        
        # 메시지 분류 및 handle_link_status 호출
        # Link up/down 등 이벤트를 체크 하여 조회 및 설정 CLI 실행. 
        is_classified, interface = classify_message(message)
        if is_classified:
            preprocessed_log = preprocess_log(message)  # Dictionary return
            if preprocessed_log:
                dev_ip_addr = self.client_address[0] # syslog 수신 주소를 사용.
                handle_link_status(preprocessed_log['message'], dev_ip_addr, interface)
            else:
                print("Message does not contain 'up' or 'down'.")

if __name__ == "__main__":
    HOST, PORT = "192.168.0.157", 514  # 514 포트 = Syslog Port
    
    # 로그 저장 스레드 시작
    threading.Thread(target=save_logs_to_csv, daemon=True).start()
    
    try:
        with socketserver.UDPServer((HOST, PORT), SyslogUDPHandler) as server:
            print(f"Syslog server started on {HOST}:{PORT}")
            server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer is shutting down gracefully.")
    except Exception as e:
        print(f"Error: {e}")
