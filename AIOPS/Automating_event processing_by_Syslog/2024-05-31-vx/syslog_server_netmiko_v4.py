
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

# 장비에 접속하여 CLI 명령을 실행하는 함수
def execute_cli_command(device_params, command):
    try:
        connection = ConnectHandler(**device_params)
        output = connection.send_command(command)
        connection.disconnect()
        return output
    except Exception as e:
        print(f"Error executing CLI command: {e}")
        return None

# 이벤트 처리 함수
def handle_event(event_type, dev_ip_addr, interface=None):
    device_params = {
        'device_type': 'cisco_ios',
        'ip': dev_ip_addr,
        'username': 'root',
        'password': 'admin',
        'session_timeout': 120,
        'timeout': 120,
        'global_delay_factor': 2,
    }

    if event_type == 'link_up':
        print(f"<AI/ML> Link Up detected on interface {interface}, executing CLI command.")
        command = f'show interface transceiver {interface}'
        print()
    elif event_type == 'link_down':
        print(f"<AI/ML> Link Down detected on interface {interface}, executing CLI command.")
        command = f'show interface {interface}'
        print()
    elif event_type == 'cpu_load':
        print(f"<AI/ML> High CPU load detected, executing CLI command.")
        command = 'sh process'
        print()
    else:
        print("Unhandled event type.")
        return

    output = execute_cli_command(device_params, command)
    print(output)

# 로그 데이터 전처리 함수
def preprocess_log(log):
    try:
        if log.startswith('<'):
            pri_end_idx = log.index('>') + 1
            pri = log[:pri_end_idx]
            log = log[pri_end_idx:].strip()
        else:
            pri = None
        parts = log.split()

        # 날짜 형식이 포함된 로그 (예: 주어진 형식)
        if len(parts) >= 5 and '-' in parts[0] and ':' in parts[1]:
            timestamp = f"{parts[0]} {parts[1]}"
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            host = parts[3]
            process = parts[4]
            message = " ".join(parts[5:])
            return {
                "pri": pri,
                "timestamp": timestamp,
                "host": host,
                "process": process,  # 프로세스 정보가 없으므로 None으로 설정
                "message": message
            }
        # 기타 형식 (날짜가 포함되지 않은 경우)
        else:
            print(f"Skipping log due to unrecognized format: {log}")
            return None

    except Exception as e:
        print(f"Error processing log: {e}")
        return None

# # 테스트 로그 메시지
# log_message = "<181> 2024-03-11 02:03:50 GMT M6424 Base NOT SYS ttyS0 root 'sh system '"
# processed_log = preprocess_log(log_message)
# print(processed_log)


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
        time.sleep(60)  # 60초 마다 저장

# 메시지 분류 함수
def classify_message(message):
    interface = None
    print("[DEBUG] ", message)
    if 'up' in message.lower():
        event_type = 'link_up'
        interface = extract_interface(message)
    elif 'down.' in message.lower():
        event_type = 'link_down'
        interface = extract_interface(message)
    elif 'cpu-usage' in message.lower():
        event_type = 'cpu_load'
    else:
        event_type = None

    return event_type, interface

# 인터페이스 추출 함수
def extract_interface(message):
    processed_log = preprocess_log(message)
    if processed_log is not None:
        process_value = processed_log.get("process")
        return process_value
    return None

## 인터페이스 추출 함수
#def extract_interface(message):
#    parts = message.split()
#    for part in parts:
#        if '/' in part:
#            return part
#    return None

# SyslogUDPHandler 클래스
class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        message = data.strip().decode('utf-8')
        print(f"Received syslog from {self.client_address[0]}: {message}")
        ''' message를 Dic 형태로 raw_message Key의 값으로 log_data에 저장 '''
        log_data.append({'raw_message': message})  
        
        # 메시지 분류 및 이벤트 핸들러 호출
        event_type, interface = classify_message(message)
        print("[DEBUG] ", event_type)
        if event_type:
            preprocessed_log = preprocess_log(message)  # message를 5개 Dictionar로 분리하여 return
            if preprocessed_log:
                dev_ip_addr = self.client_address[0]  # syslog 수신 주소를 사용.
                handle_event(event_type, dev_ip_addr, interface)
        #     else:
        #         print("Preprocessing log failed.")
        # else:
        #     print("No relevant event detected in the message.")

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
