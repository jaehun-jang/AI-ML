
'''
1. 시스템 구조
1. Syslog 서버: 네트워크 장비나 시스템에서 발생하는 로그 메시지를 수집하는 서버입니다.
2. 데이터 파이프라인: 수집된 로그 데이터를 전처리하고, 분석을 위해 저장소로 전달합니다.
3. 데이터 저장소: 전처리된 데이터를 저장하는 데이터베이스나 파일 시스템입니다.
4. AI/ML 모델: 수집된 데이터를 학습하여 패턴을 인식하고, 이상 탐지나 예측 등을 수행하는 모델입니다.
5. 자동 설정 엔진: AI/ML 모델의 예측 결과를 바탕으로 시스템 설정을 자동으로 조정하는 엔진입니다.
'''
import pandas as pd
import time
import threading
from datetime import datetime
from netmiko import ConnectHandler
import socketserver
import pyautogui

# 전역 리스트에 로그 데이터를 저장
log_data = []

# 장비에 접속하여 CLI 명령을 실행하는 함수
def execute_cli_command(device_params, commands, cmd_type):
    try:
        connection = ConnectHandler(**device_params)
        outputs = []
        if commands:
            if cmd_type == "get":
                for command in commands:
                    output = connection.send_command(command)
                    outputs.append(output)
            elif cmd_type == "set":
                connection.enable()
                output = connection.send_config_set(commands)
                outputs.append(output)
            connection.disconnect()
            return outputs
    except Exception as e:
        print(f"Error executing CLI command: {e}")
        return None

# 이벤트 처리 및 파일 저장 함수
def handle_event(event_type, message, dev_ip_addr, interface=None):
    device_params = {
        'device_type': 'cisco_ios',
        'ip': dev_ip_addr,
        'username': 'root',
        'password': 'admin',
        'session_timeout': 120,
        'timeout': 120,
        'global_delay_factor': 2,
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_base_name = f"{event_type}_{timestamp}"
    
    get_commands = set_commands = get_outputs = set_outputs =[]
    if event_type == 'link_up':
        print(f"Link Up detected on interface {interface}, executing CLI command.")
        get_commands = [
            f'show interface status {interface}',
            f'show interface {interface}'
        ]
        set_commands = [
            f'interface 1/1',
            f'shutdown'
        ]
        get_outputs = execute_cli_command(device_params, get_commands, "get")
        set_outputs = execute_cli_command(device_params, set_commands, "set")
    elif event_type == 'link_down':
        print(f"Link Down detected on interface {interface}, executing CLI command.")
        get_commands = [f'show interface status {interface}']
        set_commands = []
        get_outputs = execute_cli_command(device_params, get_commands, "get")
        set_outputs = execute_cli_command(device_params, set_commands, "set")
    elif event_type == 'cpu_load':
        print(f"High CPU load detected, executing CLI command.")
        get_commands = ['show processes cpu']
        set_commands = []
        get_outputs = execute_cli_command(device_params, get_commands, "get")
        set_outputs = execute_cli_command(device_params, set_commands, "set")
    else:
        print("Unhandled event type.")
        return

    # get_outputs와 set_outputs가 None인 경우 빈 리스트로 초기화
    get_outputs = get_outputs if get_outputs is not None else []
    set_outputs = set_outputs if set_outputs is not None else []

    combined_output = ("\n" + "-" * 70 + "\n").join(get_outputs + set_outputs) if get_outputs or set_outputs else None
    print(combined_output)
    

    # 로그 데이터를 텍스트 파일로 저장
    save_log_to_text_file(file_base_name, event_type, message, combined_output)

# 텍스트 파일 저장 함수
def save_log_to_text_file(file_base_name, event_type, message, output):
    try:
        with open(f'{file_base_name}.txt', 'a') as txt_file:
            txt_file.write(f"Event: {event_type}\n")
            txt_file.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            txt_file.write(f"Log Message: {message}\n")
            txt_file.write(f"CLI Output: {output}\n\n")
        print(f"Log saved to {file_base_name}.txt")
    except Exception as e:
        print(f"Error saving log to text file: {e}")

# CSV 파일로 로그 데이터를 저장하는 함수
def save_logs_to_csv():
    global log_data
    while True:
        if log_data:  # log_data 리스트에 로그가 있는 경우
            # 리스트 컴프리헨션으로 유효한 로그만 필터링
            valid_logs = [log for log in log_data if preprocess_log(log['raw_message']) is not None]
            if valid_logs:
                df = pd.DataFrame(valid_logs)
                df = df.apply(lambda row: preprocess_log(row['raw_message']), axis=1, result_type='expand')

                # process 값의 앞쪽에 '를 추가하는 처리
                if 'process' in df.columns:
                    df['process'] = df['process'].apply(lambda x: f"'{x}" if pd.notna(x) else x)

                df.to_csv('syslog_data.csv', mode='a', header=False, index=False)
                print("Logs saved to syslog_data.csv")
            log_data = []  # csv 파일에 저장 후 리스트 초기화
        time.sleep(60)  # 60초마다 저장

# 로그 데이터 전처리 함수
def preprocess_log(log):
    try:
        if log.startswith('<'):
            pri_end_idx = log.index('>') + 1
            pri = log[:pri_end_idx]
            log = log[pri_end_idx:].strip()
        else:
            pri = None
        parts = log.split(maxsplit=5)

        # 날짜 형식이 포함된 로그 (예: 주어진 형식)
        if len(parts) >= 6 and '-' in parts[0] and ':' in parts[1]:
            timestamp = f"{parts[0]} {parts[1]}"
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            host = parts[3]
            process = parts[4]
            message = parts[5]
            return {
                "pri": pri,
                "timestamp": timestamp,
                "host": host,
                "process": process,
                "message": message
            }
        # 기타 형식 (날짜가 포함되지 않은 경우)
        else:
            print(f"Skipping log due to unrecognized format: {log}")
            return None

    except Exception as e:
        print(f"Error processing log: {e}")
        return None

# 메시지 분류 함수
def classify_message(message):
    interface = None

    if 'interface is up' in message.lower():
        event_type = 'link_up'
        interface = extract_interface(message)
    elif 'interface is down' in message.lower():
        event_type = 'link_down'
        interface = extract_interface(message)
    elif 'cpu load' in message.lower():
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

# SyslogUDPHandler 클래스
class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request # self.request[0]은 데이터, self.request[1]은 소켓
        message = data.strip().decode('utf-8')
        print(f"Received syslog from {self.client_address[0]}: {message}")
        log_data.append({'raw_message': message})

        # 메시지 분류 및 이벤트 핸들러 호출
        event_type, interface = classify_message(message)
        if event_type:
            dev_ip_addr = self.client_address[0]  # syslog 수신 주소를 사용.
            handle_event(event_type, message, dev_ip_addr, interface)
        else:
            return None

if __name__ == "__main__":
    PORT = 514
    HOST = pyautogui.prompt("ENTER THE IP ADDRESS: ",' START AUTOMATION SERVER ',default = '127.0.0.1')
#    HOST, PORT = "192.168.0.157", 514  # 514 포트 = Syslog Port

    # 로그 저장 스레드 시작
    threading.Thread(target=save_logs_to_csv, daemon=True).start()

    # 시스로그 서버 시작
    try:
        with socketserver.UDPServer((HOST, PORT), SyslogUDPHandler) as server:
            print(f"Syslog server started on {HOST}:{PORT}")
            server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer is shutting down gracefully.")
    except Exception as e:
        print(f"Error: {e}")
