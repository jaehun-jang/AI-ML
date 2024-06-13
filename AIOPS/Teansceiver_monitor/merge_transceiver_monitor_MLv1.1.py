import re
import time
import threading
from datetime import datetime
from collections import defaultdict
import pandas as pd
from netmiko import ConnectHandler
import socketserver
import pyautogui
from sklearn.ensemble import RandomForestClassifier
import numpy as np

log_data = []
network_state = {'link_status': 'up', 'link_event': 0}
network_state_lock = threading.Lock()

# 임계값 설정
TX_POWER_THRESHOLD = -3.0
RX_POWER_THRESHOLD = -8.0
FCS_ERROR_THRESHOLD = 100

# collected_data 변수 초기화
collected_data = []

# 머신 러닝 모델 초기화
model = RandomForestClassifier()
model_trained = False

def connect_device(host):
    device = {
        'device_type': 'cisco_ios',
        'host': host,
        'username': 'root',
        'password': 'admin',
        'port': 22,  # 기본 SSH 포트
        'secret': 'your_enable_password',  # 필요 시
    }
    return ConnectHandler(**device)

# Transceiver 정보 수집
def read_cli_and_write_to_csv(m_box):
    global collected_data
    filename = 'network_stats.csv'
    while True:
        child = connect_device(m_box)
        results = gather_network_stats(child)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with network_state_lock:
            link_event = network_state['link_event']
            link_status = network_state['link_status']
        data_to_write = {
            'Timestamp': timestamp,
            'Vendor': results['Vendor'],
            'Part No': results['Part No'],
            'Tx Power (dBm)': results['Tx Power (dBm)'],
            'Rx Power (dBm)': results['Rx Power (dBm)'],
            'FCS Error': results['FCS Error'],
            'Input Dropped': results['Input Dropped'],
            'Output Dropped': results['Output Dropped'],
            'Link Event Count': link_event,
            'Link Status': link_status
        }
        write_to_csv(filename, data_to_write)
        
        # 수집된 데이터를 collected_data에 추가
        collected_data.append(data_to_write)        
        print("[DEBUG] collected_data: ", len(collected_data))

        # 임계값 체크 및 이벤트 트리거
        check_thresholds_and_trigger_event(results, m_box, interface='1/1')
        
        if model_trained == True:
            print("[DEBUG] Starting prediction")    
            # 머신 러닝 모델 예측
            predict_link_down(results)

        child.disconnect()
        time.sleep(60)  # 1분 간격으로 실행

def gather_network_stats(child):
    results = defaultdict(lambda: None)

    read_Int_Transceiver = child.send_command("sh interface transceiver 1/1")   
    read_Interface = child.send_command("sh interface 1/1")      
    
    vendor_pattern = r"Vendor\s+:\s+(\w+)"
    part_no_pattern = r"Part No.\s+:\s+(\w+)"
    txrx_power_pattern = r"Tx/Rx Pwr\s+:\s+(-?\d{1,2}\.\d) dBm\s*,\s*(-?\d{1,2}\.\d) dBm"       
    fcs_pattern = r"FCS error\s+(\d+)"
    input_dropped_pattern = r"input packets.*?dropped\s+(\d+)"
    output_dropped_pattern = r"output packets.*?dropped\s+(\d+)"

    vender_match = re.search(vendor_pattern, read_Int_Transceiver)
    part_no_match = re.search(part_no_pattern, read_Int_Transceiver)
    txrx_power_match = re.search(txrx_power_pattern, read_Int_Transceiver)
    fcs_error_match = re.search(fcs_pattern, read_Interface)
    input_dropped_match = re.search(input_dropped_pattern, read_Interface)
    output_dropped_match = re.search(output_dropped_pattern, read_Interface)

    results['Vendor'] = vender_match.group(1) if vender_match else None
    results['Part No'] = part_no_match.group(1) if part_no_match else None
    if txrx_power_match:
        results['Tx Power (dBm)'] = float(txrx_power_match.group(1))
        results['Rx Power (dBm)'] = float(txrx_power_match.group(2))
    else:
        results['Tx Power (dBm)'] = None
        results['Rx Power (dBm)'] = None
    results['FCS Error'] = int(fcs_error_match.group(1)) if fcs_error_match else None
    results['Input Dropped'] = int(input_dropped_match.group(1)) if input_dropped_match else None
    results['Output Dropped'] = int(output_dropped_match.group(1)) if output_dropped_match else None
    
    return results

def check_thresholds_and_trigger_event(results, dev_ip_addr, interface):
    if results['Tx Power (dBm)'] is not None and results['Tx Power (dBm)'] < TX_POWER_THRESHOLD:
        handle_event('tx_power_low', f'Tx Power below threshold: {results["Tx Power (dBm)"]} dBm', dev_ip_addr, interface)
    if results['Rx Power (dBm)'] is not None and results['Rx Power (dBm)'] < RX_POWER_THRESHOLD:
        handle_event('rx_power_low', f'Rx Power below threshold: {results["Rx Power (dBm)"]} dBm', dev_ip_addr, interface)
    if results['FCS Error'] is not None and results['FCS Error'] > FCS_ERROR_THRESHOLD:
        handle_event('fcs_error_high', f'FCS Error above threshold: {results["FCS Error"]}', dev_ip_addr, interface)

def write_to_csv(filename, data):
    df = pd.DataFrame([data])
    df.to_csv(filename, mode='a', header=not pd.io.common.file_exists(filename), index=False)

    # CSV 파일로 저장된 후 network_state['link_event'] 초기화
    with network_state_lock:
        network_state['link_event'] = 0

def execute_cli_command(child, commands, cmd_type):
    try:
        outputs = []
        if commands:
            if cmd_type == "get":
                for command in commands:
                    output = child.send_command(command)
                    outputs.append(output)
            elif cmd_type == "set":
                child.enable()
                output = child.send_config_set(commands)
                outputs.append(output)
            return outputs
    except Exception as e:
        print(f"Error executing CLI command: {e}")
        return None

def handle_event(event_type, message, dev_ip_addr, interface=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_base_name = f"{event_type}"
    
    get_commands = []
    set_commands = []
    child = connect_device(dev_ip_addr)
    if event_type == 'link_up':
        print(f"Link Up detected on interface {interface}, executing CLI command.")
        with network_state_lock:
            network_state['link_status'] = 'up'
        get_commands = [
            f'show interface status {interface}',
            f'show interface {interface}'
        ]
        set_commands = []

    elif event_type == 'link_down':
        print(f"Link Down detected on interface {interface}, executing CLI command.")
        with network_state_lock:
            network_state['link_status'] = 'down'
            network_state['link_event'] += 1
        get_commands = [f'show interface status {interface}']
        set_commands = []
    
    elif event_type in ['tx_power_low', 'rx_power_low', 'fcs_error_high']:
        print(f"{event_type.replace('_', ' ').title()} detected, executing CLI command.")
        get_commands = [
            f'show interface transceiver {interface}'
        ]
        set_commands = []

    else:
        print("Unhandled event type.")
        return

    get_outputs = execute_cli_command(child, get_commands, "get")
    set_outputs = execute_cli_command(child, set_commands, "set")
    child.disconnect()

    get_outputs = get_outputs if get_outputs is not None else []
    set_outputs = set_outputs if set_outputs is not None else []

    combined_output = ("\n" + "-" * 70 + "\n").join(get_outputs + set_outputs) if get_outputs or set_outputs else None
    print(combined_output)
    save_log_to_text_file(file_base_name, event_type, message, combined_output)

def save_log_to_text_file(file_base_name, event_type, message, output):
    try:
        with open(f'{file_base_name}.txt', 'a') as txt_file:
            txt_file.write(f"Event: {event_type} ")
            txt_file.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            txt_file.write(f"Log Message: {message}\n")
            txt_file.write(f"CLI Output: {output}\n")
            txt_file.write("-" * 70 + "\n") 
        print(f"Log saved to {file_base_name}.txt")
    except Exception as e:
        print(f"Error saving log to text file: {e}")

def save_logs_to_csv(valid_logs):
    if valid_logs:
        df = pd.DataFrame(valid_logs)
        df = df.apply(lambda row: preprocess_log(row['raw_message']), axis=1, result_type='expand')

        # Add "'" to process column to display interface number correctly 
        if 'process' in df.columns:
            df['process'] = df['process'].apply(lambda x: f"'{x}" if pd.notna(x) else x)

        df.to_csv('syslog_data.csv', mode='a', header=False, index=False)
        print("Logs saved to syslog_data.csv")

def preprocess_log_and_save_logs_to_csv():
    global log_data
    while True:
        if log_data:
            valid_logs = [log for log in log_data if preprocess_log(log['raw_message']) is not None]
            # save_logs_to_csv(valid_logs)
            log_data = []
        time.sleep(300)  # 5분 간격으로 실행

def preprocess_log(log):
    try:
        if log.startswith('<'):
            pri_end_idx = log.index('>') + 1
            pri = log[:pri_end_idx]
            log = log[pri_end_idx:].strip()
        else:
            pri = None
        parts = log.split(maxsplit=5)

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
        else:
            print(f"Skipping log due to unrecognized format: {log}")
            return None

    except Exception as e:
        print(f"Error processing log: {e}")
        return None

def classify_syslog_event(message):
    interface = None

    if 'interface is up' in message.lower():
        event_type = 'link_up'
        interface = extract_interface(message)
    elif 'interface is down' in message.lower():
        event_type = 'link_down'
        interface = extract_interface(message)
    else:
        event_type = None

    return event_type, interface

def extract_interface(message):
    processed_log = preprocess_log(message)
    if processed_log is not None:
        process_value = processed_log.get("process")
        return process_value
    return None

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Receive Syslog Message and extract sender ip address
        data, socket = self.request
        message = data.strip().decode('utf-8')
        print(f"Received syslog from {self.client_address[0]}: {message}")
        log_data.append({'raw_message': message})

        event_type, interface = classify_syslog_event(message)
        if event_type:
            dev_ip_addr = self.client_address[0]
            handle_event(event_type, message, dev_ip_addr, interface)
        else:
            return None

def train_model(data):
    global model, model_trained

    # 예제 데이터를 data에 추가
    example_data = [
        {'Tx Power (dBm)': -1.0, 'Rx Power (dBm)': -2.0, 'FCS Error': 0, 'Link Status': 'up'},
        {'Tx Power (dBm)': -10.0, 'Rx Power (dBm)': -12.0, 'FCS Error': 100, 'Link Status': 'down'},
        {'Tx Power (dBm)': -2.0, 'Rx Power (dBm)': -3.0, 'FCS Error': 1, 'Link Status': 'up'},
        {'Tx Power (dBm)': -8.0, 'Rx Power (dBm)': -9.0, 'FCS Error': 150, 'Link Status': 'down'},
        # 추가 데이터...
    ]

    # 최소 데이터 수집 개수 설정
    MIN_DATA_COUNT = 10
    if len(data) >= MIN_DATA_COUNT:
        # 예제 데이터를 data에 추가
        data.extend(example_data)
        df = pd.DataFrame(data)
        features = df[['Tx Power (dBm)', 'Rx Power (dBm)', 'FCS Error']].values
        target = (df['Link Status'] == 'down').astype(int).values  # 링크 다운 여부를 0 또는 1로 변환

        if len(np.unique(target)) < 2:
            print("[ERROR] Training data does not contain both classes.")
            return False

        model.fit(features, target)
        # print("[DEBUG] Training model with data:", data)
        model_trained = True
        return True
    else:
        print("[DEBUG] Not enough data to train. Current data count:", len(data))
        return False

def predict_link_down(results):
    global model

    features = np.array([[results['Tx Power (dBm)'], results['Rx Power (dBm)'], results['FCS Error']]])
    
    try:
        proba = model.predict_proba(features)
        print("[DEBUG] Predicted probabilities:", proba)

        if proba.shape[1] > 1:
            prediction = proba[0, 1]  # 링크 다운 확률
        else:
            print("[ERROR] The model did not return probabilities for two classes.")
            prediction = None
    except IndexError as e:
        print("[ERROR] IndexError:", e)
        prediction = None

    if prediction is not None:
        print(f"Prediction: {prediction:.2f}")
        if prediction > 0.5:  # 임계값 설정
            print(f"Warning: High probability of link down ({prediction:.2f})")
        else:
            print(f"Link is likely to stay up ({1-prediction:.2f})")

def collect_and_train():
    global collected_data
    while True:
        print("[DEBUG] Checking collected_data")
        if collected_data:
            # 데이터가 충분할 때만 훈련
            if train_model(collected_data):
                collected_data = []  # 훈련 후 데이터 초기화
        time.sleep(600)  # 10분 간격으로 학습

if __name__ == "__main__":
    PORT = 514
    HOST = pyautogui.prompt("ENTER THE IP ADDRESS: ", 'START AUTOMATION SERVER', default='127.0.0.1')

    # 로그 처리 및 저장 시작
    threading.Thread(target=preprocess_log_and_save_logs_to_csv, daemon=True).start()

    # 네트워크 통계 수집 시작
    m_box_ip = "192.168.0.201"
    time.sleep(60)  # 1분 후 실행
    threading.Thread(target=read_cli_and_write_to_csv, args=(m_box_ip,), daemon=True).start()

    # 모델 학습 시작
    threading.Thread(target=collect_and_train, daemon=True).start()

    try:
        with socketserver.UDPServer((HOST, PORT), SyslogUDPHandler) as server:
            print(f"Syslog server started on {HOST}:{PORT}")
            server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer is shutting down gracefully.")
    except Exception as e:
        print(f"Error: {e}")
