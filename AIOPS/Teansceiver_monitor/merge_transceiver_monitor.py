import re
import time
import threading
from datetime import datetime
from collections import defaultdict
import pandas as pd
from netmiko import ConnectHandler
import socketserver
import pyautogui

log_data = []
network_state = {'link_status': 'up'}

def connect(host):
    device = {
        'device_type': 'cisco_ios',
        'host': host,
        'username': 'root',
        'password': 'admin',
        'port': 22,  # 기본 SSH 포트
        'secret': 'your_enable_password',  # 필요 시
    }
    return ConnectHandler(**device)

def readCli(child):
    results = defaultdict(list)

    read_TxRx_Power = child.send_command("sh interface transceiver 1/1")   
    read_Fcs_Error_drop = child.send_command("sh interface 1/1")      
    
    # 패턴을 정의합니다.
    txrx_power_pattern = r"Tx/Rx Pwr\s+:\s+(-?\d{1,2}\.\d) dBm\s*,\s*(-?\d{1,2}\.\d) dBm"       
    fcs_pattern = r"FCS error\s+(\d+)"
    input_dropped_pattern = r"input packets.*?dropped\s+(\d+)"
    output_dropped_pattern = r"output packets.*?dropped\s+(\d+)"

    # 패턴에 맞는 값을 찾습니다.
    txrx_power_match = re.search(txrx_power_pattern, read_TxRx_Power)
    fcs_error_match = re.search(fcs_pattern, read_Fcs_Error_drop)
    input_dropped_match = re.search(input_dropped_pattern, read_Fcs_Error_drop)
    output_dropped_match = re.search(output_dropped_pattern, read_Fcs_Error_drop)

    if txrx_power_match:
        tx_pwr = txrx_power_match.group(1)
        rx_pwr = txrx_power_match.group(2)
        results['Tx Power (dBm)'].append(tx_pwr)
        results['Rx Power (dBm)'].append(rx_pwr)
    else:
        results['Tx Power (dBm)'].append(None)
        results['Rx Power (dBm)'].append(None)

    if fcs_error_match:
        fcs_error = fcs_error_match.group(1)
        results['FCS Error'].append(fcs_error)
    else:
        results['FCS Error'].append(None)

    if input_dropped_match:
        in_dropped = input_dropped_match.group(1)
        results['Input Dropped'].append(in_dropped)
    else:
        results['Input Dropped'].append(None)

    if output_dropped_match:
        out_dropped = output_dropped_match.group(1)
        results['Output Dropped'].append(out_dropped)
    else:
        results['Output Dropped'].append(None)
    
    return results

def write_to_csv(filename, data):
    df = pd.DataFrame(data)
    df.to_csv(filename, mode='a', header=not pd.io.common.file_exists(filename), index=False)

def main():
    filename = 'network_stats.csv'
    m_box = "192.168.0.201"  # 실제 장치 정보를 여기에 입력

    child = connect(m_box)
    while True:
        results = readCli(child)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data_to_write = {
            'Timestamp': [timestamp],
            'Tx Power (dBm)': results['Tx Power (dBm)'],
            'Rx Power (dBm)': results['Rx Power (dBm)'],
            'FCS Error': results['FCS Error'],
            'Input Dropped': results['Input Dropped'],
            'Output Dropped': results['Output Dropped'],
            'Link Status': [network_state['link_status']]
        }
        write_to_csv(filename, data_to_write)
        time.sleep(300)  # 5분 간격으로 실행

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
    file_base_name = f"{event_type}_{timestamp}"
    
    get_commands = set_commands = get_outputs = set_outputs = []
    child = connect(dev_ip_addr)  # 한 번의 연결로 모든 명령 실행
    if event_type == 'link_up':
        print(f"Link Up detected on interface {interface}, executing CLI command.")
        network_state['link_status'] = 'up'
        get_commands = [
            f'show interface status {interface}',
            f'show interface {interface}'
        ]
        set_commands = [
            f'interface {interface}',
            'no shutdown'
        ]
        get_outputs = execute_cli_command(child, get_commands, "get")
        set_outputs = execute_cli_command(child, set_commands, "set")
    elif event_type == 'link_down':
        print(f"Link Down detected on interface {interface}, executing CLI command.")
        network_state['link_status'] = 'down'
        get_commands = [f'show interface status {interface}']
        set_commands = [
            f'interface {interface}',
            'shutdown'
        ]
        get_outputs = execute_cli_command(child, get_commands, "get")
        set_outputs = execute_cli_command(child, set_commands, "set")
    elif event_type == 'cpu_load':
        print(f"High CPU load detected, executing CLI command.")
        get_commands = ['show processes cpu']
        set_commands = []
        get_outputs = execute_cli_command(child, get_commands, "get")
        set_outputs = execute_cli_command(child, set_commands, "set")
    else:
        print("Unhandled event type.")
        return

    get_outputs = get_outputs if get_outputs is not None else []
    set_outputs = set_outputs if set_outputs is not None else []

    combined_output = ("\n" + "-" * 70 + "\n").join(get_outputs + set_outputs) if get_outputs or set_outputs else None
    print(combined_output)
    save_log_to_text_file(file_base_name, event_type, message, combined_output)

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

def save_logs_to_csv():
    global log_data
    while True:
        if log_data:
            valid_logs = [log for log in log_data if preprocess_log(log['raw_message']) is not None]
            if valid_logs:
                df = pd.DataFrame(valid_logs)
                df = df.apply(lambda row: preprocess_log(row['raw_message']), axis=1, result_type='expand')

                if 'process' in df.columns:
                    df['process'] = df['process'].apply(lambda x: f"'{x}" if pd.notna(x) else x)

                df.to_csv('syslog_data.csv', mode='a', header=False, index=False)
                print("Logs saved to syslog_data.csv")
            log_data = []
        time.sleep(60)

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

def extract_interface(message):
    processed_log = preprocess_log(message)
    if processed_log is not None:
        process_value = processed_log.get("process")
        return process_value
    return None

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        message = data.strip().decode('utf-8')
        print(f"Received syslog from {self.client_address[0]}: {message}")
        log_data.append({'raw_message': message})

        event_type, interface = classify_message(message)
        if event_type:
            dev_ip_addr = self.client_address[0]
            handle_event(event_type, message, dev_ip_addr, interface)
        else:
            return None

if __name__ == "__main__":
    PORT = 514
    HOST = pyautogui.prompt("ENTER THE IP ADDRESS: ", 'START AUTOMATION SERVER', default='127.0.0.1')

    threading.Thread(target=save_logs_to_csv, daemon=True).start()

    try:
        with socketserver.UDPServer((HOST, PORT), SyslogUDPHandler) as server:
            print(f"Syslog server started on {HOST}:{PORT}")
            server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer is shutting down gracefully.")
    except Exception as e:
        print(f"Error: {e}")

    main()  # Start the network monitoring
