import re
import time
from datetime import datetime
from collections import defaultdict
import pandas as pd
from netmiko import ConnectHandler

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

def readCli(m_box):
    results = defaultdict(list)

    with connect(m_box) as child:  
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

    while True:
        results = readCli(m_box)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data_to_write = {
            'Timestamp': [timestamp],
            'Tx Power (dBm)': results['Tx Power (dBm)'],
            'Rx Power (dBm)': results['Rx Power (dBm)'],
            'FCS Error': results['FCS Error'],
            'Input Dropped': results['Input Dropped'],
            'Output Dropped': results['Output Dropped']
        }
        write_to_csv(filename, data_to_write)
        time.sleep(60)  # 5분 간격으로 실행

if __name__ == "__main__":
    main()