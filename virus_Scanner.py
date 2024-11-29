import os
import requests
import PySimpleGUI as sg
import time


sg.theme('DefaultNoMoreNagging')

# Gan Key API cua Virus Total
API_KEY = '4d7d14cf872549c99bcb18aaea0de18bac42888a646b52e61c69aac60d46e3d0'


# Tao layout giao dien
layout = [
    [sg.Text('Select a file to scan for viruses:')],
    [sg.Input(key='file_path', enable_events=True, visible=False), sg.FileBrowse()],
    [sg.Button('Scan')],
    [sg.Output(size=(80, 20))]
]

# Tao cua so
window = sg.Window('Virus Scanner', layout)

def scan_file(file_path):
    try:
        # Mo va doc noi dung trong file
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Gui file toi Virus Total de quet
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': API_KEY}
        files = {'file': ('file', file_content)}
        response = requests.post(url, files=files, params=params)

        # Lay ID scan tu reqsponse tra ve
        scan_id = response.json()['scan_id']

        # Kiem tra ket qua quet moi 15 giay cho den khi hoan tat
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': API_KEY, 'resource': scan_id}
        while True:
            response = requests.get(url, params=params)
            result = response.json()
            if 'scan_date' in result and result['scan_date'] != '1970-01-01 00:00:00':
                break
            time.sleep(15)

        # Hien thi ket qua quet ra man hinh
        sg.Print('Scan Results:')
        for scanner, result in result['scans'].items():
            sg.Print(f'{scanner}: {result["result"]}')
    except Exception as e:
        sg.Print(f'Error: {e}')
        pass

while True:
    event, values = window.read()

    # Xu ly su kien cua so
    if event == sg.WIN_CLOSED:
        break
    elif event == 'file_path':
        file_path = values['file_path']
    elif event == 'Scan':
        file_path = values['file_path']
        if not os.path.isfile(file_path):
            sg.Print('Error: Please select a valid file.')
        else:
            sg.Print(f'Scanning file: {file_path} Please wait ..')
            scan_file(file_path)

# Dong cua so
window.close()