# MutateShell
 MutateShell — Advanced Payload Obfuscation Framework for Offensive Security

 [MutateShell Banner](https://img.shields.io/badge/OffensiveSecurity-Tool-blue?style=flat-square)
> Evasion-ready stager + stub generator + encoding framework  
> **XOR + Gzip + Base64** multi-layer encoding with sandbox bypass & AV test integration.

---

🛠️ About

MutateShell is an advanced payload transformation tool that helps offensive security researchers and red teamers create **evasive, polymorphic payloads**. It transforms raw shellcode or malicious binaries into heavily obfuscated, sandbox-aware stubs written in **C, Python, or PowerShell**.

---

 🚀 Features

- ✅ XOR multi-layer encoding
- ✅ Gzip compression
- ✅ Base64 encoding
- ✅ Sandbox evasion techniques
- ✅ Stub generation in C / Python / PowerShell
- ✅ Variable & function name randomization
- ✅ Optional compilation (`gcc`, `pyinstaller`)
- ✅ VirusTotal detection checker 🔬
- ✅ CLI interface with multiple customization options

---

 📦 Installation

```bash
git clone https://github.com/yourname/MutateShell.git
cd MutateShell
pip install -r requirements.txt

python shell.py --xor 3 --gzip --base64 --stub c --rename --anti-sandbox --compile

🔑 Parameters
Option	Description
--xor	XOR encode N layers
--gzip	Apply Gzip compression
--base64	Encode in Base64
--stub	Output stub format: c, py, ps1
--rename	Randomize function/variable names
--anti-sandbox	Inject anti-analysis checks
--compile	Auto compile C/Python stubs
--output	Output filename
--input	Path to raw shellcode file

🧪 VirusTotal Integration
You can upload generated payloads directly to VirusTotal using your API key to check real-time AV detection rate.

bash
Copy
Edit
python shell.py --upload-vt --api-key "   " --input output.exe
Returns:

✅ Detection ratio

✅ Engine names

✅ VT report link

⚠️ Avoid frequent scans to prevent AV signature sharing.

🔥 Examples

 Basic Python stub with encoding
python shell.py --stub py --xor 2 --gzip --base64

 C stub with anti-sandbox & compile
python shell.py --stub c --xor 3 --gzip --anti-sandbox --rename --compile

 Upload output to VirusTotal
python shell.py --upload-vt --input payload.exe --api-key <your_api_key>

🧠 Advanced Roadmap (Optional Add-ons)
Feature	Description
Staged Loader	Pull second-stage from remote C2 (HTTP/DNS)
AES/RC4 Encoder	Add custom encryption support
PE Spoofing	Modify metadata like file version, compile time
Sandbox Triggers	Simulate user activity to bypass detonation
C2 Integration	Beacon launcher or socket-based C2 support
Payload Templates	Quick generate reverse shell or loader boilerplates

📁 Folder Structure

MutateShell/
├── shell.py              # Main engine
├── encoder/              # Custom encoding modules
├── stubs/                # Templates for C, Python, PowerShell
├── compiled/             # Compiled payloads
├── output/               # Final generated files
├── vt_scan_result.txt    # (Optional) VT scan summary
├── README.md

⚠️ Legal Disclaimer
This tool is intended for educational and research purposes only.
Use it only in authorized environments (e.g. labs, simulations, pentests with permission).
The author is not responsible for misuse or damage caused by this tool.
