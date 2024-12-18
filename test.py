from pymetasploit3.msfrpc import MsfRpcClient

try:
    # Connect to the Metasploit RPC server
    client = MsfRpcClient(password='password', server='localhost', port=55553)
    print("Connected to Metasploit RPC server successfully!")

    # Test the connection by listing available exploits
    print("Fetching available exploits...")
    exploits = client.modules.exploits
    print(f"Number of exploits available: {len(exploits)}")
    print("Sample exploits:")
    for exploit in exploits[:5]:  # Display the first 5 exploits
        print(f" - {exploit}")

except Exception as e:
    print(f"Error: {e}")
