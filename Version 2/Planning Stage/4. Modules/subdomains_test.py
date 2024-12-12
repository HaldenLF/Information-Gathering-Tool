# Throws an index out of range error within the sublist3r module
# For now I have removed this error from the output
# To view error, comment out line 12,13 & 17-32


import sublist3r
import sys
import re

def get_subdomains(domain):
    # Redirect standard error to a string
    old_stderr = sys.stderr
    sys.stderr = open('stderr.txt', 'w')

    # Run Sublist3r
    subdomains = sublist3r.main(domain, 40, savefile=False, ports=None, silent=False, verbose=True, enable_bruteforce=False, engines=None)

    # Restore standard error
    sys.stderr.close()
    sys.stderr = old_stderr

    # Read the error message from the file
    with open('stderr.txt', 'r') as f:
        error_message = f.read()

    # Use regex to remove the error message
    error_pattern = r'Traceback \(most recent call last\):.*?IndexError: list index out of range'
    cleaned_error_message = re.sub(error_pattern, '', error_message, flags=re.DOTALL)

    # Print the cleaned error message
    print(cleaned_error_message)

    return subdomains

domain = "example.com"
get_subdomains(domain)

