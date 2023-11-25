import pandas as pd
import os
import sys
sys.path.append('/Users/pennywise97/Documents/SAT/SAT FINAL PROJECT/VASC/src')
from src.CipherScan import cscan

# Ensure that the code runs without errors for a normal case
# Make sure the required input files exist
# Provide some sample data in WeakCiphers.csv
# Ensure the necessary directories for Output exist

def test_CipherScan_expected_values():
    # Run the function
    ciphersSSLv2, ciphersSSLv3, ciphersTLS10, ciphersTLS11, ciphersTLS12, weak_sites, security_packages, exceptions, vulnerable_sites = cscan(["https://gatech.instructure.com"], pd.DataFrame(), {"https://gatech.instructure.com": "192.168.1.1"})

    # Assert statements to check the expected outcomes
    assert ciphersSSLv2.empty
    assert ciphersSSLv3.empty
    assert ciphersTLS10.empty
    assert ciphersTLS11.empty
    assert ciphersTLS12.empty
    assert weak_sites
    assert security_packages.empty
    assert exceptions.empty
    assert vulnerable_sites.empty


def test_CipherScan_weakCipher_not_found():
    # Test the case where WeakCiphers.csv is not found
    # Expecting to print an error message

    # Run the function
    try:
        ciphersSSLv2, ciphersSSLv3, ciphersTLS10, ciphersTLS11, ciphersTLS12, weak_sites, security_packages, exceptions, vulnerable_sites = cscan([], pd.DataFrame(), {})
    except FileNotFoundError as e:
        assert "File WeakCiphers.csv can't be opened" in str(e)
    else:
        assert False, "Expected FileNotFoundError"



def test_CipherScan_exporting_fails():
    # Test the case where exporting Exceptions.csv fails
    # Expecting to print an error message

    # Run the function
    try:
        ciphersSSLv2, ciphersSSLv3, ciphersTLS10, ciphersTLS11, ciphersTLS12, weak_sites, security_packages, exceptions, vulnerable_sites = cscan(["example.com"], pd.DataFrame(), {"example.com": "192.168.1.1"})
        # Simulate a failure in exporting Exceptions.csv
        exceptions.to_csv = None
    except Exception as e:
        assert "Error exporting list of exceptions" in str(e)
    else:
        assert False, "Expected an exception"



def test_CipherScan_output():
    # Ensure that the output files are created successfully
    # Verify the content of some of the output files

    # Run the function
    ciphersSSLv2, ciphersSSLv3, ciphersTLS10, ciphersTLS11, ciphersTLS12, weak_sites, security_packages, exceptions, vulnerable_sites = cscan(["example.com"], pd.DataFrame(), {"example.com": "192.168.1.1"})

    # Assert statements to check the existence of output files and their content
    assert os.path.isfile('./Output/SSLv2Ciphers.csv')
    assert os.path.isfile('./Output/Packages.csv')
    # Check the content of the created files if needed
