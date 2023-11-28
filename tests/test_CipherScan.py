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
    ciphersSSLv2, ciphersSSLv3, ciphersTLS10, ciphersTLS11, ciphersTLS12, weak_sites, security_packages, exceptions, vulnerable_sites = cscan(["https://omscs.gatech.edu"], pd.DataFrame(), {"https://omscs.gatech.edu": "130.207.7.95"})

    # Assert statements to check the expected outcomes
    assert ciphersSSLv2.empty
    assert ciphersSSLv3.empty
    assert ciphersTLS10.empty
    assert ciphersTLS11.empty
    assert ciphersTLS12.empty
    assert weak_sites == []
    assert security_packages.empty
    assert not exceptions.empty
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
        assert "Expected FileNotFoundError"



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
        assert "Expected an exception"

def test_CipherScan_Failure_Test_Case():
    # This test case is bound to fail to trigger a failure pipeline

    try:
        ciphersSSLv2, ciphersSSLv3, ciphersTLS10, ciphersTLS11, ciphersTLS12, weak_sites, security_packages, exceptions, vulnerable_sites = cscan(["example.com"], pd.DataFrame(), {"example.com": "192.168.1.1"})
        vulnerable_sites.to_csv = None
    except Exception as e:
        assert "Error exporting list of vulnerable sites" in str(e)
    else:
        assert "Expected an exception"
