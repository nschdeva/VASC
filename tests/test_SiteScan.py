import pandas as pd
import os
import sys
sys.path.append('/Users/pennywise97/Documents/SAT/SAT FINAL PROJECT/VASC/src')
from src.SiteScan import getIP


def test_get_one_correct_IP():
    websites = ["omscs.gatech.edu"]
    iplist, siteDict = getIP(pd, websites)
    
    ip_expected = ["130.207.7.95"]
    siteDict_expected = {'omscs.gatech.edu': '130.207.7.95'}

    assert iplist == ip_expected
    assert siteDict == siteDict_expected


def test_get_multiple_correct_IP():
    websites = ["buzzport.gatech.edu", "github.gatech.edu"]
    iplist, siteDict = getIP(pd, websites)
    
    ip_expected = ["130.207.188.44", "130.207.175.93"]
    siteDict_expected = {'buzzport.gatech.edu': '130.207.188.44', 
                         'github.gatech.edu': '130.207.175.93'}

    assert iplist == ip_expected
    assert siteDict == siteDict_expected


def test_get_incorrect_IP():
    websites = ["omscs.gatech.edu", "scholars.em.gatech.edu"]
    iplist, siteDict = getIP(pd, websites)
    
    ip_expected = ["130.207.188.44", "130.207.175.93"]
    siteDict_expected = {'omscs.gatech.edu': '130.207.188.44', 
                         'scholars.em.gatech.edu': '130.207.175.93'}

    assert not iplist == ip_expected
    assert not siteDict == siteDict_expected


def test_unavailable_website():
    websites = ["omscs.gatech.edu", "scholarsts.em.gatech.edu"]
    iplist, siteDict = getIP(pd, websites)
    
    ip_expected = ["130.207.188.44"]
    siteDict_expected = {'omscs.gatech.edu': '130.207.188.44'}

    assert not iplist == ip_expected
    assert not siteDict == siteDict_expected
