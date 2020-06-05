#!/usr/bin/python

# Base imports for all integrations, only remove these at your own risk!
import json
import sys
import os
import time
import pandas as pd
from getpass import getpass
from collections import OrderedDict

from IPython.core.magic import (Magics, magics_class, line_magic, cell_magic, line_cell_magic)
from IPython.core.display import HTML

# Your Specific integration imports go here, make sure they are in requirements!
import requests
import socket
from requests.packages.urllib3.exceptions import SubjectAltNameWarning, InsecureRequestWarning
from requests_toolbelt.adapters import host_header_ssl
requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)


# BeakerX integration is highly recommened, but at this time IS optional, so we TRY beakerx, and then fail well if its not there. 
try:
    from beakerx import *
    from beakerx.object import beakerx
except:
    pass

#import IPython.display
from IPython.display import display_html, display, Javascript, FileLink, FileLinks, Image
import ipywidgets as widgets

@magics_class
class Drill(Magics):
    # Static Variables
    ipy = None        # IPython variable for updating things
    session = None    # Session if ingeration uses it
    connected = False # Is the integration connected
    passwd = ""       # If the itegration uses a password, it's temp stored here
    last_query = ""
    last_use = ""
    name_str = "drill"

    debug = False     # Enable debug mode

    # Variables Dictionary
    opts = {}

    # Option Format: [ Value, Description]

    # Pandas Variables
    opts['pd_display_idx'] = [False, "Display the Pandas Index with output"]
    opts['pd_replace_crlf'] = [True, "Replace extra crlfs in outputs with String representations of CRs and LFs"]
    opts['pd_max_colwidth'] = [50, 'Max column width to display']
    opts['pd_display.max_rows'] = [1000, 'Number of Max Rows']
    opts['pd_display.max_columns'] = [None, 'Max Columns']

    opts['pd_use_beaker'] = [False, 'Use the Beaker system for Pandas Display']
    opts['pd_beaker_bool_workaround'] = [True, 'Look for Dataframes with bool columns, and make it object for display in BeakerX']

    pd.set_option('display.max_columns', opts['pd_display.max_columns'][0])
    pd.set_option('display.max_rows', opts['pd_display.max_rows'][0])
    pd.set_option('max_colwidth', opts['pd_max_colwidth'][0])

    # Get Env items (User and/or Base URL)
    try:
        tuser = os.environ['JUPYTERHUB_' + name_str.upper() + '_USER']
    except:
        tuser = ''
    try:
        turl = os.environ['JUPYTERHUB_' + name_str.upper() + '_BASE_URL']
    except:
        turl = ""

    # Hive specific variables as examples
    opts[name_str + '_max_rows'] = [1000, 'Max number of rows to return, will potentially add this to queries']
    opts[name_str + '_user'] = [tuser, "User to connect with  - Can be set via ENV Var: JUPYTER_" + name_str.upper() + "_USER otherwise will prompt"]
    opts[name_str + '_base_url'] = [turl, "URL to connect to server. Can be set via ENV Var: JUPYTER_" + name_str.upper() + "_BASE_URL"]
    opts[name_str + '_base_url_host'] = ["", "Hostname of connection derived from base_url"]
    opts[name_str + '_base_url_port'] = ["", "Port of connection derived from base_url"]
    opts[name_str + '_base_url_scheme'] = ["", "Scheme of connection derived from base_url"]

    opts['drill_pin_to_ip'] = [False, "Obtain an IP from the name and connect directly to that IP"]
    opts['drill_pinned_ip'] = ["", "IP of pinned connection"]
    opts['drill_rewrite_host'] = [False, "When using Pin to IP, rewrite the host header to match the name of base_url"]
    opts['drill_inc_port_in_rewrite'] = [False, "When rewriting the host header, include :%port% in the host header"]
    opts['drill_headers'] = [{}, "Customer Headers to use for Drill connections"]
    opts['drill_url'] = ['', "Actual URL used for connection (base URL is the URL that is passed in as default"]
    opts['drill_verify'] = ['/etc/ssl/certs/ca-certificates.crt', "Either the path to the CA Cert validation bundle or False for don't verify"]
    opts['drill_ignore_ssl_warn'] = [False, "Supress SSL warning upon connection - Not recommended"]


    # Class Init function - Obtain a reference to the get_ipython()
    def __init__(self, shell, pd_use_beaker=False, drill_rewrite_host=False, drill_pin_to_ip=False, *args, **kwargs):
        super(Drill, self).__init__(shell)
        self.ipy = get_ipython()
        self.opts['drill_pin_to_ip'][0] = drill_pin_to_ip
        self.opts['drill_rewrite_host'][0] = drill_rewrite_host
        self.opts['pd_use_beaker'][0] = pd_use_beaker
        if pd_use_beaker == True:
            try:
                beakerx.pandas_display_table()
            except:
                print("WARNING - BEAKER SUPPORT FAILED")

    def retStatus(self):

        print("Current State of %s Interface:" % self.name_str.capitalize())
        print("")
        print("{: <30} {: <50}".format(*["Connected:", str(self.connected)]))
        print("{: <30} {: <50}".format(*["Debug Mode:", str(self.debug)]))

        print("")

        print("Display Properties:")
        print("-----------------------------------")
        for k, v in self.opts.items():
            if k.find("pd_") == 0:
                try:
                    t = int(v[1])
                except:
                    t = v[1]
                if v[0] is None:
                    o = "None"
                else:
                    o = v[0]
                myrow = [k, o, t]
                print("{: <30} {: <50} {: <20}".format(*myrow))
                myrow = []


        print("")
        print("%s Properties:" %  self.name_str.capitalize())
        print("-----------------------------------")
        for k, v in self.opts.items():
            if k.find(self.name_str + "_") == 0:
                if v[0] is None:
                    o = "None"
                else:
                    o = str(v[0])
                myrow = [k, o, v[1]]
                print("{: <30} {: <50} {: <20}".format(*myrow))
                myrow = []


    def setvar(self, line):
        pd_set_vars = ['pd_display.max_columns', 'pd_display.max_rows', 'pd_max_colwidth', 'pd_use_beaker']
        allowed_opts = pd_set_vars + ['pd_replace_crlf', 'pd_display_idx', 'drill_base_url', 'drill_verify', 'drill_pin_to_ip', 'drill_rewrite_host', 'drill_ignore_ssl_warn', 'drill_inc_port_in_rewrite']

        tline = line.replace('set ', '')
        tkey = tline.split(' ')[0]
        tval = tline.split(' ')[1]
        if tval == "False":
            tval = False
        if tval == "True":
            tval = True
        if tkey in allowed_opts:
            self.opts[tkey][0] = tval
            if tkey in pd_set_vars:
                try:
                    t = int(tval)
                except:
                    t = tval
                pd.set_option(tkey.replace('pd_', ''), t)
        else:
            print("You tried to set variable: %s - Not in Allowed options!" % tkey)

    def disconnect(self):
        if self.connected == True:
            print("Disconnected %s Session from %s" % (self.name_str.capitalize(), self.opts[self.name_str + '_base_url'][0]))
        else:
            print("%s Not Currently Connected - Resetting All Variables" % self.name_str.capitalize())
        self.mysession = None
        self.passwd = None
        self.connected = False

    def connect(self, prompt=False):
        global tpass
        if self.connected == False:
            if prompt == True or self.opts[self.name_str + '_user'][0] == '':
                print("User not specified in JUPYTER_%s_USER or user override requested" % self.name_str.upper())
                tuser = input("Please type user name if desired: ")
                self.opts[self.name_str + '_user'][0] = tuser
            print("Connecting as user %s" % self.opts[self.name_str + '_user'][0])
            print("")

            if prompt == True or self.opts[self.name_str  + "_base_url"][0] == '':
                print("%s Base URL not specified in JUPYTER_%s_BASE_URL or override requested" % (self.name_str.capitalize(), self.name_str.upper()))
                turl = input("Please type in the full %s URL: " % self.name_str.capitalize())
                self.opts[self.name_str + '_base_url'][0] = turl
            print("Connecting to %s URL: %s" % (self.name_str.capitalize(), self.opts['_base_url'][0]))
            print("")

            myurl = self.opts[self.name_str + '_base_url'][0]
            ts1 = myurl.split("://")
            self.opts[self.name_str + '_base_url_scheme'][0] = ts1[0]
            t1 = ts1[1]
            ts2 = t1.split(":")
            self.opts[self.name_str + '_base_url_host'][0] = ts2[0]
            self.opts[self.name_str + '_base_url_port'][0] = ts2[1]

#            Use the following if your data source requries a password
            print("Please enter the password you wish to connect with:")
            tpass = ""
            self.ipy.ex("from getpass import getpass\ntpass = getpass(prompt='Connection Password: ')")
            tpass = self.ipy.user_ns['tpass']

            self.passwd = tpass
            self.ipy.user_ns['tpass'] = ""

            if self.opts['drill_ignore_ssl_warn'][0] == True:
                print("Warning: Setting session to ignore SSL warnings - Use at your own risk")
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

            result = self.auth()
            if result == 0:
                self.connected = True
                print("%s - %s Connected!" % (self.name_str.capitalize(), self.opts[self.name_str + '_base_url'][0]))
            else:
                print("Connection Error - Perhaps Bad Usename/Password?")

        else:
            print(self.name_str.capitalize() + "is already connected - Please type %" + self.name_str + " for help on what you can you do")

        if self.connected != True:
            self.disconnect()
##### Where we left off
    def auth(self):
        self.session = None
        result = -1
        self.session = requests.Session()
        self.session.allow_redirects = False

        if self.opts['drill_pin_to_ip'][0] == True:
                self.opts['drill_pinned_ip'][0] = self.getipurl(self.opts['drill_base_url'][0])
                print("")
                print("Pinning to IP for this session: %s" % self.opts['drill_pinned_ip'][0])
                print("")
                self.opts['drill_url'][0] = "%s://%s:%s" % ( self.opts['drill_base_url_scheme'][0],  self.opts['drill_pinned_ip'][0] ,  self.opts['drill_base_url_port'][0])
                if self.opts['drill_rewrite_host'][0] == True:
                    self.session.mount("https://", host_header_ssl.HostHeaderSSLAdapter())
                    if self.opts['drill_inc_port_in_rewrite'][0] == True:
                        self.opts['drill_headers'][0]['host'] = self.opts['drill_base_url_host'][0] + ":" + self.opts['drill_base_url_port'][0]
                    else:
                        self.opts['drill_headers'][0]['host'] = self.opts['drill_base_url_host'][0]
                    if self.debug:
                        print("Headers in connect: %s" % self.opts['drill_headers'][0])
        else:
            self.opts['drill_url'][0] = self.opts['drill_base_url'][0]
        myurl = self.drill_opts['drill_url'][0] + "/j_security_check"
        if self.debug:
            print("")
            print("Connecting URL: %s" % myurl)
            print("")
        login = {'j_username': self.opts['drill_user'][0], 'j_password': self.passwd}
        if self.debug:
            print("")
            print("Headers in auth: %s" % self.opts['drill_headers'][0])
            print("")
        if self.debug:
            print("Adapters: %s" % self.session.adapters)
        r = self.session.post(myurl, allow_redirects=self.session.allow_redirects, data=login, headers=self.opts['drill_headers'][0], verify=self.opts['drill_verify'][0])

        if r.status_code == 200:
            if r.text.find("Invalid username/password credentials") >= 0:
                result = -2
                raise Exception("Invalid username/password credentials")
            elif r.text.find('<li><a href="/logout">Log Out (') >= 0:
                pass
                result = 0
            else:
                raise Exception("Unknown HTTP 200 Code: %s" % r.text)
        elif r.status_code == 303:
            pass
            result = 0
        else:
            raise Exception("Status Code: %s - Error" % r.status_code)

        if results == 0:
            if self.last_use != "":
                print("Reconnect, running %s to get you back to your database" % self.last_use)
                tdf, blahtime, blah = self.runQuery(self.last_use)


        return result


    def validateQuery(self, query):
        bRun = True
        bReRun = False
        if self.last_query == query:
            # If the validation allows rerun, that we are here:
            bReRun = True
        # Ok, we know if we are rerun or not, so let's now set the last_query 
        self.last_query = query

        # Example Validation

        # Warn only - Don't change bRun
        # This one is looking for a ; in the query. We let it run, but we warn the user
        # Basically, we print a warning but don't change the bRun variable and the bReRun doesn't matter
        if query.find(";") >= 0:
            print("WARNING - Do not type a trailing semi colon on queries, your query will fail (like it probably did here)")

        # Warn and don't submit after first attempt - Second attempt go ahead and run
        # If the query doesn't have a day query, then maybe we want to WARN the user and not run the query.
        # However, if this is the second time in a row that the user has submitted the query, then they must want to run without day
        # So if bReRun is True, we allow bRun to stay true. This ensures the user to submit after warnings
        if query.lower().find("limit ") < 0:
            print("WARNING - Queries shoud have a limit so you don't bonkers your DOM")
            if bReRun == False:
                print("First Submission - Not Sending to Server - Run again to submit as is")
                bRun = False
            else:
                print("Query will be submitted - Poor DOM")
        # Warn and do not allow submission
        # There is no way for a user to submit this query 
#        if query.lower().find('limit ") < 0:
#            print("ERROR - All queries must have a limit clause - Query will not submit without out")
#            bRun = False
        return bRun

    def runQuery(self, query):

        mydf = None
        status = "-"
        starttime = int(time.time())
        run_query = self.validateQuery(query)
        if run_query:
            if self.connected == True:
                url = self.opts['drill_url'][0] + "/query.json"
                payload = {"queryType":"SQL", "query":query}
                cur_headers = self.opts['drill_headers'][0]
                cur_headers["Content-type"] = "application/json"
                try:
                    r = self.session.post(url, data=json.dumps(payload), headers=cur_headers, verify=self.opts['drill_verify'][0])
                    if r.status_code == 200:
                        if r.text.find("Invalid username/password credentials.") >= 0:
                                print("It looks like your Drill Session has expired, please run %drill connect to resolve")
                                self.disconnect()
                                self.ipy.set_next_input("%drill connect")
                                status = "Failure: Session Expired"
                        else:
                            try:
                                jrecs = json.loads(res.text, object_pairs_hook=OrderedDict)
                                try:
                                    cols = jrecs['columns']
                                    rows = jrecs['rows']
                                    if len(cols) == 0 or len(rows) == 0:
                                        status = "Success - No Results"
                                        mydf = None
                                    else:
                                        status = "Success"
                                        mydf = pd.read_json(json.dumps(rows))
                                        mydf = mydf[cols]
                                except:
                                    if len(cols) == 0 or len(rows) == 0:
                                        status = "Success - No Results"
                                        mydf = None
                            except:
                                status = "Failure: Error Loading JSON records or parsing into dataframe"
                except Exception as e:
                    str_err = str(e)
                    if self.opts['verbose_errors'][0] == True:
                        status = "Failure - query_error: " + str_err
                    else:
                        msg_find = "errorMessage=\""
                        em_start = str_err.find(msg_find)
                        find_len = len(msg_find)
                        em_end = str_err[em_start + find_len:].find("\"")
                        str_out = str_err[em_start + find_len:em_start + em_end + find_len]
                        status = "Failure - query_error: " + str_out
            else:
                mydf = None
                status = "%d Not Connected" % self.name_str.capitalize()
        else:
            status = "Validation Error"
            mydf = None
        endtime = int(time.time())
        query_time = endtime - starttime
        return mydf, query_time, status


# Display Help must be completely customized, please look at this Hive example
    def displayCustomHelp(self):
        print("jupyter_hive is a interface that allows you to use the magic function %hive to interact with an Hive installation.")
        print("")
        print("jupyter_hive has two main modes %hive and %%hive")
        print("%hive is for interacting with a Hive installation, connecting, disconnecting, seeing status, etc")
        print("%%hive is for running queries and obtaining results back from the Hive cluster")
        print("")
        print("%hive functions available")
        print("###############################################################################################")
        print("")
        print("{: <30} {: <80}".format(*["%hive", "This help screen"]))
        print("{: <30} {: <80}".format(*["%hive status", "Print the status of the Hive connection and variables used for output"]))
        print("{: <30} {: <80}".format(*["%hive connect", "Initiate a connection to the Hive cluster, attempting to use the ENV variables for Hive URL and Hive Username"]))
        print("{: <30} {: <80}".format(*["%hive connect alt", "Initiate a connection to the Hive cluster, but prompt for Username and URL regardless of ENV variables"]))
        print("{: <30} {: <80}".format(*["%hive disconnect", "Disconnect an active Hive connection and reset connection variables"]))
        print("{: <30} {: <80}".format(*["%hive set %variable% %value%", "Set the variable %variable% to the value %value%"]))
        print("{: <30} {: <80}".format(*["%hive debug", "Sets an internal debug variable to True (False by default) to see more verbose info about connections"]))
        print("")
        print("Running queries with %%hive")
        print("###############################################################################################")
        print("")
        print("When running queries with %%hive, %%hive will be on the first line of your cell, and the next line is the query you wish to run. Example:")
        print("")
        print("%%hive")
        print("select * from `mydatabase`.`mytable`")
        print("")
        print("Some query notes:")
        print("- If the number of results is less than pd_display.max_rows, then the results will be diplayed in your notebook")
        print("- You can change pd_display.max_rows with %hive set pd_display.max_rows 2000")
        print("- The results, regardless of display will be place in a Pandas Dataframe variable called prev_hive")
        print("- prev_hive is overwritten every time a successful query is run. If you want to save results assign it to a new variable")

    # This is the function that is actually called. 
    def displayHelp(self):
        self.displayCustomHelp()

    # This is the magic name. I left hive in for an example, this would equate to %hive
    @line_cell_magic
    def drill(self, line, cell=None):
        if cell is None:
            line = line.replace("\r", "")
            if line == "":
                self.displayHelp()
            elif line.lower() == "status":
                self.retStatus()
            elif line.lower() == "debug":
                print("Toggling Debug from %s to %s" % (self.debug, not self.debug))
                self.debug = not self.debug
            elif line.lower() == "disconnect":
                self.disconnect()
            elif line.lower() == "connect alt":
                self.connect(True)
            elif line.lower() == "connect":
                self.connect(False)
            elif line.lower().find('set ') == 0:
                self.setvar(line)
            else:
                print("I am sorry, I don't know what you want to do, try just %" + self.name_str + "for help options")
        else: # This is run is the cell is not none, thus it's a cell to process  - For us, that means a query
            cell = cell.replace("\r", "")
            if self.connected == True:
                result_df, qtime, status = self.runQuery(cell)
                if status.find("Failure") == 0:
                    print("Error: %s" % status)
                elif status.find("Success - No Results") == 0:
                    print("No Results returned in %s seconds" % qtime)
                else:
                   self.ipy.user_ns['prev_' + self.name_str] = result_df
                   mycnt = len(result_df)
                   print("%s Records in Approx %s seconds" % (mycnt,qtime))
                   print("")
                   if mycnt <= int(self.opts['pd_display.max_rows'][0]):
                       if self.debug:
                           print("Testing max_colwidth: %s" %  pd.get_option('max_colwidth'))
                       if self.opts['pd_use_beaker'][0] == True:
                           if self.opts['pd_beaker_bool_workaround'][0]== True:
                                for x in result_df.columns:
                                    if result_df.dtypes[x] == 'bool':
                                        result_df[x] = result_df[x].astype(object)
                           display(TableDisplay(result_df))
                       else:
                           display(HTML(result_df.to_html(index=self.opts['pd_display_idx'][0])))
                   else:
                       print("Number of results (%s) greater than pd_display_max(%s)" % (mycnt, self.opts['pd_display.max_rows'][0]))
            else:
                print(self.name_str.capitalize() + " is not connected: Please see help at %" + self.name_str)

  #Helper Functions

    def getipurl(self, url):
        ts1 = url.split("://")
        scheme = ts1[0]
        t1 = ts1[1]
        ts2 = t1.split(":")
        host = ts2[0]
        port = ts2[1]
        try:
            ip = socket.gethostbyname(host)
        except:
            print("Failure on IP Lookup - URL: %s Host: %s Port: %s" % (url, host, port))
        return ip

