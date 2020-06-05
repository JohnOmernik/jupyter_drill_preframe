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

# Your Specific integration imports go here, make sure they are in requirements! Examples left in for hive
import requests
import socket
from pyhive import hive as hivemod


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
class Integration(Magics):
    # Static Variables
    ipy = None        # IPython variable for updating things
    session = None    # Session if ingeration uses it
    connected = False # Is the integration connected
    passwd = ""       # If the itegration uses a password, it's temp stored here
    last_query = ""
    name_str = integration

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

    # Class Init function - Obtain a reference to the get_ipython()
    def __init__(self, shell, pd_use_beaker=False, *args, **kwargs):
        super(Integration, self).__init__(shell)
        self.myip = get_ipython()
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
        allowed_opts = pd_set_vars + ['pd_replace_crlf', 'pd_display_idx', self.name_str + '_base_url']

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
            print("Disconnected %s Session from %s" % (self.name_str.capitalize(), self.opts[self.name_str + '_base_url'][0])
        else:
            print("%s Not Currently Connected - Resetting All Variables" % self.name_str.capitalize())
        self.mysession = None
        self.connected = False

    def connect(self, prompt=False):
        global tpass
        if self.connected == False:
            if prompt == True or self.opts[self.name_str + '_user'][0] == '':
                print("User not specified in JUPYTER_%s_USER or user override requested" % self.name_str.upper())
                tuser = input("Please type user name if desired: ")
                self.opts[self.name_str + '_user'][0] = tuser
            print("Connecting as user %s" % self.opts[self.name_str'_user'][0])
            print("")

            if prompt == True or self.opts[self.name_str  + "_base_url'][0] == '':
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

    #        Use the following if your data source requries a password
    #        print("Please enter the password you wish to connect with:")
    #        tpass = ""
    #        self.ipy.ex("from getpass import getpass\ntpass = getpass(prompt='Connection Password: ')")
    #        tpass = self.ipy.user_ns['tpass']

    #        self.passwd = tpass
    #        self.ipy.user_ns['tpass'] = ""

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
        try:
            # To do, allow settings hive setting from ENV
#            self.session = hivemod.Connection(host=self.opts['base_url_host'][0], port=self.opts['base_url_port'][0], username=self.opts['user'][0])
            result = 0
        except:
            print("%s Connection Error!" % self.name_str.capitalize())
            result = -2
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
        if query.lower().find("day = ") < 0:
            print("WARNING - Queries shoud have day = component to ensure you don't have to many map tasks")
            if bReRun == False:
                print("First Submission - Not Sending to Server - Run again to submit as is")
                bRun = False
            else:
                print("Query will be submitted ")
        # Warn and do not allow submission
        # There is no way for a user to submit this query 
        if query.lower().find('limit ") < 0:
            print("ERROR - All queries must have a limit clause - Query will not submit without out")
            bRun = False
        return bRun

    def runQuery(self, query):

        mydf = None
        status = "-"
        starttime = int(time.time())
        run_query = self.validateQuery(query)
        if run_query:
            if self.connected == True:
                try:
                    mydf = pd.read_sql(query, self.session)
                    status = "Success"
                except (TypeError):
                    status = "Success - No Results"
                    mydf = None
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
            status = "ValidationError"
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
    def hive(self, line, cell=None):
        # Handle all Line items %hive item1 %hive item2 etc
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
                   self.myip.user_ns['prev_' + self.name_str] = result_df
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
                print(self.name_str.capitalize() + " is not connected: Please see help at %" + self.name_str + ")


