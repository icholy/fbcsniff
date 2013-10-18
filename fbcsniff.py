#!/usr/bin/env python

######################
# Author: ilia choly
# Date: March 2011
# Name: fbcsniff
# Version: 0.3
# Licence: GPL v3
######################

import dpkt, sys, time, getopt
from socket import inet_ntoa

messages = []
msg_filter = None
sleep_time = 0
loop = False
output_file = None
capture_file = None

def parse_response(json):

        global messages
        global msg_filter
        global output_file
        
        # convert to object
        parsed_json = None
        try: parsed_json = eval(json)
        except: return
        
        # make sure it's a msg type response
        if parsed_json['t'] != 'msg': return
        
        # find the actual msg object
        for msg in parsed_json['ms']:
                try:
                        if 'type' in msg and msg['type'] == 'msg':
                                
                                #make sure this isn't a duplicate message
                                if msg['msg']['msgID'] in messages: continue
        
                                f_message = "%s > %s : %s" % (msg['from_name'],msg['to_name'],msg['msg']['text'])
                                
                                # if there is a filter only find if it matches
                                if msg_filter != None:
                                        for filt in msg_filter:
                                                filt = filt.strip()
                                                if len(filt) == 0: continue
                                                if filt in f_message:
                                                        print f_message
                                                        if output_file: output_file.write(f_message + "\n")
                                                        break
                                else: 
                                        print f_message
                                        if output_file: output_file.write(f_message + "\n")
        
                                messages.append(msg['msg']['msgID'])
                except: pass # parsing exception

def start_sniffer(capture_file):
        
        # patterns used for parsing out json
        start_pattern = 'for (;;);'
        end_pattern = '}]}'
        start_pattern_l = len(start_pattern)
        end_pattern_l = len(end_pattern)

        f = None
        pc = None
        
        # read the capture file
        try:
                f = open(capture_file, 'rb')
                pc = dpkt.pcap.Reader(f)
        except:
                print "unable to open: %s" % (capture_file)
                sys.exit()      
        try:
                for ts, buf in pc:
        
                        data = None
                        try:
                                # make sure it's the right type 
                                eth = dpkt.ethernet.Ethernet(buf)
                                if eth.type != dpkt.ethernet.ETH_TYPE_IP: continue
                                ip = eth.data
                                if ip.p != dpkt.ip.IP_PROTO_TCP: continue
                                data = ip.data.data
                        except: continue

                        try:
                                
                                # find the start of the json
                                start_pos = data.find(start_pattern)
                                if start_pos != -1: data = data[start_pos+start_pattern_l:]
                                else: continue
                                
                                # find the end of the json
                                end_pos = data.find(end_pattern)
                                if end_pos != -1: data = data[:end_pos+end_pattern_l]
                                else: continue

                                parse_response(data)
                                
                        except: pass
                f.close()
                
        except KeyboardInterrupt:
                print "CTRL-C closing..."
                if output_file: output_file.close()
                f.close()
                sys.exit()
        except: pass
        f.close()

def usage():
        print "usage: python fbcsniff.py [OPTIONS] -c <pcap file>"
        print
        print "-c <pcap file>"
        print "-f <msg filter> (comma separated)"
        print "-s <sleep time> (use with -l)"
        print "-o <output file>"
        print "-l (keep looking for new messages)"
        print "-h (show this message)"
        print
        
def parse_argv():

        global msg_filter
        global sleep_time
        global output_file
        global capture_file
        global loop
        
        opts = None
        args = None
        
        try: opts, args = getopt.getopt(sys.argv[1:], "hlc:f:o:s:")
        except:
                usage()
                sys.exit()
        
        if len(args) != 0:
                print "Unknown argument(s):",
                for arg in args: print arg,
                print
                print
                usage()
                sys.exit()
                
        for opt in opts:
                if opt[0] == '-c': capture_file = opt[1]
                elif opt[0] == '-f': msg_filter = opt[1].split(",")
                elif opt[0] == '-o':
                        try: output_file = open(opt[1], 'w')
                        except: 
                                print "could not open output file"
                                sys.exit()
                elif opt[0] == '-s':
                        try:
                                sleep_time = int(opt[1])
                        except:
                                print "invalid sleep time"
                                sys.exit()
                elif opt[0] == '-h':
                        usage()
                        sys.exit()
                elif opt[0] == '-l': loop = True
        
        if capture_file == None:
                usage()
                sys.exit()

if __name__ == '__main__':

        print
        print "Facebook Chat Sniffer v0.3"
        print
        
        parse_argv()
        
        start_sniffer(capture_file)
        
        # loop if the flag is up
        while loop:
                time.sleep(sleep_time)
                start_sniffer(capture_file)
        print

