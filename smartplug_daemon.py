#!/usr/bin/python

# This is mostly from http://www.desert-home.com/

from xbee import ZigBee 
import logging
import datetime
import time
import serial
import sys
import argparse
import statsd

# global variables
XBEEPORT = '/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_AD02FMB2-if00-port0'
XBEEBAUD_RATE = 9600

switchLongAddr = '12'
switchShortAddr = '12'

# default log level
DEFAULT_LOG_LEVEL = 'INFO'

# deal with command line arguments
arg_parser = argparse.ArgumentParser(description='process arguments')
arg_parser.add_argument('--log-level', help="Log level", default=DEFAULT_LOG_LEVEL)
args = arg_parser.parse_args()

print "Log Level: {0}".format(args.log_level)

# validate log_level
log_level = getattr(logging, args.log_level.upper(), None)
if not isinstance(log_level, int):
    raise ValueError('Invalid log level: %s' % argLogLevel)

#-------------------------------------------------
logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s %(name)s %(message)s')

#------------ XBee Stuff -------------------------
# Open serial port for use by the XBee
ser = serial.Serial(XBEEPORT, XBEEBAUD_RATE)

# this is a call back function.  When a message
# comes in this function will get the data
def messageReceived(data):
    #print 'gotta packet' 
    #print data
    # This is a test program, so use global variables and
    # save the addresses so they can be used later
    global switchLongAddr
    global switchShortAddr
    switchLongAddr = data['source_addr_long'] 
    switchShortAddr = data['source_addr']
    clusterId = (ord(data['cluster'][0])*256) + ord(data['cluster'][1])
    sourceAddrHex = switchLongAddr.encode("hex")
    clusterIdHex = hex(clusterId)
    gauge = statsd.Gauge('xbee-{0}'.format(sourceAddrHex))
    #print 'Addr:', sourceAddr, 'Cluster ID:', hex(clusterId),
    logging.debug("Packet from addr {0} cluster {1}".format(sourceAddrHex, clusterIdHex))
    if (clusterId == 0x13):
        # This is the device announce message.
        # due to timing problems with the switch itself, I don't 
        # respond to this message, I save the response for later after the
        # Match Descriptor request comes in.  You'll see it down below.
        # if you want to see the data that came in with this message, just
        # uncomment the 'print data' comment up above
        #print 'Device Announce Message'
        pass
    elif (clusterId == 0x8005):
        # this is the Active Endpoint Response This message tells you
        # what the device can do, but it isn't constructed correctly to match 
        # what the switch can do according to the spec.  This is another 
        # message that gets it's response after I receive the Match Descriptor
        #print 'Active Endpoint Response'
        pass
    elif (clusterId == 0x0006):
        # Match Descriptor Request; this is the point where I finally
        # respond to the switch.  Several messages are sent to cause the 
        # switch to join with the controller at a network level and to cause
        # it to regard this controller as valid.
        #
        # First the Active Endpoint Request
        payload1 = '\x00\x00'
        zb.send('tx_explicit',
            dest_addr_long = switchLongAddr,
            dest_addr = switchShortAddr,
            src_endpoint = '\x00',
            dest_endpoint = '\x00',
            cluster = '\x00\x05',
            profile = '\x00\x00',
            data = payload1
        )
        #print 'sent Active Endpoint'
        # Now the Match Descriptor Response
        payload2 = '\x00\x00\x00\x00\x01\x02'
        zb.send('tx_explicit',
            dest_addr_long = switchLongAddr,
            dest_addr = switchShortAddr,
            src_endpoint = '\x00',
            dest_endpoint = '\x00',
            cluster = '\x80\x06',
            profile = '\x00\x00',
            data = payload2
        )
        #print 'Sent Match Descriptor'
        # Now there are two messages directed at the hardware
        # code (rather than the network code.  The switch has to 
        # receive both of these to stay joined.
        payload3 = '\x11\x01\x01'
        zb.send('tx_explicit',
            dest_addr_long = switchLongAddr,
            dest_addr = switchShortAddr,
            src_endpoint = '\x00',
            dest_endpoint = '\x02',
            cluster = '\x00\xf6',
            profile = '\xc2\x16',
            data = payload2
        )
        payload4 = '\x19\x01\xfa\x00\x01'
        zb.send('tx_explicit',
            dest_addr_long = switchLongAddr,
            dest_addr = switchShortAddr,
            src_endpoint = '\x00',
            dest_endpoint = '\x02',
            cluster = '\x00\xf0',
            profile = '\xc2\x16',
            data = payload4
        )
        #print 'Sent hardware join messages'

    elif (clusterId == 0xef):
        clusterCmd = ord(data['rf_data'][2])
        if (clusterCmd == 0x81):
            #print 'Instantaneous Power',
            #print ord(data['rf_data'][3]) + (ord(data['rf_data'][4]) * 256)
            watts = ord(data['rf_data'][3]) + (ord(data['rf_data'][4]) * 256)
            gauge.send('instant_power', watts)
        elif (clusterCmd == 0x82):
            #print "Minute Stats:",
            #print 'Usage, ',
            usage = (ord(data['rf_data'][3]) +
                (ord(data['rf_data'][4]) * 256) +
                (ord(data['rf_data'][5]) * 256 * 256) +
                (ord(data['rf_data'][6]) * 256 * 256 * 256) )
            gauge.send('watt_hours', usage/3600)
            #print usage, 'Watt Seconds ',
            #print 'Up Time,',
            upTime = (ord(data['rf_data'][7]) +
                (ord(data['rf_data'][8]) * 256) +
                (ord(data['rf_data'][9]) * 256 * 256) +
                (ord(data['rf_data'][10]) * 256 * 256 * 256) )
            #print upTime, 'Seconds'
            gauge.send('uptime', upTime)
    elif (clusterId == 0xf0):
        clusterCmd = ord(data['rf_data'][2])
        #print "Cluster Cmd:", hex(clusterCmd),
        if (clusterCmd == 0xfb):
            #print "Temperature ??"
            pass
        else:
            #print "Unimplemented"
            pass
    elif (clusterId == 0xf6):
        clusterCmd = ord(data['rf_data'][2])
        if (clusterCmd == 0xfd):
            rssi = ord(data['rf_data'][3])
            print "RSSI value: {0}".format(rssi)
            gauge.send('rssi', rssi)
        elif (clusterCmd == 0xfe):
            print "Version Information"
        else:
            print data['rf_data']
    elif (clusterId == 0xee):
        clusterCmd = ord(data['rf_data'][2])
        if (clusterCmd == 0x80):
            switch_status = "OFF"
            if (ord(data['rf_data'][3]) & 0x01):
                switch_status = "ON"
            logging.debug("Packet from addr {0} cluster {1} Switch Status {2}".format(sourceAddrHex, clusterIdHex, switch_status))
    else:
        print "Unimplemented Cluster ID", hex(clusterId)
        print

def sendSwitch(whereLong, whereShort, srcEndpoint, destEndpoint, 
                clusterId, profileId, clusterCmd, databytes):
    
    payload = '\x11\x00' + clusterCmd + databytes
    # print 'payload',
    # for c in payload:
        # print hex(ord(c)),
    # print
    # print 'long address:',
    # for c in whereLong:
        # print hex(ord(c)),
    # print
        
    zb.send('tx_explicit',
        dest_addr_long = whereLong,
        dest_addr = whereShort,
        src_endpoint = srcEndpoint,
        dest_endpoint = destEndpoint,
        cluster = clusterId,
        profile = profileId,
        data = payload
        )
    
# Create XBee library API object, which spawns a new thread
zb = ZigBee(ser, escaped=True, callback=messageReceived)

# TODO add some means of communicating with the switch? Sockets?
logging.warning("starting")
#print "started at ", time.strftime("%A, %B, %d at %H:%M:%S")
while True:
    try:
        time.sleep(0.001)
    except KeyboardInterrupt:
        print "Keyboard interrupt"
        break
    except NameError as e:
        print "NameError:",
        print e.message.split("'")[1]
    except:
        print "Unexpected error:", sys.exc_info()[0]
        break

print "Exiting"
# halt() must be called before closing the serial
# port in order to ensure proper thread shutdown
zb.halt()
ser.close()
