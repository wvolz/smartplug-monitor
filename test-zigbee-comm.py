#! /usr/bin/python
# This is the an implementation of controlling the Lowe's Iris Smart
# Switch.  It will join with a switch and allow you to control the switch
#
#  Only ONE switch though.  This implementation is a direct port of the 
# work I did for an Arduino and illustrates what needs to be done for the 
# basic operation of the switch.  If you want more than one switch, you can
# adapt this code, or use the ideas in it to make your own control software.
#
# Have fun

from xbee import ZigBee 
import logging
import datetime
import time
import serial
import sys

# on the Raspberry Pi the serial port is ttyAMA0
XBEEPORT = '/dev/ttyUSB2'
XBEEBAUD_RATE = 9600

switchLongAddr = '12'
switchShortAddr = '12'

#-------------------------------------------------
logging.basicConfig()

#------------ XBee Stuff -------------------------
# Open serial port for use by the XBee
ser = serial.Serial(XBEEPORT, XBEEBAUD_RATE)
#ser.setXON()
xbee = ZigBee(ser, escaped=True)

while True:
    try:
        print(xbee.wait_read_frame())
        #print ser.read()
    except KeyboardInterrupt:
        break

ser.close()
