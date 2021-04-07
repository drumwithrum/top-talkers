import os
from flask import Flask, request, Response
import pyshark
import collections
import math
import numpy as np
from flask_cors import CORS

api = Flask(__name__)
CORS(api)

#name of the parameter in body to store file in
FILE_PARAM = 'data'

ALLOWED_EXTENSIONS = {'pcap'}
UPLOAD_FOLDER = './'
HELPER_FILE = 'testfile.pcap'
SOURCE_INDEX = 2
PACKET_SIZE_INDEX = 5
KILOBYTE_SIZE = 1024
MINIMUM_SIZE = 0.1
MALFORMED = 'malformed'
SECOND_LAYER_IDENTIFIER = 'II'

def float_round(num, places = 0, direction = math.floor):
    return direction(num * (10**places)) / float(10**places)

#check if file has correct extension
def isFileAllowed(filename):
    extension = filename.rsplit('.', 1)[1].lower()
    return '.' in filename and extension in ALLOWED_EXTENSIONS

def bytesToKiloBytes(bytes, decimalPlaces = 1, ceil = False):
    kilobytes = 0
    if ceil:
        kilobytes = float_round(bytes / KILOBYTE_SIZE, decimalPlaces, math.ceil)
    else:
        kilobytes = round(bytes / KILOBYTE_SIZE, decimalPlaces)
    return kilobytes if kilobytes > MINIMUM_SIZE else MINIMUM_SIZE

@api.route('/files', methods=['POST'])
def upload():
    #checks if data parameter is provided
    if FILE_PARAM not in request.files:
        return 'Field data of type file is required', 400
    
    data = request.files[FILE_PARAM]

    #checks if data is not empty
    if data.filename == '':
        return 'Field data of type file is required', 400

    #checks if data is in correct format 
    if not data or not isFileAllowed(data.filename):
        return 'Wrong file extension provided, accepted extensions: .pcap', 400

    #saving helper file to open it with pyshark
    data.save(os.path.join(UPLOAD_FOLDER, HELPER_FILE))
    cap = pyshark.FileCapture(HELPER_FILE,only_summaries=True)

    ipAddresses = {}
    packets = {}
    outputPackets = {}
    edgeRanges = [0]
    biggestPacket = 0
    ranges = []
    topTalkers = []
    packetStats = []
    
    for packet in cap:
        try:
            parsedPacket = str(packet)
            packetArray = parsedPacket.split(" ")
            ipAddress = packetArray[SOURCE_INDEX]
            packetSize = int(packetArray[PACKET_SIZE_INDEX])
            #checks if there is an ip address in packet and if packet is not malformed
            if ipAddress and MALFORMED not in parsedPacket and SECOND_LAYER_IDENTIFIER not in parsedPacket:
                if ipAddress in ipAddresses:
                    ipAddresses[ipAddress] = ipAddresses[ipAddress] + packetSize
                else:
                    ipAddresses[ipAddress] = packetSize
                
                if packetSize in packets:
                    packets[packetSize] = packets[packetSize] + 1
                else:
                    packets[packetSize] = 1
        except:
            continue
        else:
            continue

    cap.close()
    #parsing ip addresses collection to array with collections
    for key, val in ipAddresses.items():
            talker = {'ip': key, 'load': bytesToKiloBytes(val), 'unit': 'kB'}
            topTalkers.append(talker)


    for key, val in packets.items():
            rangeItem = bytesToKiloBytes(key, 1)
            if biggestPacket < bytesToKiloBytes(key, 1, True):
                biggestPacket = bytesToKiloBytes(key, 1, True)
            if rangeItem not in edgeRanges:
                edgeRanges.append(rangeItem)
    
    edgeRanges = sorted(edgeRanges)
    areRangesEven = len(edgeRanges) % 2 == 0
    lastRange = -1
    if not areRangesEven:
        lastRange = edgeRanges.pop()
    
    ranges = np.array_split(edgeRanges, math.floor(len(edgeRanges) / 2))
    if lastRange > 0:
        ranges.append([edgeRanges[len(edgeRanges) - 1], lastRange])

    for key, val in packets.items():
        currRange = ''
        # kilobytesKey = bytesToKiloBytes(key)
        for arr in ranges:
            if len(arr) == 1:
                currRange = str(arr[0])
                continue
            if bytesToKiloBytes(key) >= arr[0] and bytesToKiloBytes(key) <= arr[1]:
                currRange = str(arr[0]) + ' - ' + str(arr[1])
                break
        if currRange in outputPackets:
            outputPackets[currRange] = outputPackets[currRange] + val
        else:
            outputPackets[currRange] = val

    for key, val in sorted(outputPackets.items()):
            packetStat = {'size': key, 'unit': 'kB', 'amount': val}
            packetStats.append(packetStat)

    #forming final response with code 200
    response = {'topTalkers': topTalkers, 'packetStats': packetStats}
    return response, 200


if __name__ == "__main__":
    api.run(debug=True, port=8000)