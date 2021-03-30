import os
from flask import Flask, request, Response
import pyshark
import collections

api = Flask(__name__)

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

#check if file has correct extension
def isFileAllowed(filename):
    extension = filename.rsplit('.', 1)[1].lower()
    return '.' in filename and extension in ALLOWED_EXTENSIONS

def bytesToKiloBytes(bytes):
    kilobytes = round(bytes / KILOBYTE_SIZE, 1)
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
    topTalkers = []
    packetStats = []
    for packet in cap:
        try:
            parsedPacket = str(packet)
            packetArray = parsedPacket.split(" ")
            ipAddress = packetArray[SOURCE_INDEX]
            packetSize = int(packetArray[PACKET_SIZE_INDEX])

            #checks if there is an ip address in packet and if packet is not malformed
            if ipAddress and MALFORMED not in parsedPacket:
                if ipAddress in ipAddresses:
                    ipAddresses[ipAddress] = ipAddresses[ipAddress] + packetSize
                else:
                    ipAddresses[ipAddress] = packetSize
                
                if packetSize in packets:
                    packets[packetSize] = packets[packetSize] + 1
                else:
                    packets[packetSize] = 1
        except:
            cap.close()
        else:
            cap.close()

    #parsing ip addresses collection to array with collections
    for key, val in ipAddresses.items():
            talker = {'ip': key, 'load': bytesToKiloBytes(val), 'unit': 'kB'}
            topTalkers.append(talker)

    #parsing packets collection to array with collections
    for key, val in packets.items():
            kilobytesKey = bytesToKiloBytes(key)
            if kilobytesKey in outputPackets:
                outputPackets[kilobytesKey] = outputPackets[kilobytesKey] + val
            else:
                outputPackets[kilobytesKey] = val

    for key, val in sorted(outputPackets.items()):
            packetStat = {'size': key, 'unit': 'kB', 'amount': val}
            packetStats.append(packetStat)

    #forming final response with code 200
    response = {'topTalkers': topTalkers, 'packetStats': packetStats}
    return response, 200


if __name__ == "__main__":
    api.run(debug=True, port=8000)