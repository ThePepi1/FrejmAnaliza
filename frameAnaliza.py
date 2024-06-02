S = "OO 1b 21 3О d7 b9 OO О7 ec 77 4c Оа О8 OO 45 OO" 
S +=" OO 5f 1c 36 4О OO 3f О6 9e аf 93 5b аd О8 93 5b"
S += "аc f4 OO 6e d7 2f 83 d6 dc аf 2c О3 7c cf 5О 18"
S += "О5 b4 48 2f OO OO 2b 4f 4b 2О 5О 4f 5О 33 20 7О"
S+= "65 72 64 69 74 6f 6e 2О 72 65 61 64 79 2О 6f 6e"
S+= "2О 6e 65 77 73 6d 74 7О 2e 75 6e 73 2e 61 63 2e"
S+= "72 73 2О 3О 3О 3О 32 62 61 62 63 Оd Оа"
#S = input("Enter the frame: ")



# Path: frameAnaliza.py
class FrameInternet:
    def parse_frame (self,frame):
        new_frame = ""
        frame = frame.replace(" ","")
        for i in range(len(frame)):
            if frame[i] == "O" or frame[i] == "О":
                new_frame += "0"
            elif frame[i] == "а":
                new_frame += "a"
            else:
                new_frame += frame[i]
        return new_frame

    def parse_hexadecimal(self,hex_string):
        decimal_number = 0
        for i in range(len(hex_string)):
            decimal_number = decimal_number * 16 + int(hex_string[i], 16)
        return decimal_number
    def parse_address(self,hex_string):
        address = ""
        for i in range(0, len(hex_string), 2):
            address += str(self.parse_hexadecimal(hex_string[i:i + 2])) + "."
        return address[:-1]
    def __init__(self,frame):
        self.frame = self.parse_frame(frame)
        self.workwithethernet(self.frame)
        self.calclIp(self.Data)
        self.calcProtocol(self.DataIP,self.Protocol)
        
    def workwithethernet(self,frame):
        self.DestinationMAC = (frame[:12])
        self.SourceMAC = (frame[12:24])
        self.Type = self.parse_hexadecimal(frame[24:28])
        if(self.Type < 1500):
            self.EthernetType = "IEEE 802.3"
            self.DSAP = self.parse_hexadecimal(frame[24:26])
            self.SSAP = self.parse_hexadecimal(frame[26:28])
            self.Control = self.parse_hexadecimal(frame[28:30])
            self.Data = frame[30:]
        else:
            self.EthernetType = "Ethernet II"
            self.Data = frame[28:]
        
    def calclIp(self,data):
        self.Version = self.parse_hexadecimal(data[0:1])
        if(self.Version == 4):
            self.IHLP = self.parse_hexadecimal(data[1:2])

            self.TOS = self.parse_hexadecimal(data[2:4])
            self.TotalLength = self.parse_hexadecimal(data[4:8])
            self.Identification = self.parse_hexadecimal(data[8:12])
            FlagesAndOfset = self.parse_hexadecimal(data[12:16])
            self.Flags = FlagesAndOfset >> 13
            self.Ofset = FlagesAndOfset & 0x1FFF
            self.TTL = self.parse_hexadecimal(data[16:18])
            self.Protocol = self.parse_hexadecimal(data[18:20])
            if(self.Protocol == 6):
                self.Protocol = "TCP"
            elif(self.Protocol == 17):
                self.Protocol = "UDP"
            
            self.Checksum = self.parse_hexadecimal(data[20:24])
            self.SourceIP = self.parse_address(data[24:32])
            self.DestinationIP = self.parse_address(data[32:40])
            i = self.IHLP - 5
            self.Options = ""
            while(i > 0):
                self.Options += data[40 + i * 4: 40 + i * 4 + 8]
                i -= 1
            self.DataIP = data[self.IHLP * 8:]
        elif(self.Version == 6):
            pass
        else:
            print("Unknown version")

    def calcProtocol(self,data,protocol):
        if(protocol == "TCP"):
            self.SourcePort = self.parse_hexadecimal(data[0:4])
            self.DestinationPort = self.parse_hexadecimal(data[4:8])
            self.SequenceNumber = self.parse_hexadecimal(data[8:16])
            self.AcknowledgmentNumber = self.parse_hexadecimal(data[16:24])
            self.DRF = self.parse_hexadecimal(data[24:28])
            self.ChecksumProtocol = self.parse_hexadecimal(data[28:32])
            self.UrgentPointer = self.parse_hexadecimal(data[32:36])
            self.DataProtocol = data[36:]
        elif(protocol == "UDP"):
            self.SourcePort = self.parse_hexadecimal(data[0:4])
            self.DestinationPort = self.parse_hexadecimal(data[4:8])
            self.Length = self.parse_hexadecimal(data[8:12])
            self.ChecksumProtocol = self.parse_hexadecimal(data[12:16])
            self.DataProtocol = data[16:]



# Path: frameAnaliza.py
frame= FrameInternet(S) 
print("Ethernet Type: " + frame.EthernetType)
print("Version: " + str(frame.Version))
print("Time to live: " + str(frame.TTL))
print("Ip Sender: " + frame.SourceIP)
print("Ip Receiver: " + frame.DestinationIP)
print("Protocol: " + str(frame.Protocol))
print("Source Port: " + str(frame.SourcePort))
print("Destination Port: " + str(frame.DestinationPort))



