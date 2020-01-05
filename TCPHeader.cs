using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Sniffer_WPF
{
    public class TCPHeader
    {
        private int indexIPheader;
        //TCP header fields
        private ushort usSourcePort;
        private ushort usDestinationPort;
        private ushort usSequenceNumber;
        private ushort usAcknowlegmentNumber;
        private ushort usFlags;
        private ushort usWindowSizeValue;
        private short sChecksum;
        private ushort usUrgentPointer;


        private byte[] byTCPData = new byte[4096];  //Data carried by the UDP packet

        public TCPHeader(byte[] byBuffer, int nReceived, int indexIPheader)
        {
            MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);
            BinaryReader binaryReader = new BinaryReader(memoryStream);

            this.indexIPheader = indexIPheader;

            //The first sixteen bits contain the source port
            usSourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());


            usDestinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());


            usSequenceNumber = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //The next sixteen bits contain the checksum
            usAcknowlegmentNumber = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            usFlags = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());


            usWindowSizeValue = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            sChecksum = (short)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            Array.Copy(byBuffer,
                       8,
                       byTCPData,
                       0,
                       nReceived);
        }
        public int  IndexIpHeader
        {
            get
            {
                return indexIPheader;
            }
        }
        public string SourcePort
        {
            get
            {
                return usSourcePort.ToString();
            }
        }

        public string DestinationPort
        {
            get
            {
                return usDestinationPort.ToString();
            }
        }

        public string SequenceNumber
        {
            get
            {
                return usSequenceNumber.ToString();
            }
        }
        public string AcknowlegmentNumber
        {
            get
            {
                return usAcknowlegmentNumber.ToString();
            }
        }


        public string Flags
        {
            get
            {
                return usFlags.ToString();
            }
        }
        public string WindowSizeValue
        {
            get
            {
                return usWindowSizeValue.ToString();
            }
        }

        public string Checksum
        {
            get
            {
                //Return the checksum in hexadecimal format
                return string.Format("0x{0:x2}", sChecksum);
            }
        }


        public string UrgentPointer
        {
            get
            {
                return usUrgentPointer.ToString();
            }
        }


    }
}
