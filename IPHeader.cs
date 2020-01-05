using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Sniffer_WPF
{
    public class IPHeader
    {

        private byte byVersionAndHeaderLength;      // Eight bits for version and header 
                                                    // length 
        private byte byDifferentiatedServices;      // Eight bits for differentiated 
                                                    // services
        private ushort usTotalLength;               // Sixteen bits for total length 
        private ushort usIdentification;            // Sixteen bits for identification
        private ushort usFlagsAndOffset;            // Eight bits for flags and frag. 
                                                    // offset 
        private byte byTTL;                         // Eight bits for TTL (Time To Live) 
                                                    // Eight bits for the underlying 
        private byte byProtocol;                    // protocol 
        private short sChecksum;                    // Sixteen bits for checksum of the 
                                                    //  header 
        private uint uiSoursIPAdress;               // Thirty two bit source IP Address 
        private uint uiDestinationIPAdress;         // Thirty two bit destination IP Address 

        private byte byHeaderLength;
        private byte[] byIpData = new byte[4096];


        public IPHeader(byte[] byBuffer, int nRecieved)
        {
            try
            {
                //Create MemoryStream out of the received bytes
                MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nRecieved);

                //Next we create a BinaryReader out of the MemoryStream
                BinaryReader binariReader = new BinaryReader(memoryStream);

                //The first eight bits of the IP header contain the version and
                //header length so we read them
                byVersionAndHeaderLength = binariReader.ReadByte();

                //The next eight bits contain the Differentiated services
                byDifferentiatedServices = binariReader.ReadByte();

                //Next eight bits hold the total length of the datagram
                usTotalLength = (ushort)IPAddress.NetworkToHostOrder(binariReader.ReadInt16());

                //Next sixteen have the identification bytes
                usIdentification = (ushort)IPAddress.NetworkToHostOrder(binariReader.ReadInt16());

                //Next sixteen bits contain the flags and fragmentation offset
                usFlagsAndOffset = (ushort)IPAddress.NetworkToHostOrder(binariReader.ReadInt16());

                //Next eight bits have the TTL value
                byTTL = binariReader.ReadByte();

                //Next eight represent the protocol encapsulated in the datagram
                byProtocol = binariReader.ReadByte();

                //Next sixteen bits contain the checksum of the header
                sChecksum = (short)IPAddress.NetworkToHostOrder(binariReader.ReadInt16());

                //Next thirty two bits have the source IP address
                uiSoursIPAdress = (uint)IPAddress.NetworkToHostOrder(binariReader.ReadInt32());

                //Next thirty two hold the destination IP address
                uiDestinationIPAdress = (uint)IPAddress.NetworkToHostOrder(binariReader.ReadInt32());

                //Now we calculate the header length
                byHeaderLength = byVersionAndHeaderLength;

                //The last four bits of the version and header length field contain the
                //header length, we perform some simple binary arithmetic operations to
                //extract them
                byHeaderLength <<= 4;
                byHeaderLength >>= 4;

                //Multiply by four to get the exact header length
                byHeaderLength *= 4;

                //Copy the data carried by the datagram into another array so that
                //according to the protocol being carried in the IP datagram
                Array.Copy(byBuffer,
                           byHeaderLength, //start copying from the end of the header
                           byIpData, 0, usTotalLength - byHeaderLength);

            }
            catch
            {
                Console.WriteLine("Constructor IPHeader->ERROR");
            }
        }

        public string VersionAndHeaderLength
        {
            get
            {
                return byVersionAndHeaderLength.ToString();
            }
        }

        public string SourcePort
        {
            get
            {
                return byVersionAndHeaderLength.ToString();
            }
        }

        public string DifferentiatedServices
        {
            get
            {
                return byDifferentiatedServices.ToString();
            }
        }

        public string TotalLength
        {
            get
            {
                return usTotalLength.ToString();
            }
        }

        public string Identification
        {
            get
            {
                return usIdentification.ToString();
            }
        }

        public string FlagsAndOffset
        {
            get
            {
                return usFlagsAndOffset.ToString();
            }
        }

        public string TTL
        {
            get
            {
                return byTTL.ToString();
            }
        }

        public string Protocol()
        {
            
                if (byProtocol.ToString() == "6")
                    return "TCP";
                else if (byProtocol.ToString() == "17")
                    return "UDP";

            return null;
            
        }

        public string Checksum
        {
            get
            {
                return string.Format("0x{0:x2}", sChecksum);
            }
        }

        public string SoursIPAdress
        {
            get
            {
                return uiSoursIPAdress.ToString();
            }
        }

        public string DestinationIPAdress
        {
            get
            {
                return uiDestinationIPAdress.ToString();
            }
        }

        public byte[] Data
        {
            get
            {
                return byIpData;
            }
        }

        public int MessageLength()
        {
            return byHeaderLength;
        }
    }
}
