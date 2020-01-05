using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace Sniffer_WPF
{
    public class Sniffer
    {
        private Socket mainSocket;                          //The socket which captures all incoming packets
        private byte[] byteData = new byte[4096];
        
        MainWindow form;
        int i = 0;
        private List<TCPHeader> list_tcpHeader;
        private List<UDPHeader> list_udpHeader;
        private List<IPHeader> list_ipHeader;
        private string socketIp;
        private bool allProtocol;
        private bool tcpProtocol;
        private bool udpProtocol;



        public Sniffer(MainWindow form)
        {
            this.form = form;
            list_ipHeader = new List<IPHeader>();
            list_udpHeader =new List<UDPHeader> ();
            list_tcpHeader = new List<TCPHeader>();
            allProtocol = true;
            tcpProtocol = false;
            udpProtocol = false;
            
        }

        public void Sniffer_Start()
        {
            try
            {
            // For sniffing the socket to capture the packets 
            // has to be a raw socket, with the address family
            // being of type internetwork, and protocol being IP
             mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

                // Bind the socket to the selected IP address
                mainSocket.Bind(new IPEndPoint(IPAddress.Parse(socketIp), 0));


                // Set the socket options
                mainSocket.SetSocketOption(SocketOptionLevel.IP,            //Applies only to IP packets
                                       SocketOptionName.HeaderIncluded, //Set the include the header
                                       true);


            byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
            byte[] byOut = new byte[4] { 1, 0, 0, 0 };

                
                mainSocket.IOControl(IOControlCode.ReceiveAll,              //Equivalent to SIO_RCVALL constant
                                 byTrue,
                                 byOut);

            byte[] byteData; byteData = new byte[4096];

                //Start receiving the packets asynchronously
                mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                                    new AsyncCallback(OnReceive), null);

            }
            catch
            {
                MessageBox.Show("Not Connected -> Change IP Adress","Sniffer");
            }
            
        }
        private void OnReceive(IAsyncResult ar)
        {

            try
            {
                int nReceived = mainSocket.EndReceive(ar);

                //Analyze the bytes received...

                ParseData(byteData, nReceived);


                byteData = new byte[4096];

                //Another call to BeginReceive so that we continue to receive the incoming
                //packets
                mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                    new AsyncCallback(OnReceive), null);

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
        ///////////////////////////////////////////////////////////////////////////////
        private async void ParseData(byte[] byteData, int nReceived)
        {

            this.form.Dispatcher.Invoke(() =>
            {

                IPHeader ipHeader = new IPHeader(byteData, nReceived);

                  if (allProtocol==true && ipHeader.Protocol() == "TCP"|| tcpProtocol == true && ipHeader.Protocol() == "TCP")
                    {
                        TCPHeader tcpHeader = new TCPHeader(ipHeader.Data, ipHeader.MessageLength(), i);
                        list_tcpHeader.Add(tcpHeader);
                        Package packege = new Package(i++, ipHeader.SoursIPAdress, ipHeader.DestinationIPAdress, "TCP ", 
                                                                    ipHeader.TotalLength, tcpHeader.SourcePort + " -> "
                                                                           + tcpHeader.DestinationPort + "  Seq = "
                                                                           + tcpHeader.SequenceNumber + "  Ack = "
                                                                           + tcpHeader.AcknowlegmentNumber + "  Win = "
                                                                           + tcpHeader.WindowSizeValue + "  Len = " 
                                                                           + ipHeader.TotalLength);
                        this.form.dataGrid.Items.Add(packege);
                        list_ipHeader.Add(ipHeader);
                    
                    }

                     if (allProtocol == true && ipHeader.Protocol() == "UDP" || udpProtocol == true && ipHeader.Protocol() == "UDP")
                    {
                        UDPHeader udpHeader = new UDPHeader(ipHeader.Data, ipHeader.MessageLength(),i);
                        list_udpHeader.Add(udpHeader);
                        list_ipHeader.Add(ipHeader);
                        Package packege = new Package(i++, ipHeader.SoursIPAdress, ipHeader.DestinationIPAdress, "UDP ", ipHeader.TotalLength, udpHeader.SourcePort + " -> " + udpHeader.DestinationPort + " Len = " + udpHeader.Length);
                        this.form.dataGrid.Items.Add(packege);
                       
                    }


            });

        }
        public void SnifferClose()
        {
            mainSocket.Close();

        }

        public IPHeader GetIPHeader(int index)
        {
            return list_ipHeader[index];

        }
        public TCPHeader GetTcpHeader(int index)
        {
            foreach(TCPHeader protocol in list_tcpHeader)
                if(protocol.IndexIpHeader==index)
                   return protocol;
            return null;

        }
        public UDPHeader GetUdpHeader(int index)
        {
            foreach (UDPHeader protocol in list_udpHeader)
                if (protocol.IndexIpHeader == index)
                    return protocol;
            return null;

        }
        public void SetSocketIP(string ip)
        {
            this.socketIp = ip;
        }

        public void SetAllProtocol(bool flag)
        {
            this.allProtocol = flag;
        }

        public void SetTCPProtocol(bool flag)
        {
            this.tcpProtocol = flag;
        }

        public void SetUdpProtocol(bool flag)
        {
            this.udpProtocol = flag;
        }

        public List<UDPHeader> Getlist_udpHeader()
        {
            return this.list_udpHeader;
        }
        public List<TCPHeader> Getlist_tcpHeader()
        {
            return this.list_tcpHeader;
        }
    }
}
