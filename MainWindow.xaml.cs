using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace Sniffer_WPF
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public Sniffer sniffer;
        public IPHeader ipHeader;
        public TCPHeader tcpHeader;
        public UDPHeader udpHeader;
        public bool startSniff = false;
        Thread sniff;
        public int rowIndex;
        public delegate void InvokeDelegate();
        public MainWindow()
        {
            InitializeComponent();
             sniffer = new Sniffer(this);
        }

        private void btnStart_Click(object sender, RoutedEventArgs e)
        {
            snifferStart();

        }

        private void snifferStart()
        {
            try
            {
                if (comboBox.Text == "")
                    MessageBox.Show("Enter IP", "Sniffer");
                else
                {
                   
                    startSniff = true;
                   sniffer.SetSocketIP(comboBox.Text);
                    sniff = new Thread(new ThreadStart(sniffer.Sniffer_Start));
                   sniff.Start();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());

            }

        }


        private void btnStop_Click(object sender, RoutedEventArgs e)
        {
            startSniff = false;
            sniffer.SnifferClose();
        }

        private void button3_Click(object sender, RoutedEventArgs e)
        {
            
            if (comboBox1.Text == "")
                    MessageBox.Show("Enter Protocol", "Sniffer");
            

                else
                {
                  try
                {  //sniffer.SetSocketIP(comboBox.Text);
                    //sniffer.SnifferClose();
                    dataGrid.Items.Clear();

                    switch (comboBox1.Text)
                    {
                        case "All":
                            sniffer.SetAllProtocol(true);
                            sniffer.SetTCPProtocol(false);
                            sniffer.SetUdpProtocol(false);
                            break;
                        case "tcp":
                            sniffer.SetAllProtocol(false);
                            sniffer.SetTCPProtocol(true);
                            sniffer.SetUdpProtocol(false);
                            break;
                        case "udp":
                            sniffer.SetAllProtocol(false);
                            sniffer.SetTCPProtocol(false);
                            sniffer.SetUdpProtocol(true);
                            break;

                    }

                    // Thread sniff = new Thread(new ThreadStart(sniffer.Sniffer_Start));
                    // sniff.Start();

                }
                catch(Exception ex)
                {
                   // MessageBox.Show(ex.ToString());
                }
            }
            if (startSniff == false)
                MessageBox.Show("Press the Start button", "Sniffer");


        }


        public  void CreateTree()
        {

            try
            {
                ipHeader = sniffer.GetIPHeader(rowIndex);
                //Create TreeView IPheader
                TreeViewItem protocolIP = new TreeViewItem();
                protocolIP.Header = "Internet Protocol Version 4";

                TreeViewItem version = new TreeViewItem();
                version.Header = "Version: 4";

                TreeViewItem headerlength = new TreeViewItem();
                headerlength.Header = "Header Length: " + ipHeader.VersionAndHeaderLength;

                TreeViewItem different = new TreeViewItem();
                different.Header = "Differentiated Services Field: " + ipHeader.DifferentiatedServices;

                TreeViewItem totallength = new TreeViewItem();
                totallength.Header = "Total Length: " + ipHeader.TotalLength;

                TreeViewItem identif = new TreeViewItem();
                identif.Header = "Identification: " + ipHeader.Identification;

                TreeViewItem flags = new TreeViewItem();
                flags.Header = "Flags: " + ipHeader.FlagsAndOffset;

                TreeViewItem timelive = new TreeViewItem();
                timelive.Header = "Time to live: " + ipHeader.TTL;

                TreeViewItem protocol = new TreeViewItem();
                protocol.Header = "Protocol: " + ipHeader.Protocol();

                TreeViewItem checksum = new TreeViewItem();
                checksum.Header = "Header Checksum: " + ipHeader.Checksum;

                TreeViewItem source = new TreeViewItem();
                source.Header = "Source: " + ipHeader.SoursIPAdress;

                TreeViewItem distIP = new TreeViewItem();
                distIP.Header = "Destination: " + ipHeader.DestinationIPAdress;

                protocolIP.Items.Add(version);
                protocolIP.Items.Add(headerlength);
                protocolIP.Items.Add(different);
                protocolIP.Items.Add(totallength);
                protocolIP.Items.Add(identif);
                protocolIP.Items.Add(flags);
                protocolIP.Items.Add(timelive);
                protocolIP.Items.Add(protocol);
                protocolIP.Items.Add(checksum);
                protocolIP.Items.Add(source);
                protocolIP.Items.Add(distIP);
                treeView1.Items.Add(protocolIP);
                
                switch (ipHeader.Protocol())
                {
                    case "TCP":
                        tcpHeader = sniffer.GetTcpHeader(rowIndex);
                        
                        TreeViewItem tcpProtocol = new TreeViewItem();
                        tcpProtocol.Header = "Transmission Control Protocol";
                        TreeViewItem sourcePort = new TreeViewItem();
                        sourcePort.Header = "Source Port: " + tcpHeader.SourcePort;
                        TreeViewItem destPort = new TreeViewItem();
                        destPort.Header = "Destination Port: " + tcpHeader.DestinationPort;
                        TreeViewItem sequence = new TreeViewItem();
                        sequence.Header = "Sequence number: " + tcpHeader.SequenceNumber;
                        TreeViewItem acknowl = new TreeViewItem();
                        acknowl.Header = "Acknowledgment number: " + tcpHeader.AcknowlegmentNumber;
                        TreeViewItem flag = new TreeViewItem();
                        flag.Header = "Flags: " + tcpHeader.Flags;
                        TreeViewItem winsize = new TreeViewItem();
                        winsize.Header = "Window size value: " + tcpHeader.WindowSizeValue;
                        TreeViewItem checksu = new TreeViewItem();
                        checksu.Header = "Checksum: " + tcpHeader.Checksum;
                        TreeViewItem urgpointer = new TreeViewItem();
                        urgpointer.Header = "Urgent pointer: " + tcpHeader.UrgentPointer;

                        tcpProtocol.Items.Add(sourcePort);
                        tcpProtocol.Items.Add(destPort);
                        tcpProtocol.Items.Add(sequence);
                        tcpProtocol.Items.Add(acknowl);
                        tcpProtocol.Items.Add(flag);
                        tcpProtocol.Items.Add(winsize);
                        tcpProtocol.Items.Add(checksu);
                        tcpProtocol.Items.Add(urgpointer);
                        treeView1.Items.Add(tcpProtocol);
                        break;

                    case "UDP":

                        udpHeader = sniffer.GetUdpHeader(rowIndex);
                        TreeViewItem udpProtocol = new TreeViewItem();
                        udpProtocol.Header = "User Datagram Protocol";
                        TreeViewItem sourcPort = new TreeViewItem();
                        sourcPort.Header = "Source Port: " + tcpHeader.SourcePort;
                        TreeViewItem desPort = new TreeViewItem();
                        desPort.Header = "Destination Port: " + tcpHeader.DestinationPort;
                        TreeViewItem length = new TreeViewItem();
                        length.Header = "Length: " + tcpHeader.SequenceNumber;
                        TreeViewItem checks = new TreeViewItem();
                        checks.Header = "Checksum: " + tcpHeader.Checksum;

                        udpProtocol.Items.Add(sourcPort);
                        udpProtocol.Items.Add(desPort);
                        udpProtocol.Items.Add(length);
                        udpProtocol.Items.Add(checks);

                        treeView1.Items.Add(udpProtocol);
                        break;
                }
                
            }catch(Exception ex)
            {
                MessageBox.Show(ex.ToString(), "Sniffer");
            }
                
            
        }

        private void button_Click(object sender, RoutedEventArgs e)
        {
            WindowGraf graf = new WindowGraf(sniffer);
            graf.Show();
        }
               

        private void dataGrid_SelectedCellsChanged(object sender, SelectedCellsChangedEventArgs e)
        {
            try
            {
                rowIndex = dataGrid.Items.IndexOf(dataGrid.CurrentItem);
                treeView1.Items.Clear();
                CreateTree();
            }
            catch (Exception ex)
            {
             MessageBox.Show(ex.ToString(), "Sniffer");
            }
           

            }
    }
}

