using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace Sniffer_WPF
{
    /// <summary>
    /// Interaction logic for WindowGraf.xaml
    /// </summary>
    public partial class WindowGraf : Window
    {
        private Sniffer snif;
        public WindowGraf(Sniffer snif)
        {
            InitializeComponent();
            this.snif = snif;
        }

        private void ColumnSeries_Loaded_1(object sender, RoutedEventArgs e)
        {
            myChart.ItemsSource =
                            new KeyValuePair<string, int>[]{
        new KeyValuePair<string,int>("TCP", snif.Getlist_tcpHeader().Count),
        new KeyValuePair<string,int>("UDP", snif.Getlist_udpHeader().Count)
         };
        }
    }
}
