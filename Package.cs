using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sniffer_WPF
{
  public  class Package
    {
       public int number { get; set; }
       public string source { get; set; }
       public string distination { get; set; }
       public string protocol { get; set; }
       public string length { get; set; }
       public string info{ get; set; }

        public Package(int number, string source, string distination, string protocol, string length, string info)
        {
            this.number = number;
            this.source = source;
            this.distination = distination;
            this.protocol = protocol;
            this.length = length;
            this.info = info;
        }

        public int Number()
        {
            return this.number;
        }

        public string Source()
        {
            return this.source;
        }
        public string Distination()
        {
            return this.distination;
        }

        public string Protocol()
        {
            return this.protocol;
        }

        public string Length()
        {
            return this.length;
        }
        public string Info()
        {
            return this.info;
        }
    }
}
