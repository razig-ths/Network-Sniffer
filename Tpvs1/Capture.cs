using System;
using System.Collections;// ArrayList, etc.
using System.Runtime.InteropServices;// DllImport, StructLayout, etc.
using System.Text; // StringBuilder, etc.
using System.Windows.Forms; // form, MessageBox, etc.
using System.Threading; // Thread
using System.Collections.Generic;
using System.Linq;
using System.Drawing;
namespace Tpvs1
{
    class Capture
    {
      //  Form1 ff = new Form1();
        

        public Dictionary<int, byte[]> capturedPackets_list = new Dictionary<int, byte[]>();
        //------------------------     Déclaration des variables globales    -----------------------------
        
        public delegate void Disp(); //déclaration d'un type délégué appelé Disp
        Thread ListenThread = null;// nlancer exec processus
        IntPtr header = IntPtr.Zero;//donné de packet capturé
        IntPtr data = IntPtr.Zero;//nul

        ArrayList deviceList = new ArrayList();//la liste ta3 ls interfaces dynamiq
        string device_name;//elment from array
        IntPtr pcap_t;//cnstructeur
        Form1 fm1;//objet dunterface Form
        int cmpt;//byach n7sab ls packet diwaaslo
        public static ListView TrafficListView;

        //------------------------     Déclaration des DLLs    -----------------------------fct system

        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)]
        private extern static IntPtr /* pcap_t* */ pcap_open_live(string dev, int packetLen, short mode, short timeout, StringBuilder errbuf);
                                                  //lancer la capture :pcap openliv
        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)]
        private extern static int pcap_findalldevs(ref IntPtr /* pcap_if_t** */ alldevs, StringBuilder /* char* */ errbuf);//chercher tous les interfca fi alldv:retourné une class---arr:code errreur
                                                  
        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)]
        private extern static void pcap_freealldevs(IntPtr /* pcap_if_t * */ alldevs);

        [DllImport("wpcap.dll")]
        private static extern int pcap_setmintocopy(IntPtr p, int size);

        [DllImport("wpcap.dll")]
        private static extern int pcap_next_ex(IntPtr p, ref IntPtr pkt_header, ref IntPtr packetdata);

        [DllImport("wpcap.dll")]
        private static extern void pcap_close(IntPtr p);

        [DllImport("wpcap.dll")]
        private static extern int pcap_sendpacket(IntPtr p, byte[] buff, int size);


        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_if /* Pcap interface*/
        {
            public IntPtr /* pcap_if* */	Next;
            public string Name;			                /* name to hand to "pcap_open_live()" */
            public string Description;	                /* textual description of interface, or NULL */
            public IntPtr /*pcap_addr * */	Addresses;
            public uint Flags;			                /* PCAP_IF_ interface flags */
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_addr
        {
            public IntPtr /* pcap_addr* */	Next;
            public IntPtr /* sockaddr* */	Addr;		/* address */
            public IntPtr /* sockaddr* */  Netmask;	/* netmask for that address */
            public IntPtr /* sockaddr* */	Broadaddr;	/* broadcast address for that address */
            public IntPtr /* sockaddr* */	Dstaddr;	/* P2P destination address for that address */
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct sockaddr
        {
            public short family; /* address family */
            public ushort port;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] addr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] zero;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_pkthdr
        {											//timestamp
            public int tv_sec;				///< seconds
            public int tv_usec;			///< microseconds
            public int caplen;			/* length of portion present */
            public int len;			/* length this packet (off wire) */
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct pcap_pktdata
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 65536)]
            public byte[] bytes;
        };

        //------------------------     Les fonctions    -----------------------------

        public ArrayList GetDevicesList()
        {
            deviceList.Clear();//nms7o chi difih
            IntPtr ptrDevs = IntPtr.Zero, next = IntPtr.Zero; // pointer to a pcap_if struct//n7attoh fi fct de l'etape 1 fltp p7
            pcap_if dev;
            StringBuilder errbuf = new StringBuilder(256); //will hold errors
            string dev_name;

            int res = pcap_findalldevs(ref ptrDevs, errbuf);
            if (res == -1)
            {
                string err = "Error in findalldevs(): " + errbuf;
                throw new Exception(err);
            }
            else
            {
                next = ptrDevs;
                while (next != IntPtr.Zero)
                {
                    dev = (pcap_if)Marshal.PtrToStructure(next, typeof(pcap_if));//pcapif=intptrfl c#

                    dev_name = dev.Name.ToString() + " : " + dev.Description.ToString();//bych nfar9o binatham

                    deviceList.Add(dev_name);
                    next = dev.Next;
                }
            }
            pcap_freealldevs(ptrDevs);  // free buffers, librer interfaces-objects mnzidouch nsta3mloham
            return deviceList;// list nom:description
        }
        
         
        public void LiveCapture(string dev_name, Form1 f)
        {
            fm1 = f;
            

            device_name = dev_name;

            TrafficListView.Items.Clear(); cmpt = 0;

            if (ListenThread != null)//IF THER IS AOTHER THREAD, WE STOP IT
            {
                ListenThread.Abort();
            }
            ListenThread = new Thread(new ThreadStart(Listen));
            ListenThread.IsBackground = true;//execution dans ariere plan
            ListenThread.Start();
        }

        public void Listen()
        {
            StringBuilder errbuf = new StringBuilder();
            //tempon pcap t
            pcap_t = pcap_open_live(device_name, 1514, 1, 1000, errbuf);//nom interface-taill-tem max d'attente :ch7al y93d fltempon - erreur

            if (pcap_t == null)
            {
                MessageBox.Show(" erreur de sniffing");
            }
            else
            {
                IntPtr pkthdr = IntPtr.Zero;
                IntPtr pktdata = IntPtr.Zero;

                while (true)
                {
                    int state = pcap_next_ex(pcap_t, ref pkthdr, ref pktdata);//ta9ra mn( tempon -fayn t7at lpacket psg par variable (recureable)entet- donnees
                    if (state == 1) /* SUCCESS */
                    {
                        header = pkthdr;//packet header
                        data = pktdata;//packet data
                        //pour afficher ysta3mal les delegee byach y3awan thread(thread myaffichich)
                        Disp Analyze = new Disp(Analyzing); //déclarer une variable de type Disp (de type délégué c-à-d un pointeur de fonction puis attribuer le délégué déclaré à une fonction (la fonction Analyzing))
                        fm1.Invoke(Analyze); // lancer la fonction du délégué 
                    }
                }/* end_while */
            }
        }

        public void Analyzing()
        {
            pcap_pkthdr h = (pcap_pkthdr)Marshal.PtrToStructure(header, typeof(pcap_pkthdr));

            byte[] packet_header = new byte[16];
            Marshal.Copy(header, packet_header, 0, 16);

            byte[] packet_data = new byte[(int)h.len];
            Marshal.Copy(data, packet_data, 0, (int)h.len);
            
            
            //--------------------------------------------------------------------------

           capturedPackets_list.Add(cmpt, Combine(packet_header,packet_data));


            //
            ListViewItem LItem;
            LItem = TrafficListView.Items.Add(cmpt.ToString());
            LItem.Text = cmpt.ToString();

            string filter = null;
          
            string i = packet_data[12].ToString("x02") + packet_data[13].ToString("x02");
            if (i == "0806" )

            {  LItem.SubItems.Add(packet_data[6].ToString("x02") + ":" + packet_data[7].ToString("x02") + ":" + packet_data[8].ToString("x02") + ":" + packet_data[9].ToString("x02") + ":" + packet_data[10].ToString("x02") + ":" + packet_data[11].ToString("x02"));
               LItem.SubItems.Add(packet_data[0].ToString("x02") + ":" + packet_data[1].ToString("x02") + ":" + packet_data[2].ToString("x02") + ":" + packet_data[3].ToString("x02") + ":" + packet_data[4].ToString("x02") + ":" + packet_data[5].ToString("x02"));
               LItem.SubItems.Add("ARP");
               LItem.BackColor = Color.AliceBlue;
            }
            else
            {
          // mac    LItem.SubItems.Add(packet_data[6].ToString("x02") + ":" + packet_data[7].ToString("x02") + ":" + packet_data[8].ToString("x02") + ":" + packet_data[9].ToString("x02") + ":" + packet_data[10].ToString("x02") + ":" + packet_data[11].ToString("x02"));
           // mac    LItem.SubItems.Add(packet_data[0].ToString("x02") + ":" + packet_data[1].ToString("x02") + ":" + packet_data[2].ToString("x02") + ":" + packet_data[3].ToString("x02") + ":" + packet_data[4].ToString("x02") + ":" + packet_data[5].ToString("x02"));
               // LItem.SubItems.Add(i);
                if (i == "0800")
                {
                    LItem.SubItems.Add(packet_data[26].ToString("d") + "." + packet_data[27].ToString("d") + "." + packet_data[28].ToString("d") + "." + packet_data[29].ToString("d"));
                    LItem.SubItems.Add(packet_data[30].ToString("d") + "." + packet_data[31].ToString("d") + "." + packet_data[32].ToString("d") + "." + packet_data[33].ToString("d"));
                    String demx = packet_data[23].ToString("x02");
                    switch (demx)
                    {   
                        case "06":
                            {
                                    LItem.SubItems.Add("TCP");
                                    LItem.BackColor = Color.Beige;
                                

                            }
                            break;
                        case "01":
                            {
                                
                                   
                                    LItem.SubItems.Add("ICMP");
                                    LItem.BackColor = Color.Brown;
                                
                            }
                            break;
                        case "17":
                            {
                                
                                   
                                    LItem.SubItems.Add("UDP");
                                    LItem.BackColor = Color.Coral;
                                }
                            
                            break;

                        default:
                            
                               // LItem.SubItems.Add(packet_data[26].ToString("d") + "." + packet_data[27].ToString("d") + "." + packet_data[28].ToString("d") + "." + packet_data[29].ToString("d"));
                               // LItem.SubItems.Add(packet_data[30].ToString("d") + "." + packet_data[31].ToString("d") + "." + packet_data[32].ToString("d") + "." + packet_data[33].ToString("d"));
                                LItem.SubItems.Add(packet_data[23].ToString("autre")); 
                            break;

                    }

                
                }
                else if (i == "86dd")
                {
                 LItem.SubItems.Add("IPv6 ");
                LItem.BackColor = Color.Cornsilk;
                }
                else if (i == "809B")
                {
                    LItem.SubItems.Add("AppleTalk ");
                    LItem.BackColor = Color.Cornsilk;
                }
                else if (i == "8035")
                {
                    LItem.SubItems.Add("RARP");
                    LItem.BackColor = Color.Cornsilk;
                }



            }
  

            cmpt++;// 9d mayji packet nzido

            //here work
            //--------------------------------------------------------------------------
        }
        
        

        int idpacket;
        // combine the header and data 
        public static byte[] Combine(byte[] first, byte[] second)
        {
            return first.Concat(second).ToArray();
        }

       
        // retreive info of selected item
        string aq;
        string selptype;// the selected type 
        public void getcapt()
        {
            String sel = fm1.getselectid();
             idpacket = Int32.Parse(sel);

            int a = idpacket;
            Dictionary<int, byte[]> d = capturedPackets_list;

              b = d[a];// b get the write packet from dict
              bb = d[a];// second getting of the packet
            // byte az = b[21];
             //LItem.SubItems.Add(packet_data[21].ToString("x02") + ":" + packet_data[22].ToString("x02") + ":" + packet_data[23].ToString("x02") + ":" + packet_data[24].ToString("x02") + ":" + packet_data[25].ToString("x02") + ":" + packet_data[26].ToString("x02"));

            // TextBox at;   bech ne3raf sa7 ladress
              aq = b[22].ToString("x02") + ":" + b[23].ToString("x02") + ":" + b[24].ToString("x02") + ":" + b[25].ToString("x02") + ":" + b[26].ToString("x02") + ":" + b[27].ToString("x02");
           


            ////////////////
             macadress();
            
             ipadress();
             portadress();
             icmptype();
            ip_protocol();
            // ethertype();
            string type=fm1.type();
            selptype = type;
            switch (type) {
                case "TCP":
                    {
                       
                        fm1.treeView1.Nodes.Add("Packet number:" + idpacket);
                        fm1.treeView1.Nodes[0].Nodes.Add("Interface name:" + device_name);// device_name;
                        fm1.treeView1.Nodes[0].Nodes.Add("length :" + plength());


                        fm1.treeView1.Nodes.Add("Ethernet:" + ethertype());
                        fm1.treeView1.Nodes[1].Nodes.Add("source mac adress:" + macsrc);// device_name;
                        fm1.treeView1.Nodes[1].Nodes.Add("destination mac adress :" + macdist);

                       // fm1.treeView1.Nodes[1].Nodes.Add("Destination: Broadcast (" + macdist + ")");
                       // fm1.treeView1.Nodes[1].Nodes.Add("Source:" + macsrc + "(" + macsrc + ")");

                        fm1.treeView1.Nodes.Add("Hardware Addr Type :" + ethertype());

                        operat();
                        fm1.treeView1.Nodes.Add("Tcp :");
                        fm1.treeView1.Nodes[2].Nodes.Add("hardware Type :" + ethertype());
                        fm1.treeView1.Nodes[2].Nodes.Add("Protocol Type : IPv4 (0x0800)");
                       // fm1.treeView1.Nodes[2].Nodes.Add("opcode :" + op);
                         fm1.treeView1.Nodes[2].Nodes.Add("source ip adress:"+addsrc);
                        fm1.treeView1.Nodes[2].Nodes.Add("distination ip adress:"+adrdist);

          
                         fm1.treeView1.Nodes[2].Nodes.Add("protocol :" + prot);

                     //   fm1.treeView1.Nodes[2].Nodes.Add("source port:" + srcp);
                      //  fm1.treeView1.Nodes[2].Nodes.Add("distination port:" + distp);





                    }
                    break;
                case "UDP":
                    {
                        
                        fm1.treeView1.Nodes.Add("Packet number:" + idpacket);
                        fm1.treeView1.Nodes[0].Nodes.Add("Interface name:" + device_name);// device_name;
                        fm1.treeView1.Nodes[0].Nodes.Add("length :" + plength());
                        fm1.treeView1.Nodes.Add("Ethernet:" + ethertype());

                        fm1.treeView1.Nodes.Add("Dest MAC Addr :" + ethertype());

                        fm1.treeView1.Nodes.Add("Operation :" + op);
                    }
                    break;
                case "ARP":
                    {
                        //fm1.textBox1.Text = "tcp";
                        fm1.treeView1.Nodes.Add("Packet number:" + idpacket);
                        fm1.treeView1.Nodes[0].Nodes.Add("Interface name:" + device_name);// device_name;
                        fm1.treeView1.Nodes[0].Nodes.Add("length :" + plength());
                        

                        fm1.treeView1.Nodes.Add("Ethernet:" + ethertype());
                        fm1.treeView1.Nodes[1].Nodes.Add("Destination: Broadcast (" + macdist+")");
                        fm1.treeView1.Nodes[1].Nodes.Add("Source:"+ macsrc+"(" + macsrc + ")");
                        ether();
                        fm1.treeView1.Nodes[1].Nodes.Add("type:" + eth);

                        fm1.treeView1.Nodes.Add("Hardware Addr Type :" + ethertype());

                        operat();
                        fm1.treeView1.Nodes.Add("Adress Resolution Protocol :" + op);
                        fm1.treeView1.Nodes[2].Nodes.Add("hardware Type :" + ethertype());
                        fm1.treeView1.Nodes[2].Nodes.Add("Protocol Type : IPv4 (0x0800)");
                        fm1.treeView1.Nodes[2].Nodes.Add("opcode :" + op);




                 }
                    break;
                case "ICMP":
                     {

                         fm1.treeView1.Nodes.Add("Ethernet:" + ethertype());
                         fm1.treeView1.Nodes[0].Nodes.Add("Interface name:" + device_name);// device_name;
                         fm1.treeView1.Nodes[0].Nodes.Add("length :" + plength());

                         fm1.treeView1.Nodes.Add("Hardware Addr Type :" + ethertype());
                         fm1.treeView1.Nodes[1].Nodes.Add("source mac adress:" + macsrc);// device_name;
                         fm1.treeView1.Nodes[1].Nodes.Add("destination mac adress :" + macdist);


                         
                         fm1.treeView1.Nodes.Add("ICMP: ("+icmp_type+")");
                         fm1.treeView1.Nodes[2].Nodes.Add("type :" + icmp_type);
                         fm1.treeView1.Nodes[2].Nodes.Add("code :" + code_icmp);
                         fm1.treeView1.Nodes[2].Nodes.Add("source ip adress:" + addsrc);
                         fm1.treeView1.Nodes[2].Nodes.Add("distination ip adress:" + adrdist);


                     
                     
                     }
                      break;
               
                default:
                   // textBox2.Text = "";
                    break;
                }
        }

         byte[] b;
        string eth;
        public void ether()
        {
            string s = b[12].ToString("x02") + b[13].ToString("x02");
            switch (s)
            {
                case "0806":
                    {
                       eth = " ARP";
                    }
                    break;
                case "0800":
                    {
                        eth = "IP";
                    }
                    break;
                default:
                    {
                       eth = "autre";
                    }
                    break;

            }
        }


       

        byte[] bb;
        //packet lenght
        public string plength()
        { return b[12].ToString("d") + b[13].ToString("d") + b[14].ToString("d") + b[15].ToString("d"); }
       
        //ether Type
        public String ethertype()
        {
           // Byte[] b;
            if(b[30].ToString("d")+b[31].ToString("d")=="01")
            { return "Ethernet" ;}
            else
                if (b[30].ToString("d") + b[31].ToString("d") == "06")
                {
                    return "IEEE 802 LAN";
                }
                else
                {
                    return b[31].ToString("x");
                }
                     }
     

        public String mactype()
        {
            // Byte[] b;

            return b[29].ToString("x02") + b[29].ToString("x02") + b[29].ToString("x02");
        }

        //operation protocol
        public string op;
        public void operat()
        {
     
            if (b[36].ToString("x") + b[37].ToString("x") == "01")
            {
                op="Request";
               }
            else
                if (b[29].ToString("x") + b[29].ToString("x") == "02")
                {   op="Reply";
              
                } }
        ///// Paquets IP 
       
        string prot;
///
        ///////ip protocols
        public void ip_protocol()
        {
            byte aa = b[39];

            string s = b[39].ToString("d");
            switch (s)
            {
                case "1":
                    {
                        code_icmp = " ICMP";
                    }
                    break;
                case "2":
                    {
                        code_icmp = "IGMP";
                    }
                    break;
                case "6":
                    {
                        code_icmp = "TCP";
                    }
                    break;
                case "9":
                    {
                        code_icmp = " IGRP ";
                    }
                    break;
                case "17":
                    {
                        code_icmp = "UDP ";
                    }
                    break;
                case "47":
                    {
                        code_icmp = " GRE ";
                    }
                    break;
                case "50":
                    {
                        code_icmp = " ESP";
                    }
                    break;

                case "51":
                    {
                        code_icmp = "AH";
                    }
                    break;
                case "57":
                    {
                        code_icmp = "SKIP";
                    }
                    break;
                case "88":
                    {
                        code_icmp = " EIGRP";
                    }
                    break;
                case "89":
                    {
                        code_icmp = "OSPF";
                    }
                    break;
                case "115":
                    {
                        code_icmp = " L2TP";
                    }
                    break;

            }


        }
        ////////////////////////////////////////////
        //ip +macs
        string addsrc;
        string adrdist;
        public void ipadress()
        {  
            addsrc=b[42].ToString("d") + "." +b[43].ToString("d")+"." +b[44].ToString("d")+"." +b[45].ToString("d");
           adrdist=b[46].ToString("d")+"." +b[47].ToString("d")+"." +b[48].ToString("d")+"." +b[49].ToString("d");
        
        }
        string srcp;
        string distp;

        public void portadress()
        {
            srcp = b[50].ToString("d") + "." + b[51].ToString("d") ;
            distp = b[52].ToString("d") + "." + b[53].ToString("d");

        }
        
        string macsrc;
        string macdist;
        public void macadress()
        {  
            macdist=b[16].ToString("x02") + ":" + b[17].ToString("x02") + ":" + b[18].ToString("x02") + ":" + b[19].ToString("x02") + ":" + b[20].ToString("x02") + ":" + b[21].ToString("x02");
            macsrc=b[22].ToString("x02") + ":" + b[23].ToString("x02") + ":" + b[24].ToString("x02") + ":" + b[25].ToString("x02") + ":" + b[26].ToString("x02") + ":" + b[27].ToString("x02");
        
        }



        //Icmp parser---------------------------------------------------------------------------------------------------
        public string icmp_type;
        public string code_icmp;

        public void icmptype()
        {string x=b[50].ToString("x");
       
        string code = b[51].ToString("x");
            if (x == "1")
            { icmp_type = "Echo Reply"; }
            else
                if (x == "3")
                { icmp_type = "Destination Unreachable";
                switch (code)
                {
                    case "0":
                        {
                            code_icmp = " Net Unreachable";
                        }
                        break;
                    case "1":
                        {
                            code_icmp = "Host Unreachabl";
                        }
                        break;
                    case "2":
                        {
                            code_icmp = "Protocol Unreachable ";
                        }
                        break;
                    case "3":
                        {
                            code_icmp = " Port Unreachable ";
                        }
                        break;
                    case "4":
                        {
                            code_icmp = " Fragmentation Needed & DF Set ";
                        }
                        break;
                    case "5":
                        {
                            code_icmp = " Source Route Failed ";
                        }
                        break;
                    case "6":
                        {
                            code_icmp = " Destination Network Unknown ";
                        }
                        break;
                    case "7":
                        {
                            code_icmp = " Destination Host Unknown ";
                        }
                        break;
                    case "8":
                        {
                            code_icmp = "Source Host Isolated ";
                        }
                        break;
                    case "9":
                        {
                            code_icmp = " Network Administratively Prohibited";
                        }
                        break;
                    case "10":
                        {
                            code_icmp = " Host Administratively Prohibited";
                        }
                        break;
                    case "11":
                        {
                            code_icmp = "Network Unreachable for TOS ";
                        }
                        break;
                    case "12":
                        {
                            code_icmp = " Host Unreachable for TOS";
                        }
                        break;

                    case "13":
                        {
                            code_icmp = " Communication Admin Prohibited ";
                        }
                        break;
                }
                }
            /////////
            if (x == "4")
            { icmp_type = "Source Quench"; }

            ///////
            if (x == "5")
            {
                icmp_type = "Source Quench";
                switch (code)
                {
                    case "0":
                        {
                            code_icmp = " Redirect Datagram for the Network ";
                        }
                        break;
                    case "1":
                        {
                            code_icmp = "Redirect Datagram for the Host ";
                        }
                        break;
                    case "2":
                        {
                            code_icmp = " Redirect Datagram for TOS & Network ";
                        }
                        break;
                    case "3":
                        {
                            code_icmp = " Redirect Datagram for TOS & Host";
                        }
                        break;

                }
            }
            /////////////////////
            if (x == "8")
            { icmp_type = "Echo"; code_icmp = "0"; }
            /////////////////////////
            if (x == "9")
            { icmp_type = "Router Advertisement "; }
            /////////////////////////
            if (x == "10")
            { icmp_type = "Router Selection"; }
            /////////////////////////
            if (x == "11")
            {
                icmp_type = "Time Exceeded";
            switch (code)
            {
                case "0":
                    {
                        code_icmp = "Time to Live exceeded in Transit ";
                    }
                    break;
                case "1":
                    {
                        code_icmp = "Fragment Reassembly Time Exceeded";
                    }
                    break;
            
            }
            }
            //////////////////////////////
            if (x == "12")
            { icmp_type = "Parameter Problem";
            switch (code)
            {
                case "0":
                    {
                        code_icmp = "Pointer indicates the error";
                    }
                    break;
                case "1":
                    {
                        code_icmp = "Missing a Required Option";
                    }
                    break;
                case "2":
                    {
                        code_icmp = " Bad Length";
                    }
                    break;
            
            }}
            /////////////////////////
            /////////////////////
            if (x == "13")
            { icmp_type = "Timestamp "; }
            ///////////////////////// /////////////////////
            if (x == "14")
            { icmp_type = "Timestamp Reply "; }
            ///////////////////////// /////////////////////
            if (x == "15")
            { icmp_type = "Information Request "; }
            ///////////////////////// /////////////////////
            if (x == "16")
            { icmp_type = "Information Reply "; }
            ///////////////////////// /////////////////////
            if (x == "17")
            { icmp_type = "Address Mask Request "; }
            ///////////////////////// /////////////////////
            if (x == "18")
            { icmp_type = "Address Mask Reply "; }
            ///////////////////////// /////////////////////
            if (x == "30")
            { icmp_type = "Traceroute"; }
            /////////////////////////
            if (x == "0")
            { icmp_type = "echo( replay )"; code_icmp = "0"; }
            /////////////////////////
          }
  //-------------------------
        //UDP pars
        string udp_prts;
        public void udpports()
        {
            string x = b[6].ToString("d") + b[6].ToString("d");
            switch (x)
            {
                case "7":
                    {
                        code_icmp = "Time to Live exceeded in Transit ";
                    }
                    break;
                case "19":
                    {
                        code_icmp = "Fragment Reassembly Time Exceeded";
                    }
                    break;
                   case "37":
                    {
                        code_icmp = "Time to Live exceeded in Transit ";
                    }
                    break;
                case "53":
                    {
                        code_icmp = "Fragment Reassembly Time Exceeded";
                    }
                    break;
                  case "67":
                    {
                        code_icmp = "Time to Live exceeded in Transit ";
                    }
                    break;
                case "68":
                    {
                        code_icmp = "Fragment Reassembly Time Exceeded";
                    }
                    break;
                 case "69":
                    {
                        code_icmp = "Time to Live exceeded in Transit ";
                    }
                    break;
                case "137":
                    {
                        code_icmp = "Fragment Reassembly Time Exceeded";
                    }
                    break;
                   case "138":
                    {
                        code_icmp = "Time to Live exceeded in Transit ";
                    }
                    break;
                case "161":
                    {
                        code_icmp = "Fragment Reassembly Time Exceeded";
                    }
                    break;
                   case "162":
                    {
                        code_icmp = "Time to Live exceeded in Transit ";
                    }
                    break;
                case "500":
                    {
                        code_icmp = "Fragment Reassembly Time Exceeded";
                    }
                    break;
                  case "514":
                    {
                        code_icmp = "Time to Live exceeded in Transit ";
                    }
                    break;
                case "520":
                    {
                        code_icmp = "Fragment Reassembly Time Exceeded";
                    }
                    break;
                case "33434":
                    {
                        code_icmp = "Fragment Reassembly Time Exceeded";
                    }
                    break;
        }}
//////////////////////////////////////////////////////////////////////////////////////////////////////

        int max = 0;
   public void parser()
       {
           int i=0;
           if (selptype == "ARP")
           { max = 58; }
           else
           {
               if (selptype == "ICMP")
               { max = 74; }
               if (selptype == "TCP")
               { max = 66; }
               if (selptype == "UDP")
               { max = 58; }
           }
           while (i < max)
           {
              
                // b[i].ToString("x02"); }
                   fm1.richTextBox1.AppendText(bb[i].ToString("x02") +" ");
               
               i++;
           }

           
         
        }




          
        
        
        
        
            
                


        











        
        




        public void StopListen()
        {
            if (ListenThread != null)
            {
                if (ListenThread.IsAlive)
                {
                    ListenThread.Abort();
                }

                if (pcap_t != IntPtr.Zero)
                {
                    pcap_close(pcap_t);
                }

                ListenThread = null;
            }
        }
    }
}
