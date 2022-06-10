using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Collections;// ArrayList, etc.

//using class Capture;
//using StopListen.Capture.Tpvs1;

//using Tpvs1.Capture;
namespace Tpvs1
{
    public partial class Form1 : Form
    {
        ArrayList devicesList = new ArrayList();
       Capture cap = new Capture();
        String[] str_tab;
        String dev_name;
       // Dictionary<int, byte[]> dd = cap.capturedPackets_list;

        

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

            listView1.FullRowSelect = true;
            //------ chargement de la forme ----


            this.CenterToScreen(); // afficher au centre d'ecran

            devicesList = cap.GetDevicesList();

            for (int i = 0; i < devicesList.Count; i++)
            {
                comboBox1.Items.Add((string)devicesList[i]);
            }

            if (comboBox1.Items.Count > 0)
            {
                comboBox1.SelectedIndex = 0;
                str_tab = ((string)devicesList[comboBox1.SelectedIndex]).Split(':');
                dev_name = str_tab[0].Trim();
            }

            Tpvs1.Capture.TrafficListView = this.listView1;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            cap.LiveCapture(dev_name, this);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            cap.StopListen();
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            str_tab = ((string)devicesList[comboBox1.SelectedIndex]).Split(':');
            dev_name = str_tab[0].Trim();
        }

       

        private void listView1_MouseClick(object sender, MouseEventArgs e)
        {  
            cap.getcapt();
            cap.parser();
          
            //System.EventArgs
            //  string[] row = { "walid", "taher", "deffase" };
            /*for (int i=0; i<listView1.Items.Count;i++)
            {
              row.add
            
            }*/
            // var LItem = new ListViewItem(row);
            c = listView1.SelectedItems[0].SubItems[0].Text;
            //textBox1.Text = c;

            //getcapt(int i,  Dictionary<int, byte[]> d)
            // cap.getcapt(c, cap.capturedPackets_list);
      

            
        }
        String c   ;

        public String getselectid() { return listView1.SelectedItems[0].SubItems[0].Text; }
        public String type() { return listView1.SelectedItems[0].SubItems[3].Text; }

        private void treeView1_AfterSelect(object sender, TreeViewEventArgs e)
        {

        }

        private void listView1_MouseMove(object sender, MouseEventArgs e)
        {
            //treeView1.Nodes.Clear();
        }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {
            treeView1.Nodes.Clear();
            richTextBox1.Text = null;
        }

        private void treeView1_MouseClick(object sender, MouseEventArgs e)
        {
            richTextBox1.BackColor = Color.Azure;
          //  richTextBox1.Text.
        }
    }

        
}
