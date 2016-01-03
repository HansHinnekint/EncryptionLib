using System;
using System.Windows.Forms;


using EncryptionLibrary;

namespace StringEncryptionApp
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            // Do something
            DateTimeGenerator myDTG;
            DateTime TheNetworkTime;
            DateTime TheLocalTime;
            TimeSpan span;

            myDTG = DateTimeGenerator.Instance;

            TheLocalTime = DateTime.UtcNow;
            TheNetworkTime = await myDTG.GetNTPTime();

            span = TheNetworkTime.Subtract(TheLocalTime);

            textBox1.Text = TheLocalTime.ToString();
            textBox2.Text = TheNetworkTime.ToString();

            textBox3.Text = span.ToString();
        }

    }
}
