
namespace EncryptionLibrary.Data
{
    /// <summary>
    /// Simple Class to store an Integer Value and a String
    /// </summary>
    public class InfoBlock
    {
        public const int UNDEFINED = 0;
        public const int SOMETHINGELSE = 07;


        private int myToken;
        private string myString;

        //-------------------------------------------------------------------------------------------------
        //--- Constructor to initialise the internal variables
        //-------------------------------------------------------------------------------------------------
        public InfoBlock()
        {
            myToken = UNDEFINED;
            myString = "";
        }

        //-------------------------------------------------------------------------------------------------
        //--- Getter - Setter Properties
        //-------------------------------------------------------------------------------------------------
        public int Token
        {
            get
            {
                return myToken;
            }
            set
            {
                myToken = value;
            }
        }
        public string Data
        {
            get
            {
                return myString;
            }
            set
            {
                myString = value;
            }
        }
    }
}
