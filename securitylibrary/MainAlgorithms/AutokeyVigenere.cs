using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            string letters = "abcdefghijklmnopqrstuvwxyz";

            int n1;
            int n2;
            int index;
            string suppKey = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                n1 = letters.IndexOf(cipherText[i]);
                n2 = letters.IndexOf(plainText[i]);
                index = (n1 - n2 + 26) % 26;

                suppKey += letters[index];
            }

            string key = "";
            key += suppKey[0];
            key += suppKey[1];
            for (int i = 2; i < suppKey.Length; i++)
            {
                if (suppKey[i] == plainText[0] && suppKey[i + 1] == plainText[1])
                {
                    break;
                }
                else
                {
                    key += suppKey[i];
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string letters = "abcdefghijklmnopqrstuvwxyz";

            int diff = cipherText.Length - key.Length;
            for (int i = 0; i < diff; i++)
            {
                key += letters[(letters.IndexOf(cipherText[i]) - letters.IndexOf(key[i]) + 26) % 26];
            }

            int n1;
            int n2;
            int index;
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                n1 = letters.IndexOf(cipherText[i]);
                n2 = letters.IndexOf(key[i]);
                index = (n1 - n2 + 26) % 26;

                plainText += letters[index];
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string letters = "abcdefghijklmnopqrstuvwxyz";

            int diff = plainText.Length - key.Length;
            for (int i = 0; i < diff; i++)
            {
                key += plainText[i];
            }

            int n1;
            int n2;
            int index;
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                n1 = letters.IndexOf(plainText[i]);
                n2 = letters.IndexOf(key[i]);
                index = (n1 + n2) % 26;

                cipherText += letters[index];
            }

            return cipherText.ToUpper();
        }
    }
}
