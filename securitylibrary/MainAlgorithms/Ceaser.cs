using System;
using System.Text;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.ToLower();
            string cipherText = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText += ShiftCharacter(plainText[i], key);
            }

            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText += ShiftCharacter(cipherText[i], 26 - key);
            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < 26; i++)
            {
                if (Decrypt(cipherText, i).Equals(plainText))
                {
                    return i;
                }
            }

            return 0;
        }

        private char ShiftCharacter(char character, int shift)
        {
            return (char)(((((character + shift - 'a') % 26) + 26) % 26) + 'a');
        }
    }
}
