using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            var key = new char[26];
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            for (var i = 0; i < cipherText.Length; i++)
            {
                var h1 = plainText[i] - 'a';
                var h2 = cipherText[i] - 'a';
                key[h1] = (char)('a' + h2);
            }

            var cr = 'a';
            for (var i = 0; i < key.Length; i++)
                if (key[i] < 'a')
                {
                    while (key.Contains(cr))
                        cr++;
                    key[i] = cr;
                }
            return new string(key);
        }

        public string Decrypt(string cipherText, string key)
        {
            var DWord = new char[cipherText.Length];
            cipherText = cipherText.ToLower();

            for (var i = 0; i < cipherText.Length; i++)
                if (cipherText[i] == ' ')
                {
                    DWord[i] = ' ';
                }
                else
                {

                    var hold = key.IndexOf(cipherText[i]);
                    DWord[i] = (char)(hold + 'a');
                }

            var Decrypted_Word = new string(DWord);
            return Decrypted_Word;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();

            var EWord = new char[plainText.Length];

            for (var i = 0; i < plainText.Length; i++)
                if (plainText[i] == ' ')
                    EWord[i] = ' ';
                else

                    EWord[i] = key[plainText[i] - 'a'];

            var Encrypted_word = new string(EWord);
            return Encrypted_word;
        }


        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            Dictionary<Char, Double> eng_Freq = new Dictionary<char, double>();
            Dictionary<Char, Double> cipher_Freq = new Dictionary<char, double>();
            Double[] eVal = { 8.04, 1.54, 3.06, 3.99, 12.51, 2.30, 1.96, 5.49, 7.26, 0.16, 0.67, 4.14, 2.53, 7.09, 7.60, 2.00, 0.11, 6.12, 6.54, 9.25, 2.71, 0.99, 1.92, 0.19, 1.73, 0.09 };

            for (char i = 'a'; i <= 'z'; i++)
            {
                eng_Freq.Add(i, eVal[(i - 'a')]);
                cipher_Freq.Add(i, 0);
            }
            foreach (char a in cipher)
            {
                cipher_Freq[a] += 1;
            }

            int cipherLen = cipher.Length;
            for (char i = 'a'; i <= 'z'; i++)
            {
                cipher_Freq[i] /= cipherLen;
            }

            var freq_In_EnglishList = eng_Freq.ToList();
            freq_In_EnglishList.Sort((x, y) => x.Value.CompareTo(y.Value));

            var freq_In_CipherList = cipher_Freq.ToList();
            freq_In_CipherList.Sort((x, y) => x.Value.CompareTo(y.Value));

            bool[] char_Replaced = new bool[cipher.Length];
            StringBuilder Ptext = new StringBuilder(cipher);

            for (int i = 0; i < 26; i++)
            {
                char charInCipher = freq_In_CipherList[i].Key;
                char charInEnglish = freq_In_EnglishList[i].Key;
                for (int j = 0; j < cipher.Length; j++)
                {
                    if (Ptext[j] == charInCipher && char_Replaced[j] != true)
                    {
                        Ptext[j] = charInEnglish;
                        char_Replaced[j] = true;
                    }
                }
            }

            return Ptext.ToString();
        }
    }
}