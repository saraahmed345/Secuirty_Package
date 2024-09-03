﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public struct KOMatrices
    {
        public Dictionary<char, Tuple<int, int>> KM;
        public List<List<char>> OM;
    }
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            // Define English letter frequencies
            Dictionary<char, double> englishFrequencies = new Dictionary<char, double>
    {
        {'a', 0.08167}, {'b', 0.01492}, {'c', 0.02782}, {'d', 0.04253},
        {'e', 0.12702}, {'f', 0.02228}, {'g', 0.02015}, {'h', 0.06094},
        {'i', 0.06966}, {'j', 0.00153}, {'k', 0.00772}, {'l', 0.04025},
        {'m', 0.02406}, {'n', 0.06749}, {'o', 0.07507}, {'p', 0.01929},
        {'q', 0.00095}, {'r', 0.05987}, {'s', 0.06327}, {'t', 0.09056},
        {'u', 0.02758}, {'v', 0.00978}, {'w', 0.0236}, {'x', 0.0015},
        {'y', 0.01974}, {'z', 0.00074}
    };

            // Normalize the inputs to lowercase
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            // Count the frequency of each character in the cipher text
            Dictionary<char, int> cipherFrequencies = new Dictionary<char, int>();
            foreach (char c in cipherText)
            {
                if (char.IsLetter(c))
                {
                    if (cipherFrequencies.ContainsKey(c))
                        cipherFrequencies[c]++;
                    else
                        cipherFrequencies[c] = 1;
                }
            }

            // Sort the frequencies in descending order
            var sortedCipherFrequencies = cipherFrequencies.OrderByDescending(kv => kv.Value);

            // Determine the mapping from cipher characters to English characters
            Dictionary<char, char> mapping = new Dictionary<char, char>();
            foreach (var kv in sortedCipherFrequencies)
            {
                char cipherChar = kv.Key;
                char englishChar = englishFrequencies.OrderByDescending(e => e.Value)
                                                      .First().Key;
                mapping[cipherChar] = englishChar;
                englishFrequencies.Remove(englishChar);
            }

            // Apply the mapping to decrypt the cipher text
            string decryptedText = "";
            foreach (char c in cipherText)
            {
                if (mapping.ContainsKey(c))
                    decryptedText += mapping[c];
                else
                    decryptedText += c; // Non-letter characters remain unchanged
            }

            // Check if the decrypted text matches the provided plain text
            int count = Enumerable.Range(0, plainText.Length)
                                  .Count(i => plainText[i] == decryptedText[i]);

            // Ensure that the decrypted text matches the plain text with an accuracy of more than 50%
            if (count * 100 / plainText.Length > 50)
                return decryptedText;
            else
                throw new Exception("Unable to decrypt with sufficient accuracy.");
















            // throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            List<string> smallSegs = new List<string>();
            bool flag = false;
            if (cipherText.Length > 100)
            {
                smallSegs = divideIt(cipherText);
                flag = true;
            }

            KOMatrices matrix = KOFunc(ModifiedKey(key));
            string FPT = "";
            for (int j = 0; j < smallSegs.Count || !flag; j++)
            {
                if (flag)
                {
                    cipherText = smallSegs[j];
                }
                int CTLength = cipherText.Length;
                string PT = "";
                flag = true;
                for (int i = 0; i < CTLength; i += 2)
                {
                    char c1 = cipherText[i], c2 = cipherText[i + 1];
                    if (matrix.KM[c1].Item2 == matrix.KM[c2].Item2)
                    {
                        PT += matrix.OM[(matrix.KM[c1].Item1 + 4) % 5][matrix.KM[c1].Item2];
                        PT += matrix.OM[(matrix.KM[c2].Item1 + 4) % 5][matrix.KM[c2].Item2];
                    }
                    else if (matrix.KM[c1].Item1 == matrix.KM[c2].Item1)
                    {
                        PT += matrix.OM[matrix.KM[c1].Item1][(matrix.KM[c1].Item2 + 4) % 5];
                        PT += matrix.OM[matrix.KM[c2].Item1][(matrix.KM[c2].Item2 + 4) % 5];
                    }
                    else
                    {
                        PT += matrix.OM[matrix.KM[c1].Item1][matrix.KM[c2].Item2];
                        PT += matrix.OM[matrix.KM[c2].Item1][matrix.KM[c1].Item2];
                    }
                }


                string ans = PT;
                if (PT[PT.Length - 1] == 'x')
                {
                    ans = ans.Remove(PT.Length - 1);
                }

                int w = 0;
                for (int i = 0; i < ans.Length; i++)
                {
                    if (PT[i] == 'x')
                    {
                        if (PT[i - 1] == PT[i + 1])
                        {
                            if (i + w < ans.Length && (i - 1) % 2 == 0)
                            {
                                ans = ans.Remove(i + w, 1);
                                w--;
                            }
                        }
                    }
                }

                FPT += ans;
            }

            Console.WriteLine(FPT);
            return FPT;



















            // throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string CT = "";

            KOMatrices KOkey = KOFunc(ModifiedKey(key));
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Substring(0, i + 1) + 'x' + plainText.Substring(i + 1);
                }

            }
            if (plainText.Length % 2 == 1) plainText += 'x';
            int PTLength = plainText.Length;
            for (int i = 0; i < PTLength; i += 2)
            {
                char c1 = plainText[i], c2 = plainText[i + 1];
                if (KOkey.KM[c1].Item2 == KOkey.KM[c2].Item2) //same column
                {
                    CT += KOkey.OM[(KOkey.KM[c1].Item1 + 1) % 5][KOkey.KM[c1].Item2];
                    CT += KOkey.OM[(KOkey.KM[c2].Item1 + 1) % 5][KOkey.KM[c2].Item2];
                }
                else if (KOkey.KM[c1].Item1 == KOkey.KM[c2].Item1)//same row
                {
                    CT += KOkey.OM[KOkey.KM[c1].Item1][(KOkey.KM[c1].Item2 + 1) % 5];
                    CT += KOkey.OM[KOkey.KM[c2].Item1][(KOkey.KM[c2].Item2 + 1) % 5];
                }
                else
                {
                    CT += KOkey.OM[KOkey.KM[c1].Item1][KOkey.KM[c2].Item2];
                    CT += KOkey.OM[KOkey.KM[c2].Item1][KOkey.KM[c1].Item2];
                }
            }


            Console.WriteLine(CT.ToUpper());
            Console.WriteLine("\n\n");
            return CT.ToUpper();

            //throw new NotImplementedException();
        }
        public KOMatrices KOFunc(HashSet<char> Mkey)
        {
            Dictionary<char, Tuple<int, int>> KMatrix = new Dictionary<char, Tuple<int, int>>();
            List<List<char>> OMatrix = new List<List<char>>();
            int counter = 0;
            for (int i = 0; i < 5; i++)
            {
                List<char> tmp = new List<char>();
                for (int j = 0; j < 5; j++)
                {
                    if (counter < 25)
                    {
                        KMatrix.Add(Mkey.ElementAt(counter), new Tuple<int, int>(i, j));
                        tmp.Add(Mkey.ElementAt(counter));
                        counter++;
                    }
                }

                OMatrix.Add(tmp);
            }

            KOMatrices komatrix = new KOMatrices();
            komatrix.KM = KMatrix;
            komatrix.OM = OMatrix;

            return komatrix;
        }
        public HashSet<char> ModifiedKey(string key)
        {
            string alphabet = "abcdefghiklmnopqrstuvwxyz"; // j removed
            HashSet<char> Mkey = new HashSet<char>();
            int keyLength = key.Length;
            for (int i = 0; i < keyLength; i++)
            {
                if (key[i] == 'j')
                {
                    Mkey.Add('i');
                }
                else
                {
                    Mkey.Add(key[i]);
                }
            }

            for (int i = 0; i < 25; i++)
            {
                Mkey.Add(alphabet[i]); // j not exist!
            }

            return Mkey;

        }
        public List<string> divideIt(string x)
        {
            List<string> largeString = new List<string>();
            int chunk = 100;
            int xLength = x.Length;
            for (int i = 0; i < xLength; i += chunk)
            {
                if (i + chunk > xLength) chunk = xLength - i;
                largeString.Add(x.Substring(i, chunk));

            }

            return largeString;
        }














    }
}
