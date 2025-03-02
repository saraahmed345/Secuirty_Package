﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            List<int> possibleKeys = new List<int>();
            char sec = cipherText[1];
            foreach (char c in plainText)
            {
                if (c == sec) possibleKeys.Add(plainText.IndexOf(c));
            }

            foreach (int key in possibleKeys)
            {
                Console.WriteLine(key.ToString());
                string s = Encrypt(plainText, key).ToLower();
                Console.WriteLine(cipherText + " " + s);
                if (string.Equals(cipherText, s))
                {
                    Console.WriteLine(key);
                    return key;
                }
            }

            return -1;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int PTLength = (int)Math.Ceiling((double)cipherText.Length / key);
            return Encrypt(cipherText, PTLength).ToLower();
        }

        public string Encrypt(string plainText, int key)
        {
            String.Join(plainText, plainText.Split(' '));
            Console.WriteLine(plainText);
            List<List<char>> table = new List<List<char>>();
            int each = (int)Math.Ceiling((double)plainText.Length / key);
            int counter = 0;
            string CT = "";
            for (int i = 0; i < key; i++)
            {
                table.Add(new List<char>());
            }

            for (int i = 0; i < each; i++)
            {
                for (int j = 0; j < key && j < plainText.Length; j++)
                {
                    table[j].Add(plainText[counter++]);
                    if (counter == plainText.Length) break;
                }
            }

            foreach (List<char> row in table)
            {
                CT += string.Join("", row);
            }
            return CT.ToUpper();
        }
    }
}
