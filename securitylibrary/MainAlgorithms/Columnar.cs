using System.Collections.Generic;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int key_Length = 0;
            List<int> Key = new List<int>();

            for (int i = 0; i < plainText.Length; i++)
            {
                string toFind = plainText[0].ToString() + plainText[i + 0] + plainText[2 * i + 0];
                if (cipherText.Contains(toFind))
                {
                    string toFind2 = plainText[1].ToString() + plainText[i + 1] + plainText[(i * 2) + 1];
                    if (cipherText.Contains(toFind2))
                    {
                        key_Length = i;
                        break;
                    }

                }
            }
            int WordLength = cipherText.Length / key_Length;
            for (int i = 0; i < key_Length; i++)
            {
                string Find;
                Find = plainText[i].ToString() + plainText[i + key_Length] + plainText[i + (2 * key_Length)];
                Key.Add((cipherText.IndexOf(Find) / WordLength) + 1);
            }
            return Key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            try
            {
                Dictionary<int, int> dec = new Dictionary<int, int>();
                for (int i = 0; i < key.Count; i++)
                {
                    dec.Add(i, key[i] - 1);
                }
                string plaintext = "";
                int num_Rows;
                num_Rows = (cipherText.Length + key.Count - 1) / key.Count;//it is round up the result

                for (int i = 0; i < num_Rows; i++)
                {
                    int start = dec[0];
                    for (int j = 0; j < key.Count; j++)
                    {
                        plaintext += cipherText[(start * num_Rows) + i];

                        start = j + 1;
                        start %= key.Count;
                        start = dec[start];

                    }

                }
                return plaintext;
            }
            catch (System.Exception)
            {

                return cipherText;
            }

        }


        public string Encrypt(string plainText, List<int> key)
        {

            string c = "";
            int count = 0;
            int Rows;
            Rows = (plainText.Length + key.Count - 1) / key.Count;
            int Cols = key.Count;
            Dictionary<int, int> d = new Dictionary<int, int>();
            for (int i = 0; i < key.Count; i++)
            {
                int index = key.FindIndex(a => a.Equals(i + 1));
                d.Add(i, index);
            }
            foreach (var colm in d)
            {
                int a = colm.Value;
                for (int j = 0; j < Rows; j++)
                {
                    if (a >= plainText.Length) { break; }
                    c += plainText[a];
                    a += Cols;
                }
                count++;
            }

            return c;
        }
    }
}