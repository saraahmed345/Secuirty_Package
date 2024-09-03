using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{

	/// <summary>
	/// If the string starts with 0x.... then it's Hexadecimal not string
	/// </summary>
	public class DES : CryptographicTechnique
	{
		readonly int[,] pc = new int[8, 7] {
				{ 57, 49, 41, 33, 25, 17, 9 },
				{ 1, 58, 50, 42, 34, 26, 18 },
				{ 10, 2, 59, 51, 43, 35, 27 },
				{ 19, 11, 3, 60, 52, 44, 36 },
				{ 63, 55, 47, 39, 31, 23, 15 },
				{ 7, 62, 54, 46, 38, 30, 22 },
				{ 14, 6, 61, 53, 45, 37, 29 },
				{ 21, 13, 5, 28, 20, 12, 4 } };
		readonly int[,] pc2 = new int[8, 6] {
				{ 14, 17, 11, 24, 1, 5 },
				{ 3, 28, 15, 6, 21, 10 },
				{ 23, 19, 12, 4, 26, 8 },
				{ 16, 7, 27, 20, 13, 2 },
				{ 41, 52, 31, 37, 47, 55 },
				{ 30, 40, 51, 45, 33, 48 },
				{ 44, 49, 39, 56, 34, 53 },
				{ 46, 42, 50, 36, 29, 32 } };
		readonly int[,] s1 = new int[4, 16] {
				{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
				{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
				{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
				{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
		readonly int[,] s2 = new int[4, 16] {
				{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
				{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
				{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
				{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
		readonly int[,] s3 = new int[4, 16] {
				{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
				{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
				{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
				{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
		readonly int[,] s4 = new int[4, 16] {
				{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
				{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
				{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
				{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
		readonly int[,] s5 = new int[4, 16] {
				{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
				{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
				{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
				{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
		readonly int[,] s6 = new int[4, 16] {
				{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
				{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
				{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
				{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
		readonly int[,] s7 = new int[4, 16] {
				{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
				{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
				{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
				{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
		readonly int[,] s8 = new int[4, 16] {
				{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
				{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
				{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
				{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
		readonly int[,] P = new int[8, 4] {
				{ 16, 7, 20, 21 },
				{ 29, 12, 28, 17 },
				{ 1, 15, 23, 26 },
				{ 5, 18, 31, 10 },
				{ 2, 8, 24, 14 },
				{ 32, 27, 3, 9 },
				{ 19, 13, 30, 6 },
				{ 22, 11, 4, 25 } };
		readonly int[,] eb = new int[8, 6] {
				{ 32, 1, 2, 3, 4, 5 },
				{ 4, 5, 6, 7, 8, 9  },
				{ 8, 9, 10, 11, 12, 13 },
				{ 12, 13, 14, 15, 16, 17 },
				{ 16, 17, 18, 19, 20, 21 },
				{ 20, 21, 22, 23, 24, 25 },
				{ 24, 25, 26, 27, 28, 29 },
				{ 28, 29, 30, 31, 32, 1  } };
		readonly int[,] ip = new int[8, 8] {
				{ 58, 50, 42, 34, 26, 18, 10, 2 },
				{ 60, 52, 44, 36, 28, 20, 12, 4 },
				{ 62, 54, 46, 38, 30, 22, 14, 6 },
				{ 64, 56, 48, 40, 32, 24, 16, 8 },
				{ 57, 49, 41, 33, 25, 17, 9, 1  },
				{ 59, 51, 43, 35, 27, 19, 11, 3 },
				{ 61, 53, 45, 37, 29, 21, 13, 5 },
				{ 63, 55, 47, 39, 31, 23, 15, 7 } };
		readonly int[,] ip1 = new int[8, 8] {
				{ 40, 8, 48, 16, 56, 24, 64, 32 },
				{ 39, 7, 47, 15, 55, 23, 63, 31 },
				{ 38, 6, 46, 14, 54, 22, 62, 30 },
				{ 37, 5, 45, 13, 53, 21, 61, 29 },
				{ 36, 4, 44, 12, 52, 20, 60, 28 },
				{ 35, 3, 43, 11, 51, 19, 59, 27 },
				{ 34, 2, 42, 10, 50, 18, 58, 26 },
				{ 33, 1, 41, 9, 49, 17, 57, 25  } };

		// function to shift bits of the key
		private string ShiftKeyLeft(string k)
		{
			//string t = k[1].ToString();
			string t = k[0].ToString();
			k = k.Remove(0, 1);
			//k++
			k = k + t;
			t = k[0].ToString();
			k = k.Remove(0, 1);
			k = k + t;
			return k;
			//Console.WriteLine(k)
		}

		//  function to perform a permutation 
		public string initPermutation(int[,] permutationTable, string inputString, int Rws, int Cols)
		{
			string result = "";
			for (int i = 0; i < Rws; i++)
			{
				for (int j = 0; j < Cols; j++)
				{
					result = result + inputString[permutationTable[i, j] - 1];
					// Console.WriteLine(result)
				}
			}
			return result;
			//Console.WriteLine(result)
		}

		public void ShiftLeft(List<string> a1, List<string> a2, string key2_28, string key1_28)
		{
			for (int i = 0; i < 16; i++)
			{
				// string temp = "";
				if (new[] { 0, 1, 8, 15 }.Contains(i))
				{
					key1_28 = key1_28.Substring(1) + key1_28[0];
					//key1_28 = key1_28.Substring(-1) + key1_28[1];
					key2_28 = key2_28.Substring(1) + key2_28[0];
				}

				else
				{
					key1_28 = ShiftKeyLeft(key1_28);
					key2_28 = ShiftKeyLeft(key2_28);
				}

				a1.Add(key1_28);
				a2.Add(key2_28);
				//Console.WriteLine(key1_28);
				//Console.WriteLine(key2_28);

			}
			//Console.WriteLine(key1_28);
			//Console.WriteLine(key2_28);

		}

		public List<string> ConversionTo48(List<string> bitkey56)
		{
			List<string> bitkey48 = new List<string>();
			for (int i = 0; i < bitkey56.Count; i++)
			{
				string b56 = bitkey56[i];
				string b48 = initPermutation(pc2, b56, 8, 6);
				//string b48 = initPermutation(pc2 b56, 16, 3);
				bitkey48.Add(b48);
			}
			return bitkey48;
			//Console.WriteLine(bitkey48)
		}


		public string S_Box(List<string> separatedPlain)
		{
			string r = "";

			for (int s = 0; s < separatedPlain.Count; s++)
			{
				string t = separatedPlain[s];
				string t1 = t[0].ToString() + t[5];
				//string t1 = t[1].ToString() + t[4];

				string t2 = t[1].ToString() + t[2] + t[3] + t[4];
				//string t2 = t[4].ToString() + t[1] + t[2] + t[3];
				//string t2 = t[3].ToString() + t[1] + t[2] + t[4];
				//string t2 = t[2].ToString() + t[1] + t[3] + t[4];

				int row = Convert.ToInt32(t1, 2);
				int col = Convert.ToInt32(t2, 2);
				//Console.WriteLine(row)
				//Console.WriteLine(column)

				int res;
				switch (s)
				{
					case 0:
						res = s1[row, col];
						r = r + Convert.ToString(res, 2).PadLeft(4, '0');
						//Console.WriteLine(r);
						break;
					case 1:
						res = s2[row, col];
						r = r + Convert.ToString(res, 2).PadLeft(4, '0');
						//Console.WriteLine(r);
						break;
					case 2:
						res = s3[row, col];
						r = r + Convert.ToString(res, 2).PadLeft(4, '0');
						//Console.WriteLine(r);
						break;
					case 3:
						res = s4[row, col];
						r = r + Convert.ToString(res, 2).PadLeft(4, '0');
						//Console.WriteLine(r);
						break;
					case 4:
						res = s5[row, col];
						r = r + Convert.ToString(res, 2).PadLeft(4, '0');
						//Console.WriteLine(r);
						break;
					case 5:
						res = s6[row, col];
						r = r + Convert.ToString(res, 2).PadLeft(4, '0');

						//Console.WriteLine(r);
						break;
					case 6:
						res = s7[row, col];
						r = r + Convert.ToString(res, 2).PadLeft(4, '0');
						//Console.WriteLine(r);
						break;
					case 7:
						res = s8[row, col];
						r = r + Convert.ToString(res, 2).PadLeft(4, '0');
						//Console.WriteLine(r);
						break;
				}
			}

			return r;
			//Console.WriteLine(r);
		}


		public override string Decrypt(string cipherText, string key)
		{
			//string binaryk = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
			string binaryP = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
			//Console.WriteLine(binaryp);
			string binaryk = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
			//Console.WriteLine(binaryp);
			List<string> key_16 = GenerateKeys(binaryk);

			string initialPermutation = initPermutation(ip, binaryP, 8, 8);
			string left = initialPermutation.Substring(0, 32);
			//Console.WriteLine(left);
			string right = initialPermutation.Substring(32, 32);
			//Console.WriteLine(right);
			List<string> lefts = new List<string> { left };
			List<string> rights = new List<string> { right };

			for (int i = 0; i < 16; i++)
			{
				lefts.Add(rights[i]);
				string xor = XORWithKey(key_16[key_16.Count - 1 - i], initPermutation(eb, rights[i], 8, 6));
				string sboxResult = S_Box(Separate(xor, 6));
				string lastPermutation = initPermutation(P, sboxResult, 8, 4);
				rights.Add(XOR(lefts[i], lastPermutation));
			}

			string result = rights[16] + lefts[16];
			string plaintext = initPermutation(ip1, result, 8, 8);
			return "0x" + Convert.ToInt64(plaintext, 2).ToString("X").PadLeft(16, '0');
		}

		public override string Encrypt(string plainText, string key)
		{
			string binaryk = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
			//Console.WriteLine(binaryk);
			string binaryP = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
			//Console.WriteLine(binaryp);
			List<string> key_16 = GenerateKeys(binaryk);

			string initialPermutation = initPermutation(ip, binaryP, 8, 8);
			string left = initialPermutation.Substring(0, 32);
			//Console.WriteLine(left);
			string right = initialPermutation.Substring(32, 32);
			//Console.WriteLine(right);
			List<string> lefts = new List<string> { left };
			List<string> rights = new List<string> { right };

			for (int i = 0; i < 16; i++)
			{
				lefts.Add(rights[i]);
				string xor = XORWithKey(key_16[i], initPermutation(eb, rights[i], 8, 6));
				string sboxResult = S_Box(Separate(xor, 6));
				//Console.WriteLine(sboxResult);
				string lastPermutation = initPermutation(P, sboxResult, 8, 4);
				//Console.WriteLine(lastPermutation);
				rights.Add(XOR(lefts[i], lastPermutation));
			}

			string result = rights[16] + lefts[16];
			//Console.WriteLine(result);
			string cipherText = initPermutation(ip1, result, 8, 8);
			//Console.WriteLine(cipherText);
			return "0x" + Convert.ToInt64(cipherText, 2).ToString("X");
		}

		private List<string> GenerateKeys(string binaryKey)
		{
			string permutedK = initPermutation(pc, binaryKey, 8, 7);
			//Console.WriteLine(permutK);
			string l = permutedK.Substring(0, 28);
			//Console.WriteLine(l);
			string r = permutedK.Substring(28, 28);
			//Console.WriteLine(r);

			List<string> ls = new List<string>();
			List<string> rs = new List<string>();
			ShiftLeft(ls, rs, r, l);

			List<string> keys_56 = new List<string>();
			for (int i = 0; i < rs.Count; i++)
			{
				keys_56.Add(ls[i] + rs[i]);
			}

			return ConversionTo48(keys_56);
			//Console.WriteLine(ConversionTo48(keys_56));
		}

		private string XORWithKey(string key, string input)
		{
			string res = "";
			for (int i = 0; i < input.Length; i++)
			{
				res = res + (key[i] ^ input[i]).ToString();
			}
			return res;
			//Console.WriteLine(res);
		}

		private List<string> Separate(string input, int length)
		{
			List<string> res = new List<string>();
			for (int i = 0; i < input.Length; i += length)
			{
				string tmp = "";
				for (int j = i; j < i + length; j++)
				{
					tmp = tmp + input[j];
					//Console.WriteLine(tmp);
				}
				res.Add(tmp);
			}
			return res;
			//Console.WriteLine(res);
		}
		private string XOR(string left, string right)
		{
			string res = "";
			for (int i = 0; i < left.Length; i++)
			{
				res = res + (left[i] ^ right[i]).ToString();
				//Console.WriteLine(res);
			}
			//Console.WriteLine(res);
			return res;
		}


	}
}