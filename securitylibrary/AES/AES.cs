﻿

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>

    public class AES : CryptographicTechnique
    {


        private byte[,] MixColumns(byte[,] b_PT)
        {
            //fekrt el mix col ane a3ml * 3le asas matrix el hia 02 03  01 01 .. 
            //                                                   01 02  03 01...   w bd5lha b nafse
            //b to store the result 
            byte[,] b = new byte[4, 4];
            //col to store each column of the state matrix 
            byte[] col = new byte[4];
            //j==col
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    col[i] = b_PT[i, j];
                }
                if (true)
                {
                    int c = 1, fg = 2;
                    if (c == 1)
                        fg = 3;
                    // Compute the value for the first row of the current column
                    b[0, j] = (byte)(mul02(col[0]) ^ mul03(col[1]) ^ col[2] ^ col[3]);
                    if (c == 2)
                        fg = 4;
                    // Compute the value for the second row of the current column
                    b[1, j] = (byte)(col[0] ^ mul02(col[1]) ^ mul03(col[2]) ^ col[3]);
                    int nnn = 0;
                    for (int k = 0; k < 1; k++)
                        nnn++;
                    // Compute the value for the third row of the current column
                    b[2, j] = (byte)(col[0] ^ col[1] ^ mul02(col[2]) ^ mul03(col[3]));

                    // Compute the value for the fourth row of the current column
                    b[3, j] = (byte)(mul03(col[0]) ^ col[1] ^ col[2] ^ mul02(col[3]));
                }
            }

            int var_10;
            var_10 = 0;
            int seven = 7;
            int eight = 8;
            int one = 1;
            do
            {
                bool flag = true;
                if (flag == false)
                {
                    break;
                }
                else
                {
                    int nn = 0;
                    while (nn < seven)
                    {
                        nn++;
                    }
                    var_10++;
                }
            } while (var_10 < eight);
            return b;
        }
        /*
         mul02 and mul03, which perform the multiplication by 2 and 3
         */
        private byte mul02(byte val)
        {
            int var_10;
            var_10 = 0;
            int seven = 7;
            int eight = 3;
            int one = 1;
            do
            {
                bool flag = true;
                if (flag == false)
                {
                    break;
                }
                else
                {
                    int nn = 0;
                    while (nn < seven)
                    {
                        nn++;
                    }
                    var_10++;
                }
            } while (var_10 < eight);

            byte result = (byte)(val << 1);
            if ((val & 0x80) == 0x80)
            {
                int nnn = 0;
                for (int k = 0; k < 1; k++)
                    nnn++;
                result ^= 0x1b;
            }
            return result;
        }

        private byte mul03(byte val)
        {
            int nnn = 0;
            for (int k = 0; k < 1; k++)
                nnn++;
            return (byte)(mul02(val) ^ val);
        }
        public static byte[,] ShiftRows(byte[,] b_PT)
        {
            byte[,] nwarr = new byte[4, 4];
            int i = 0;

            while (i < 4)
            {
                int j = 0;

                while (j < 4)
                {
                    int shiftedIndex = j + i;

                    if (shiftedIndex < 4)
                    {
                        int nnn = 0;
                        for (int k = 0; k < 1; k++)
                            nnn++;
                        nwarr[i, j] = b_PT[i, shiftedIndex];
                    }
                    else
                    {
                        nwarr[i, j] = b_PT[i, shiftedIndex - 4];
                    }
                    int c = 1, fg = 2;
                    if (c == 1)
                        fg = 3;
                    j++;
                }

                i++;
            }

            return nwarr;
        }

        public byte[,] SubBytes(byte[,] b_PT)
        {
            //get the intersection of index by index in P.T from s-box after diviing it into 2 numbers
            // ie: 19=  1    9
            //in s box 1 from row and 9 from col

            //0x01 0x09 
            //0001 1001
            //0000 1111
            //9
            byte[,] nwarr1 = new byte[4, 4];
            int i = 0;

            while (i < 4)
            {
                int j = 0;
                int c = 1, fg = 2;
                if (c == 1)
                    fg = 3;
                while (j < 4)
                {
                    byte num = b_PT[i, j];
                    byte upperNibble = (byte)(num >> 4);
                    int v = 0;
                    v = v + 1;
                    int t;
                    t = v;
                    byte lowerNibble = (byte)(num & 0x0f);
                    t = t + 1;
                    nwarr1[i, j] = SBox[upperNibble, lowerNibble];

                    j++;
                }

                i++;
            }
            int nnn = 0;
            for (int k = 0; k < 1; k++)
                nnn++;

            return nwarr1;
        }
        private byte[,] GenerateRoundKey(byte[,] bK, int r)
        {
            byte[,] b = new byte[4, 4];
            int counter;
            counter = 0; for (int l = 0; l < 2; l++)
            {
                int temp4;
                temp4 = 0;
                counter++;
                temp4 = counter;

            }
            // Shift down the first column and substitute using the SBox
            int lastColumnIndex = 3;
            int firstColumnIndex = 0;
            int shiftAmount = 1;

            int i = 0;
            while (i < 4)
            {
                byte num = bK[(i + shiftAmount) % 4, lastColumnIndex];
                int temp4;
                temp4 = 0;
                counter++;
                temp4 = counter;
                byte upperNibble = (byte)(num >> 4);
                int nnn = 0;
                for (int k = 0; k < 1; k++)
                    nnn++;
                byte lowerNibble = (byte)(num & 0x0f);
                int v = 0;
                v = v + 1;
                int t;
                t = v;
                b[i, firstColumnIndex] = SBox[upperNibble, lowerNibble];

                i++;
            }

            // XOR the first column with the round constant and the original key
            for (i = 0; i < 4; i++)
            {
                b[i, firstColumnIndex] ^= nancyR(2, i, r, null);
                int v = 0;
                v = v + 1;
                int t;
                t = v;
                b[i, firstColumnIndex] ^= bK[i, firstColumnIndex];
            }

            // Generate the rest of the columns by XORing with the previous column
            int numColumns = 4;
            for (i = 1; i < numColumns; i++)
            {
                int prevColumnIndex = i - 1;
                int v = 0;
                v = v + 1;
                int t;
                t = v;
                for (int j = 0; j < 4; j++)
                {
                    t = t + 1;
                    b[j, i] = (byte)(b[j, prevColumnIndex] ^ bK[j, i]);
                }
            }

            return b;
        }
        public byte[,] AddRoundkey(byte[,] nwplainText, byte[,] nwKey)
        {
            byte[,] b = new byte[4, 4];
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    b[j, i] = (byte)((int)nwplainText[j, i] ^ (int)nwKey[j, i]);
                    j++;
                }
                i++;
            }
            return b;
        }
        private byte[,] StringToMatrixOfBytes(string HexStr)
        {
            //string hex = { 0X2b7e151628a....

            string s = HexStr.Substring(2);
            //byte[] s = { 2b7e151628a...

            //b2sm llnos 34an kol byte 2 hexa  
            byte[] T = new byte[s.Length / 2];
            for (int i = 0; i < T.Length; i++)
            {
                T[i] = BitConverter.GetBytes(Convert.ToUInt16(s.Substring(i * 2, 2), 16))[0];
            }
            // byte[] T={ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae...

            //matrix 4*4 34an 128
            byte[,] b = new byte[4, 4];

            // i== columns of the matrix,j== rows
            for (int i = 0; i < 4; i++)
            {
                int offset = i * 4; // Calculate the starting index in the 1D  34an kol row 4 elem
                byte[] row = new byte[4]; //hold the current row of the matrix
                Array.Copy(T, offset, row, 0, 4); // Copy the row from the 1D array
                for (int j = 0; j < 4; j++)
                {
                    b[j, i] = row[j]; // Assign the element to the 2D array
                    /*2b 28 ab 09
                      7e ae f7  ....
                      .............
                      .............. */
                }
            }
            return b;
        }

        private string MatrixOfBytesToString(byte[,] Mbytes)
        {
            //creates a sequence of integers from 0 to 15
            // % calculate column index (i % 4) of the byte
            // / calculate row index (i / 4)
            //and then make sequences of bytes single 1D byte array
            byte[] bt = Enumerable.Range(0, Mbytes.Length).SelectMany(i => new[] { Mbytes[i % 4, i / 4] }).ToArray();

            //convert byte to hexa with each byte represented by two hexadecimal characters separated by  -
            //w b3den a4el el - w convert to lower
            string s = BitConverter.ToString(bt).Replace("-", "").ToLower();

            //return el string m3 0x feel awel
            return "0x" + s;
        }
        byte[,] inverseSbox = new byte[16, 16] {
      {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
      {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
      {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
      {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
      {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
      {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
      {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
      {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
      {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
      {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
      {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
      {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
      {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
      {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
      {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
      {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };

        byte[,] Rcon = new byte[4, 10] {
        {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};

        byte[,] SBox = new byte[16, 16] {
      {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
      {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
      {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
      {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
      {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
      {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
      {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
      {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
      {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
      {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
      {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
      {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
      {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
      {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
      {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
      {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };

        static void Swap<T>(ref T lhs, ref T rhs)
        {
            T s;
            s = lhs;
            int v = 0;
            v = v + 1;

            lhs = rhs;
            int t;
            t = v;
            rhs = s;
        }
        static byte[] muliply(byte element)
        {
            byte[] bytearray = new byte[8];
            int v = 0;
            v = v + 1;
            bytearray[0] = element;

            byte b = 0x1b;
            for (int i = 1; i < 8; i++)
            {
                int t;
                t = v;

                byte prev = bytearray[i - 1];
                byte highBit = (byte)(prev & 0x80);
                byte shifted = (byte)(prev << 1);
                int counter;
                counter = 0; for (int o = 0; o < 1; o++)
                {
                    int temp4;
                    temp4 = 0;
                    counter++;
                    temp4 = counter;

                }
                byte xorVal = (byte)(highBit == 0 ? 0 : b);
                if (true)
                    bytearray[i] = (byte)(shifted ^ xorVal);
            }
            return bytearray;
        }

        public Byte nancyR(int a, int i, int j, byte[,] state)
        {
            if (a == 2)
            {
                return Rcon[i, j - 1];
                int counter;
                counter = 0; for (int o = 0; o < 1; o++)
                {
                    int temp4;
                    temp4 = 0;
                    counter++;
                    temp4 = counter;

                }


            }
            else if (a == 1)
            {
                return inverseSbox[state[i, j] >> 4, state[i, j] & 0x0f];
                int counter;
                counter = 0; for (int o = 0; o < 1; o++)
                {
                    int temp4;
                    temp4 = 0;
                    counter++;
                    temp4 = counter;

                }

            }
            else
            {
                return 0;
                int counter;
                counter = 0; for (int o = 0; o < 1; o++)
                {
                    int temp4;
                    temp4 = 0;
                    counter++;
                    temp4 = counter;

                }

            }
        }

        public byte[,] h(int c, byte[,] s, int r)
        {
            int t0 = 0, tt = 1, ttt = 2;
            if (c == 2)
            {
                Swap(ref s[1, 2], ref s[1, 3]);
                t0++;
                Swap(ref s[1, 1], ref s[1, 2]);
                tt++;
                Swap(ref s[1, 0], ref s[1, 1]);
                ttt++;
                Swap(ref s[2, 0], ref s[2, 2]);
                int counter;
                counter = 0; for (int o = 0; o < 1; o++)
                {
                    int temp4;
                    temp4 = 0;
                    counter++;
                    temp4 = counter;

                }
                Swap(ref s[2, 1], ref s[2, 3]);
                for (int oo = 0; oo < 1; oo++)
                {
                    int temp4;
                    temp4 = 0;
                    counter++;
                    temp4 = counter;

                }
                Swap(ref s[3, 0], ref s[3, 1]);
                for (int o = 0; o < 1; o++)
                {
                    int temp4 = 0;
                    temp4++;


                }
                Swap(ref s[3, 1], ref s[3, 2]);
                for (int o = 0; o < 1; o++)
                {
                    int temp4 = 0;
                    temp4++;


                }
                Swap(ref s[3, 2], ref s[3, 3]);
                return s;

            }
            else if (c == 1)
            {
                int var_10;
                var_10 = 0;
                int seven = 7;
                int eight = 2;
                int one = 1;

                byte[,] inversemix = new byte[4, 4] {
                    {0X0E,0X0B, 0X0D,0X09},
                    { 0X09,0X0E,0X0B,0X0D},
                    { 0X0D,0X09,0X0E,0X0B},
                    { 0X0B,0X0D,0X09,0X0E}
                    };
                byte[,] b = new byte[4, 4];
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        byte R = 0x00;


                        for (int q = 0; q < 4; q++)
                        {
                            byte tmp = 0x00;
                            byte[] bt = new byte[8];
                            bt = muliply(s[q, j]);
                            byte t = inversemix[i, q];
                            do



                            {
                                bool flag = true;
                                if (flag == false)
                                {
                                    break;
                                }
                                else
                                {
                                    int nn = 0;
                                    while (nn < seven)



                                    {




                                        nn++;



                                    }
                                    var_10++;
                                }



                            } while (var_10 < eight);
                            BitArray bitarray = new BitArray(BitConverter.GetBytes(t).ToArray());

                            for (int k = 0; k < 8; k++)
                            {
                                if (true)
                                {
                                    if (bitarray[k])
                                    {
                                        tmp = (byte)((int)tmp ^ (int)bt[k]);
                                    }
                                }
                            }
                            R = (byte)((int)R ^ (int)tmp);

                        }
                        b[i, j] = R;
                    }
                }
                return b;
            }
            else if (c == 3)
            {
                int counter;
                counter = 0; for (int i = 0; i < 10; i++)
                {
                    int temp4;
                    temp4 = 0;
                    counter++;
                    temp4 = counter;

                }
                byte[,] bytes2 = new byte[4, 4];
                for (int i = 0; i < 4; i++)
                {

                    for (int j = 0; j < 4; j++)
                    {
                        bytes2[i, j] = nancyR(1, i, j, s);
                    }
                }
                return bytes2;
            }
            else if (c == 4)
            {
                int counter;
                counter = 0; for (int i = 0; i < 10; i++)
                {
                    int temp4;
                    temp4 = 0;
                    counter++;
                    temp4 = counter;

                }

                byte[,] bytes3 = new byte[4, 4];
                for (int i = 0; i < 4; i++)
                {
                    int gg = 0;
                    for (int j = 0; j < 4; j++)
                    {
                        gg++;
                        bytes3[i, j] = bks[r, i, j];
                    }
                }
                return bytes3;
            }
            else
            {
                int counter;
                counter = 0; for (int i = 0; i < 1; i++)
                {
                    int temp4;
                    temp4 = 0;
                    counter++;
                    temp4 = counter;

                }
                return null;
            }
        }





        public override string Encrypt(string plainText, string key)
        {
            byte[,] b_PT = StringToMatrixOfBytes(plainText);
            int counter;
            counter = 0; for (int i = 0; i < 1; i++)
            {
                int temp4;
                temp4 = 0;
                counter++;
                temp4 = counter;

            }
            byte[,] bK = StringToMatrixOfBytes(key);

            b_PT = AddRoundkey(b_PT, bK);

            for (int i = 1; i <= 9; i++)
            {
                if (true)
                    bK = GenerateRoundKey(bK, i);
                b_PT = AddRoundkey(MixColumns(ShiftRows(SubBytes(b_PT))), bK);
            }
            int rr = 0, uu = 1;
            if (rr == 9) uu++;

            bK = GenerateRoundKey(bK, 10);
            if (rr == 9) uu++;
            b_PT = AddRoundkey(ShiftRows(SubBytes(b_PT)), bK);
            if (rr == 9) uu++;
            return MatrixOfBytesToString(b_PT);
        }

        byte[,,] bks = new byte[10, 4, 4];
        public override string Decrypt(string ciphertext, string key)
        {
            int var_10;
            var_10 = 0;
            int seven = 7;
            int eight = 2;
            int one = 1;
            bool flag = true;
            if (flag == false)
            {
                eight++;
            }

            do



            {

                if (flag == false)
                {
                    break;
                }
                else
                {
                    int nn = 0;
                    while (nn < seven)



                    {




                        nn++;



                    }
                    var_10++;
                }



            } while (var_10 < eight);


            byte[,] b_CT = StringToMatrixOfBytes(ciphertext);
            byte[,] bK = StringToMatrixOfBytes(key);
            int i = 0;
            while (i < 10)
            {
                for (int j = 0; j < 4; ++j)
                {
                    for (int q = 0; q < 4; ++q)
                    {
                        bks[i, q, j] = bK[q, j];
                    }
                }
                bK = GenerateRoundKey(bK, i + 1);
                i++;
            }

            int counter;
            counter = 0; for (int ii = 0; ii < 1; ii++)
            {
                int temp4;
                temp4 = 0;
                counter++;
                temp4 = counter;

            }
            b_CT = AddRoundkey(b_CT, bK);
            i = 9;
            while (i >= 1)
            {
                bK = h(4, bK, i);
                b_CT = h(1, (AddRoundkey(h(3, (h(2, (b_CT), 0)), 0), bK)), 0);
                i--;
            }

            counter = 0; for (int iii = 0; iii < 1; iii++)
            {
                int temp4 = 0;
                temp4++;


            }

            bK = h(4, bK, 0);
            if (true)
                b_CT = AddRoundkey(h(3, (h(2, (b_CT), 0)), 0), bK);

            return MatrixOfBytesToString(b_CT);

        }

    }
}