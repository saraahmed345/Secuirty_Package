using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            int C = PowMod(M, e, n);

            return (int)C;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            int d = InverseMod(e, phi);
            int M = PowMod(C, d, n);

            return M;
        }
        private int InverseMod(int a, int m)
        {
            int x = 1, y = 0;
            int m1 = m;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                int q = a / m;
                int t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m1;

            return x;
        }
        public static int PowMod(int b, int e, int m)
        {
            int result = 1;
            b %= m;

            while (e > 0)
            {
                if ((e & 1) == 1)
                {
                    result = MultiplyMod(result, b, m);

                }

                e /= 2;
                b = MultiplyMod(b, b, m);

            }

            return result;
        }
        public static int MultiplyMod(int a, int b, int m)
        {
            int result = 0;

            while (b > 0)
            {
                if ((b & 1) == 1)
                {
                    result = (result + a) % m;
                }

                a = (a * 2) % m;
                b /= 2;
            }

            return result;
        }









    }
}
