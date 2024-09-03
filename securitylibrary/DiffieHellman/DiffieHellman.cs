using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public static int yb, ya, A_key, B_key;

        int POW(int q, int xa, int xb)
        {
            int i = 1;
            int Power = 1;
            if (xb == 1)
            {
                return xa;
            }
            else
            {
                while (i <= xb)
                {
                    Power = Power * xa;
                    Power = Power % q;
                    i++;
                }
            }
            return Power;
        }







        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> lst = new List<int>();
            if (xa < q && xb < q)
            {
                ya = POW(q, alpha, xa);
                yb = POW(q, alpha, xb);
                A_key = POW(q, yb, xa);
                B_key = POW(q, ya, xb);
                if (A_key == B_key)
                {
                    lst.Add(A_key);
                    lst.Add(B_key);
                }
            }

            return lst;









            // throw new NotImplementedException();
        }
    }
}
