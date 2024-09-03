using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int a = number;
            int b = baseN;

            int x = 0, y = 1, lastX = 1, lastY = 0, temp;
            while (b != 0)
            {
                int quotient = a / b;
                int remainder = a % b;

                a = b;
                b = remainder;

                temp = x;
                x = lastX - quotient * x;
                lastX = temp;

                temp = y;
                y = lastY - quotient * y;
                lastY = temp;
            }

            if (a != 1)
            {
                // Multiplicative inverse doesn't exist
                return -1;
            }
            else
            {
                int multiplicativeInverse = lastX % baseN;
                if (multiplicativeInverse < 0)
                {
                    multiplicativeInverse += baseN; // Ensure positive result
                }
                return multiplicativeInverse;
            }
            //throw new NotImplementedException();
        }
    }
}