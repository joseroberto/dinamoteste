using System;
using System.Runtime.InteropServices;

namespace Dinamo.Hsm
{
    /// <summary>
    /// Classe de Excecao para erros do Dinamo
    /// </summary>
    public class DinamoException : Exception
    {
        private int _errorCode;
        private string _description;

        /// <summary>
        /// Classe de exceção para as operações criptográficas. 
        /// </summary>
        /// <param name="errorCode">Número de erro.</param>
        /// <param name="description">Descrição do erro.</param>
        public DinamoException(int errorCode, string description)
        {
            _errorCode = errorCode;
            _description = description;
        }

        public int ErrorCode
        {
            get
            {
                return _errorCode;
            }
        }

        public string Function
        {
            get
            {
                return _description;
            }
        }

        public override string Message
        {
            get
            {
                string result = null;
                if (_errorCode != 0)
                {
                    IntPtr pMessage, pCode;

                    pMessage = Marshal.AllocHGlobal(500);
                    pCode = Marshal.AllocHGlobal(50);


                    DinamoApi.DGetErrorString(_errorCode, pCode, pMessage);

                    result = Marshal.PtrToStringAnsi(pMessage);

                    Marshal.FreeHGlobal(pMessage);
                    Marshal.FreeHGlobal(pCode);
                }
                return result;
            }
        }
    }
}
