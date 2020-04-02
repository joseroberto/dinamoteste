using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections;
using System.IO;
using System.Collections.Generic;

/// <summary>
/// Namespace que denota um conjunto de funções para acesso ao HSM Dinamo e suas respectivas <i>exceptions</i>.
/// </summary>
namespace Dinamo.Hsm
{
    /// <summary>
    /// Classe que encapsula os componentes de assinatura JWS.
    ///
    /// </summary>
    public class JwsComponents
    {
        public byte[] Header { get; set; }
        public byte[] Payload { get; set; }
        public Int32 ReturnCode { get; set; }

        public JwsComponents(byte[] header, byte[] payload, Int32 returnCode)
        {
            this.Header = header;
            this.Payload = payload;
            this.ReturnCode = returnCode;
        }
    }

    /// <summary>
    /// Classe que encapsula a resposta de uma requisição HTTP PIX padrão SPI(Sistema de Pagamentos Instantâneos).
    ///
    /// </summary>
    public class PIXResponse
    {
        public byte[] Header { get; set; }
        public byte[] Body { get; set; }

        public PIXResponse(byte[] header, byte[] payload)
        {
            this.Header = header;
            this.Body = payload;
        }
    }

    /// <summary>
    /// Classe que encapsula a associação do par certificado e chave privada.
    ///
    /// </summary>
    public class CertAssociation
    {
        public string CertificateName { get; set; }
        public string PrivateKeyName { get; set; }

        public override string ToString()
        {
            return "Certificate: " + CertificateName + "   Private Key: " + PrivateKeyName;
        }

    }
    /// <summary>
    /// Classe de API para acesso às funcionalidades do HSM Dinamo.  Nessa classe é possível programar
    /// utilizando as funcionalidades administrativas de monitoramento das máquinas, log, backup, além
    /// das funcionalidades primitivas como criptografia de chave simétrica e assimétrica e funcionalidades dos módulos do HSM.
    ///
    /// </summary>
    public class DinamoClient
    {
        private static bool m_bInitialized = false;
        private IntPtr m_ctx = IntPtr.Zero;

        public enum BARCODE : int
        {
            BARCODE128 = 1,
            BARCODEPDF417 = 2,
        };

        /**
        PKCS#7 Modes
        */
        public enum P7_MODE : uint
        {
            TAC_MOD_CORE_P7_TEXT = 0x0001,      /**< Apenas Texto. */
            TAC_MOD_CORE_P7_NOCERTS = 0x0002,      /**< Não incluir os certificados. */
            TAC_MOD_CORE_P7_NOSIGS = 0x0004,
            TAC_MOD_CORE_P7_NOCHAIN = 0x0008,
            TAC_MOD_CORE_P7_NOINTERN = 0x0010,
            TAC_MOD_CORE_P7_NOVERIFY = 0x0020,
            TAC_MOD_CORE_P7_DETACHED = 0x0040,
            TAC_MOD_CORE_P7_BINARY = 0x0080,
            TAC_MOD_CORE_P7_NOATTR = 0x0100,
            TAC_MOD_CORE_P7_NOSMIMECAP = 0x0200,
            TAC_MOD_CORE_P7_NOOLDMIMETYPE = 0x0400,
            TAC_MOD_CORE_P7_CRLFEOL = 0x0800,
            TAC_MOD_CORE_P7_NOCRL = 0x2000,
            TAC_MOD_CORE_P7_COSIGN = 0x80000000
        }

        public enum OATH_TYPE : uint
        {
            ISSUE_OATH_GENERATE_HOTP = DinamoApi.ISSUE_OATH_GENERATE_HOTP,
            ISSUE_OATH_GENERATE_TOTP = DinamoApi.ISSUE_OATH_GENERATE_TOTP,
            ISSUE_OATH_IMPORT_HOTP = DinamoApi.ISSUE_OATH_IMPORT_HOTP,
            ISSUE_OATH_IMPORT_TOTP = DinamoApi.ISSUE_OATH_IMPORT_TOTP
        };

        /// <summary>
        /// Algoritmo de Hash para assinatura.
        /// </summary>
        public enum HASH_ALG : int
        {
            /// <summary>Algoritmo Message-Digest algorithm 5 (16 bytes).</summary>
            ALG_MD5 = 1,
            /// <summary>Algoritmo Secure Hash Algorithm Versão 1 (20 bytes).</summary>
            ALG_SHA1 = 2,
            /// <summary>Algoritmo Hash para autenticação de cliente em SSLv3.</summary>
            ALG_SSL_SHA1_MD5 = 3,
            /// <summary>Algoritmo SHA2 - 256 bits (32 bytes)</summary>
            ALG_SHA2_256 = 4,
            /// <summary>Algoritmo SHA2 - 384 (48 bytes)</summary>
            ALG_SHA2_384 = 5,
            /// <summary>Algoritmo SHA2 - 512 (32 bytes)</summary>
            ALG_SHA2_512 = 6,
        };

        /// <summary>
        /// Bundles de hash canonicalização para assinatura XML.
        /// </summary>
        public enum HASH_MODE : byte
        {
            /// <summary>Hash MD5 com canonicalização InclC14N.</summary>
            ALG_MD5_InclC14N = 1,
            /// <summary>Hash SHA1 com canonicalização InclC14N.</summary>
            ALG_SHA1_InclC14N = 2,
            /// <summary>Hash SHA256 com canonicalização InclC14N.</summary>
            ALG_SHA256_InclC14N = 3,
            /// <summary>Hash SHA384 com canonicalização InclC14N.</summary>
            ALG_SHA384_InclC14N = 4,
            /// <summary>Hash SHA512 com canonicalização InclC14N.</summary>
            ALG_SHA512_InclC14N = 5,
            /// <summary>Hash SHA224 com canonicalização InclC14N.</summary>
            ALG_SHA224_InclC14N = 6,
            /// <summary>Hash MD5 com canonicalização ExclC14N.</summary>
            ALG_MD5_ExclC14N = 31,
            /// <summary>Hash SHA1 com canonicalização ExclC14N.</summary>
            ALG_SHA1_ExclC14N = 32,
            /// <summary>Hash MD5 com canonicalização InclC14NWithComments.</summary>
            ALG_MD5_InclC14NWithComments = 33,
            /// <summary>Hash SHA1 com canonicalização InclC14NWithComments.</summary>
            ALG_SHA1_InclC14NWithComments = 34,
            /// <summary>Hash MD5 com canonicalização ExclC14NWithComments.</summary>
            ALG_MD5_ExclC14NWithComments = 35,
            /// <summary>Hash SHA1 com canonicalização ExclC14NWithComments.</summary>
            ALG_SHA1_ExclC14NWithComments = 36,
            /// <summary>Hash SHA256 com canonicalização ExclC14N.</summary>
            ALG_SHA256_ExclC14N = 37,
            /// <summary>Hash SHA256 com canonicalização InclC14NWithComments.</summary>
            ALG_SHA256_InclC14NWithComments = 38,
            /// <summary>Hash SHA256 com canonicalização InclC14NWithComments.</summary>
            ALG_SHA256_ExclC14NWithComments = 39,
            /// <summary>Hash SHA384 com canonicalização ExclC14N.</summary>
            ALG_SHA384_ExclC14N = 40,
            /// <summary>Hash SHA384 com canonicalização InclC14NWithComments.</summary>
            ALG_SHA384_InclC14NWithComments = 41,
            /// <summary>Hash SHA384 com canonicalização ExclC14NWithComments.</summary>
            ALG_SHA384_ExclC14NWithComments = 42,
            /// <summary>Hash SHA512 com canonicalização ExclC14N.</summary>
            ALG_SHA512_ExclC14N = 43,
            /// <summary>Hash SHA512 com canonicalização InclC14NWithComments.</summary>
            ALG_SHA512_InclC14NWithComments = 44,
            /// <summary>Hash SHA512 com canonicalização ExclC14NWithComments.</summary>
            ALG_SHA512_ExclC14NWithComments = 45,
            /// <summary>Hash SHA224 com canonicalização ExclC14N.</summary>
            ALG_SHA224_ExclC14N = 46,
            /// <summary>Hash SHA224 com canonicalização InclC14NWithComments.</summary>
            ALG_SHA224_InclC14NWithComments = 47,
            /// <summary>Hash SHA224 com canonicalização ExclC14NWithComments.</summary>
            ALG_SHA224_ExclC14NWithComments = 48
        };

        public enum KEY_ALG : uint
        {
            ALG_DES = 1,
            ALG_3DES_112 = 2,
            ALG_3DES_168 = 3,
            ALG_DESX = 91,
            ALG_AES_128 = 7,
            ALG_AES_192 = 8,
            ALG_AES_256 = 9,
            ALG_ARC4 = 10,

            ALG_RSA_512 = 4,
            ALG_RSA_1024 = 5,
            ALG_RSA_2048 = 6,
            ALG_RSA_4096 = 11,
            ALG_OBJ_BLOB_HOTP = 16,

            ALG_RSA_512_PUB = 0x80000004,
            ALG_RSA_1024_PUB = 0x80000005,
            ALG_RSA_2048_PUB = 0x80000006,
            ALG_RSA_4096_PUB = 0x80000007,
        };
        public enum OBJTYPE : uint
        {
            ALG_OBJ_BLOB = DinamoApi.ALG_OBJ_BLOB,
            ALG_RSA_2048 = DinamoApi.ALG_RSA_2048,
            ALG_RSA_1024 = DinamoApi.ALG_RSA_1024,
            ALG_OBJ_EXT_MAP_2_OBJ = DinamoApi.ALG_OBJ_EXT_MAP_2_OBJ
        }

        public enum KEYNAME : uint
        {
            /// <summary>
            /// Tipo Nome da chave
            /// </summary>
            /// <seealso cref="DinamoApi.SPB_GENERATE_KEY_NAME"/>
            SPB_GENERATE_KEY_NAME = DinamoApi.SPB_GENERATE_KEY_NAME,
            SPB_GENERATE_CER_NAME = DinamoApi.SPB_GENERATE_CER_NAME
        }

        public enum ALG : uint
        {
            /// <summary>
            /// Hash MD5
            /// </summary>
            ALG_MD5 = 1,
            ALG_SHA1 = 2,
            ALG_SSL_SHA1_MD5 = 3,
            ALG_SHA2_256 = 4,
            ALG_SHA2_384 = 5,
            ALG_SHA2_512 = 6,

            ALG_DES = 1,
            ALG_3DES_112 = 2,
            ALG_3DES_168 = 3,
            ALG_DESX = 91,
            ALG_AES_128 = 7,
            ALG_AES_192 = 8,
            ALG_AES_256 = 9,
            ALG_ARC4 = 10,

            ALG_RSA_512 = 4,
            ALG_RSA_1024 = 5,
            ALG_RSA_2048 = 6,
            ALG_RSA_4096 = 11,

            ALG_RSA_512_PUB = 0x80000004,
            ALG_RSA_1024_PUB = 0x80000005,
            ALG_RSA_2048_PUB = 0x80000006,
            ALG_RSA_4096_PUB = 0x80000007,

            ALG_OBJ_BLOB = DinamoApi.ALG_OBJ_BLOB,
            ALG_OBJ_BLOB_X509 = DinamoApi.ALG_OBJ_BLOB_X509,
            ALG_OBJ_BLOB_PKCS7 = DinamoApi.ALG_OBJ_BLOB_PKCS7,
            ALG_OBJ_BLOB_CRL = DinamoApi.ALG_OBJ_BLOB_CRL,
            ALG_OBJ_BLOB_HOTP = DinamoApi.ALG_OBJ_BLOB_HOTP,
            ALG_OBJ_BLOB_DPGO3 = DinamoApi.ALG_OBJ_BLOB_DPGO3,
            ALG_OBJ_MAP = DinamoApi.ALG_OBJ_MAP,
            ALG_OBJ_EXT_MAP_2_OBJ = DinamoApi.ALG_OBJ_EXT_MAP_2_OBJ
        };

        public enum MODE_TYPE : int
        {
            MODE_NONE = DinamoApi.MODE_NONE,
            MODE_ECB = DinamoApi.MODE_ECB,
            MODE_CBC = DinamoApi.MODE_CBC
        }

        public enum PADDING_TYPE : int
        {
            NO_PADDING = DinamoApi.D_NO_PADDING,
            PKCS5_PADDING = DinamoApi.D_PKCS5_PADDING,
            ZERO_PADDING = DinamoApi.D_ZERO_PADDING,
            NO_RSA_PADDING = DinamoApi.D_NO_RSA_PADDING,
            PKCS1_PADDING = DinamoApi.D_PKCS1_PADDING
        }

        public enum BLOB_TYPE : int
        {
            PRIVATEKEY_BLOB = 1,
            PUBLICKEY_BLOB = 2,
            SIMPLE_BLOB = 3,
            PLAINTEXTKEY_BLOB = 4,
            RAW_BLOB = 5,
            HOTP_BLOB = 6,
        };


        /// <summary>
        /// Método construtor da classe.
        /// </summary>
        public DinamoClient()
        {
            if (!m_bInitialized)
            {
                DinamoApi.DInitialize(0);
                m_bInitialized = true;
            }
        }



        /**
         \addtogroup session

         @{ */

        /// <summary>
        /// Estabelece uma conexão cifrada com o HSM utilizando as configurações de <i>load balance</i>.
        /// <param name="User">Usuário/Partição HSM.</param>
        /// <param name="Password">Senha do usuário.</param>
        /// </summary>
        ///
        /// <exception cref="Dinamo.Hsm.DinamoException">Lançada quando ocorre um erro no acesso ou validação do usuário.</exception>
        public void Connect(
            string User,
            string Password
            )
        {
            Connect("", User, Password, true, true);
        }

        /// <summary>
        /// Conecta a um HSM especifico usando uma conexão criptografada.
        ///
        /// <param name="Address">Endereço IP do HSM. Se passado em branco o sistema utiliza o <i>load balance</i></param>
        /// <param name="User">Usuário/Partição HSM.</param>
        /// <param name="Password">Senha do usuário.</param>
        /// </summary>
        /// <exception cref="Dinamo.Hsm.DinamoException">Lançada quando ocorre um erro no acesso ou validação do usuário.</exception>
        public void Connect(
            string Address,
            string User,
            string Password
            )
        {
            Connect(Address, User, Password, true, false);
        }

        /// <summary>
        /// Cria uma conexão cifrada com autenticacao forte via OTP e <i>load balance</i>.
        /// </summary>
        /// <param name="User">Usuário do HSM.</param>
        /// <param name="Password">Senha do usuário do HSM.</param>
        /// <param name="Otp">OTP cadastrado para o usuário.</param>
        /// <exception cref="Dinamo.Hsm.DinamoException">Lançada quando ocorre um erro no acesso ou validação do usuário.</exception>
        public void ConnectWithLB(
            string User,
            string Password,
            string Otp)
        {

            Connect("", User, Password, Otp, true, true);
        }

        /// <summary>
        /// Cria uma conexão cifrada com autenticacao forte via OTP
        /// </summary>
        /// <param name="Address">Endereço IP do HSM.</param>
        /// <param name="User">Usuário do HSM.</param>
        /// <param name="Password">Senha do usuário do HSM.</param>
        /// <param name="Otp">OTP cadastrado para o usuário.</param>
        ///
        /// <exception cref="Dinamo.Hsm.DinamoException">Lançada quando ocorre um erro no acesso ou validação do usuário.</exception>
        public void ConnectWithLB(string Address, string User, string Password, string Otp)
        {
            Connect(Address, User, Password, Otp, true, false);
        }

        /// <summary>
        /// Estabelece uma conexão com o HSM usando todos os parâmetros da API.
        /// </summary>
        /// <param name="Address">Endereço IP do HSM.</param>
        /// <param name="User">Usuário do HSM.</param>
        /// <param name="Password">Senha do usuário do HSM.</param>
        /// <param name="Encrypted">Indica se os dados trafegados durante esta sessão serão cifrados.</param>
        /// <param name="UseLoadBalance">Indica se as configurações de load balance serão utilizadas ou não. Caso este valor seja definido como false, o campo Address será utilizado.</param>
        ///
        /// <exception cref="Dinamo.Hsm.DinamoException">Lançada quando ocorre um erro no acesso ou validação do usuário.</exception>
        public void Connect(
            string Address,
            string User,
            string Password,
            bool Encrypted,
            bool UseLoadBalance
            )
        {
            Connect(Address, User, Password, null, Encrypted, UseLoadBalance);
        }

        /// <summary>
        /// Encerra a conexão com o HSM.
        /// </summary>
        /// <param name="flagClose">Determina se a sessão será fechada fisicamente, ou apenas liberada no cache local.</param>
        public void Disconnect(
            bool flagClose
            )
        {
            Int32 dwParam = 0;

            if (flagClose)
                dwParam = DinamoApi.CLOSE_PHYSICALLY;

            if (m_ctx != IntPtr.Zero)
                DinamoApi.DCloseSession(out m_ctx, dwParam);
        }

        /// <summary>
        /// Encerra a conexão com o HSM.
        /// </summary>
        public void Disconnect()
        {
            Disconnect(false);
        }

        /** @} End of Sessao grouping*/

        private void Connect(
            string Address,
            string User,
            string Password,
            string Otp,
            bool Encrypted,
            bool UseLoadBalance
         )
        {
            Int32 ret = DinamoApi.D_OK;
            Int32 flags = 0;
            byte[] byOtp = null;

            if (Encrypted)
                flags |= DinamoApi.ENCRYPTED_CONN;

            if (!UseLoadBalance)
                flags |= DinamoApi.LB_BYPASS;

            DinamoApi.AUTH_PWD_EX_2 auth = new DinamoApi.AUTH_PWD_EX_2();
            auth.szAddr = Address;
            auth.szUserId = User;
            auth.nPort = 4433;
            auth.dwAuthType = DinamoApi.SA_AUTH_NONE;

            if ((!string.IsNullOrEmpty(Password)) &&
                (Password.Length <= DinamoApi.MAX_USR_PWD))
            {
                byte[] byPassword = Encoding.ASCII.GetBytes(Password.ToCharArray());
                auth.pbPassword = new byte[DinamoApi.MAX_USR_PWD];
                Array.Copy(byPassword, auth.pbPassword, byPassword.Length);
            }

            if (!string.IsNullOrEmpty(Otp))
            {
                auth.dwAuthType = DinamoApi.SA_AUTH_OTP;
                byOtp = Encoding.ASCII.GetBytes(Otp.ToCharArray());
                auth.pbStrongAuth = Marshal.AllocHGlobal(byOtp.Length);
                Marshal.Copy(byOtp, 0, auth.pbStrongAuth, byOtp.Length);
                auth.nStrongAuthLen = byOtp.Length;
            }

            ret = DinamoApi.DOpenSession(out m_ctx, DinamoApi.SS_USR_PWD_EX, ref auth, DinamoApi.AUTH_PWD_LEN, flags);

            if (byOtp != null && byOtp.Length > 0)
            {
                Marshal.FreeHGlobal(auth.pbStrongAuth);
            }

            if (ret != DinamoApi.D_OK)
                throw new DinamoException(ret, "DOpenSession");
        }

        /**
\addtogroup management

@{ */
        /// <summary>
        /// Retorna a mensagem com a descrição do erro.
        /// </summary>
        /// <param name="_errorCode">Código do erro.</param>
        /// <returns>Descrição do erro.</returns>
        public string GetErrorString(Int32 _errorCode)
        {
            IntPtr pMessage, pCode;

            pMessage = Marshal.AllocHGlobal(500);
            pCode = Marshal.AllocHGlobal(50);


            DinamoApi.DGetErrorString(_errorCode, pCode, pMessage);

            string result = Marshal.PtrToStringAnsi(pMessage);

            Marshal.FreeHGlobal(pMessage);
            Marshal.FreeHGlobal(pCode);
            return result;
        }
        /// <summary>
        /// Retorna a data/hora do HSM
        /// </summary>
        /// <returns>Data no formato DateTime</returns>
        public DateTime GetHSMDate()
        {
            byte pbFinal = 1;
            UInt64 qwDateTime = 0;
            UInt32 dwDateTimeLen = (UInt32)Marshal.SizeOf(qwDateTime);

            int nRet = DinamoApi.DGetHsmInfo(m_ctx,
                                                ref pbFinal,
                                                DinamoApi.HI_CURRENT_DATE,
                                                ref qwDateTime,
                                                ref dwDateTimeLen,
                                                0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetHsmInfo HI_CURRENT_DATE");

            return new DateTime(1970, 1, 1).AddSeconds(qwDateTime);
        }

        public void SetHSMDateTime(DateTime stDateTime)
        {
            IntPtr ptrDateTime;

            DinamoApi.tm stTmDateTime = new DinamoApi.tm();

            //Let's transform the strucutres

            stTmDateTime.tm_sec = stDateTime.Second;
            stTmDateTime.tm_min = stDateTime.Minute;
            stTmDateTime.tm_hour = stDateTime.Hour;

            stTmDateTime.tm_mday = stDateTime.Day;

            stTmDateTime.tm_mon = stDateTime.Month - 1;
            stTmDateTime.tm_year = stDateTime.Year - 1900;

            stTmDateTime.tm_wday = (int)stDateTime.DayOfWeek;
            stTmDateTime.tm_yday = stDateTime.DayOfYear;
            TimeZone tz = TimeZone.CurrentTimeZone;
            stTmDateTime.tm_isdst = tz.IsDaylightSavingTime(stDateTime) == true ? 1 : 0;


            ptrDateTime = Marshal.AllocHGlobal(Marshal.SizeOf(stTmDateTime));
            Marshal.StructureToPtr(stTmDateTime, ptrDateTime, false);

            int nRet = DinamoApi.DAdmOperation(m_ctx, Dinamo.Hsm.DinamoApi.AO_SET_DATE_TIME, ptrDateTime, Marshal.SizeOf(stTmDateTime), 0);

            Marshal.FreeHGlobal(ptrDateTime);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DAdmOperation");
        }



        public enum TOKEN_TYPE : int
        {
            TIME = 1,
            EVENT = 2,
            CHAP = 3,
            NTP = 4
        }

        /// <summary>
        /// Recupera informações de contadores de sistema do HSM.
        /// </summary>
        public DinamoApi.SYS_COUNTER_INFO GetHSMCounterInfo()
        {
            DinamoApi.SYS_COUNTER_INFO stCounterInfo = new DinamoApi.SYS_COUNTER_INFO();

            byte pbFinal = 1;
            UInt32 uiHSMInfoLen = 0;
            uiHSMInfoLen = (UInt32)Marshal.SizeOf(stCounterInfo);
            IntPtr ptrCounterInfo;
            ptrCounterInfo = Marshal.AllocHGlobal(Marshal.SizeOf(stCounterInfo));
            Marshal.StructureToPtr(stCounterInfo, ptrCounterInfo, false);

            int nRet = DinamoApi.DGetHsmInfo(m_ctx,
                                            ref pbFinal,
                                            DinamoApi.HI_COUNTER_INFO,
                                            ptrCounterInfo,
                                            ref uiHSMInfoLen,
                                            0);

            stCounterInfo = (DinamoApi.SYS_COUNTER_INFO)Marshal.PtrToStructure(ptrCounterInfo, typeof(DinamoApi.SYS_COUNTER_INFO));

            Marshal.FreeHGlobal(ptrCounterInfo);

            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DGetHsmInfo HI_COUNTER_INFO");
            }

            return stCounterInfo;
        }

        public void GetHSMHardwareInfo()
        {
            byte pbFinal = 1;
            DinamoApi.SYS_HW_STR_INFO stHSMInfo = new DinamoApi.SYS_HW_STR_INFO();
            UInt32 uiHSMInfoLen = 0;
            uiHSMInfoLen = (UInt32)Marshal.SizeOf(stHSMInfo);

            int nRet = DinamoApi.DGetHsmInfo(m_ctx,
                                                ref pbFinal,
                                                DinamoApi.HI_HW_STR,
                                                ref stHSMInfo,
                                                ref uiHSMInfoLen,
                                                0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetHsmInfo SYS_HW_STR_INFO");
        }

        public void Backup(string DestFile, string Pin)
        {
            int nRet = DinamoApi.DBackupData(m_ctx, DestFile, Pin, DinamoApi.MAKE_BACKUP);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DBackupData");
        }

        public void Restore(string SourceFile, string Pin, bool IncludeNetworkParameters)
        {
            int nDirection = DinamoApi.MAKE_RESTORE;

            if (!IncludeNetworkParameters)
                nDirection = DinamoApi.MAKE_RESTORE_WITHOUT_NET_CONFIG;

            int nRet = DinamoApi.DBackupData(m_ctx, SourceFile, Pin, nDirection);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DBackupData");
        }

        public int GetLogSize()
        {
            int nLogSize = 0;

            int nRet = DinamoApi.DGetStatLogSize(m_ctx, out nLogSize);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetStatLogSize");

            return nLogSize;
        }

        public byte[] DGetStatLog()
        {
            return DGetStatLog(DinamoApi.GET_LOG_START_FULL, DinamoApi.GET_LOG_END_FULL);
        }

        public byte[] DGetStatLog(int StartPos, int BytesToRead)
        {
            byte[] byLog;
            IntPtr ptrLog;
            int cbLog;

            int nRet = DinamoApi.DGetStatLog(m_ctx, StartPos, BytesToRead, out cbLog, out ptrLog);

            if (nRet == DinamoApi.D_OK)
            {
                byLog = new byte[cbLog];

                Marshal.Copy(ptrLog, byLog, 0, cbLog);

                DinamoApi.DFree(ptrLog);
            }
            else
                throw new DinamoException(nRet, "DGetStatLog");

            return byLog;
        }

        public int IPFilterOperationStatus()
        {
            Int32 dwStatus = 0;
            IntPtr pParam = IntPtr.Zero;

            int nRet = DinamoApi.DIPFilterOperation(m_ctx, DinamoApi.D_IPF_LIST, null, null,
                                null, pParam, out dwStatus, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "IPFilterOperation");

            return dwStatus;
        }

        public int IPFilterOperationAdd(string szUser, string szIP)
        {
            Int32 dwStatus = 0;
            IntPtr pParam = IntPtr.Zero;

            int nRet = DinamoApi.DIPFilterOperation(m_ctx, DinamoApi.D_IPF_ADD, szUser, szIP,
                                null, pParam, out dwStatus, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "IPFilterOperationAdd");

            return dwStatus;
        }

        public int IPFilterOperationRemove(string szUser, string szIP)
        {
            Int32 dwStatus = 0;
            IntPtr pParam = IntPtr.Zero;
            int nRet = DinamoApi.DIPFilterOperation(m_ctx, DinamoApi.D_IPF_DEL, szUser, szIP,
                                null, pParam, out dwStatus, 0);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "IPFilterOperationRemove");
            return dwStatus;
        }

        public int IPFilterSetStatus(bool bStatus)
        {
            Int32 dwStatus = 0;
            IntPtr pParam = IntPtr.Zero;
            byte bOp = (byte)(bStatus ? DinamoApi.D_IPF_ENABLE : DinamoApi.D_IPF_DISABLE);
            int nRet = DinamoApi.DIPFilterOperation(m_ctx,
                                        bOp, null,
                                        null, null, pParam, out dwStatus, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "IPFilterStatus");

            return dwStatus;
        }

        public int IPFilterOptList(DinamoApi.ListIpFilterCallback filterIpCallBack, IntPtr param)
        {
            Int32 dwStatus = 0;

            int nRet = DinamoApi.DIPFilterOperation(m_ctx,
                                DinamoApi.D_IPF_LIST, null, null,
                                filterIpCallBack, param, out dwStatus, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "IPFilterOptList");

            return dwStatus;
        }

        public void SaveLog(string fileName)
        {
            Int32 logSize;
            IntPtr logDataPointer;

            int nRet = DinamoApi.DGetStatLog(m_ctx, DinamoApi.GET_LOG_START_FULL, DinamoApi.GET_LOG_END_FULL, out logSize, out logDataPointer);

            if (nRet == DinamoApi.D_OK)
            {
                byte[] logData = new byte[logSize];
                Marshal.Copy(logDataPointer, logData, 0, logSize);

                DinamoApi.DFree(logDataPointer);

                FileStream logFile = new FileStream(fileName, FileMode.CreateNew);
                logFile.Write(logData, 0, logSize);
                logFile.Close();
            }
            else
                throw new DinamoException(nRet, "DGetStatLog");
        }

        public void ClearLog()
        {
            int nRet = DinamoApi.DTruncateLog(m_ctx);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DTruncateLog");
        }

        /** @} End of Gerencia grouping*/

        /**
        \addtogroup users
         *
         *

        @{ */

        public void ChangePasswordUser(string szPassword)
        {
            Int32 dwParam = DinamoApi.UP_PASSWORD;

            IntPtr ptrPassword = Marshal.StringToHGlobalAnsi(szPassword);

            int nRet = DinamoApi.DSetUserParam(m_ctx, dwParam, ptrPassword, szPassword.Length + 1, 0);

            Marshal.FreeHGlobal(ptrPassword);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DSetUserParam");

        }

        public void AssignEventToken(string szUserId, byte[] byKey)
        {
            Int32 dwParam = DinamoApi.AT_OATH_TOKEN;
            DinamoApi.OATH_SA_v1 pOathV1 = new DinamoApi.OATH_SA_v1();
            pOathV1.key = new byte[DinamoApi.MAX_OATH_HMAC_LEN];

            Array.Copy(byKey, pOathV1.key, byKey.Length);

            pOathV1.type = DinamoApi.OATH_SA_v1_type_SHA1;
            pOathV1.key_len = (byte)byKey.Length;
            pOathV1.truncation_offset = DinamoApi.OATH_SA_v1_HOTP_DYN_TRUNC_OFF;

            Int32 dwDataLen = Marshal.SizeOf(pOathV1);
            IntPtr pData = Marshal.AllocHGlobal(dwDataLen);

            Marshal.StructureToPtr(pOathV1, pData, false);

            int nRet = DinamoApi.DAssignToken(m_ctx, szUserId, dwParam, pData, dwDataLen);

            Marshal.FreeHGlobal(pData);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DAssignToken");
        }

        public void AssignTimeToken(string szUserId, byte[] byKey, UInt64 iInitialTime, Int16 iStep)
        {
            Int32 dwParam = DinamoApi.AT_OATH_TOKEN_TOTP;
            DinamoApi.OATH_SA_v2 pOathV2 = new DinamoApi.OATH_SA_v2();
            pOathV2.sa_v1.key = new byte[DinamoApi.MAX_OATH_HMAC_LEN];

            Array.Copy(byKey, pOathV2.sa_v1.key, byKey.Length);

            pOathV2.sa_v1.type = DinamoApi.OATH_SA_v1_type_SHA1;
            pOathV2.sa_v1.key_len = (byte)byKey.Length;
            pOathV2.sa_v1.truncation_offset = DinamoApi.OATH_SA_v1_HOTP_DYN_TRUNC_OFF;
            pOathV2.T0 = DinamoApi.OATH_SA_v2_default_T0_Epoch;
            pOathV2.time_step = DinamoApi.OATH_SA_v2_default_TIME_STEP;

            if (iInitialTime > 0)
            {
                pOathV2.T0 = iInitialTime;
            }

            if (iStep > 0)
            {
                pOathV2.time_step = iStep;
            }

            Int32 dwDataLen = Marshal.SizeOf(pOathV2);
            IntPtr pData = Marshal.AllocHGlobal(dwDataLen);

            Marshal.StructureToPtr(pOathV2, pData, false);

            int nRet = DinamoApi.DAssignToken(m_ctx, szUserId, dwParam, pData, dwDataLen);

            Marshal.FreeHGlobal(pData);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DAssignToken");

        }

        public void UnassignToken(string szUserId)
        {
            Int32 dwParam = DinamoApi.AT_OATH_TOKEN;

            int nRet = DinamoApi.DUnassignToken(m_ctx, dwParam, szUserId);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DUnassignToken");
        }

        public void OATHResync(string szUser, string szOTP1, string szOTP2)
        {
            Int32 dwParam = 0;
            int nRet = DinamoApi.DOATHResync(m_ctx, szUser, szOTP1, szOTP2, dwParam);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DOATHResync");
        }

        public void ListUsers(DinamoApi.ListCallback listCallback, object param)
        {
            int nRet = DinamoApi.DListUsers(m_ctx, listCallback, ref param);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DListUsers");

        }

        public int GetUserAuthMask(string szUserName)
        {
            Int32 dwUserAuthMask = 0;

            int nRet = DinamoApi.DGetUserAcl(m_ctx, szUserName, out dwUserAuthMask);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetUserParam");

            return dwUserAuthMask;
        }



        public void ListUserTrusts(string user, byte bType, Dinamo.Hsm.DinamoApi.ListUserTrustsCallback functionCallBack, ref object pParam)
        {
            int nRet = DinamoApi.DListUserTrusts(m_ctx, user, bType, functionCallBack, ref pParam);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DListUserTrusts");
        }

        public string[] ListUsers()
        {
            ArrayList UserList = new ArrayList();
            object param = UserList;

            int nRet = DinamoApi.DListUsers(m_ctx, ListCallback, ref param);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DListUsers");

            return (string[])UserList.ToArray(typeof(System.String));
        }

        public void BlockUser(string szUserName, bool bBlock)
        {
            Int32 dwParam = DinamoApi.UP_BLOCK_USR;

            if (!bBlock)
            {
                dwParam = DinamoApi.UP_UNBLOCK_USR;
            }

            IntPtr ptrUserName = Marshal.StringToHGlobalAnsi(szUserName);

            int nRet = DinamoApi.DSetUserParam(m_ctx, dwParam, ptrUserName, szUserName.Length + 1, 0);

            Marshal.FreeHGlobal(ptrUserName);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DSetUserParam");
        }

        public void SetUserBlock(string szUserName, bool blocked)
        {
            DinamoApi.USER_BLOCK stUserBlock = new DinamoApi.USER_BLOCK();

            stUserBlock.szUserId = szUserName;
            stUserBlock.dwAttempts = 0;
            stUserBlock.nBlocked = blocked ? 1 : 0;

            Int32 dwUser = Marshal.SizeOf(stUserBlock);
            IntPtr ptrUser = Marshal.AllocHGlobal(dwUser);

            int nRet = DinamoApi.DSetUserParam(m_ctx, DinamoApi.UP_BLOCK_USR, ptrUser, dwUser, 0);
            Marshal.FreeHGlobal(ptrUser);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DSetUserParam");
        }

        public void SetUserAuthMask(string szUserName, int iACL)
        {
            DinamoApi.USER_INFO userInfo = new DinamoApi.USER_INFO();
            userInfo.szUserId = szUserName;
            userInfo.dwAuthMask = iACL;
            Int32 dwUser = Marshal.SizeOf(userInfo);
            IntPtr ptrUser = Marshal.AllocHGlobal(dwUser);

            Marshal.StructureToPtr(userInfo, ptrUser, false);

            int nRet = DinamoApi.DSetUserParam(m_ctx, DinamoApi.UP_AUTH_MASK, ptrUser, dwUser, 0);

            Marshal.FreeHGlobal(ptrUser);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DSetUserParam");
        }



        public int GetUserInvalidLoginAttempts(string szUserName)
        {

            DinamoApi.USER_BLOCK stUserBlock = new DinamoApi.USER_BLOCK();

            stUserBlock.szUserId = szUserName;
            stUserBlock.dwAttempts = 0;
            stUserBlock.nBlocked = 0;

            Int32 dwUserBlockSize = Marshal.SizeOf(stUserBlock);

            int nRet = DinamoApi.DGetUserParam(m_ctx, DinamoApi.UP_INVALID_LOGIN_ATTEMPTS, ref stUserBlock, ref dwUserBlockSize, 0);

            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DGetUserParam");
            }

            int nAttempts = stUserBlock.dwAttempts;

            return nAttempts;
        }

        public bool IsUserBlocked(string szUserName)
        {
            DinamoApi.USER_BLOCK stUserBlock = new DinamoApi.USER_BLOCK();

            stUserBlock.szUserId = szUserName;
            stUserBlock.dwAttempts = 0;
            stUserBlock.nBlocked = 0;

            Int32 dwUserBlockSize = Marshal.SizeOf(stUserBlock);
            int nRet = DinamoApi.DGetUserParam(m_ctx, DinamoApi.UP_BLOCK_USR, ref stUserBlock, ref dwUserBlockSize, 0);


            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DGetUserParam");
            }
            return (0 != stUserBlock.nBlocked);
        }

        public void CreateUser(string UserId, string Password)
        {
            DinamoApi.USER_INFO user = new DinamoApi.USER_INFO();

            user.dwAuthMask = 0;
            user.szUserId = UserId;
            user.szPassword = Password;

            int nRet = DinamoApi.DCreateUser(m_ctx, user);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DCreateUser");
        }

        public void RemoveUser(string UserId)
        {
            int nRet = DinamoApi.DRemoveUser(m_ctx, UserId);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DRemoveUser");
        }

        /** @} End of usuarios grouping*/

        /**
        \addtogroup keys

        @{ */

        /// <summary>
        /// Gera uma chave permanente no HSM.
        /// </summary>
        /// <param name="KeyId">Identificador da chave no HSM</param>
        /// <param name="Alg">Algoritmo a ser utilizado. <see cref="Dinamo.Hsm.DinamoClient.KEY_ALG"/></param>
        /// <param name="Exportable">Flag indicador de geração de uma chave exportável.</param>
        /// <returns>Handle para o objeto chave gerado.</returns>
        public IntPtr GenerateKey(string KeyId, DinamoClient.KEY_ALG Alg, bool Exportable)
        {
            return GenerateKey(KeyId, Alg, Exportable, false);
        }

        /// <summary>
        /// Gera chave
        /// </summary>
        /// <param name="KeyId">Identificação da chave no HSM.</param>
        /// <param name="Alg">Algoritmo da chave. <see cref="Dinamo.Hsm.DinamoClient.KEY_ALG"/></param>
        /// <param name="Exportable">Flag para gerar a chave exportável.</param>
        /// <param name="Temporary">Flag para gerar chave temporária.  Essa chave tem o ciclo de vida enquanto durar a sessão.</param>
        /// <returns>Handle da chave.</returns>
        public IntPtr GenerateKey(string KeyId, DinamoClient.KEY_ALG Alg, bool Exportable, bool Temporary)
        {
            IntPtr hKey = IntPtr.Zero;
            int dwFlags = 0;

            if (Exportable)
                dwFlags |= DinamoApi.EXPORTABLE_KEY;

            if (Temporary)
                dwFlags |= DinamoApi.TEMPORARY_KEY;

            int nRet = DinamoApi.DGenerateKey(m_ctx, KeyId, (int)Alg, dwFlags, out hKey);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGenerateKey");

            return hKey;
        }

        public void DestroyKey(IntPtr hKey)
        {
            int nRet = DinamoApi.DDestroyKey(ref hKey, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DDestroyKey");
        }


        public int GetKeyAlgId(string strKeyId)
        {
            IntPtr hKey;
            int nRet = DinamoApi.DGetUserKey(m_ctx, strKeyId, 0, out hKey);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetUserKey");

            nRet = GetKeyAlgId(hKey);

            DinamoApi.DDestroyKey(ref hKey, 0);

            return nRet;
        }

        /// <summary>
        /// Retorna o tipo de uma chave
        /// </summary>
        /// <param name="hKey">Handle da chave</param>
        /// <returns>Tipo da chave</returns>
        private int GetKeyAlgId(IntPtr hKey)
        {
            int nRet = 0;
            int dwParam = DinamoApi.DKP_ALGID;

            int dwDataLen = sizeof(int);
            byte[] dwData = new byte[dwDataLen];

            nRet = DinamoApi.DGetKeyParam(hKey, dwParam, dwData, ref dwDataLen, 0);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetKeyParam");

            return BitConverter.ToInt32(dwData, 0);
        }

        public int GetKeyPadding(IntPtr hKey)
        {
            int nRet = 0;
            int dwParam = DinamoApi.DKP_PADDING;
            byte[] dwData = new byte[sizeof(int)];
            int dwDataLen = sizeof(int);

            nRet = DinamoApi.DGetKeyParam(hKey, dwParam, dwData, ref dwDataLen, 0);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetKeyParam");

            return BitConverter.ToInt32(dwData, 0);
        }
        /// <summary>
        /// Retorna o tamanho de uma chave.
        /// </summary>
        /// <param name="KeyId">Identificacao da chave</param>
        /// <returns>Tamanho da chave em bits</returns>
        public int GetUserKeyLen(string KeyId)
        {
            IntPtr hKey = IntPtr.Zero;

            int nRet = DinamoApi.DGetUserKey(m_ctx, KeyId, 0, out hKey);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetUserKey");
            int ans = GetUserKeyLen(hKey);

            DestroyKey(hKey);

            return ans;
        }

        /// <summary>
        /// Retorna o tamanho de uma chave.
        /// </summary>
        /// <param name="hKey">Handle da chave</param>
        /// <returns>Tamanho da chave em bits</returns>
        public int GetUserKeyLen(IntPtr hKey)
        {
            int nRet = 0;
            int dwParam = DinamoApi.DKP_KEYLEN;
            int dwDataLen = Marshal.SizeOf(typeof(int));
            byte[] dwData = new byte[dwDataLen];

            nRet = DinamoApi.DGetKeyParam(hKey, dwParam, dwData, ref dwDataLen, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetKeyParam");

            return BitConverter.ToInt32(dwData, 0) * 8; //Valor em bits

        }
        /// <summary>
        /// Retorna Handler de uma chave (deve ser chamada a DestroyUserKey apos a alocacao).
        /// </summary>
        /// <param name="KeyId"></param>
        /// <returns>Handle do objeto Usuário</returns>
        private IntPtr GetUserKey(string KeyId)
        {
            IntPtr hKey = IntPtr.Zero;

            int nRet = DinamoApi.DGetUserKey(m_ctx, KeyId, 0, out hKey);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetUserKey");

            return hKey;
        }

        /// <summary>
        /// Testa existencia de uma chave
        /// </summary>
        /// <param name="KeyId">Identificador da chave no HSM.</param>
        /// <returns>Verdadeiro se a chave existir</returns>
        public bool IsKeyExist(string KeyId)
        {
            IntPtr hKey = IntPtr.Zero;
            int nRet = DinamoApi.DGetUserKey(m_ctx, KeyId, 0, out hKey);

            return (nRet == DinamoApi.D_OK) && (hKey != IntPtr.Zero);
        }

        /// <summary>
        /// Recupera a informacao de mapa (compatibilidade retroativa)
        /// </summary>
        /// <param name="ObjectId">Nome do mapa</param>
        /// <param name="Obj1Id">Nome do objeto no primeiro slot</param>
        /// <param name="Obj2Id">Nome do objeto no segundo slot</param>
        public void GetMapInfo(string ObjectId, ref string Obj1Id, ref string Obj2Id)
        {
            int Obj1TypeId = 0;
            int Obj2TypeId = 0;
            GetMapInfo(ObjectId, ref Obj1Id, ref Obj1TypeId, ref Obj2Id, ref Obj2TypeId);
        }

        /// <summary>
        /// Recupera a informacao de mapa
        /// </summary>
        /// <param name="ObjectId">Nome do mapa</param>
        /// <param name="Obj1Id">Nome do objeto no primeiro slot</param>
        /// <param name="Obj1TypeId">Tipo do objeto no primeiro slot</param>
        /// <param name="Obj2Id">Nome do objeto no segundo slot</param>
        /// <param name="Obj2TypeId">Tipo do objeto no segundo slot</param>
        public void GetMapInfo(string ObjectId, ref string Obj1Id, ref int Obj1TypeId, ref string Obj2Id, ref int Obj2TypeId)
        {
            DinamoApi.EXT_MAP_2_OBJ_INFO stMapInfo = new DinamoApi.EXT_MAP_2_OBJ_INFO();

            stMapInfo.szObjId1 = "";
            stMapInfo.szObjId2 = "";

            int cbMapInfo = Marshal.SizeOf(stMapInfo);
            int nRet = DinamoApi.DGetObjInfo(m_ctx, ObjectId, (int)ALG.ALG_OBJ_EXT_MAP_2_OBJ, ref stMapInfo, ref cbMapInfo);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetObjInfo");

            Obj1Id = stMapInfo.szObjId1;
            Obj1TypeId = stMapInfo.dwObjAlgId1;
            Obj2Id = stMapInfo.szObjId2;
            Obj2TypeId = stMapInfo.dwObjAlgId2;

        }

        /// <summary>
        /// Lista os certificados e suas chaves privadas associadas.
        /// </summary>
        /// <param name="onlyWithAssociation">True se desejar apenas os certificados que possuam chaves associadas</param>
        /// <returns>
        /// Retorna uma lista de associações de certificados com as suas respectivas chaves privadas.</returns>
        public List<CertAssociation> ListCertAssociations(bool onlyWithAssociation = false)
        {
            IntPtr metaData = IntPtr.Zero;
            int nRet = DinamoApi.DCreateObjMetadata(ref metaData, 0);
            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DCreateObjMetadata");
            }

            Int32 keyType = 1; //CKO_CERTIFICATE
            nRet = DinamoApi.DSetObjMetadata(metaData,
                                            DinamoApi.MNG_OBJ_META_A_CLASS,
                                            ref keyType,
                                            Marshal.SizeOf(keyType),
                                            0);
            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DSetObjMetadata");
            }

            IntPtr searchCtx = IntPtr.Zero;
            nRet = DinamoApi.DFindObjMetadataInit(m_ctx,
                                                    metaData,
                                                    out searchCtx, 0);
            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DFindObjMetadataInit");
            }

            List<CertAssociation> outList = new List<CertAssociation>();

            int foundDataCount = 512;
            while ((nRet == DinamoApi.D_OK) &&
                    (foundDataCount > 0))
            {
                IntPtr[] foundData = new IntPtr[foundDataCount];
                nRet = DinamoApi.DFindObjMetadataCont(searchCtx,
                                                        foundData,
                                                        foundDataCount,
                                                        out foundDataCount,
                                                        0);
                if (nRet != DinamoApi.D_OK)
                {
                    throw new DinamoException(nRet, "DFindObjMetadataCont");
                }

                for (int i = 0; i < foundDataCount; i++)
                {
                    if (onlyWithAssociation
                        && String.IsNullOrEmpty(GetObjMetadataStr(foundData[i], DinamoApi.MNG_OBJ_META_A_HSM_ASSOCIATE)))
                        continue;

                    outList.Add(new CertAssociation
                    {
                        CertificateName = GetObjMetadataStr(foundData[i], DinamoApi.MNG_OBJ_META_A_HSM_OBJ_ID),
                        PrivateKeyName = GetObjMetadataStr(foundData[i], DinamoApi.MNG_OBJ_META_A_HSM_ASSOCIATE)
                    });

                    DinamoApi.DDestroyObjMetadata(ref foundData[i], 0);
                }
            }


            DinamoApi.DFindObjMetadataEnd(ref searchCtx, 0);

            DinamoApi.DDestroyObjMetadata(ref metaData, 0);

            return outList;
        }

        private string GetObjMetadataStr(IntPtr metaHandle, int attribute)
        {
            Int32 nameLen = 0;
            int nRet = DinamoApi.DGetObjMetadata(metaHandle,
                                                attribute,
                                                null,
                                                ref nameLen,
                                                0);
            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DGetObjMetadata");
            }

            byte[] retBuffer = new byte[nameLen];
            nameLen = retBuffer.Length;
            DinamoApi.DGetObjMetadata(metaHandle,
                                        attribute,
                                        retBuffer,
                                        ref nameLen,
                                        0);
            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DGetObjMetadata");
            }


            return System.Text.Encoding.ASCII.GetString(retBuffer);
        }

        /// <summary>
        /// Testa se a chave e exportavel
        /// </summary>
        /// <param name="KeyId">Nome da chave</param>
        /// <returns>True se a chave for exportavel</returns>
        public bool IsKeyReadLock(string KeyId)
        {
            IntPtr hKey = IntPtr.Zero;
            int nRet = DinamoApi.DGetUserKey(m_ctx, KeyId, 0, out hKey);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetUserKey");
            bool ans = IsKeyReadLock(hKey);
            DestroyKey(hKey);
            return ans;
        }

        /// <summary>
        /// Testa se a chave e exportavel
        /// </summary>
        /// <param name="hKey">Handle da chave</param>
        /// <returns>True se a chave for exportavel</returns>
        public bool IsKeyReadLock(IntPtr hKey)
        {
            byte[] isReadLock = new byte[sizeof(Int32)];
            Int32 dataSize = sizeof(Int32);

            int nRet = DinamoApi.DGetKeyParam(hKey, DinamoApi.DKP_READ_LOCK, isReadLock, ref dataSize, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetKeyParam");

            return Convert.ToBoolean(BitConverter.ToInt32(isReadLock, 0));
        }

        /// <summary>
        /// Testa se a chave esta encriptada
        /// </summary>
        /// <param name="KeyId">Nome da chave</param>
        /// <returns>True se a chave estiver encriptada</returns>
        public bool IsKeyEncrypted(string KeyId)
        {
            IntPtr hKey = IntPtr.Zero;
            int nRet = DinamoApi.DGetUserKey(m_ctx, KeyId, 0, out hKey);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetUserKey");
            bool ans = IsKeyEncrypted(hKey);
            DestroyKey(hKey);
            return ans;
        }

        /// <summary>
        /// Testa se a chave esta encriptada 
        /// </summary>
        /// <param name="hKey">Handle da chave</param>
        /// <returns>True se a chave estiver encriptada</returns>
        public bool IsKeyEncrypted(IntPtr hKey)
        {
            byte[] isEncrypted = new byte[sizeof(Int32)];


            Int32 dataSize = sizeof(Int32);

            int nRet = DinamoApi.DGetKeyParam(hKey, DinamoApi.DKP_ENCRYPTED, isEncrypted, ref dataSize, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetKeyParam");

            return Convert.ToBoolean(BitConverter.ToInt32(isEncrypted, 0));
        }

        public void BlockObject(string szObjectName, bool bBlock)
        {
            int nRet = 0;
            byte[] dwParam = BitConverter.GetBytes(DinamoApi.TRUE);


            if (!bBlock)
            {
                dwParam = BitConverter.GetBytes(DinamoApi.FALSE);
            }

            IntPtr hKey = IntPtr.Zero;

            nRet = DinamoApi.DGetUserKey(m_ctx, szObjectName, 0, out hKey);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetUserKey");


            nRet = DinamoApi.DSetKeyParam(hKey, DinamoApi.DKP_BLOCKED, dwParam, Marshal.SizeOf(dwParam), 0);


            if (IntPtr.Zero != hKey)
            {
                DinamoApi.DDestroyKey(ref hKey, 0);
            }

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DSetUserParam");
        }

        public bool IsObjectBlocked(string szObjectName)
        {
            int nRet = 0;
            byte[] dwParam = new byte[4];
            IntPtr hKey = IntPtr.Zero;

            nRet = DinamoApi.DGetUserKey(m_ctx, szObjectName, 0, out hKey);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetUserKey");


            Int32 dwParamSize = Marshal.SizeOf(dwParam);

            nRet = DinamoApi.DGetKeyParam(hKey, DinamoApi.DKP_BLOCKED, dwParam, ref dwParamSize, 0);


            if (IntPtr.Zero != hKey)
            {
                DinamoApi.DDestroyKey(ref hKey, 0);
            }

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DSetUserParam");

            if (0 != BitConverter.ToInt32(dwParam, 0))
            {
                return false;
            }

            return true;
        }

        public void GenerateMap(string MapId, string Obj1Id, ALG Obj1Type, string Obj2Id, ALG Obj2Type)
        {
            int nRet = DinamoApi.DGenerateMapObj(m_ctx, MapId, Obj1Id, (int)Obj1Type, Obj2Id, (int)Obj2Type);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGenerateMapObj");
        }

        public void RemoveObject(string ObjectId)
        {
            int nRet = DinamoApi.DRemoveObj(m_ctx, ObjectId);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DRemoveObj");
        }

        public string[] ListObjects()
        {
            ArrayList ObjList = new ArrayList();
            object param = ObjList;

            int nRet = DinamoApi.DListObjs(m_ctx, ListCallback, ref param);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DListObjs");

            return (string[])ObjList.ToArray(typeof(System.String));
        }

        public Int32 ListCallback(string szName, ref object pParam, Int32 bFinal)
        {
            ArrayList ObjList = (ArrayList)pParam;

            if (bFinal == 0)
                ObjList.Add(szName);

            return 0;
        }

        public string[] ListObjects(ALG type)
        {
            string[] objList = ListObjects();
            ArrayList newObjList = new ArrayList();

            int nRet;
            foreach (string objId in objList)
            {
                IntPtr hKey;
                nRet = DinamoApi.DGetUserKey(m_ctx, objId, 0, out hKey);

                if (nRet != DinamoApi.D_OK)
                    throw new DinamoException(nRet, "DGetUserKey");

                Int32 dataSize = sizeof(Int32);
                byte[] objType = new byte[dataSize];

                nRet = DinamoApi.DGetKeyParam(hKey, DinamoApi.DKP_ALGID, objType, ref dataSize, 0);

                DinamoApi.DDestroyKey(ref hKey, 0);

                if (nRet != DinamoApi.D_OK)
                    throw new DinamoException(nRet, "DGetKeyParam");

                Int32 objType32 = BitConverter.ToInt32(objType, 0);

                if (objType32 == (int)type)
                    newObjList.Add(objId);
            }

            return (string[])newObjList.ToArray(typeof(System.String));

        }

        public byte[] ReadFile(string FileId)
        {
            ArrayList arrFileData = new ArrayList();
            object param = arrFileData;

            int nRet = DinamoApi.DReadFile(m_ctx, FileId, WriteLocalFileCallback, ref param);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DReadFile");

            return (byte[])arrFileData.ToArray(typeof(System.Byte));
        }

        public Int32 WriteLocalFileCallback(IntPtr pbData, Int32 cbData, ref object pParam, Int32 bFinal)
        {
            byte[] byData = new byte[cbData];
            Marshal.Copy(pbData, byData, 0, cbData);

            ArrayList arrFileData = (ArrayList)pParam;

            for (int i = 0; i < cbData; i++)
                arrFileData.Add(byData[i]);

            return 0;
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="FileId"></param>
        /// <param name="byFileData"></param>
        public void WriteFile(string FileId, byte[] byFileData)
        {
            object param = byFileData;

            int nRet = DinamoApi.DWriteFile(m_ctx, FileId, byFileData.Length, ReadLocalFileCallback, ref param);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DWriteFile");
        }

        public Int32 ReadLocalFileCallback(IntPtr pbData, ref Int32 pcbData, ref object pParam, out Int32 pbFinal)
        {
            byte[] byFileData = (byte[])pParam;

            Marshal.Copy(byFileData, 0, pbData, byFileData.Length);
            pcbData = byFileData.Length;

            pbFinal = 1;

            return 0;
        }

        public byte[] ExportKey(IntPtr hKey, IntPtr hKeyEncryptionKey, BLOB_TYPE BlobType)
        {
            byte[] byBlob = null;
            int cbBlob = 0;

            int nRet = DinamoApi.DExportKey(hKey, hKeyEncryptionKey, (int)BlobType, 0, byBlob, ref cbBlob);

            if (DinamoApi.D_OK == nRet || DinamoApi.D_MORE_DATA == nRet)
            {
                byBlob = new byte[cbBlob];

                nRet = DinamoApi.DExportKey(hKey, hKeyEncryptionKey, (int)BlobType, 0, byBlob, ref cbBlob);
            }

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DExportKey");

            return byBlob;
        }

        public IntPtr ImportKey(string KeyId, IntPtr hKeyEncryptionKey, byte[] byKeyBlob, BLOB_TYPE BlobType, KEY_ALG AlgId)
        {
            return ImportKey(KeyId, hKeyEncryptionKey, byKeyBlob, BlobType, AlgId, true, false);
        }

        public IntPtr ImportKey(string KeyId, IntPtr hKeyEncryptionKey, byte[] byKeyBlob, BLOB_TYPE BlobType, KEY_ALG AlgId, bool Exportable, bool Temporary)
        {
            IntPtr hKey = IntPtr.Zero;
            int dwFlags = 0;

            if (Exportable)
                dwFlags |= DinamoApi.EXPORTABLE_KEY;

            if (Temporary)
                dwFlags |= DinamoApi.TEMPORARY_KEY;

            int nRet = DinamoApi.DImportKey(m_ctx, KeyId, hKeyEncryptionKey, (int)BlobType, (int)AlgId, dwFlags, byKeyBlob, byKeyBlob.Length, out hKey);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DImportKey");

            return hKey;
        }

        public Int32 ImportPKCS12(string FilePath, string Password, string KeyId, string CertId, bool Exportable)
        {
            Int32 dwFlags = 0;
            if (Exportable)
                dwFlags |= DinamoApi.EXPORTABLE_KEY;

            int nRet = DinamoApi.DImportPKCS12(m_ctx, FilePath, Password, KeyId, dwFlags, CertId);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DImportPKCS12");

            return nRet;
        }


        public byte[] PKCS8ExportKey(string szKeyId, string szSecret)
        {
            IntPtr pbDataOut;
            Int32 pdwDataOutLen = 0;
            byte[] bBufferOut = null;

            int nRet = DinamoApi.DPKCS8ExportKey(m_ctx, szKeyId, szSecret, out pbDataOut, out pdwDataOutLen);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DPKCS8ExportKey");

            bBufferOut = new byte[pdwDataOutLen];
            Marshal.Copy(pbDataOut, bBufferOut, 0, pdwDataOutLen);

            DinamoApi.DFree(pbDataOut);

            return bBufferOut;
        }

        public byte[] SPBExportPKCS12(string szISPB, string szSecret)
        {
            IntPtr pbDataOut;
            Int32 pdwDataOutLen = 0;
            byte[] bBufferOut = null;

            int nRet = DinamoApi.DSPBExportPKCS12(m_ctx, szISPB, szSecret, null, out pbDataOut, out pdwDataOutLen, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DSPBExportPKCS12");

            bBufferOut = new byte[pdwDataOutLen];
            Marshal.Copy(pbDataOut, bBufferOut, 0, pdwDataOutLen);

            DinamoApi.DFree(pbDataOut);

            return bBufferOut;
        }

        public byte[] ExportPKCS12(string szKeyId, string szCertId, string szSecret)
        {
            IntPtr pbDataOut;
            Int32 pdwDataOutLen = 0;
            byte[] bBufferOut = null;

            int nRet = DinamoApi.DExportPKCS12(m_ctx, szSecret, szKeyId, szCertId, null, out pbDataOut, out pdwDataOutLen, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DExportPKCS12");

            bBufferOut = new byte[pdwDataOutLen];
            Marshal.Copy(pbDataOut, bBufferOut, 0, pdwDataOutLen);

            DinamoApi.DFree(pbDataOut);

            return bBufferOut;
        }


        public void PKCS8ImportKey(string szKeyId, string szSecret, int dwKeyAlg, int dwAttrib, byte[] bKeyEnvelope)
        {
            Int32 dwEnvelopeKeyLen = bKeyEnvelope.Length;
            IntPtr pbEnvelopeKey = Marshal.AllocHGlobal(dwEnvelopeKeyLen);

            Marshal.Copy(bKeyEnvelope, 0, pbEnvelopeKey, dwEnvelopeKeyLen);

            int nRet = DinamoApi.DPKCS8ImportKey(m_ctx, szKeyId, szSecret, dwKeyAlg, dwAttrib, pbEnvelopeKey, dwEnvelopeKeyLen);

            Marshal.FreeHGlobal(pbEnvelopeKey);

            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DPKCS8ImportKey");
            }
        }



        public void SPBImportPKCS12(string szKeyId, string szSecret, string szDomain, int dwKeyAlg, int dwAttrib, string file)
        {

            int nRet = DinamoApi.DSPBImportPKCS12(m_ctx, 0, null, file, szSecret, szDomain, dwAttrib);

            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DSPBImportPKCS12");
            }
        }

        /** @} End of chaves grouping*/

        /**
        \addtogroup cryptography

        @{ */

        /// <summary>
        /// Encrypt blocos ou arquivos passando a referencia da chave.
        /// Utiliza o mode/padding default, ou seja, MODE CBC e padding PKCS#5
        /// </summary>
        /// <param name="hKey">Handle da chave</param>
        /// <param name="Final">Indica se o bloco é o último</param>
        /// <param name="byData">Dados a serem criptografados. Quando a função retorna, os dados originais são sobrescritos pelo resultado da operação de criptografia. O tamanho buffer é especificado pelo parâmetro dwBufLen, o número de bytes a serem processados é especificado pelo parâmetro pdwDataLen. O tamanho do buffer deve ser grande o suficiente para conter os dados criptografados mais o padding.</param>
        /// <param name="DataLen">Tamanho do bloco.Quando parâmetro de entrada, contém o número de bytes que serão processados, quando parâmetro de saída, contém o número de bytes dos dados criptografados.Se o buffer alocado não for suficiente para receber todo o dado cifrado (faltar, por exemplo, espaço para o padding) a função irá falhar retornando D_MORE_DATA.</param>
        /// <param name="BufferLen">Tamanho do buffer.Para operações simétricas que exijam padding o buffer deve ter o tamanho mínimo do comprimento do dado mais o tamanho do bloco de operação do algoritmo a ser utilizado.</param>
        public void Encrypt(IntPtr hKey, bool Final, byte[] byData, ref int DataLen, int BufferLen)
        {
            Encrypt(hKey, IntPtr.Zero, Final, 0, null, MODE_TYPE.MODE_CBC, PADDING_TYPE.PKCS5_PADDING, byData, ref DataLen, BufferLen);
        }

        /// <summary>
        /// Encripta um bloco no modo ECB sem nenhum Padding.  Essa funcao e util para PIN BLOCK.
        /// Tamanho do array de dados precisa ser compativel com o tipo de chave.
        /// </summary>
        /// <param name="strKeyId">Referencia da chave</param>
        /// <param name="byData">Dados a serem criptografados. Quando a função retorna, os dados originais são sobrescritos
        /// pelo resultado da operação de criptografia.
        /// O tamanho buffer é especificado pelo parâmetro dwBufLen, o número de bytes a serem processados
        /// é especificado pelo parâmetro pdwDataLen. O tamanho do buffer deve ser grande o suficiente para conter os
        /// dados criptografados mais o padding.</param>
        public void Encrypt(String strKeyId, byte[] byData)
        {
            IntPtr hKey = GetUserKey(strKeyId);
            int BufferLen = byData.Length;
            int DataLen = byData.Length;
            Encrypt(hKey, IntPtr.Zero, true, 0,
                null, MODE_TYPE.MODE_ECB, PADDING_TYPE.NO_PADDING, byData,
                ref DataLen, BufferLen);
            DestroyKey(hKey);

        }

        /// <summary>
        /// Encripta um bloco utilizando a parametrização padrão do HSM.
        /// 
        /// Para chaves simétricas:
        /// MODE_CBC: Cipher Block Chain (CBC)
        /// PKCS5_PADDING: O padding é feito seguindo o padrão definido no PKCS#5.
        /// IV: Preenchido com zeros.
        /// 
        /// Para chaves assimétricas RSA:
        /// PKCS1_PADDING: É utilizado o padding PKCS#1 v1.5.
        /// 
        /// </summary>
        /// <param name="strKeyId">Referencia da chave</param>
        /// <param name="byData">Dados a serem criptografados.</param>
        /// <returns>Os dados encriptados.</returns>
        public byte[] EncryptDefault(String strKeyId, byte[] byData)
        {
            IntPtr hKey = GetUserKey(strKeyId);
            int DataLen = byData.Length;
            int BufferLen = byData.Length;

            EncryptDefault(hKey, IntPtr.Zero, true, 0,
                null, null,
                ref DataLen, BufferLen);

            byte[] encBuffer = new byte[DataLen];
            byData.CopyTo(encBuffer, 0);
            DataLen = byData.Length;
            EncryptDefault(hKey, IntPtr.Zero, true, 0,
                null, encBuffer,
                ref DataLen, encBuffer.Length);

            DestroyKey(hKey);

            if (DataLen < encBuffer.Length)
            {
                System.Array.Resize(ref encBuffer, DataLen);
            }

            return encBuffer;
        }

        /// <summary>
        /// Encripta um hash, dado geral ou um arquivo.
        /// </summary>
        /// <param name="strKeyId">Referencia da chave</param>
        /// <param name="hHash">Ponteiro para um hash</param>
        /// <param name="Final">Indica se o bloco é o último</param>
        /// <param name="iv">
        /// Vetor de inicialização usado com algoritmos de bloco de acordo com o seu modo de operação de criptografia simétrica.
        /// O tamanho do vetor de inicialização depende do algoritmo simétrico utilizado, já que tem o mesmo comprimento do bloco de operação. Mais detalhes na sessão Observações.
        /// Válido apenas para chaves simétricas.
        /// </param>
        /// <param name="mode">
        /// Indica o modo de operação de criptografia do algoritmo de bloco.
        /// MODE_ECB: Eletronic Codebook (ECB)
        /// MODE_CBC: Cipher Block Chain (CBC)
        /// MODE_CFB: Cipher-Feedback. Ainda não suportada.
        /// MODE_OFB: Output-Feedback. Ainda não suportada.
        /// Válido apenas para chaves simétricas e algoritmos de bloco.
        /// </param>
        /// <param name="padding">A biblioteca pode trabalhar com 3 formas de padding:
        /// NO_PADDING: Não é feito padding, os dados passados para criptografia já deve ter comprimento múltiplo do tamanho do bloco de operação.
        /// PKCS5_PADDING: O padding é feito seguindo o padrão definido no PKCS#5.
        /// ZERO_PADDING: Caso o comprimento dos dados não seja múltiplo do tamanho do bloco de operação, ele é completado com zeros a direita até que tenha um tamanho suportado pelo algoritmo. Este tipo de padding não deve ser usado com dados onde pode haver bytes com valor zero, pois pode gerar ambigüidade na operação de decriptografia. Caso os dados contenham apenas texto ASCII, por exemplo, não há problema.
        /// Válido apenas para chaves simétricas.
        /// </param>
        /// <param name="byData">Dados a serem criptografados. Quando a função retorna, os dados originais são sobrescritos
        /// pelo resultado da operação de criptografia.
        /// O tamanho buffer é especificado pelo parâmetro dwBufLen, o número de bytes a serem processados
        /// é especificado pelo parâmetro pdwDataLen. O tamanho do buffer deve ser grande o suficiente para conter os
        /// dados criptografados mais o padding.</param>
        /// <param name="DataLen">Tamanho do bloco.Quando parâmetro de entrada, contém o número de bytes que serão processados, quando parâmetro de saída,
        /// contém o número de bytes dos dados criptografados.Se o buffer alocado não for suficiente para receber todo
        /// o dado cifrado (faltar, por exemplo, espaço para o padding) a função irá falhar retornando D_MORE_DATA.</param>
        /// <param name="BufferLen">Tamanho do buffer.Para operações simétricas que exijam padding o buffer deve ter o tamanho mínimo do comprimento do dado mais o
        /// tamanho do bloco de operação do algoritmo a ser utilizado.</param>
        public void Encrypt(string strKeyId, IntPtr hHash, bool Final,
           byte[] iv, MODE_TYPE mode, PADDING_TYPE padding, byte[] byData,
           ref int DataLen, int BufferLen)
        {
            IntPtr hKey = GetUserKey(strKeyId);

            Encrypt(hKey, hHash, Final, 0, iv, mode, padding, byData, ref DataLen, BufferLen);

            DestroyKey(hKey);
        }

        /// <summary>
        /// Encripta um hash, dado geral ou um arquivo.
        /// </summary>
        /// <param name="hKey">Contexto da chave</param>
        /// <param name="hHash">Ponteiro para um hash</param>
        /// <param name="Final">Indica se o bloco é o último</param>
        /// <param name="dwFlags">Reservado para uso futuro (deve ser 0).</param>
        /// <param name="iv">
        /// Vetor de inicialização usado com algoritmos de bloco de acordo com o seu modo de operação de criptografia simétrica.
        /// O tamanho do vetor de inicialização depende do algoritmo simétrico utilizado, já que tem o mesmo comprimento do bloco de operação. Mais detalhes na sessão Observações.
        /// Válido apenas para chaves simétricas.
        /// </param>
        /// <param name="mode">
        /// Indica o modo de operação de criptografia do algoritmo de bloco.
        /// MODE_ECB: Eletronic Codebook (ECB)
        /// MODE_CBC: Cipher Block Chain (CBC)
        /// MODE_CFB: Cipher-Feedback. Ainda não suportada.
        /// MODE_OFB: Output-Feedback. Ainda não suportada.
        /// Válido apenas para chaves simétricas e algoritmos de bloco.
        /// </param>
        /// <param name="padding">A biblioteca pode trabalhar com 3 formas de padding:
        /// NO_PADDING: Não é feito padding, os dados passados para criptografia já deve ter comprimento múltiplo do tamanho do bloco de operação.
        /// PKCS5_PADDING: O padding é feito seguindo o padrão definido no PKCS#5.
        /// ZERO_PADDING: Caso o comprimento dos dados não seja múltiplo do tamanho do bloco de operação, ele é completado com zeros a direita até que tenha um tamanho suportado pelo algoritmo. Este tipo de padding não deve ser usado com dados onde pode haver bytes com valor zero, pois pode gerar ambigüidade na operação de decriptografia. Caso os dados contenham apenas texto ASCII, por exemplo, não há problema.
        /// Válido apenas para chaves simétricas.
        /// </param>
        /// <param name="byData">Dados a serem criptografados. Quando a função retorna, os dados originais são sobrescritos
        /// pelo resultado da operação de criptografia.
        /// O tamanho buffer é especificado pelo parâmetro dwBufLen, o número de bytes a serem processados
        /// é especificado pelo parâmetro pdwDataLen. O tamanho do buffer deve ser grande o suficiente para conter os
        /// dados criptografados mais o padding.</param>
        /// <param name="DataLen">Tamanho do bloco. Quando parâmetro de entrada, contém o número de bytes que serão processados, quando parâmetro de saída, contém o número de bytes dos dados criptografados.Se o buffer alocado não for suficiente para receber todo o dado cifrado (faltar, por exemplo, espaço para o padding) a função irá falhar retornando D_MORE_DATA.</param>
        /// <param name="BufferLen">Tamanho do buffer.Para operações simétricas que exijam padding o buffer deve ter o tamanho mínimo do comprimento do dado mais o
        /// tamanho do bloco de operação do algoritmo a ser utilizado.</param>
        public void Encrypt(IntPtr hKey, IntPtr hHash, bool Final, int dwFlags,
            byte[] iv, MODE_TYPE mode, PADDING_TYPE padding, byte[] byData,
            ref int DataLen, int BufferLen)
        {
            int nRet = 0;
            if (iv != null && iv.Length > 0)
            {
                nRet = DinamoApi.DSetKeyParam(hKey, DinamoApi.DKP_IV, iv, iv.Length, 0);
                if (nRet != DinamoApi.D_OK)
                    throw new DinamoException(nRet, "DSetKeyParam");
            }

            if (mode != MODE_TYPE.MODE_NONE)
            {
                byte[] modedata = BitConverter.GetBytes((Int32)mode);
                nRet = DinamoApi.DSetKeyParam(hKey, DinamoApi.DKP_MODE, modedata, modedata.Length, 0);
                if (nRet != DinamoApi.D_OK)
                    throw new DinamoException(nRet, "DSetKeyParam");
            }

            if (padding != PADDING_TYPE.NO_PADDING)
            {
                byte[] paddingdata = BitConverter.GetBytes((Int32)padding);
                nRet = DinamoApi.DSetKeyParam(hKey, DinamoApi.DKP_PADDING, paddingdata, paddingdata.Length, 0);
                if (nRet != DinamoApi.D_OK)
                    throw new DinamoException(nRet, "DSetKeyParam");
            }

            nRet = DinamoApi.DEncrypt(hKey, hHash, Final ? 1 : 0, dwFlags, byData, ref DataLen, BufferLen);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DEncrypt");
        }


        /// <summary>
        /// Encripta utilizando a parametrização padrão do HSM.
        /// 
        /// Para chaves simétricas:
        /// MODE_CBC: Cipher Block Chain (CBC)
        /// PKCS5_PADDING: O padding é feito seguindo o padrão definido no PKCS#5.
        /// 
        /// Para chaves assimétricas RSA:
        /// PKCS1_PADDING: É utilizado o padding PKCS#1 v1.5.
        /// 
        /// 
        /// </summary>
        /// <param name="hKey">Contexto da chave</param>
        /// <param name="hHash">Ponteiro para um hash</param>
        /// <param name="Final">Indica se o bloco é o último</param>
        /// <param name="dwFlags">Reservado para uso futuro (deve ser 0).</param>
        /// <param name="iv">
        /// Vetor de inicialização usado com algoritmos de bloco de acordo com o seu modo de operação de criptografia simétrica.
        /// O tamanho do vetor de inicialização depende do algoritmo simétrico utilizado, já que tem o mesmo comprimento do bloco de operação. Mais detalhes na sessão Observações.
        /// Válido apenas para chaves simétricas. Caso seja passado null, será utilizado o IV preenchido com zeros.
        /// </param>
        /// <param name="byData">Dados a serem criptografados. Quando a função retorna, os dados originais são sobrescritos
        /// pelo resultado da operação de criptografia.
        /// O tamanho buffer é especificado pelo parâmetro dwBufLen, o número de bytes a serem processados
        /// é especificado pelo parâmetro pdwDataLen. O tamanho do buffer deve ser grande o suficiente para conter os
        /// dados criptografados mais o padding.</param>
        /// <param name="DataLen">Tamanho do bloco. Quando parâmetro de entrada, contém o número de bytes que serão processados, quando parâmetro de saída, contém o número de bytes dos dados criptografados.Se o buffer alocado não for suficiente para receber todo o dado cifrado (faltar, por exemplo, espaço para o padding) a função irá falhar retornando D_MORE_DATA.</param>
        /// <param name="BufferLen">Tamanho do buffer.Para operações simétricas que exijam padding o buffer deve ter o tamanho mínimo do comprimento do dado mais o
        /// tamanho do bloco de operação do algoritmo a ser utilizado.</param>

        public void EncryptDefault(IntPtr hKey, IntPtr hHash, bool Final, int dwFlags,
            byte[] iv, byte[] byData, ref int DataLen, int BufferLen)
        {
            int nRet = 0;
            if (iv != null && iv.Length > 0)
            {
                nRet = DinamoApi.DSetKeyParam(hKey, DinamoApi.DKP_IV, iv, iv.Length, 0);
                if (nRet != DinamoApi.D_OK)
                    throw new DinamoException(nRet, "DSetKeyParam");
            }

            nRet = DinamoApi.DEncrypt(hKey, hHash, Final ? 1 : 0, dwFlags, byData, ref DataLen, BufferLen);

            if ((nRet != DinamoApi.D_OK) &&
                 ((nRet != DinamoApi.D_MORE_DATA) &&
                    byData != null))
            {
                throw new DinamoException(nRet, "DEncrypt");
            }

        }

        /// <summary>
        /// Retorna o tamanho do buffer de criptografia
        /// </summary>
        /// <param name="hKey">Contexto da chave</param>
        /// <param name="hHash">Ponteiro para um hash</param>
        /// <param name="DataLen">Tamanho do dado a ser criptografado</param>
        /// <returns>Tamanho do buffer de criptografia</returns>
        public int GetEncryptBuffLen(IntPtr hKey, IntPtr hHash, int DataLen)
        {
            int nDataLen = DataLen;

            int nRet = DinamoApi.DEncrypt(hKey, hHash, 1, 0, null, ref nDataLen, 0);

            if (!((nRet == DinamoApi.D_MORE_DATA) ||
                (nRet == DinamoApi.D_OK)))
            {
                throw new DinamoException(nRet, "DEncrypt");
            }

            return nDataLen;
        }
        /// <summary>
        /// Codifica uma chave simetrica que está fora do HSM usando uma RSA dentro do HSM
        /// </summary>
        /// <param name="strKeyId">Identificação da Chave RSA</param>
        /// <param name="byKey">Conteúdo da chave simétrica</param>
        /// <returns>Chave simétrica criptografada</returns>
        public byte[] KEKEncode(String strKeyId, byte[] byKey)
        {
            IntPtr hKey = GetUserKey(strKeyId);
            uint iType = (uint)GetKeyAlgId(hKey) | 0x80000000;
            KEY_ALG cKeyAlg = (KEY_ALG)Enum.ToObject(typeof(KEY_ALG), iType);
            byte[] bPublicKey = ExportKey(hKey, IntPtr.Zero, BLOB_TYPE.PUBLICKEY_BLOB);

            IntPtr hPublicKey = ImportKey("PubKey", IntPtr.Zero, bPublicKey, BLOB_TYPE.PUBLICKEY_BLOB, cKeyAlg, false, true);

            int BufferLen = GetUserKeyLen(hKey) / 8;
            int DataLen = byKey.Length;
            byte[] ans = new byte[BufferLen];

            Array.Copy(byKey, ans, DataLen);

            Encrypt(hPublicKey, IntPtr.Zero, true, 0,
                null, MODE_TYPE.MODE_NONE, PADDING_TYPE.NO_PADDING, ans,
                ref DataLen, BufferLen);

            DestroyKey(hPublicKey);

            DestroyKey(hKey);
            return ans;
        }

        /// <summary>
        /// Decodifica uma chave simétrica que está fora do HSM usando uma RSA dentro do HSM.
        /// </summary>
        /// <param name="strKeyId">Identificação da Chave RSA</param>
        /// <param name="byKey">Conteúdo da chave simétrica criptografada</param>
        public byte[] KEKDecode(String strKeyId, byte[] byKey)
        {
            IntPtr hKey = GetUserKey(strKeyId);
            int DataLen = byKey.Length;

            Decrypt(hKey, IntPtr.Zero, true, 0,
                null, MODE_TYPE.MODE_NONE, PADDING_TYPE.NO_PADDING, byKey,
                ref DataLen);

            DestroyKey(hKey);
            return byKey;
        }

        /// <summary>
        /// Decripta um hash, dado geral ou um arquivo.
        /// </summary>
        /// <param name="strKeyId">Referencia da chave</param>
        /// <param name="hHash">Ponteiro para um hash</param>
        /// <param name="Final">Indica se o bloco é o último</param>
        /// <param name="byData">Buffer que contem os dados a serem decriptografados. Quando a função retorna, os dados originais
        /// são sobrescritos pelo resultado da operação de criptografia.
        /// Para operações simétricas de bloco, é necessário que o tamanho dos dados seja sempre múltiplo do bloco
        /// usado pelo algoritmo em questão.</param>
        /// <param name="DataLen">Retorna o tamanho dos dados em byData. Quando parâmetro de entrada, contém o número de bytes que serão processados, quando parâmetro de saída,
        /// contém o número de bytes dos dados em texto claro.</param>
        public void Decrypt(string strKeyId, IntPtr hHash, bool Final, byte[] byData, ref int DataLen)
        {
            IntPtr hKey = GetUserKey(strKeyId);

            Decrypt(hKey, hHash, Final, byData, ref DataLen);

            DestroyKey(hKey);
        }

        /// <summary>
        /// Decripta um hash, dado geral ou um arquivo.
        /// </summary>
        /// <param name="hKey">Contexto da chave</param>
        /// <param name="hHash">Ponteiro para um hash</param>
        /// <param name="Final">Indica se o bloco é o último</param>
        /// <param name="byData">Buffer que contem os dados a serem decriptografados. Quando a função retorna, os dados originais
        /// são sobrescritos pelo resultado da operação de criptografia.
        /// Para operações simétricas de bloco, é necessário que o tamanho dos dados seja sempre múltiplo do bloco
        /// usado pelo algoritmo em questão.</param>
        /// <param name="DataLen">Retorna o tamanho dos dados em byData. Quando parâmetro de entrada, contém o número de bytes que serão processados, quando parâmetro de saída, contém o número de bytes dos dados em texto claro.</param>
        public void Decrypt(IntPtr hKey, IntPtr hHash, bool Final, byte[] byData, ref int DataLen)
        {
            Decrypt(hKey, hHash, Final, 0, null, MODE_TYPE.MODE_CBC, PADDING_TYPE.PKCS5_PADDING, byData, ref DataLen);
        }

        /// <summary>
        /// Decripta um bloco no modo ECB sem nenhum Padding.  Essa funcao e util para PIN BLOCK.
        /// Tamanho do array de dados precisa ser compativel com o tipo de chave.
        /// </summary>
        /// <param name="strKeyId">Referencia da chave</param>
        /// <param name="byData">Buffer de dados</param>
        public void Decrypt(string strKeyId, byte[] byData)
        {
            int DataLen = byData.Length;
            IntPtr hKey = GetUserKey(strKeyId);
            Decrypt(hKey, IntPtr.Zero, true, 0, null, MODE_TYPE.MODE_ECB, PADDING_TYPE.NO_PADDING, byData, ref DataLen);
            DestroyKey(hKey);
        }

        /// <summary>
        /// Decripta um bloco utilizando a parametrização padrão do HSM.
        /// 
        /// Para chaves simétricas:
        /// MODE_CBC: Cipher Block Chain (CBC)
        /// PKCS5_PADDING: O padding é feito seguindo o padrão definido no PKCS#5.
        /// IV: Preenchido com zeros.
        /// 
        /// Para chaves assimétricas RSA:
        /// PKCS1_PADDING: É utilizado o padding PKCS#1 v1.5.
        /// 
        /// </summary>
        /// <param name="strKeyId">Referencia da chave</param>
        /// <param name="byData">Buffer de dados</param>
        /// <returns>Os dados decriptados.</returns>
        public byte[] DecryptDefault(string strKeyId, byte[] byData)
        {
            int DataLen = byData.Length;
            IntPtr hKey = GetUserKey(strKeyId);
            DecryptDefault(hKey, IntPtr.Zero, true, 0, null, byData, ref DataLen);
            DestroyKey(hKey);

            if (DataLen != byData.Length)
            {
                System.Array.Resize(ref byData, DataLen);
            }

            return byData;
        }

        /// <summary>
        /// Decripta um hash, dado geral ou um arquivo.
        /// </summary>
        /// <param name="strKeyId">Referencia da chave</param>
        /// <param name="hHash">Ponteiro para um hash</param>
        /// <param name="Final">Indica se o bloco é o último</param>
        /// <param name="iv">
        /// Vetor de inicialização usado com algoritmos de bloco de acordo com o seu modo de operação de criptografia simétrica.
        /// O tamanho do vetor de inicialização depende do algoritmo simétrico utilizado, já que tem o mesmo comprimento do bloco de operação. Mais detalhes na sessão Observações.
        /// Válido apenas para chaves simétricas.
        /// </param>
        /// <param name="mode">
        /// Indica o modo de operação de criptografia do algoritmo de bloco.
        /// MODE_ECB: Eletronic Codebook (ECB)
        /// MODE_CBC: Cipher Block Chain (CBC)
        /// MODE_CFB: Cipher-Feedback. Ainda não suportada.
        /// MODE_OFB: Output-Feedback. Ainda não suportada.
        /// Válido apenas para chaves simétricas e algoritmos de bloco.
        /// </param>
        /// <param name="padding">A biblioteca pode trabalhar com 3 formas de padding:
        /// NO_PADDING: Não é feito padding, os dados passados para criptografia já deve ter comprimento múltiplo do tamanho do bloco de operação.
        /// PKCS5_PADDING: O padding é feito seguindo o padrão definido no PKCS#5.
        /// ZERO_PADDING: Caso o comprimento dos dados não seja múltiplo do tamanho do bloco de operação, ele é completado com zeros a direita até que tenha um tamanho suportado pelo algoritmo. Este tipo de padding não deve ser usado com dados onde pode haver bytes com valor zero, pois pode gerar ambigüidade na operação de decriptografia. Caso os dados contenham apenas texto ASCII, por exemplo, não há problema.
        /// Válido apenas para chaves simétricas.
        /// </param>
        /// <param name="byData">Buffer que contem os dados a serem decriptografados. Quando a função retorna, os dados originais
        /// são sobrescritos pelo resultado da operação de criptografia.
        /// Para operações simétricas de bloco, é necessário que o tamanho dos dados seja sempre múltiplo do bloco
        /// usado pelo algoritmo em questão.</param>
        /// <param name="DataLen">Retorna o tamanho dos dados em byData. Quando parâmetro de entrada, contém o número de bytes que serão processados, quando parâmetro de saída, contém o número de bytes dos dados em texto claro.</param>
        public void Decrypt(string strKeyId, IntPtr hHash, bool Final, byte[] iv, MODE_TYPE mode, PADDING_TYPE padding, byte[] byData, ref int DataLen)
        {
            IntPtr hKey = GetUserKey(strKeyId);

            Decrypt(hKey, hHash, Final, 0, iv, mode, padding, byData, ref DataLen);

            DestroyKey(hKey);
        }

        /// <summary>
        /// Decripta um hash, dado geral ou um arquivo.
        /// </summary>
        /// <param name="hKey">Conexto da chave</param>
        /// <param name="hHash">Ponteiro para um hash</param>
        /// <param name="Final">Indica se o bloco é o último</param>
        /// <param name="dwFlags">Reservado para uso futuro (deve ser 0).</param>
        /// <param name="iv">
        /// Vetor de inicialização usado com algoritmos de bloco de acordo com o seu modo de operação de criptografia simétrica.
        /// O tamanho do vetor de inicialização depende do algoritmo simétrico utilizado, já que tem o mesmo comprimento do bloco de operação. Mais detalhes na sessão Observações.
        /// Válido apenas para chaves simétricas.
        /// </param>
        /// <param name="mode">
        /// Indica o modo de operação de criptografia do algoritmo de bloco.
        /// MODE_ECB: Eletronic Codebook (ECB)
        /// MODE_CBC: Cipher Block Chain (CBC)
        /// MODE_CFB: Cipher-Feedback. Ainda não suportada.
        /// MODE_OFB: Output-Feedback. Ainda não suportada.
        /// Válido apenas para chaves simétricas e algoritmos de bloco.
        /// </param>
        /// <param name="padding">A biblioteca pode trabalhar com 3 formas de padding:
        /// NO_PADDING: Não é feito padding, os dados passados para criptografia já deve ter comprimento múltiplo do tamanho do bloco de operação.
        /// PKCS5_PADDING: O padding é feito seguindo o padrão definido no PKCS#5.
        /// ZERO_PADDING: Caso o comprimento dos dados não seja múltiplo do tamanho do bloco de operação, ele é completado com zeros a direita até que tenha um tamanho suportado pelo algoritmo. Este tipo de padding não deve ser usado com dados onde pode haver bytes com valor zero, pois pode gerar ambigüidade na operação de decriptografia. Caso os dados contenham apenas texto ASCII, por exemplo, não há problema.
        /// Válido apenas para chaves simétricas.
        /// </param>
        /// <param name="byData">Buffer que contem os dados a serem decriptografados. Quando a função retorna, os dados originais
        /// são sobrescritos pelo resultado da operação de criptografia.
        /// Para operações simétricas de bloco, é necessário que o tamanho dos dados seja sempre múltiplo do bloco
        /// usado pelo algoritmo em questão.</param>
        /// <param name="DataLen">Retorna o tamanho dos dados em byData. Quando parâmetro de entrada, contém o número de bytes que serão processados, quando parâmetro de saída,
        /// contém o número de bytes dos dados em texto claro.</param>
        public void Decrypt(IntPtr hKey, IntPtr hHash, bool Final, int dwFlags, byte[] iv, MODE_TYPE mode, PADDING_TYPE padding, byte[] byData, ref int DataLen)
        {
            int nRet = 0;
            if (iv != null && iv.Length > 0)
            {
                nRet = DinamoApi.DSetKeyParam(hKey, DinamoApi.DKP_IV, iv, iv.Length, 0);
                if (nRet != DinamoApi.D_OK)
                    throw new DinamoException(nRet, "DSetKeyParam");
            }

            if (mode != MODE_TYPE.MODE_NONE)
            {
                byte[] modedata = BitConverter.GetBytes((Int32)mode);
                nRet = DinamoApi.DSetKeyParam(hKey, DinamoApi.DKP_MODE, modedata, modedata.Length, 0);
                if (nRet != DinamoApi.D_OK)
                    throw new DinamoException(nRet, "DSetKeyParam");
            }
            if (padding != PADDING_TYPE.NO_PADDING)
            {
                byte[] paddingdata = BitConverter.GetBytes((Int32)padding);
                nRet = DinamoApi.DSetKeyParam(hKey, DinamoApi.DKP_PADDING, paddingdata, paddingdata.Length, 0);
                if (nRet != DinamoApi.D_OK)
                    throw new DinamoException(nRet, "DSetKeyParam");
            }

            nRet = DinamoApi.DDecrypt(hKey, hHash, Final ? 1 : 0, dwFlags, byData, ref DataLen);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DDecrypt");
        }


        /// <summary>
        /// Decripta utilizando a parametrização padrão do HSM.
        /// 
        /// Para chaves simétricas:
        /// MODE_CBC: Cipher Block Chain (CBC)
        /// PKCS5_PADDING: O padding é feito seguindo o padrão definido no PKCS#5.
        /// 
        /// Para chaves assimétricas RSA:
        /// PKCS1_PADDING: É utilizado o padding PKCS#1 v1.5.
        /// 
        /// </summary>
        /// <param name="hKey">Conexto da chave</param>
        /// <param name="hHash">Ponteiro para um hash</param>
        /// <param name="Final">Indica se o bloco é o último</param>
        /// <param name="dwFlags">Reservado para uso futuro (deve ser 0).</param>
        /// <param name="iv">
        /// Vetor de inicialização usado com algoritmos de bloco de acordo com o seu modo de operação de criptografia simétrica.
        /// O tamanho do vetor de inicialização depende do algoritmo simétrico utilizado, já que tem o mesmo comprimento do bloco de operação. Mais detalhes na sessão Observações.
        /// Válido apenas para chaves simétricas. Caso seja passado null, será utilizado o IV preenchido com zeros.
        /// </param>
        /// <param name="byData">Buffer que contem os dados a serem decriptografados. Quando a função retorna, os dados originais
        /// são sobrescritos pelo resultado da operação de criptografia.
        /// Para operações simétricas de bloco, é necessário que o tamanho dos dados seja sempre múltiplo do bloco
        /// usado pelo algoritmo em questão.</param>
        /// <param name="DataLen">Retorna o tamanho dos dados em byData. Quando parâmetro de entrada, contém o número de bytes que serão processados, quando parâmetro de saída,
        /// contém o número de bytes dos dados em texto claro.</param>
        public void DecryptDefault(IntPtr hKey, IntPtr hHash, bool Final, int dwFlags, byte[] iv, byte[] byData, ref int DataLen)
        {
            int nRet = 0;
            if (iv != null && iv.Length > 0)
            {
                nRet = DinamoApi.DSetKeyParam(hKey, DinamoApi.DKP_IV, iv, iv.Length, 0);
                if (nRet != DinamoApi.D_OK)
                    throw new DinamoException(nRet, "DSetKeyParam");
            }

            nRet = DinamoApi.DDecrypt(hKey, hHash, Final ? 1 : 0, dwFlags, byData, ref DataLen);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DDecrypt");
        }

        /// <summary>
        /// Cria um handle para um hash
        /// </summary>
        /// <param name="AlgId">Algoritmo de hash</param>
        /// <returns>IntPtr Ponteiro para o recurso de hash</returns>
        public IntPtr CreateHash(HASH_ALG AlgId)
        {
            IntPtr hHash;

            int nRet = DinamoApi.DCreateHash(m_ctx, (Int32)AlgId, IntPtr.Zero, 0, out hHash);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DCreateHash");

            return hHash;
        }
        /// <summary>
        /// Encontra o hash para um dado e o associa ao handle de hash.
        /// </summary>
        /// <param name="hHash">IntPtr Ponteiro para o recurso de hash</param>
        /// <param name="byData">Dado em bytes</param>
        public void HashData(IntPtr hHash, byte[] byData)
        {
            int nRet = DinamoApi.DHashData(hHash, byData, byData.Length, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DHashData");
        }

        /// <summary>
        /// Retorna o hash de um dado
        /// </summary>
        /// <param name="alg">Algoritmo de hash</param>
        /// <param name="data">Dado em bytes</param>
        /// <returns>Valor do hash em bytes</returns>
        public byte[] Hash(HASH_ALG alg, byte[] data)
        {
            IntPtr pHash = CreateHash(alg);
            HashData(pHash, data);
            byte[] bHash = GetHashValue(pHash);
            DestroyHash(pHash);
            return bHash;
        }
        /// <summary>
        /// Libera o handle do recurso de hash
        /// </summary>
        /// <param name="hHash">IntPtr Ponteiro para o recurso de hash</param>
        public void DestroyHash(IntPtr hHash)
        {
            int nRet = DinamoApi.DDestroyHash(ref hHash);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DDestroyHash");
        }


        /// <summary>
        /// Envia um lote de blocos para assinatura no HSM.
        /// </summary>
        /// <param name="strKeyId">Nome da chave.</param>
        /// <param name="pbBlock">Array de bytes contendo os blocos que serão assinados concatenados e com os devidos paddings feitos. Adicionar no início deste array de blocos o padding zero de tamanho DN_BATCH_SIGN_BLOCK_HEADER.
        /// A estrutura deverá ser como a seguinte. Padding zero de tamanho DN_BATCH_SIGN_BLOCK_HEADER | BLOCO 1 | BLOCO 2 | BLOCO 3 | ... Os blocos assinados serão retornados nas mesmas posições dos blocos de entrada.</param>
        /// <param name="dwBlockCount">Quantidade de blocos contidos em pbBlock.</param>
        /// <param name="dwFlags">Reservado para uso futuro (deve ser 0).</param>
        public void BatchSign(string strKeyId, byte[] pbBlock, Int32 dwBlockCount, Int32 dwFlags)
        {
            IntPtr hKey = GetUserKey(strKeyId);


            int nRet = DinamoApi.DBatchSign(hKey, pbBlock, dwBlockCount, dwFlags);
            if (nRet != DinamoApi.D_OK)
            {
                DestroyKey(hKey);
                throw new DinamoException(nRet, "DBatchSign");
            }

            DestroyKey(hKey);
        }



        /// <summary>
        /// Envia um lote de blocos para assinatura no HSM.
        /// </summary>
        /// <param name="hPrivateKey">Contexto da chave.</param>
        /// <param name="pbBlock">Array de bytes contendo os blocos que serão assinados concatenados e com os devidos paddings feitos. Adicionar no início deste array de blocos o padding zero de tamanho DN_BATCH_SIGN_BLOCK_HEADER.
        /// A estrutura deverá ser como a seguinte. Padding zero de tamanho DN_BATCH_SIGN_BLOCK_HEADER | BLOCO 1 | BLOCO 2 | BLOCO 3 | ... Os blocos assinados serão retornados nas mesmas posições dos blocos de entrada.</param>
        /// <param name="dwBlockCount">Quantidade de blocos contidos em pbBlock.</param>
        /// <param name="dwFlags">Reservado para uso futuro (deve ser 0).</param>
        public void BatchSign(IntPtr hPrivateKey, byte[] pbBlock, Int32 dwBlockCount, Int32 dwFlags)
        {

            int nRet = DinamoApi.DBatchSign(hPrivateKey, pbBlock, dwBlockCount, dwFlags);
            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DBatchSign");
            }

        }

        /// <summary>
        /// Assina um hash
        /// </summary>
        /// <param name="keyId">Identificador da chave privada</param>
        /// <param name="bHash">Array com o hash</param>
        /// <param name="algHash">Algoritmo de hash utilizado. Veja: <see cref="HASH_ALG"/></param>
        /// <returns>array de bytes</returns>
        public byte[] SignHash(String keyId, byte[] bHash, DinamoClient.HASH_ALG algHash)
        {
            IntPtr pKey = GetUserKey(keyId);
            IntPtr pHash = CreateHash(algHash);
            SetHashValue(pHash, bHash);

            byte[] ans = SignHash(pHash, pKey, false);

            DestroyHash(pHash);
            DestroyKey(pKey);

            return ans;
        }

        /// <summary>
        /// Assina um hash
        /// </summary>
        /// <param name="keyId">Identificador da chave privada</param>
        /// <param name="pHash">Ponteiro para um objeto de hash dentro do HSM</param>
        /// <param name="algHash">Algoritmo de hash utilizado. Veja: <see cref="HASH_ALG"/></param>
        /// <returns>array de bytes</returns>
        public byte[] SignHash(String keyId, IntPtr pHash, DinamoClient.HASH_ALG algHash)
        {
            IntPtr pKey = GetUserKey(keyId);

            byte[] ans = SignHash(pHash, pKey, false);

            DestroyHash(pHash);
            DestroyKey(pKey);

            return ans;
        }

        /// <summary>
        /// Assina um hash
        /// </summary>
        /// <param name="hHash">Ponteiro para o recurso de hash</param>
        /// <param name="hPrivateKey">Ponteiro para a chave privada</param>
        /// <param name="PKCS7Compliance">Verdadeiro para ter compatibilidade com o PKCS7</param>
        /// <returns>Assinatura como um array de bytes.</returns>
        private byte[] SignHash(IntPtr hHash, IntPtr hPrivateKey, bool PKCS7Compliance)
        {
            byte[] bySignature = null;
            int cbSignature = 0;
            int dwFlags = 0;

            if (PKCS7Compliance)
                dwFlags = DinamoApi.NO_HASH_OID;

            int nRet = DinamoApi.DSignHash(hHash, hPrivateKey, dwFlags, bySignature, ref cbSignature);

            if (DinamoApi.D_OK == nRet || DinamoApi.D_MORE_DATA == nRet)
            {
                bySignature = new byte[cbSignature];
                nRet = DinamoApi.DSignHash(hHash, hPrivateKey, dwFlags, bySignature, ref cbSignature);
            }

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DSignHash");

            return bySignature;
        }
        /// <summary>
        /// Verifica uma assinatura
        /// </summary>
        /// <param name="hHash">Ponteiro para o recurso de hash</param>
        /// <param name="hPublicKey">Ponteiro para o recurso da chave pública</param>
        /// <param name="bySignature">Array da assinatura</param>
        /// <returns>Verdadeiro em caso de validação ok da assinatura</returns>
        public bool VerifySignature(IntPtr hHash, IntPtr hPublicKey, byte[] bySignature)
        {
            int nRet = DinamoApi.DVerifySignature(hHash, bySignature, bySignature.Length, hPublicKey, 0);

            if (nRet != DinamoApi.D_OK && nRet != DinamoApi.D_INVALID_SIGNATURE)
                throw new DinamoException(nRet, "DVerifySignature");

            return nRet == 0;
        }
        /// <summary>
        /// Armazena um hash
        /// </summary>
        /// <param name="hHash">Ponteiro para o recurso de hash</param>
        /// <param name="Value">Valor do hash</param>
        public void SetHashValue(IntPtr hHash, byte[] Value)
        {
            int nRet = DinamoApi.DSetHashParam(hHash, DinamoApi.DHP_HASH_VALUE, Value, Value.Length, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DSetHashParam");
        }
        /// <summary>
        /// Retorna o valor do hash
        /// </summary>
        /// <param name="hHash">Ponteiro para o recurso de hash</param>
        /// <returns>Array com o hash</returns>
        public byte[] GetHashValue(IntPtr hHash)
        {
            byte[] byValue = null;
            int cbValue = 0;

            int nRet = DinamoApi.DGetHashParam(hHash, DinamoApi.DHP_HASH_VALUE, byValue, ref cbValue, 0);

            if (DinamoApi.D_OK == nRet || DinamoApi.D_MORE_DATA == nRet)
            {
                byValue = new byte[cbValue];

                nRet = DinamoApi.DGetHashParam(hHash, DinamoApi.DHP_HASH_VALUE, byValue, ref cbValue, 0);
            }

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetHashParam");

            return byValue;
        }
        /// <summary>
        /// Retorna um número aleatório do gerador do HSM
        /// </summary>
        /// <param name="dwReturnLen">Tamanho em bytes do número aleatório</param>
        /// <returns>Array de bytes do número aleatório encontrado</returns>
        public byte[] GetRandom(Int32 dwReturnLen)
        {
            byte[] byData = new byte[dwReturnLen];

            int nRet = DinamoApi.DGetRandom(m_ctx, byData, dwReturnLen);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DGetRandom");

            return byData;
        }

        /** @} End of criptografia grouping*/

        /**
        \addtogroup eft

        @{ */


        /// <summary>
        /// Gera o nome da BDK a partir de uma KSI (Key Serial Identification).
        /// </summary>
        /// <param name="pbKSI">Buffer de tamanho MIN_KSI_LEN contendo o KSI. </param>
        /// <returns>O nome de chave BDK gerada a partir do KSI informado em pbKSI.</returns>
        public string GenBDKName(byte[] pbKSI)
        {
            return GenBDKName(pbKSI, 0);
        }

        /// <summary>
        /// Gera o nome da BDK a partir de uma KSI (Key Serial Identification).
        /// </summary>
        /// <param name="pbKSI">Buffer de tamanho MIN_KSI_LEN contendo o KSI. </param>
        /// <param name="dwParam">Reservado para uso futuro.</param>
        /// <returns>O nome de chave BDK gerada a partir do KSI informado em pbKSI.</returns>
        public string GenBDKName(byte[] pbKSI, uint dwParam)
        {
            IntPtr ptrBDKName = Marshal.AllocHGlobal(DinamoApi.MAX_OBJ_ID_FQN_LEN);

            int nRet = DinamoApi.DGenerateBDKName(pbKSI, ptrBDKName, dwParam);
            if (nRet != DinamoApi.D_OK)
            {
                Marshal.FreeHGlobal(ptrBDKName);
                throw new DinamoException(nRet, "DGenerateBDKName");
            }

            string szBDKName = Marshal.PtrToStringAnsi(ptrBDKName);

            Marshal.FreeHGlobal(ptrBDKName);

            return szBDKName;
        }



        /// <summary>
        /// Gera o nome da BDK a partir de uma KSI (Key Serial Identification).
        /// </summary>
        /// <param name="pbKSI">Buffer de tamanho MIN_KSI_LEN contendo o KSI. </param>
        /// <param name="pbDID_CTR">Buffer de tamanho MIN_CTR_LEN contendo o DID e CTR (últimos 05 bytes do KSN). </param>
        /// <param name="dwParam">Flags de operação de acordo com a tabela abaixo.
        /// NEW_DUKPT_MODE_DUK : Gera uma chave DUK (Derived Unique Key) padrão de acordo com o manual ISO X9.24-1-2004.
        /// NEW_DUKPT_MODE_PEK : Gera uma chave PEK (PIN Encryption Key) de acordo com o manual ISO X9.24-1-2004 A aplicando o XOR da máscara 0000 0000 0000 FF00 nas partes da chave.
        /// NEW_DUKPT_MODE_MEK : Gera uma chave MEK (MAC Encryption Key) de acordo com o manual ISO X9.24-1-2004 A aplicando o XOR da máscara 0000 0000 0000 00FF nas partes da chave.
        /// NEW_DUKPT_MODE_DE : Diversifica a chave gerada no formato Data Encryption. Aplica um XOR da máscara 0000 0000 00FF 0000 0000 0000 00FF 0000 sobre a chave DUKPT gerada, encripta a chave esquerda da DUKPT utilizando a DUKPT gerada e repete a encriptação com a chave direita. Após esta operação junta as partes esquerda e direita encriptadas para formar a Data Encryption Key. Como descrito em IDTECH USER MANUAL SecureMag Encrypted MagStripe Reader (80096504-001 RevL 06/19/14).<br> Deve ser utilizada combinada (via operação OR) com uma das flags: NEW_DUKPT_MODE_DUK, NEW_DUKPT_MODE_PEK ou NEW_DUKPT_MODE_MEK
        /// NEW_DUKPT_MODE_EXP : Gera uma chave DUKPT exportável. Esta é uma flag de atributo e deve ser utilizada combinada com outras flags. Utilizar apenas se especificamente necessário.
        /// NEW_DUKPT_MODE_TMP : Gera uma chave DUKPT temporária. Esta é uma flag de atributo e deve ser utilizada combinada com outras flags.
        /// NEW_DUKPT_MODE_IPEK : Gera uma chave IPEK (Initially Loaded PIN Entry Device Key) de acordo com o manual ISO X9.24-1-2004 A-6.</param>
        /// <returns>O nome de chave BDK gerada a partir do KSI informado em pbKSI.</returns>
        public string GenDUKPT(byte[] pbKSI, byte[] pbDID_CTR, uint dwParam)
        {
            IntPtr ptrDUKPTName = Marshal.AllocHGlobal(DinamoApi.MAX_OBJ_ID_FQN_LEN);

            int nRet = DinamoApi.DGenerateDUKPT(m_ctx, pbKSI, pbDID_CTR, ptrDUKPTName, dwParam);
            if (nRet != DinamoApi.D_OK)
            {
                Marshal.FreeHGlobal(ptrDUKPTName);
                throw new DinamoException(nRet, "DGenerateDUKPT");
            }

            string szDUKPTName = Marshal.PtrToStringAnsi(ptrDUKPTName);

            Marshal.FreeHGlobal(ptrDUKPTName);

            return szDUKPTName;
        }

        /** @} End of eft grouping*/

        /**
        \addtogroup pkcs7

        @{ */

        /// <summary>
        /// Gera uma assinatura ou co-assinatura seguindo o padrão PKCS#7 (Cryptographic Message Syntax Standard).
        /// </summary>
        /// <param name="KeyId">Nome da chave dentro do HSM que será utilizada para fazer a assinatura. </param>
        /// <param name="CertId">Nome do certificado (correspondente a chave szKeyName) dentro do HSM que será utilizado na assinatura.</param>
        /// <param name="CertChainId">	Nome da cadeia de certificados (PKCS#7) ou certificado X.509 da Autoridade Certificadora (correspondente a chave szKeyName) dentro do HSM que será utilizada na assinatura.</param>
        /// <param name="mode">Modo para a assinatura gerada</param>
        /// <param name="content">Conteúdo dos dados que serão assinados</param>
        /// <returns>Retorno da função de acordo com a seleção do modo de assinatura.</returns>
        public byte[] SignPKCS7(string KeyId, string CertId, string CertChainId, P7_MODE mode, byte[] content)
        {
            IntPtr ptrSignature;
            Int32 cbSignature;
            int ret = 0;

            byte[] bySignature = null;

            ret = DinamoApi.DPKCS7Sign(m_ctx, KeyId, CertId, CertChainId, (UInt32)mode, content, content.Length, out cbSignature, out ptrSignature, 0);
            if (ret == DinamoApi.D_OK)
            {
                bySignature = new byte[cbSignature];

                Marshal.Copy(ptrSignature, bySignature, 0, cbSignature);

                DinamoApi.DFree(ptrSignature);
            }
            else
                throw new DinamoException(ret, "DPKCS7Sign");

            return bySignature;
        }
        /** @} End of pkcs7 grouping*/


        /**
         \addtogroup xml

         @{ */


        /// <summary>
        /// Assina digitalmente um documento XML usando os padrões de assinatura digital XML do W3C.
        /// Recebe os parâmetros no formato <i>string</i>.
        ///
        /// <seealso cref="SignXML(string KeyId, HASH_ALG AlgId, string CertId, byte[] byUnsignedXml, byte[] byFilter)"/>
        /// </summary>
        /// <param name="KeyId">Identificador interno ao HSM referente a chave a ser utilizada para assinatura do documento XML.</param>
        /// <param name="AlgId">Algoritmo de hash utilizado. Veja: <see cref="HASH_ALG"/></param>
        /// <param name="CertId">Identificador interno ao HSM referente ao certificado digital a ser utilizado para assinatura do documento XML.</param>
        /// <param name="UnsignedXml">Parâmetro contendo o XML a ser assinado.</param>
        /// <param name="Filter">Filtro para assinatura digital de partes do documento XML. A utilização de filtro é opcional.
        /// Veja \ref FiltroXML.</param>
        /// <returns>Array de bytes contendo o documento XML original assinado digitalmente no formato especificado.</returns>
        /// <exception cref="DinamoException">Lança exceção no caso de erros na assinatura</exception>
        public byte[] SignXML(string KeyId, HASH_ALG AlgId, string CertId, string UnsignedXml, string Filter)
        {
            ASCIIEncoding encoding = new ASCIIEncoding();
            byte[] byUnsignedXml = encoding.GetBytes(UnsignedXml);
            byte[] byFilter = encoding.GetBytes(Filter);

            return SignXML(KeyId, AlgId, CertId, byUnsignedXml, byFilter);
        }

        /// <summary>
        /// Assina digitalmente um documento XML usando os padrões de assinatura digital XML do W3C.
        /// Recebe os parâmetros no formato de byte array.
        /// </summary>
        /// <param name="KeyId">Identificador interno ao HSM referente a chave a ser utilizada para assinatura do documento XML.</param>
        /// <param name="AlgId">Algoritmo de hash utilizado. Veja: <see cref="HASH_ALG"/></param>
        /// <param name="CertId">Identificador interno ao HSM referente ao certificado digital a ser utilizado para assinatura do documento XML.</param>
        /// <param name="byUnsignedXml">Parâmetro contendo o XML a ser assinado.(*)</param>
        /// <param name="byFilter">Filtro para assinatura digital de partes do documento XML. A utilização de filtro é opcional.
        /// Veja \ref FiltroXML.</param>
        /// <returns>Array de bytes contendo o documento XML original assinado digitalmente no formato especificado.</returns>
        /// <exception cref="DinamoException">Lança exceção no caso de erros na assinatura</exception>
        ///
        /// <remarks>
        /// O documento XML original, indicado por \p byUnsignedXml, poderá ser compactado de acordo com o padrão gzip descrito nas RFCs 1950 (zlib format),
        /// 1951 (deflate format) e 1952 (gzip format). O reconhecimento da compactação é automático pelo HSM.
        /// Caso o documento XML original esteja compactado, o documento XML assinado retornado também estará compactado pelo mesmo padrão gzip.
        /// As operações de descompactação, assinatura e compactação são independentes no HSM, caso ocorra um erro interno após a assinatura do XML
        /// e não seja possível devolver o documento XML assinado compactado, será retornado o documento XML assinado em texto claro (sem compactação).
        /// Embora um erro interno desta natureza seja bastante improvável, a aplicação precisa estar preparada para tratá-lo.<br/>
        /// A compactação do documento XML não necessariamente traz um ganho de desempenho nas operações de assinatura.
        /// O ganho principal pode vir de uma redução sensível no uso de banda da rede.
        /// As circunstancias específicas de cada ambiente devem ser analisadas para a adoção da compactação do documento XML.
        /// </remarks>
        public byte[] SignXML(string KeyId, HASH_ALG AlgId, string CertId, byte[] byUnsignedXml, byte[] byFilter)
        {
            HASH_MODE bHashMode = 0;
            switch (AlgId)
            {
                case HASH_ALG.ALG_MD5:
                    bHashMode = HASH_MODE.ALG_MD5_InclC14N;
                    break;
                case HASH_ALG.ALG_SHA1:
                    bHashMode = HASH_MODE.ALG_SHA1_InclC14N;
                    break;
                case HASH_ALG.ALG_SHA2_256:
                    bHashMode = HASH_MODE.ALG_SHA256_InclC14N;
                    break;
                default:
                    throw new DinamoException(DinamoApi.D_INVALID_ALG_ID, "Invalid hash algorithm.");
            }

            return SignXML(bHashMode, 0, KeyId, CertId, byUnsignedXml, byFilter);
        }


        /// <summary>
        /// Assina digitalmente um documento XML usando os padrões de assinatura digital XML do W3C.
        /// Recebe os parâmetros no formato de byte array.
        /// </summary>
        /// <param name="HashMode">Algoritmo de hash e canonicalização utilizados. Veja: <see cref="HASH_MODE"/></param>
        /// <param name="Flags">Algoritmo de hash e canonicalização utilizados. Pode ser 0 ou DinamoApi.XML_SIGN_FLAGS_NOL.</param>
        /// <param name="KeyId">Identificador interno ao HSM referente a chave a ser utilizada para assinatura do documento XML.</param>
        /// <param name="CertId">Identificador interno ao HSM referente ao certificado digital a ser utilizado para assinatura do documento XML.</param>
        /// <param name="byUnsignedXml">Parâmetro contendo o XML a ser assinado.(*)</param>
        /// <param name="byFilter">Filtro para assinatura digital de partes do documento XML. A utilização de filtro é opcional.
        /// Veja \ref FiltroXML.</param>
        /// <returns>Array de bytes contendo o documento XML original assinado digitalmente no formato especificado.</returns>
        /// <exception cref="DinamoException">Lança exceção no caso de erros na assinatura</exception>
        ///
        /// <remarks>
        /// O documento XML original, indicado por \p byUnsignedXml, poderá ser compactado de acordo com o padrão gzip descrito nas RFCs 1950 (zlib format),
        /// 1951 (deflate format) e 1952 (gzip format). O reconhecimento da compactação é automático pelo HSM.
        /// Caso o documento XML original esteja compactado, o documento XML assinado retornado também estará compactado pelo mesmo padrão gzip.
        /// As operações de descompactação, assinatura e compactação são independentes no HSM, caso ocorra um erro interno após a assinatura do XML
        /// e não seja possível devolver o documento XML assinado compactado, será retornado o documento XML assinado em texto claro (sem compactação).
        /// Embora um erro interno desta natureza seja bastante improvável, a aplicação precisa estar preparada para tratá-lo.<br/>
        /// A compactação do documento XML não necessariamente traz um ganho de desempenho nas operações de assinatura.
        /// O ganho principal pode vir de uma redução sensível no uso de banda da rede.
        /// As circunstancias específicas de cada ambiente devem ser analisadas para a adoção da compactação do documento XML.
        /// </remarks>
        public byte[] SignXML(HASH_MODE HashMode,
                                Int32 Flags,
                                string KeyId,
                                string CertId,
                                byte[] byUnsignedXml,
                                byte[] byFilter)
        {
            Int32 ret = 0;
            byte[] bySignedXml = null;

            IntPtr ptrSignedXml;
            Int32 cbSignedXml;

            ret = DinamoApi.DSignXml2(m_ctx,
                                    (byte)HashMode,
                                    Flags,
                                    KeyId,
                                    CertId,
                                    byUnsignedXml.Length,
                                    byUnsignedXml,
                                    byFilter.Length,
                                    byFilter,
                                    out cbSignedXml,
                                    out ptrSignedXml);
            if (ret == DinamoApi.D_OK)
            {
                bySignedXml = new byte[cbSignedXml];
                Marshal.Copy(ptrSignedXml, bySignedXml, 0, cbSignedXml);
                DinamoApi.DFree(ptrSignedXml);
            }
            else
            {
                throw new DinamoException(ret, "DSignXml");
            }

            return bySignedXml;
        }

        /// <summary>
        /// Verifica a assinatura de um documento XML assinado digitalmente.
        /// Recebe os parâmetros no formato <i>string</i>.
        /// </summary>
        /// <param name="CertId">Identificador interno ao HSM referente a cadeia PKCS#7 – armazenada internamento no HSM - do certificado utilizado na assinatura do documento XML</param>
        /// <param name="SignedXml">XML assinado digitalmente.</param>
        /// <param name="Filter">Filtro para checagem da assinatura digital de partes do documento XML. A utilização de filtro é opcional.
        /// Consulte observações para maiores informações sobre filtros.</param>
        /// <returns>Verdadeiro se a checagem for efetuada com sucesso.</returns>
        public bool VerifySignedXML(string CertId, string SignedXml, string Filter)
        {
            ASCIIEncoding encoding = new ASCIIEncoding();
            byte[] bySignedXml = encoding.GetBytes(SignedXml);
            byte[] byFilter = encoding.GetBytes(Filter);

            return VerifySignedXML(CertId, bySignedXml, byFilter);
        }

        /// <summary>
        /// verifica a assinatura de um documento XML assinado digitalmente.
        /// Recebe os parâmetros no formato <i>byte array</i>.
        /// </summary>
        /// <param name="CertId">Identificador interno ao HSM referente a cadeia PKCS#7 – armazenada internamento no HSM - do certificado utilizado na assinatura do documento XML</param>
        /// <param name="bySignedXml">XML assinado digitalmente</param>
        /// <param name="byFilter">Filtro para checagem da assinatura digital de partes do documento XML. A utilização de filtro é opcional.
        /// Consulte observações para maiores informações sobre filtros.</param>
        /// <returns>Verdadeiro se a checagem for efetuada com sucesso.</returns>
        public bool VerifySignedXML(string CertId, byte[] bySignedXml, byte[] byFilter)
        {
            Int32 ret = 0;

            ret = DinamoApi.DVerifySignedXml(m_ctx, CertId, bySignedXml.Length, bySignedXml, byFilter.Length, byFilter);

            return (ret == DinamoApi.D_OK); //TODO Fazer o tratamento de erro de outro retorno que não o erro de validacao XML
        }


        /** @} End of xml grouping*/


        /**
         \addtogroup pix

         @{ */

        /// <summary>
        /// Assina digitalmente um XML no formato ISO 20.022 seguindo o padrão PIX definido no SPI (Sistema de Pagamentos Instantâneos).
        /// </summary>
        /// <param name="KeyId">Nome da chave privada utilizada para assinatura.</param>
        /// <param name="CertId">Nome do certificado digital utilizado para assinatura do documento XML.</param>
        /// <param name="byUnsignedPIXEnvelope">Parâmetro contendo o XML a ser assinado.</param>
        /// <returns>O documento XML assinado.</returns>
        /// <exception cref="DinamoException">Lança exceção no caso de erros na assinatura</exception>
        /// 
        /// <remarks>
        /// Recomendamos utilizar a tag de assinatura utilizando o fechamento completo, como visto abaixo, por motivos de performance.
        ///     <code><Sgntr></Sgntr></code>
        ///   A tag com fechamento simples também é aceita, ver abaixo.
        ///     <code><Sgntr/></code>
        /// </remarks>

        public byte[] SignPIX(string KeyId, string CertId, byte[] byUnsignedPIXEnvelope)
        {
            Int32 ret = 0;
            byte[] bySignedXml = null;

            IntPtr ptrSignedXml;
            Int32 cbSignedXml;

            ret = DinamoApi.DPIXSign(m_ctx,
                                    KeyId,
                                    CertId,
                                    byUnsignedPIXEnvelope.Length,
                                    byUnsignedPIXEnvelope,
                                    out cbSignedXml,
                                    out ptrSignedXml);

            if (ret == DinamoApi.D_OK)
            {
                bySignedXml = new byte[cbSignedXml];

                Marshal.Copy(ptrSignedXml, bySignedXml, 0, cbSignedXml);

                DinamoApi.DFree(ptrSignedXml);
            }


            return bySignedXml;
        }

        /// <summary>
        /// Verifica a assinatura de um documento XML assinado digitalmente no formato ISO 20.022 seguindo o padrão PIX definido no SPI (Sistema de Pagamentos Instantâneos).
        /// </summary>
        /// <param name="ChainId">Nome da cadeia PKCS#7 – armazenada internamente no HSM - do certificado utilizado na assinatura do documento XML. A cadeia deverá ser completa contendo da AC raiz até o próprio certificado utilizado na assinatura.</param>
        /// <param name="CRL">Nome da Lista de Certificados Revogados (CRL) onde o certificado digital será verificado. É possível passar NULL indicando que não há uma CRL para verificação.</param>
        /// <param name="SignedPIXEnvelope">XML assinado digitalmente</param>
        /// <returns>Verdadeiro se a checagem for efetuada com sucesso.</returns>
        public bool VerifyPIX(string ChainId, string CRL, string SignedPIXEnvelope)
        {
            ASCIIEncoding encoding = new ASCIIEncoding();
            byte[] bySignedXml = encoding.GetBytes(SignedPIXEnvelope);

            return VerifyPIX(ChainId, CRL, bySignedXml);
        }

        /// <summary>
        /// Verifica a assinatura de um documento XML assinado digitalmente no formato ISO 20.022 seguindo o padrão PIX definido no SPI (Sistema de Pagamentos Instantâneos).
        /// </summary>
        /// <param name="ChainId">Nome da cadeia PKCS#7 – armazenada internamente no HSM - do certificado utilizado na assinatura do documento XML. A cadeia deverá ser completa contendo da AC raiz até o próprio certificado utilizado na assinatura.</param>
        /// <param name="CRL">Nome da Lista de Certificados Revogados (CRL) onde o certificado digital será verificado. É possível passar NULL indicando que não há uma CRL para verificação.</param>
        /// <param name="SignedPIXEnvelope">XML assinado digitalmente</param>
        /// <returns>Verdadeiro se a checagem for efetuada com sucesso.</returns>
        public bool VerifyPIX(string ChainId, string CRL, byte[] SignedPIXEnvelope)
        {
            Int32 ret = 0;

            ret = DinamoApi.DPIXVerify(m_ctx,
                                        ChainId,
                                        CRL,
                                        SignedPIXEnvelope.Length,
                                        SignedPIXEnvelope);

            if (ret == DinamoApi.D_ERR_INVALID_XML_SIGNATURE)
            {
                return false;
            }

            if (ret != 0)
            {
                throw new DinamoException(ret, "DPIXVerify");
            }

            return true;
        }

        /// <summary>
        /// Faz uma assinatura JWS [RFC 7515](https://tools.ietf.org/html/rfc7515) seguindo o padrão PIX definido no SPI (Sistema de Pagamentos Instantâneos).
        /// </summary>
        /// <param name="KeyId">Nome da chave privada utilizada para assinatura.</param>
        /// <param name="byHeader">Buffer contendo o Header JWS para assinatura.</param>
        /// <param name="byPayload">Buffer contendo o Payload JWS para assinatura.</param>
        /// <returns>A assinatura JWS.</returns>
        /// <exception cref="DinamoException">Lança exceção no caso de erros na assinatura</exception>
        /// 
        /// <remarks>
        /// Utiliza o formato _Compact Serialization_ descrito na Section-3.1 da [RFC 7515](https://tools.ietf.org/html/rfc7515#section-3.1).
        /// </remarks>
        public byte[] SignPIXJWS(string KeyId, byte[] byHeader, byte[] byPayload)
        {
            Int32 ret = 0;
            Int32 cbSignedJWS = 0;

            ret = DinamoApi.DPIXJWSSign(m_ctx,
                                        KeyId,
                                        0,
                                        byHeader.Length,
                                        byHeader,
                                        byPayload.Length,
                                        byPayload,
                                        out cbSignedJWS,
                                        null);
            if (ret != 0)
            {
                throw new DinamoException(ret, "DPIXJWSSign");
            }

            byte[] bySignedJWS = new byte[cbSignedJWS];
            ret = DinamoApi.DPIXJWSSign(m_ctx,
                                        KeyId,
                                        0,
                                        byHeader.Length,
                                        byHeader,
                                        byPayload.Length,
                                        byPayload,
                                        out cbSignedJWS,
                                        bySignedJWS);

            if (ret != 0)
            {
                throw new DinamoException(ret, "DPIXJWSSign");
            }

            Array.Resize(ref bySignedJWS, cbSignedJWS);

            return bySignedJWS;
        }

        /// <summary>
        /// Valida uma assinatura JWS [RFC 7515](https://tools.ietf.org/html/rfc7515) seguindo o padrão PIX definido no SPI (Sistema de Pagamentos Instantâneos).
        /// </summary>
        /// <param name="Chain">Nome da cadeia PKCS#7 – armazenada internamente no HSM - do certificado utilizado na assinatura do documento XML. A cadeia deverá ser completa contendo da AC raiz até o próprio certificado utilizado na assinatura.</param>
        /// <param name="CRL">Nome da Lista de Certificados Revogados (CRL) onde o certificado digital será verificado. É possível passar NULL indicando que não há uma CRL para verificação.</param>
        /// <param name="byJWS">Assinatura JWS.</param>
        /// <param name="flags">Opções de verificação. Deverá ser 0.</param>
        /// <returns>Classe JwsComponents que conterá o código de retorno, o Header e o Payload da mensagem assinada.</returns>
        public JwsComponents CheckPIXJWS(string Chain, string CRL, byte[] byJWS, Int32 flags)
        {
            Int32 ret = 0;
            Int32 cbHeaderLen = 0;
            Int32 cbPayloadLen = 0;
            ret = DinamoApi.DPIXJWSCheck(m_ctx,
                                        Chain,
                                        CRL,
                                        byJWS.Length,
                                        byJWS,
                                        flags,
                                        out cbHeaderLen,
                                        null,
                                        out cbPayloadLen,
                                        null);
            if (ret != 0)
            {
                throw new DinamoException(ret, "DPIXJWSCheck");
            }

            byte[] byHeader = new byte[cbHeaderLen];
            byte[] byPayload = new byte[cbPayloadLen];
            ret = DinamoApi.DPIXJWSCheck(m_ctx,
                                        Chain,
                                        CRL,
                                        byJWS.Length,
                                        byJWS,
                                        flags,
                                        out cbHeaderLen,
                                        byHeader,
                                        out cbPayloadLen,
                                        byPayload);
            if (ret == DinamoApi.D_ERR_INVALID_SIGNATURE)
            {
                return null;
            }

            Array.Resize(ref byHeader, cbHeaderLen);
            Array.Resize(ref byPayload, cbPayloadLen);

            return new JwsComponents(byHeader, byPayload, ret);

        }

        /// <summary>
        /// Valida uma assinatura JWS [RFC 7515](https://tools.ietf.org/html/rfc7515) seguindo o padrão PIX definido no SPI (Sistema de Pagamentos Instantâneos).
        /// </summary>
        /// <param name="Chain">Nome da cadeia PKCS#7 – armazenada internamente no HSM - do certificado utilizado na assinatura do documento XML. A cadeia deverá ser completa contendo da AC raiz até o próprio certificado utilizado na assinatura.</param>
        /// <param name="CRL">Nome da Lista de Certificados Revogados (CRL) onde o certificado digital será verificado. É possível passar NULL indicando que não há uma CRL para verificação.</param>
        /// <param name="byJWS">Assinatura JWS.</param>
        /// <returns>Verdadeiro se a checagem for efetuada com sucesso.</returns>
        public bool CheckPIXJWS(string Chain, string CRL, byte[] byJWS)
        {
            JwsComponents jwsComponents = CheckPIXJWS(Chain, CRL, byJWS, 0);

            if (jwsComponents.ReturnCode == DinamoApi.D_ERR_INVALID_SIGNATURE)
            {
                return false;
            }

            if (jwsComponents.ReturnCode != 0)
            {
                throw new DinamoException(jwsComponents.ReturnCode, "CheckPIXJWS");
            }

            return true;
        }

        private PIXResponse GenPIXResponseData(IntPtr Header,
                                                Int32 HeaderLen,
                                                IntPtr Body,
                                                Int32 BodyLen)
        {

            byte[] pbHeader = new byte[HeaderLen];
            if (HeaderLen > 0)
            {
                Marshal.Copy(Header, pbHeader, 0, HeaderLen);
                DinamoApi.DFree(Header);
            }

            byte[] pbBody = new byte[BodyLen];
            if (BodyLen > 0)
            {
                Marshal.Copy(Body, pbBody, 0, BodyLen);
                DinamoApi.DFree(Body);
            }

            return new PIXResponse(pbHeader, pbBody);
        }


        /// <summary>
        /// Faz uma requisição segura HTTP POST seguindo o padrão PIX definido no SPI (Sistema de Pagamentos Instantâneos).
        /// </summary>
        /// <param name="KeyId">Nome da chave privada utilizada para fechamento do túnel.</param>
        /// <param name="CertChainId">Nome do certificado X.509 relativo à chave privada.</param>
        /// <param name="PIXCertChainId">Nome da cadeia PKCS#7 utilizada para verificar o servidor PIX.</param>
        /// <param name="URL">URL do servidor PIX.</param>
        /// <param name="RequestHeaderList">Linhas contendo os headers HTTP customizados que serão utilizados na requisição. Pode ser passado null caso queira utilizar o header padrão sem alterações.<br>
        ///Essa opção irá sobrescrever os headers padrão, caso haja sobreposição.<br>
        ///Para remover um header, passar o nome do header sem valor(Ex. "Accept:").<br>
        ///Para incluir um header, sem conteúdo utilizar ';' ao invés de ':' (Ex. "Accept;").<br>
        ///NÃO utilizar terminadores "CRLF" nos headers.A passagem desses terminadores poderá causar comportamentos indesejados.A formatação será feita internamente.<br>
        ///Esta opção não pode ser utilizada para alterar a primeira linha da requisição (Ex.POST, GET, DELETE), que não é um header.Deve-se utilizar a API correspondente, descrita neste manual.<br></param>
        /// <param name="RequestData">Dados enviados na requisição.</param>
        /// <param name="TimeOut">Tempo de timeout da operação em milisegundos. Pode ser passado 0 para não ter tempo de timeout.</param>
        /// <param name="Param">
        /// Valor|Significado
        ///    :----|:----------
        ///    0| Opção padrão para certificados SPB.Não verifica o certificado com o nome do host.
        ///    DinamoApi.PIX_VERIFY_HOST_NAME| Verifica certificado com o nome do host. Não utilizar esta opção para certificados SPB.</param></param>
        /// <returns>A resposta da requisição.</returns>
        /// <exception cref="DinamoException">Lança exceção no caso de erros na requisição</exception>
        /// 
        /// <remarks>
        /// \pixRequestRemarks
        /// </remarks>
        /// 
        public PIXResponse postPIX(string KeyId,
                                    string CertChainId,
                                    string PIXCertChainId,
                                    string URL,
                                    string[] RequestHeaderList,
                                    byte[] RequestData,
                                    Int32 TimeOut,
                                    Int32 Param)
        {
            Int32 ret = 0;
            Int32 nHeaderLen = 0;
            Int32 nBodyLen = 0;
            IntPtr pHeader = IntPtr.Zero;
            IntPtr pBody = IntPtr.Zero;
            string[] reqHeader = null;
            int reqHeaderLen = 0;


            if (RequestHeaderList != null)
            {
                reqHeader = RequestHeaderList;
                reqHeaderLen = RequestHeaderList.Length;
            }

            ret = DinamoApi.DPIXPost(m_ctx,
                                        KeyId,
                                        CertChainId,
                                        PIXCertChainId,
                                        URL,
                                        reqHeaderLen,
                                        reqHeader,
                                        RequestData.Length,
                                        RequestData,
                                        TimeOut,
                                        out nHeaderLen,
                                        out pHeader,
                                        out nBodyLen,
                                        out pBody,
                                        Param);
            if (ret != 0)
            {
                throw new DinamoException(ret, "DPIXPost");
            }

            return GenPIXResponseData(pHeader, nHeaderLen, pBody, nBodyLen);

        }

        /// <summary>
        /// Faz uma requisição segura HTTP GET seguindo o padrão PIX definido no SPI (Sistema de Pagamentos Instantâneos).
        /// </summary>
        /// <param name="KeyId">Nome da chave privada utilizada para fechamento do túnel.</param>
        /// <param name="CertChainId">Nome do certificado X.509 relativo à chave privada.</param>
        /// <param name="PIXCertChainId">Nome da cadeia PKCS#7 utilizada para verificar o servidor PIX.</param>
        /// <param name="URL">URL do servidor PIX.</param>
        /// <param name="RequestHeaderList">Linhas contendo os headers HTTP customizados que serão utilizados na requisição. Pode ser passado null caso queira utilizar o header padrão sem alterações.<br>
        ///Essa opção irá sobrescrever os headers padrão, caso haja sobreposição.<br>
        ///Para remover um header, passar o nome do header sem valor(Ex. "Accept:").<br>
        ///Para incluir um header, sem conteúdo utilizar ';' ao invés de ':' (Ex. "Accept;").<br>
        ///NÃO utilizar terminadores "CRLF" nos headers.A passagem desses terminadores poderá causar comportamentos indesejados.A formatação será feita internamente.<br>
        ///Esta opção não pode ser utilizada para alterar a primeira linha da requisição (Ex.POST, GET, DELETE), que não é um header.Deve-se utilizar a API correspondente, descrita neste manual.<br></param>
        /// <param name="TimeOut">Tempo de timeout da operação em milisegundos. Pode ser passado 0 para não ter tempo de timeout.</param>
        /// <param name="Param">
        /// Valor|Significado
        ///    :----|:----------
        ///    0| Opção padrão para certificados SPB.Não verifica o certificado com o nome do host.
        ///    DinamoApi.PIX_VERIFY_HOST_NAME| Verifica certificado com o nome do host. Não utilizar esta opção para certificados SPB.</param></param>
        /// <returns>A resposta da requisição.</returns>
        /// <exception cref="DinamoException">Lança exceção no caso de erros na requisição</exception>
        /// 
        /// <remarks>
        /// \pixRequestRemarks
        /// </remarks>
        /// 
        public PIXResponse getPIX(string KeyId,
                                    string CertChainId,
                                    string PIXCertChainId,
                                    string URL,
                                    string[] RequestHeaderList,
                                    Int32 TimeOut,
                                    Int32 Param)
        {
            Int32 ret = 0;
            Int32 nHeaderLen = 0;
            Int32 nBodyLen = 0;
            IntPtr pHeader = IntPtr.Zero;
            IntPtr pBody = IntPtr.Zero;
            string[] reqHeader = null;
            int reqHeaderLen = 0;


            if (RequestHeaderList != null)
            {
                reqHeader = RequestHeaderList;
                reqHeaderLen = RequestHeaderList.Length;
            }

            ret = DinamoApi.DPIXGet(m_ctx,
                                    KeyId,
                                    CertChainId,
                                    PIXCertChainId,
                                    URL,
                                    reqHeaderLen,
                                    reqHeader,
                                    TimeOut,
                                    out nHeaderLen,
                                    out pHeader,
                                    out nBodyLen,
                                    out pBody,
                                    Param);
            if (ret != 0)
            {
                throw new DinamoException(ret, "DPIXGet");
            }

            return GenPIXResponseData(pHeader, nHeaderLen, pBody, nBodyLen);

        }

        /// <summary>
        /// Faz uma requisição segura HTTP DELETE seguindo o padrão PIX definido no SPI (Sistema de Pagamentos Instantâneos).
        /// </summary>
        /// <param name="KeyId">Nome da chave privada utilizada para fechamento do túnel.</param>
        /// <param name="CertChainId">Nome do certificado X.509 relativo à chave privada.</param>
        /// <param name="PIXCertChainId">Nome da cadeia PKCS#7 utilizada para verificar o servidor PIX.</param>
        /// <param name="URL">URL do servidor PIX.</param>
        /// <param name="RequestHeaderList">Linhas contendo os headers HTTP customizados que serão utilizados na requisição. Pode ser passado null caso queira utilizar o header padrão sem alterações.<br>
        ///Essa opção irá sobrescrever os headers padrão, caso haja sobreposição.<br>
        ///Para remover um header, passar o nome do header sem valor(Ex. "Accept:").<br>
        ///Para incluir um header, sem conteúdo utilizar ';' ao invés de ':' (Ex. "Accept;").<br>
        ///NÃO utilizar terminadores "CRLF" nos headers.A passagem desses terminadores poderá causar comportamentos indesejados.A formatação será feita internamente.<br>
        ///Esta opção não pode ser utilizada para alterar a primeira linha da requisição (Ex.POST, GET, DELETE), que não é um header.Deve-se utilizar a API correspondente, descrita neste manual.<br></param>
        /// <param name="TimeOut">Tempo de timeout da operação em milisegundos. Pode ser passado 0 para não ter tempo de timeout.</param>
        /// <param name="Param">
        ///   Valor|Significado
        ///    :----|:----------
        ///    0| Opção padrão para certificados SPB.Não verifica o certificado com o nome do host.
        ///    DinamoApi.PIX_VERIFY_HOST_NAME| Verifica certificado com o nome do host. Não utilizar esta opção para certificados SPB.</param>
        /// <returns>A resposta da requisição.</returns>
        /// <exception cref="DinamoException">Lança exceção no caso de erros na requisição</exception>
        /// 
        /// <remarks>
        /// \pixRequestRemarks
        /// </remarks>
        /// 
        public PIXResponse deletePIX(string KeyId,
                                    string CertChainId,
                                    string PIXCertChainId,
                                    string URL,
                                    string[] RequestHeaderList,
                                    Int32 TimeOut,
                                    Int32 Param)
        {
            Int32 ret = 0;
            Int32 nHeaderLen = 0;
            Int32 nBodyLen = 0;
            IntPtr pHeader = IntPtr.Zero;
            IntPtr pBody = IntPtr.Zero;
            string[] reqHeader = null;
            int reqHeaderLen = 0;

            if (RequestHeaderList != null)
            {
                reqHeader = RequestHeaderList;
                reqHeaderLen = RequestHeaderList.Length;
            }

            ret = DinamoApi.DPIXDelete(m_ctx,
                                        KeyId,
                                        CertChainId,
                                        PIXCertChainId,
                                        URL,
                                        reqHeaderLen,
                                        reqHeader,
                                        TimeOut,
                                        out nHeaderLen,
                                        out pHeader,
                                        out nBodyLen,
                                        out pBody,
                                        Param);
            if (ret != 0)
            {
                throw new DinamoException(ret, "DPIXDelete");
            }

            return GenPIXResponseData(pHeader, nHeaderLen, pBody, nBodyLen);

        }

        /** @} End of pix grouping*/

        /**
        \addtogroup oath

        @{ */


        /// <summary>
        /// Check OTP value
        /// </summary>
        /// <param name="masterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/>.</param>
        /// <param name="otp">OTP a ser verificado de tamanho mínimo <see cref="DinamoApi.ISSUE_OATH_MIN_OTP_LEN"/> e máximo <see cref="DinamoApi.ISSUE_OATH_MAX_OTP_LEN"/>.</param>
        /// <param name="bBlob">Array de bytes contendo o blob que será utilizado para a geração do OTP.</param>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        /// <returns>>Verdadeiro se o OTP passado no parâmetro da função for válido.  Nesse caso, é importante a persistência do bBlob retornado para evitar ataques de REPLAY.</returns>
        public bool OATHCheck(string masterKeyId, string otp, byte[] bBlob)
        {
            return OATHCheck(masterKeyId, otp, bBlob, 0);
        }
        /// <summary>
        /// Check OTP value
        /// </summary>
        /// <param name="masterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/>.</param>
        /// <param name="otp">OTP a ser verificado de tamanho mínimo <see cref="DinamoApi.ISSUE_OATH_MIN_OTP_LEN"/> e máximo <see cref="DinamoApi.ISSUE_OATH_MAX_OTP_LEN"/>.</param>
        /// <param name="bBlob">Array de bytes contendo o blob que será utilizado para a geração do OTP.</param>
        /// <param name="dwFlag">A partir da versão 4.0.2 do firmware pode-se passar, neste parâmetro, 
        /// o tamanho da janela de look-ahead de autenticação. O padrão é de 10 intervalos para mais ou para menos. 
        /// No caso de tokens HOTP os intervalos 
        /// serão contados por quantidade de eventos, no caso dos tokens TOTP serão contados por quantidade de time-steps. 
        /// Valor | Significado
        /// ------|-----------
        /// 0  | Utiliza o valor default de 10 intervalos.
        /// <see cref="DinamoApi.MAX_OTP_LOOK_AHEAD_INTERVAL"/> |  Define o valor da janela de look-ahead de autenticação. 
        /// </param>
        /// <returns>Verdadeiro se o OTP passado no parâmetro da função for válido.  Nesse caso, é importante a persistência do bBlob retornado para evitar ataques de REPLAY.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public bool OATHCheck(string masterKeyId, string otp, byte[] bBlob, int dwFlag)
        {
            int ret = 0;
            int dwBlob = bBlob.Length;

            ret = DinamoApi.DOATHCheckOTP(m_ctx, masterKeyId, otp, bBlob, ref dwBlob, dwFlag);

            if (ret == DinamoApi.D_OATH_BLOB_UPDATE)
            {
                byte[] newBuffer = new byte[DinamoApi.ISSUE_OATH_OUTPUT_MAX_BLOB_LEN];
                Array.Copy(bBlob, 0, newBuffer, 0, dwBlob);
                dwBlob = newBuffer.Length;
                dwFlag = dwFlag | DinamoApi.OATH_UPDATE_BLOB;
                ret = DinamoApi.DOATHCheckOTP(m_ctx, masterKeyId, otp, newBuffer, ref dwBlob, dwFlag);
                if (ret == DinamoApi.D_OK)
                    bBlob = newBuffer;

            }

            return (ret == DinamoApi.D_OK && dwBlob > 0);
        }


        /// <summary>
        /// Re-sincroniza um blob OATH através da apresentação de dois valores de OTP contínuos.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/>.</param>
        /// <param name="szOTP1">Primeiro valor do OATH.</param>
        /// <param name="szOTP2">Segundo valor do OATH</param>
        /// <param name="bOATHBlob">Blob do OATH</param>
        /// <returns>Blob do OATH resincronizado, resultado da operação.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] OATHBlobResync(string szMasterKeyId, string szOTP1, string szOTP2, byte[] bOATHBlob)
        {
            int dwFlags = 0;
            Int32 dwOATHBlob = bOATHBlob.Length;

            int nRet = DinamoApi.DOATHBlobResync(m_ctx, szMasterKeyId, szOTP1, szOTP2, bOATHBlob, ref dwOATHBlob, dwFlags);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "OATHBlobResync");
            return bOATHBlob;
        }

        /// <summary>
        /// Recupera a semente da chave geradora do blob de OATH
        /// </summary>
        /// <param name="szMasterKey">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/>.</param>
        /// <param name="pbInBlob">Conteúdo do blob</param>
        /// <returns>Semente da chave na forma de array de bytes.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] OATHGetKey(string szMasterKey, byte[] pbInBlob)
        {
            Int32 dwParam = 0;
            Int32 dwInBlobLen = pbInBlob.Length;
            byte[] pbOutInfo = new byte[DinamoApi.ISSUE_OATH_OUTPUT_MAX_BLOB_LEN];
            Int32 pdwOutInfoLen = pbOutInfo.Length;

            int nRet = DinamoApi.DOATHGetBlobInfo(m_ctx,
                                                    szMasterKey,
                                                    pbInBlob,
                                                    dwInBlobLen,
                                                    DinamoApi.OATH_ISSUE_OATH_INFO_t,
                                                    pbOutInfo,
                                                    ref pdwOutInfoLen,
                                                    dwParam);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "OATHGetKey");

            IntPtr ptrOut = Marshal.AllocHGlobal(dwInBlobLen);
            Marshal.Copy(pbOutInfo, 0, ptrOut, pdwOutInfoLen);

            DinamoApi.ISSUE_OATH_INFO_t oath_blob = (DinamoApi.ISSUE_OATH_INFO_t)Marshal.PtrToStructure(ptrOut, typeof(DinamoApi.ISSUE_OATH_INFO_t));

            Marshal.FreeHGlobal(ptrOut);

            byte[] pOut = new byte[oath_blob.seed_len];
            Array.Copy(oath_blob.seed, pOut, pOut.Length);

            return pOut;
        }

        /// <summary>
        /// Importa sementes envelopadas no padrão PSKC (Portable Symmetric Key Container), RFC 6030.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/>.</param>
        /// <param name="szPSK">Chave de transporte que protege as sementes informadas em pbPSKC.</param>
        /// <param name="pbPSKC">Conteúdo do arquivo contendo as sementes que serão transformadas em blobs no formato do HSM</param>
        /// <returns>Array de estruturas <see cref="DinamoApi.OATH_PSKC_TRANSLATE_OUTPUT"/>. Esta estrutura conterá internamente os blobs das sementes
        /// traduzidas para o formato do HSM e o identificador de cada semente.</returns>
        /// <exception cref="DinamoException.DinamoException">Em caso de erro</exception>
        public DinamoApi.OATH_PSKC_TRANSLATE_OUTPUT[] OATHPskcTranslate(string szMasterKeyId, string szPSK, byte[] pbPSKC)
        {
            Int32 dwParam = 0;
            byte[] pbPSK = ASCIIEncoding.Default.GetBytes(szPSK);
            byte bPSKLen = (byte)pbPSK.Length;
            Int32 dwPSKCLen = pbPSKC.Length;

            IntPtr pvBlobList;

            Int32 pdwBlobListQuantity = 0;

            int nRet = DinamoApi.DOATHPskcTranslate(m_ctx, szMasterKeyId, pbPSK, bPSKLen, pbPSKC, dwPSKCLen, out pvBlobList, out pdwBlobListQuantity, dwParam);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "OATHPskcTranslate");

            var sizeInBytes = Marshal.SizeOf(typeof(DinamoApi.OATH_PSKC_TRANSLATE_OUTPUT));

            DinamoApi.OATH_PSKC_TRANSLATE_OUTPUT[] pstBlobList = new DinamoApi.OATH_PSKC_TRANSLATE_OUTPUT[pdwBlobListQuantity];

            for (int i = 0; i < pdwBlobListQuantity; i++)
            {
                IntPtr p = new IntPtr((pvBlobList.ToInt32() + i * sizeInBytes));

                pstBlobList[i] = (DinamoApi.OATH_PSKC_TRANSLATE_OUTPUT)Marshal.PtrToStructure(p, typeof(DinamoApi.OATH_PSKC_TRANSLATE_OUTPUT));

            }

            return pstBlobList;
        }
        /// <summary>
        ///  Gera um blob HOATH, ou seja, um token de evento. A semente será gerada de forma aleatória pelo HSM.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException.DinamoException">Em caso de erro</exception>
        /// <remarks>Esta função é utilizada quando é possível atribuir uma semente a um __soft token__. Será gerada uma semente com o tamanho de um SHA1</remarks>
        public byte[] OATHIssueGenerateHOTP(string szMasterKeyId)
        {
            return OATHIssueGenerateHOTP(szMasterKeyId, DinamoApi.ISSUE_OATH_SHA1_LEN);
        }
        /// <summary>
        /// Gera um blob HOATH, ou seja, um token de evento a partir de um tamanho de semente. 
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="seedLen">Semente no formato binário.</param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        /// <remarks>Esta função é utilizada quando a semente é fornecida por um dispositivo de software __soft token__ (por exemplo um app de celular) ou de hadware __hard_token__ (por exemplo um chaveiro gerador de sequencia)</remarks>
        public byte[] OATHIssueGenerateHOTP(string szMasterKeyId, byte seedLen)
        {
            DinamoApi.ISSUE_OTP_BLOB stIssueBlob = new DinamoApi.ISSUE_OTP_BLOB();

            stIssueBlob.bSeedLen = seedLen;
            stIssueBlob.bTruncationOffset = DinamoApi.ISSUE_OATH_DYN_TRUNC;
            return OATHIssueBlob(szMasterKeyId, OATH_TYPE.ISSUE_OATH_GENERATE_HOTP,
                                                      stIssueBlob);
        }
        /// <summary>
        ///  Immporta um blob HOATH, ou seja, um token de evento a partir de uma semente fornecida. 
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="bSeed">Semente no formato binário.</param>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        public byte[] OATHIssueImportHOTP(string szMasterKeyId, byte[] bSeed)
        {
            DinamoApi.ISSUE_OTP_BLOB stIssueBlob = new DinamoApi.ISSUE_OTP_BLOB();

            if (bSeed == null || bSeed.Length == 0)
            {
                return null;
            }

            stIssueBlob.bSeedLen = (byte)bSeed.Length;
            stIssueBlob.pbSeed = new byte[DinamoApi.MAX_OATH_HMAC_LEN];
            Array.Copy(bSeed, stIssueBlob.pbSeed, stIssueBlob.bSeedLen);
            stIssueBlob.bTruncationOffset = DinamoApi.ISSUE_OATH_DYN_TRUNC;
            stIssueBlob.otMovingFactor = 1;
            stIssueBlob.otT0 = DinamoApi.ISSUE_OATH_HOTP_T0;
            stIssueBlob.wTimeStep = DinamoApi.ISSUE_OATH_HOTP_TS;

            return OATHIssueBlob(szMasterKeyId, OATH_TYPE.ISSUE_OATH_IMPORT_HOTP, stIssueBlob);
        }
        /// <summary>
        /// Gera um blob TOTP, ou seja, um token de evento. A semente será gerada de forma aleatória pelo HSM.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException"> Em caso de erro</exception>
        /// <remarks>Esta função é utilizada quando é possível atribuir uma semente a um __soft token__</remarks>
        public byte[] OATHIssueGenerateTOTP(string szMasterKeyId)
        {
            return OATHIssueGenerateTOTP(szMasterKeyId, DinamoApi.ISSUE_OATH_DEFAULT_TIME_STEP, DinamoApi.ISSUE_OATH_HOTP_T0);
        }
        /// <summary>
        /// Gera um blob TOTP, ou seja, um token de evento. A semente será gerada de forma aleatória pelo HSM.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="step">Intevalo de tempo usado no cálculo, também conhecido como janela de tempo para mudança de valor.</param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] OATHIssueGenerateTOTP(string szMasterKeyId, short step)
        {
            return OATHIssueGenerateTOTP(szMasterKeyId, step, DinamoApi.ISSUE_OATH_HOTP_T0);
        }
        /// <summary>
        /// Gera um blob TOTP, ou seja, um token de evento. A semente será gerada de forma aleatória pelo HSM.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="step">Intevalo de tempo usado no cálculo, também conhecido como janela de tempo para mudança de valor.</param>
        /// <param name="offset">Atraso do relógio a ser considerado.</param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException"> Em caso de erro</exception>
        public byte[] OATHIssueGenerateTOTP(string szMasterKeyId, short step, ulong offset)
        {
            return OATHIssueGenerateTOTP(szMasterKeyId, step, offset, DinamoApi.ISSUE_OATH_SHA1_LEN);
        }
        /// <summary>
        /// Gera um blob TOTP, ou seja, um token de evento. A semente será gerada de forma aleatória pelo HSM.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="step">Intevalo de tempo usado no cálculo, também conhecido como janela de tempo para mudança de valor.</param>
        /// <param name="offset">Atraso do relógio a ser considerado.</param>
        /// <param name="seedLen">Tamanho da semente.</param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException"> Em caso de erro</exception>
        public byte[] OATHIssueGenerateTOTP(string szMasterKeyId, short step, ulong offset, byte seedLen)
        {
            DinamoApi.ISSUE_OTP_BLOB stIssueBlob = new DinamoApi.ISSUE_OTP_BLOB();

            stIssueBlob.bSeedLen = seedLen;
            stIssueBlob.wTimeStep = step;
            stIssueBlob.bTruncationOffset = DinamoApi.ISSUE_OATH_DYN_TRUNC;
            stIssueBlob.otT0 = offset;

            return OATHIssueBlob(szMasterKeyId, OATH_TYPE.ISSUE_OATH_GENERATE_TOTP,
                                                      stIssueBlob);
        }
        /// <summary>
        /// Immporta um blob TOTP, ou seja, um token de evento a partir de uma semente fornecida.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="bSeed">Semente no formato binário.</param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] OATHIssueImportTOTP(string szMasterKeyId, byte[] bSeed)
        {
            return OATHIssueImportTOTP(szMasterKeyId, bSeed, DinamoApi.ISSUE_OATH_DEFAULT_TIME_STEP, DinamoApi.ISSUE_OATH_HOTP_T0);
        }
        /// <summary>
        /// Immporta um blob TOTP, ou seja, um token de evento a partir de uma semente fornecida.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="bSeed">Semente no formato binário.</param>
        /// <param name="step">Intevalo de tempo usado no cálculo, também conhecido como janela de tempo para mudança de valor.</param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] OATHIssueImportTOTP(string szMasterKeyId, byte[] bSeed, short step)
        {
            return OATHIssueImportTOTP(szMasterKeyId, bSeed, step, DinamoApi.ISSUE_OATH_HOTP_T0);
        }
        /// <summary>
        /// Importa um blob TOTP, ou seja, um token de evento a partir de uma semente fornecida
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="bSeed">Semente no formato binário.</param>
        /// <param name="step">Intevalo de tempo usado no cálculo, também conhecido como janela de tempo para mudança de valor.</param>
        /// <param name="offset">Atraso do relógio a ser considerado.</param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] OATHIssueImportTOTP(string szMasterKeyId, byte[] bSeed, short step, ulong offset)
        {
            bool bUseDefaultMovingFactor = false; //TODO: Definir se iremos expor esse parametro.
            DinamoApi.ISSUE_OTP_BLOB stIssueBlob = new DinamoApi.ISSUE_OTP_BLOB();
            if (bSeed == null || bSeed.Length == 0)
            {
                return null;
            }

            stIssueBlob.bSeedLen = (byte)bSeed.Length;
            stIssueBlob.pbSeed = new byte[DinamoApi.MAX_OATH_HMAC_LEN];
            Array.Copy(bSeed, stIssueBlob.pbSeed, stIssueBlob.bSeedLen);

            stIssueBlob.wTimeStep = step;
            stIssueBlob.bTruncationOffset = DinamoApi.ISSUE_OATH_DYN_TRUNC;
            stIssueBlob.otT0 = offset;
            stIssueBlob.bUseDefaultMovingFactor = (byte)(bUseDefaultMovingFactor ? 1 : 0);
            stIssueBlob.otMovingFactor = 1;

            return OATHIssueBlob(szMasterKeyId, OATH_TYPE.ISSUE_OATH_IMPORT_TOTP,
                                                      stIssueBlob);
        }
        /// <summary>
        /// Gera ou immporta um blob.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="type">Tipo de OTP <see cref="Dinamo.Hsm.DinamoClient.OATH_TYPE"/</param>
        /// <param name="stIssueBlob"><see cref="DinamoApi.ISSUE_OTP_BLOB"/></param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException.DinamoException">Em caso de erro</exception>
        [System.Obsolete("Use OATHIssueBlob")]
        private byte[] OATHIssueHOTPBlob(string szMasterKeyId, OATH_TYPE type, DinamoApi.ISSUE_OTP_BLOB stIssueBlob)
        {
            Int32 dwFlags = 0;
            byte[] pbOTPBlob = new byte[DinamoApi.ISSUE_OATH_OUTPUT_MAX_BLOB_LEN];
            Int32 dwOTPBlobLen = pbOTPBlob.Length;

            Int32 dwParamBlobLen = Marshal.SizeOf(stIssueBlob);
            IntPtr pvParamBlob = Marshal.AllocHGlobal(dwParamBlobLen);

            Marshal.StructureToPtr(stIssueBlob, pvParamBlob, false);

            int nRet = DinamoApi.DOATHIssueHOTPBlob(m_ctx, szMasterKeyId, (Int32)type, pvParamBlob, dwParamBlobLen,
                pbOTPBlob, ref dwOTPBlobLen, dwFlags);

            Marshal.FreeHGlobal(pvParamBlob);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DOATHIssueHOTPBlob");

            byte[] bResult = new byte[dwOTPBlobLen];
            Array.Copy(pbOTPBlob, bResult, dwOTPBlobLen);

            return bResult;
        }

        /// <summary>
        /// Immporta um blob.
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="type">Tipo de OTP <see cref="Dinamo.Hsm.DinamoClient.OATH_TYPE"/></param>
        /// <param name="stIssueBlob"><see cref="DinamoApi.ISSUE_OTP_BLOB"/></param>
        /// <returns>Blob do OATH, resultado da operação.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        private byte[] OATHIssueBlob(string szMasterKeyId, OATH_TYPE type, DinamoApi.ISSUE_OTP_BLOB stIssueBlob)
        {
            Int32 dwFlags = 0;
            byte[] pbOTPBlob = new byte[DinamoApi.ISSUE_OATH_OUTPUT_MAX_BLOB_LEN];
            Int32 dwOTPBlobLen = pbOTPBlob.Length;

            Int32 dwParamBlobLen = Marshal.SizeOf(stIssueBlob);
            IntPtr pvParamBlob = Marshal.AllocHGlobal(dwParamBlobLen);

            Marshal.StructureToPtr(stIssueBlob, pvParamBlob, false);

            int nRet = DinamoApi.DOATHIssueBlob(m_ctx, szMasterKeyId, (UInt32)type, pvParamBlob, dwParamBlobLen,
                pbOTPBlob, ref dwOTPBlobLen, dwFlags);

            Marshal.FreeHGlobal(pvParamBlob);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DOATHIssueBlob");

            byte[] bResult = new byte[dwOTPBlobLen];
            Array.Copy(pbOTPBlob, bResult, dwOTPBlobLen);

            return bResult;
        }

        /// <summary>
        /// Função utilitária para codificar Base32.  Codificação padrão para geradores de OATH em sofware.
        /// 
        ///  Derived from https://github.com/google/google-authenticator-android/blob/master/AuthenticatorApp/src/main/java/com/google/android/apps/authenticator/Base32String.java
        /// </summary>
        /// <param name="data">Semente gerada</param>
        /// <returns>Dados codificados em BASE32.</returns>
        public string EncodeBase32(byte[] data)
        {
            char[] DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();
            int SHIFT = numberOfTrailingZeros(DIGITS.Length);
            int MASK = DIGITS.Length - 1;
            if (data.Length == 0)
            {
                return "";
            }

            // SHIFT is the number of bits per output character, so the length of the
            // output is the length of the input multiplied by 8/SHIFT, rounded up.
            if (data.Length >= (1 << 28))
            {
                // The computation below will fail, so don't do it.
                throw new ArgumentOutOfRangeException("data");
            }

            int outputLength = (data.Length * 8 + SHIFT - 1) / SHIFT;
            StringBuilder result = new StringBuilder(outputLength);

            int buffer = data[0];
            int next = 1;
            int bitsLeft = 8;
            while (bitsLeft > 0 || next < data.Length)
            {
                if (bitsLeft < SHIFT)
                {
                    if (next < data.Length)
                    {
                        buffer <<= 8;
                        buffer |= (data[next++] & 0xff);
                        bitsLeft += 8;
                    }
                    else
                    {
                        int pad = SHIFT - bitsLeft;
                        buffer <<= pad;
                        bitsLeft += pad;
                    }
                }
                int index = MASK & (buffer >> (bitsLeft - SHIFT));
                bitsLeft -= SHIFT;
                result.Append(DIGITS[index]);
            }

            return result.ToString();
        }

        private int numberOfTrailingZeros(int i)
        {
            // HD, Figure 5-14
            int y;
            if (i == 0) return 32;
            int n = 31;
            y = i << 16; if (y != 0) { n = n - 16; i = y; }
            y = i << 8; if (y != 0) { n = n - 8; i = y; }
            y = i << 4; if (y != 0) { n = n - 4; i = y; }
            y = i << 2; if (y != 0) { n = n - 2; i = y; }
            return n - (int)((uint)(i << 1) >> 31);
        }
        /// <summary>
        /// Recupera o próximo valor para o OTP
        /// </summary>
        /// <param name="szMasterKeyId">Nome da chave mestre, utilizada para proteger os blobs, de tamanho máximo <see cref="DinamoApi.MAX_OBJ_ID_FQN_LEN"/></param>
        /// <param name="lenOTP">Tamanho do OTP que será gerado, podendo ser um valor entre <see cref="DinamoApi.ISSUE_OATH_MIN_OTP_LEN"/> e <see cref="DinamoApi.ISSUE_OATH_MAX_OTP_LEN"/>.</param>
        /// <param name="bBlob">Array de bytes contendo o blob que será utilizado para a geração do OTP.</param>
        /// <returns>Valor do próximo token</returns>
        public string OATHGetNext(string szMasterKeyId, byte lenOTP, byte[] bBlob)
        {
            Int32 dwFlags = 0;
            IntPtr pOutObjName = Marshal.AllocHGlobal(DinamoApi.MAX_OBJ_ID_FQN_LEN + 1);
            Int32 dwBlobLen = bBlob.Length;

            int nRet = DinamoApi.DOATHGetNextOTP(m_ctx, szMasterKeyId, lenOTP, bBlob, dwBlobLen, pOutObjName, dwFlags);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DOATHIssueHOTPBlob");

            string szOTP = Marshal.PtrToStringAnsi(pOutObjName);
            Marshal.FreeHGlobal(pOutObjName);

            return szOTP;

        }
        /** @} End of oath grouping*/

        /**
         \addtogroup spb
         *
         @{ */
        /// <summary>
        /// Lista os objetos de um determinado tipo (chave, certificado, etc).
        /// </summary>
        /// <param name="filterCallBack">Função de callback chamada para cada objeto da interação</param>
        /// <param name="param">Parämetro</param>
        /// <param name="type">Tipo de objeto <see cref="Dinamo.Hsm.DinamoClient.OBJTYPE"/></param>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public void SPBListObjects(OBJTYPE type, DinamoApi.ListCallbackFilter filterCallBack, IntPtr param)
        {
            DinamoApi.OBJ_LIST_FILTER filter = new DinamoApi.OBJ_LIST_FILTER();

            filter.verb = (Int32)DinamoApi.Verb.OBJ_LIST_VERB_TYPE;
            filter.header.version = 0;
            filter.header.type = (int)type;
            filter.header.attrib = DinamoApi.MOD_SPB_RELATED;

            int nRet = DinamoApi.DListObjsFilter(m_ctx, DinamoApi.FilterType.LST_FILTER, ref filter,
               filterCallBack, param);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DListObjsFilter");

        }
        /// <summary>
        /// Recupera um certificado armazenado em um namespace no HSM. 
        /// </summary>
        /// <param name="strIdCertificate">identificação do certificado no formato "<ISPB>@<Dominio>". Por exemplo: "11223344@SPR".</param>
        /// <returns>Retorno do certificado no formato DER como array de bytes</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] SPBGetCertificate(string strIdCertificate)
        {
            byte[] ppbCertificate = new byte[1024 * 10];
            int intCertificateLen = ppbCertificate.Length;

            int nRet = DinamoApi.DSPBGetCertificate(m_ctx, strIdCertificate, ref ppbCertificate, ref intCertificateLen, 0);
            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DSPBGetCertificate");

            byte[] result = new byte[intCertificateLen];
            Array.Copy(ppbCertificate, 0, result, 0, intCertificateLen);

            return result;
        }
        /// <summary>
        /// Gera chave RSA 2048 no padrão SPB. Esta função sempre vai estar aderente aos requisitos do SPB, segundo o manual de segurança da RSFN.
        /// <see cref="DinamoClient.GenerateKey(string, KEY_ALG, bool)"/>
        /// </summary>
        /// <param name="ISPB">Número ISBP</param>
        /// <param name="domain">Domínio</param>
        /// <param name="isExportable">Verdadeiro para gerar uma chave exportável</param>
        /// <returns>Label da chave gerada</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public string SPBGenerateKey(string ISPB, string domain, bool isExportable)
        {
            string szID = ISPB;
            int dwKeyParam = 0;

            IntPtr pResult = Marshal.AllocHGlobal(DinamoApi.MAX_OBJ_ID_FQN_LEN);
            if (!string.IsNullOrEmpty(domain))
            {
                szID = string.Format("{0}@{1}", ISPB, domain);
            }
            if (isExportable)
            {
                dwKeyParam = DinamoApi.EXPORTABLE_KEY;
            }

            int nRet = DinamoApi.DSPBGenerateKey(m_ctx, szID, pResult, dwKeyParam, 0);


            if (nRet != DinamoApi.D_OK)
            {
                Marshal.FreeHGlobal(pResult);
                throw new DinamoException(nRet, "DSPBGenerateKey");
            }
            string result = Marshal.PtrToStringAnsi(pResult);

            Marshal.FreeHGlobal(pResult);

            return result;
        }
        /// <summary>
        /// Gera uma nova CSR baseada em uma chave existente (RSA 2048).
        /// </summary>
        /// <param name="sPrivateKeyName">Identificação da chave no HSM</param>
        /// <param name="sSubject">Descriçáo do subject do certificado DN (Dinstinguished Name) do CSR para a geração do campo Subject do certificado. Os campos de DN deverão ser separados por '/'.</param>
        /// <returns>Label da chave gerada</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] SPBGenerateCSR(string sPrivateKeyName, string sSubject)
        {
            Int32 pdwCSRLen = DinamoApi.CORE_P10_CSR_DN_MAX_LEN;

            IntPtr pCSR;

            int nRet = DinamoApi.DSPBGenerateCSR(m_ctx, sPrivateKeyName,
                DinamoApi.CORE_P10_CSR_VERSION1,
                sSubject,
                DinamoApi.P10_CSR_PEM,
                ref pdwCSRLen, out pCSR, 0);

            if (nRet != DinamoApi.D_OK)
            {
                DinamoApi.DFree(pCSR);
                throw new DinamoException(nRet, "DGeneratePKCS10CSR");
            }

            byte[] result = new byte[pdwCSRLen];
            Marshal.Copy(pCSR, result, 0, pdwCSRLen);

            DinamoApi.DFree(pCSR);

            return result;
        }
        /// <summary>
        /// Codifica uma mensagem com o cabeçalho do SPB, assinando, criptografando e incluindo todos os campos de cabeçalhos definidos no manual de segurança da RSFN.
        /// </summary>
        /// <param name="szSrcISPB">identificação do ISPB de origem no formato "<ISPB>@<Dominio>". Por exemplo: "11223344@SPR".</param>
        /// <param name="szDstISPB">identificação do ISPB de destino no formato "<ISPB>@<Dominio>". Por exemplo: "11223344@SPR".</param>
        /// <param name="pbMsgIn">Mensagem passada como um array de bytes. O HSM Não faz conversão automática de formato. No padrão do SPB o formato definido é o UTF16-BE, e cabe ao chamador da API garantir que a mensagem esteja usando o formato correto.</param>
        /// <param name="bSpecialTreatment">Indicador de tratamento especial. Vide C04 no manual de segurança do SPB.</param>
        /// <returns>Indicador de tratamento especial. Item 5.6 do manual do cabeçalho de segurança da RSFN.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] SPBEncode(string szSrcISPB, string szDstISPB, byte[] pbMsgIn, byte bSpecialTreatment)
        {
            int nRet = 0;
            byte bErrorCode = 0;  //TODO: Colocar o ErrorCode na API
            Int32 dwTotalDataLen = pbMsgIn.Length;
            Int32 dwFlags = 0;
            IntPtr hSPB;

            nRet = DinamoApi.DSPBEncodeInit(m_ctx, szSrcISPB, szDstISPB,
                                dwTotalDataLen, bErrorCode, bSpecialTreatment, out hSPB, dwFlags);

            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DSPBEncodeInit");
            }


            MemoryStream stream = new MemoryStream(DinamoApi.ND_SPB_MSG_HEADER_V2_LEN + dwTotalDataLen);

            // Mensagem de entrada
            Int32 dwTotalDataInLen = 0;
            byte[] bBufferOut = null;
            Int32 dwMessageBrowseInLen = dwTotalDataLen > DinamoApi.ND_SPB_MAX_NOTIFY_DATA_SEG ? DinamoApi.ND_SPB_MAX_NOTIFY_DATA_SEG : dwTotalDataLen;
            Int32 dwBufferOut = dwMessageBrowseInLen + 16;
            IntPtr pMessageBrowseIn = Marshal.AllocHGlobal(dwMessageBrowseInLen); // Buffer alocado
            IntPtr pBufferOut = Marshal.AllocHGlobal(dwBufferOut); // Buffer de saida

            stream.Position = DinamoApi.ND_SPB_MSG_HEADER_V2_LEN;

            do
            {
                Marshal.Copy(pbMsgIn, 0, pMessageBrowseIn, dwMessageBrowseInLen);

                nRet = DinamoApi.DSPBEncodeCont(hSPB, pMessageBrowseIn, dwMessageBrowseInLen,
                                      pBufferOut, out dwBufferOut);

                if (nRet != DinamoApi.D_OK)
                {
                    break;
                }
                bBufferOut = new byte[dwBufferOut];
                Marshal.Copy(pBufferOut, bBufferOut, 0, dwBufferOut);
                stream.Write(bBufferOut, 0, dwBufferOut);
                dwTotalDataInLen += dwMessageBrowseInLen;
                dwMessageBrowseInLen = (dwTotalDataLen - dwTotalDataInLen) > DinamoApi.ND_SPB_MAX_NOTIFY_DATA_SEG ? DinamoApi.ND_SPB_MAX_NOTIFY_DATA_SEG : (dwTotalDataLen - dwTotalDataInLen);

            } while (dwTotalDataInLen < dwTotalDataLen);

            Marshal.FreeHGlobal(pMessageBrowseIn);
            Marshal.FreeHGlobal(pBufferOut);
            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DSPBEncodeCont");
            }

            IntPtr pSPBHeader = Marshal.AllocHGlobal(DinamoApi.ND_SPB_MSG_HEADER_V2_LEN);
            Int32 pdwSPBHeaderLen = DinamoApi.ND_SPB_MSG_HEADER_V2_LEN;

            nRet = DinamoApi.DSPBEncodeEnd(out hSPB, pSPBHeader, out pdwSPBHeaderLen);
            if (nRet != DinamoApi.D_OK)
            {
                Marshal.FreeHGlobal(pSPBHeader);
                throw new DinamoException(nRet, "DSPBEncodeEnd");
            }
            bBufferOut = new byte[pdwSPBHeaderLen];
            Marshal.Copy(pSPBHeader, bBufferOut, 0, pdwSPBHeaderLen);
            stream.Position = 0;
            stream.Write(bBufferOut, 0, pdwSPBHeaderLen);
            Marshal.FreeHGlobal(pSPBHeader);

            return stream.ToArray();
        }
        /// <summary>
        /// Decodifica uma mensagem no padrão SPB, checando as assinaturas, decriptografando porem não faz a checagem de encoding. 
        /// </summary>
        /// <param name="szSrcISPB">identificação do ISPB de origem no formato "<ISPB>@<Dominio>". Por exemplo: "11223344@SPR".</param>
        /// <param name="szDstISPB">identificação do ISPB de destino no formato "<ISPB>@<Dominio>". Por exemplo: "11223344@SPR".</param>
        /// <param name="pbMsgIn">mensagem codificada no padrão SPB passada como um array de bytes.</param>
        /// <returns>Array de bytes com a mensagem decodificada.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] SPBDecode(string szSrcISPB, string szDstISPB, byte[] pbMsgIn)
        {
            return SPBDecode(szSrcISPB, szDstISPB, pbMsgIn, false, false);
        }
        /// <summary>
        /// Decodifica uma mensagem no padrão SPB, checando as assinaturas e decriptografando. 
        /// </summary>
        /// <param name="szSrcISPB">identificação do ISPB de origem no formato "<ISPB>@<Dominio>". Por exemplo: "11223344@SPR".</param>
        /// <param name="szDstISPB">identificação do ISPB de destino no formato "<ISPB>@<Dominio>". Por exemplo: "11223344@SPR". </param>
        /// <param name="pbMsgIn">mensagem codificada no padrão SPB passada como um array de bytes.</param>
        /// <param name="AcceptExpiredCert">aceita fazer operação mesmo com um certificado expirado.</param>
        /// <param name="AutoUpdateCert">Interpreta mensagens de troca de certificado e executa internamente a operação automaticamente.</param>
        /// <returns>Array de bytes com a mensagem decodificada.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public byte[] SPBDecode(string szSrcISPB, string szDstISPB, byte[] pbMsgIn,
                                                    bool AcceptExpiredCert, bool AutoUpdateCert)
        {
            int nRet = 0;
            Int32 dwFlags = DinamoApi.ND_SPB_OUT_NO_PADDING;
            IntPtr hSPB;

            Int32 dwHeaderLen = DinamoApi.ND_SPB_MSG_HEADER_V2_LEN;
            Int32 dwMessageDataLen = pbMsgIn.Length - dwHeaderLen;
            IntPtr pbHeader = Marshal.AllocHGlobal(dwHeaderLen);
            byte bAcceptExpiredCert = (byte)(AcceptExpiredCert ? 1 : 0);
            byte bAutoUpdateCert = (byte)(AutoUpdateCert ? 1 : 0);

            Marshal.Copy(pbMsgIn, 0, pbHeader, dwHeaderLen);
            nRet = DinamoApi.DSPBDecodeInit(m_ctx, szSrcISPB, szDstISPB, pbHeader, dwHeaderLen, bAcceptExpiredCert,
                bAutoUpdateCert, dwMessageDataLen, out hSPB, dwFlags);
            Marshal.FreeHGlobal(pbHeader);
            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DSPBDecodeInit");
            }

            // Cont
            Int32 dwDataInLen = dwMessageDataLen > DinamoApi.ND_SPB_MAX_NOTIFY_DATA_SEG ? DinamoApi.ND_SPB_MAX_NOTIFY_DATA_SEG : dwMessageDataLen;
            IntPtr pbDataIn = Marshal.AllocHGlobal(dwDataInLen);
            IntPtr pbDataOut;
            Int32 pdwDataOutLen = 0;
            MemoryStream stream = new MemoryStream();
            byte[] bBufferOut = null;
            Int32 dwMessageTotalLen = 0;
            do
            {

                Marshal.Copy(pbMsgIn, dwMessageTotalLen + DinamoApi.ND_SPB_MSG_HEADER_V2_LEN, pbDataIn, dwDataInLen);

                nRet = DinamoApi.DSPBDecodeCont(hSPB, pbDataIn, dwDataInLen, out pbDataOut, out pdwDataOutLen);

                if (nRet != DinamoApi.D_OK)
                {
                    break;
                }
                dwMessageTotalLen += dwDataInLen;
                bBufferOut = new byte[pdwDataOutLen];

                Marshal.Copy(pbDataOut, bBufferOut, 0, pdwDataOutLen);

                stream.Write(bBufferOut, 0, pdwDataOutLen);

                dwDataInLen = (dwMessageDataLen - dwMessageTotalLen) > DinamoApi.ND_SPB_MAX_NOTIFY_DATA_SEG ? DinamoApi.ND_SPB_MAX_NOTIFY_DATA_SEG : (dwMessageDataLen - dwMessageTotalLen);

            } while (dwMessageDataLen > dwMessageTotalLen);

            Marshal.FreeHGlobal(pbDataIn);

            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DSPBDecodeCont");
            }

            nRet = DinamoApi.DSPBDecodeEnd(out hSPB);

            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DSPBDecodeEnd");
            }
            return stream.ToArray();
        }
        /// <summary>
        /// Cria um mapa com o certificado da instituição em um slot.
        /// </summary>
        /// <param name="sIdCert">Identificação/label do certificado no HSM</param>
        /// <returns>Nome do objeto mapa criado no HSM.</returns>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public string SPBMapInfoCert(string sIdCert)
        {
            string result = "";
            DinamoApi.EXT_MAP_2_OBJ_INFO pstExtMap = new DinamoApi.EXT_MAP_2_OBJ_INFO();
            Int32 dwParam = 0;

            int nRet = DinamoApi.DSPBMapInfo(m_ctx, sIdCert, ref pstExtMap, dwParam);
            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DSPBMapInfo");
            }
            result = pstExtMap.szObjId2;
            return result;
        }
        /// <summary>
        /// Importa um certificado de um container PKCS#12 para o HSM.
        /// </summary>
        /// <param name="szPkcs12File">Caminho e nome do arquivo.</param>
        /// <param name="szPkcs12Pwd">Senha</param>
        /// <param name="szNamespace">Partição onde está o objeto.Se o objeto estiver na mesma partição logada, pode passar `null`.</param>
        /// <param name="szDomain">Dominio do SPB.</param>
        /// <param name="dwKeyAttr">
        /// Parâmetros adicionais da chave. 
        /// Valor | Significado
        /// ------|-----------
        /// <see cref="DinamoApi.NONEXPORTABLE_KEY"/> | A chave Não poderá sair do HSM.
        /// <see cref="DinamoApi.EXPORTABLE_KEY"/> | A chave poderá ser exportada do HSM. 
        /// <see cref="DinamoApi.TEMPORARY_KEY"/> | A chave somente existirá enquanto a sessão estiver ativa. Ela será destruída após o encerramento da sessão. 
        /// </param>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public void SPBImportPKCS12(string szPkcs12File, string szPkcs12Pwd, string szNamespace, string szDomain, int dwKeyAttr)
        {
            SPBImportPKCS12(szPkcs12File, szPkcs12Pwd, szNamespace, szDomain, dwKeyAttr, false);
        }
        /// <summary>
        /// Importa um certificado de um container PKCS#12 para o HSM.
        /// </summary>
        /// <param name="szPkcs12File">Caminho e nome do arquivo.</param>
        /// <param name="szPkcs12Pwd">Senha.</param>
        /// <param name="szNamespace">Partição onde está o objeto.Se o objeto estiver na mesma partição logada, pode passar `null`.</param>
        /// <param name="szDomain">Dominio do SPB.</param>
        /// <param name="dwKeyAttr"> 
        /// Parâmetros adicionais da chave. 
        /// Valor | Significado
        /// ------|-----------
        /// <see cref="DinamoApi.NONEXPORTABLE_KEY"/> | A chave Não poderá sair do HSM.
        /// <see cref="DinamoApi.EXPORTABLE_KEY"/> | A chave poderá ser exportada do HSM. 
        /// <see cref="DinamoApi.TEMPORARY_KEY"/> | A chave somente existirá enquanto a sessão estiver ativa. Ela será destruída após o encerramento da sessão. 
        /// </param>
        /// <param name="isActivate">Ativa o certificado durante a importação </param>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public void SPBImportPKCS12(string szPkcs12File, string szPkcs12Pwd, string szNamespace, string szDomain, int dwKeyAttr, bool isActivate)
        {
            int nRet = DinamoApi.DSPBImportPKCS12(m_ctx, (byte)(isActivate ? 0 : 1), szNamespace, szPkcs12File, szPkcs12Pwd, szDomain, dwKeyAttr);
            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "SPBImportPKCS12");
            }
        }
        /// <summary>
        /// Importa um certificado para um namespace do HSM. 
        /// </summary>
        /// <param name="szDomain">Dominio do SPB.</param>
        /// <param name="bCertificate">Certificado SPB no padrão SPB como um array de bytes.</param>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public void SPBImportCertificate(string szDomain, byte[] bCertificate)
        {
            SPBImportCertificate(null, szDomain, bCertificate, false);
        }
        /// <summary>
        /// Importa um certificado para um namespace do HSM. 
        /// </summary>
        /// <param name="szDomain">Dominio do SPB.</param>
        /// <param name="bCertificate">Certificado SPB no padrão SPB como um array de bytes.</param>
        /// <param name="isCIPCertificate">Verdadeiro se o certificado for no padrão CIP.</param>
        public void SPBImportCertificate(string szDomain, byte[] bCertificate, bool isCIPCertificate = false)
        {
            SPBImportCertificate(null, szDomain, bCertificate, isCIPCertificate);
        }
        /// <summary>
        /// Ativa um certificado que já foi importado para o HSM.
        /// Se houver um outro certificado ativo, ele será inativado.Somente um certificado permanecerá ativo por instituição, por domínio dentro de um namespace do HSM.
        /// </summary>
        /// <param name="szDomain">Dominio do SPB.</param>
        /// <param name="szCA">Identificação da CA (número da CA).</param>
        /// <param name="szSN">Número de série do certificado no formato Hexadecimal</param>
        /// <param name="isCIPCertificate">Verdadeiro se o certificado for no padrão CIP.</param>
        /// <remarks>Os números de CA existentes consta no manual de segurança da RSFN.</remarks>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public void SPBActivateCertificate(string szDomain, string szCA, string szSN, bool isCIPCertificate = false)
        {
            SPBActivateCertificate(null, szDomain, szCA, szSN, isCIPCertificate);
        }
        /// <summary>
        /// Ativa um certificado que já foi importado para o HSM.
        /// Se houver um outro certificado ativo, ele será inativado.Somente um certificado permanecerá ativo por instituição, por domínio dentro de um namespace do HSM.
        /// </summary>
        /// <param name="szNamespace">Partição onde está o objeto.Se o objeto estiver na mesma partição logada, pode passar `null`.</param>
        /// <param name="szDomain">Dominio do SPB.</param>
        /// <param name="bCertificate">Certificado SPB no padrão SPB como um array de bytes.</param>
        /// <param name="isCIPCertificate">Verdadeiro se o certificado for no padrão CIP.</param>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public void SPBImportCertificate(string szNamespace, string szDomain, byte[] bCertificate, bool isCIPCertificate = false)
        {
            uint dwParam = isCIPCertificate ? DinamoApi.ND_SPB_USE_CIP1 : 0;
            Int32 dwCertificateLen = bCertificate.Length;
            IntPtr pCertificate = Marshal.AllocHGlobal(dwCertificateLen);

            Marshal.Copy(bCertificate, 0, pCertificate, dwCertificateLen);

            int nRet = DinamoApi.DSPBImportCertificate(m_ctx, 0, szNamespace, pCertificate, dwCertificateLen, szDomain, dwParam);

            Marshal.FreeHGlobal(pCertificate);

            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DSPBImportCertificate");
            }
        }
        /// <summary>
        /// Ativa um certificado que já foi importado para o HSM.
        /// Se houver um outro certificado ativo, ele será inativado.Somente um certificado permanecerá ativo por instituição, por domínio dentro de um namespace do HSM.
        /// </summary>
        /// <param name="szNamespace">Partição onde está o objeto.Se o objeto estiver na mesma partição logada, pode passar `null`.</param>
        /// <param name="szDomain">Dominio do SPB.</param>
        /// <param name="szCA">Identificação da CA (número da CA).</param>
        /// <param name="szSN">Número de série do certificado no formato Hexadecimal</param>
        /// <param name="isCIPCertificate">Verdadeiro se o certificado for no padrão CIP.</param>
        /// <remarks>Os números de CA existentes consta no manual de segurança da RSFN.</remarks>
        /// <exception cref="DinamoException.DinamoException"> Em caso de erro</exception>
        public void SPBActivateCertificate(string szNamespace, string szDomain, string szCA, string szSN, bool isCIPCertificate = false)
        {
            uint dwParam = isCIPCertificate ? DinamoApi.ND_SPB_USE_CIP1 : 0;
            string szIdCert = szNamespace == null ? string.Format("{0}@{1}", szCA, szSN) : string.Format("{0}/{1}@{2}", szNamespace, szCA, szSN);
            int nRet = DinamoApi.DSPBActivateCertificate(m_ctx, szIdCert, szDomain, dwParam);

            if (nRet != DinamoApi.D_OK)
            {
                throw new DinamoException(nRet, "DSPBActivateCertificate");
            }
        }

        /// <summary>
        /// Função para auxiliar a formatação da identificação de objetos internos do HSM segundo o padrão utilizado no móduloSPB.
        /// </summary>
        /// <param name="szISPB">identificação do ISPB no formato "<ISPB>@<Dominio>". Por exemplo: "11223344@SPR". </param>
        /// <param name="szDomain">Dominio do SPB.</param>
        /// <param name="dwKeyType">Tipo de objeto. <see cref="Dinamo.Hsm.DinamoClient.KEYNAME"/></param>
        /// <returns>Nome no formato do móduloSPB.</returns>
        public string SPBCalculateObjectId(string szISPB, string szDomain, KEYNAME dwKeyType)
        {
            IntPtr pOutObjName = Marshal.AllocHGlobal(500);

            DinamoApi.DSPBCalculateObjectId(szISPB, szDomain, (int)dwKeyType, pOutObjName, 0);

            string result = Marshal.PtrToStringAnsi(pOutObjName);

            Marshal.FreeHGlobal(pOutObjName);
            return result;
        }
        /// <summary>
        /// Recupera informações do certificado
        /// </summary>
        /// <param name="certificate">Array de bytes com o certificado</param>
        /// <returns>Informções do certificado. <see cref="DinamoApi.SPB_CERT_X509_INFO"/></returns>
        public DinamoApi.SPB_CERT_X509_INFO SPBGetCertificateInfo(byte[] certificate)
        {
            DinamoApi.SPB_CERT_X509_INFO result = new DinamoApi.SPB_CERT_X509_INFO();

            int nRet = DinamoApi.DCert2CertInfo(certificate, certificate.Length,
                DinamoApi.P2C_SPB_CERT_INFO,
                out result, 0);

            if (nRet != DinamoApi.D_OK)
                throw new DinamoException(nRet, "DCert2CertInfo");

            return result;
        }

        /** @} End of spb grouping*/

    }

}
