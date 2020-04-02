using System;
using System.Text;
using System.Runtime.InteropServices;

namespace Dinamo.Hsm
{
    /// <summary>
    /// Classe de baixo nível para acesso ao HSM.  Para utilizar essa classe é necessário o entendimento mais profundo das funcionalidades
    /// e de como é feito o processo de comunicação com a máquina.  Recomendamos a utilização da classe <see cref="DinamoClient"/> para programação
    /// das aplicações.
    ///
    /// <seealso cref="DinamoClient"/>
    /// </summary>
    public class DinamoApi
    {
        //-----------------------------------------------------------------
        /*
         * Not defined in dinamo.h
         */

        public const Int32 FALSE = (0);
        public const Int32 TRUE = (1);
        public const Int32 NULL = (0);
        public const Int32 D_OK = 0;
        public const Int32 AUTH_PWD_LEN = MAX_ADDR_LEN + MAX_USR_LEN + MAX_USR_PWD + sizeof(Int32);

        public const Int32 ND_OATH_PWD_ENV_LEN = 16;
        public const Int32 ND_OATH_ENC_SEED_BLOB_LEN = 32;
        public const Int32 ND_OATH_ENC_MOB_SEED = 32;

        public const Int32 MAX_OTP_LOOK_AHEAD_INTERVAL = 255;

        public const Int32 D_INVALID_SECRET = D_ERR_INVALID_SECRET;

        /*
         * Defined in dinamo.h
         */

        /* Client network errors. Negative errors. */

        public const Int32 D_SOCKET_FAILED = (-10);
        public const Int32 D_GETHOSTNAME_FAILED = (-11);
        public const Int32 D_CONNECT_FAILED = (-12);
        public const Int32 D_SEND_FAILED = (-13);
        public const Int32 D_RECV_FAILED = (-14);
        public const Int32 D_INVALID_PACKAGE_SIZE = (-15);
        public const Int32 D_SETSOCKOPT_FAILED = (-16);
        public const Int32 D_GETSOCKOPT_FAILED = (-17);
        public const Int32 D_ALL_LOAD_BALANCE_HSM_FAILED = (-18);


        /* OpenSSL generated errors 1 to 100 */

        public const Int32 D_SSL_CTX_NEW_FAILED = (1);
        public const Int32 D_SSL_NEW_FAILED = (2);
        public const Int32 D_SSL_CONNECT_FAILED = (3);

        /* Curl generated errors 101 to 200 */

        public const Int32 D_CRL_GENERAL_ERROR = (101);
        public const Int32 D_CRL_SSL_CACERT_BADFILE = (102);
        public const Int32 D_CRL_COULDNT_RESOLVE_HOST = (103);
        public const Int32 D_CRL_COULDNT_CONNECT = (104);
        public const Int32 D_CRL_OPERATION_TIMEDOUT = (105);
        public const Int32 D_CRL_PEER_FAILED_VERIFICATION = (106);
        public const Int32 D_CRL_SSL_CONNECT_ERROR = (107);
        public const Int32 D_CRL_SEND_ERROR = (108);
        public const Int32 D_CRL_RECV_ERROR = (109);
        public const Int32 D_CRL_SSL_CERTPROBLEM = (110);
        public const Int32 D_CRL_SSL_ISSUER_ERROR = (111);
        public const Int32 D_CRL_AUTH_ERROR = (112);


        /* System errors */

        public const Int32 D_WSASTARTUP = (2001);
        public const Int32 D_MEMORY_ALLOC = (2002);


        /* Client errors */

        public const Int32 D_INVALID_PARAM = (1001);
        public const Int32 D_INVALID_TYPE = (1002);
        public const Int32 D_INVALID_STATE = (1003);
        public const Int32 D_LOGGING_NOT_STARTED = (1004);
        public const Int32 D_MORE_DATA = (1005);
        public const Int32 D_INVALID_RESPONSE = (1006);
        public const Int32 D_INVALID_CONTEXT = (1007);
        public const Int32 D_KEY_GEN_ERROR = (1008);
        public const Int32 D_KEY_DEL_ERROR = (1009);
        public const Int32 D_KEY_NOT_EXISTS = (1010);
        public const Int32 D_INVALID_DATA_LENGTH = (1011);
        public const Int32 D_INVALID_KEY_ALG = (1012);
        public const Int32 D_INVALID_PADDING = (1013);
        public const Int32 D_INVALID_KEY = (1014);
        public const Int32 D_BAD_DATA = (1015);
        public const Int32 D_INVALID_PUBKEY = (1016);
        public const Int32 D_INVALID_ALG_ID = (1017);
        public const Int32 D_INVALID_HASH = (1018);
        public const Int32 D_INIT_HASH_FAILED = (1019);
        public const Int32 D_INVALID_HASH_STATE = (1020);
        public const Int32 D_END_HASH_FAILED = (1021);
        public const Int32 D_GET_INFO_ERROR = (1022);
        public const Int32 D_INVALID_PIN_LEN = (1023);
        public const Int32 D_OPEN_FILE_FAILED = (1025);
        public const Int32 D_BACKUP_FAILED = (1026);
        public const Int32 D_RESTORE_FAILED = (1027);
        public const Int32 D_INVALID_CALLBACK = (1028);
        public const Int32 D_NOT_IMPLEMENTED = (1029);
        public const Int32 D_AUTH_FAILED = (1030);
        public const Int32 D_INVALID_CLEAR_OP = (1031);
        public const Int32 D_CHANGE_PWD_ERROR = (1032);
        public const Int32 D_PWD_SIZE_ERROR = (1033);
        public const Int32 D_IMPORT_KEY_ERROR = (1034);
        public const Int32 D_INVALID_KEY_ID = (1035);
        public const Int32 D_INVALID_FLAG = (1036);
        public const Int32 D_INVALID_SIGNATURE = (1037);
        public const Int32 D_INVALID_PUB_KEY = (1038);
        public const Int32 D_INVALID_KEY_STATE = (1039);
        public const Int32 D_CREATE_USER_ERROR = (1040);
        public const Int32 D_NO_MORE_OBJECT = (1041);
        public const Int32 D_PUT_ENV_VAR_FAILED = (1042);
        public const Int32 D_INVALID_FILE_SIZE = (1043);
        public const Int32 D_INVALID_TEXT_SIZE = (1044);
        public const Int32 D_FILE_ACCESS_ERROR = (1045);
        public const Int32 D_INVALID_COUNTER = (1046);
        public const Int32 D_INVALID_MODE = (1047);
        public const Int32 D_INVALID_STRUCT_ID = (1048);
        public const Int32 D_INVALID_IP_ADDRESS = (1049);
        public const Int32 D_GET_PEER_IP_ERROR = (1050);
        public const Int32 D_CERTIFICATE_PARSE_FAILED = (1051);
        public const Int32 D_INVALID_KEY_PART_1 = (1052);
        public const Int32 D_INVALID_KEY_PART_2 = (1053);
        public const Int32 D_INVALID_KEY_PART_3 = (1054);
        public const Int32 D_VERIFY_DAC_FAILED = (1055);
        public const Int32 D_DEPRECATED = (1056);
        public const Int32 D_NO_MATCHING_KEY_FOUND = (1057);
        public const Int32 D_CALLBACK_ERROR = (1058);
        public const Int32 D_INTERNAL_ERROR = (1059);
        public const Int32 D_KEY_NOT_EXPORTABLE_ERROR = (1060);

        public const Int32 D_INVALID_SPB_ID = (1062);
        public const Int32 D_JSON_PARSE_ERROR = (1063);
        public const Int32 D_JSON_PARSE_WRONG_TYPE_ERROR = (1064);
        public const Int32 D_JSON_SET_VALUE_ERROR = (1065);
        public const Int32 D_JSON_UNSET_VALUE_ERROR = (1066);
        public const Int32 D_JSON_VALUE_NOT_FOUND = (1067);
        public const Int32 D_JSON_OBJ_CREATE_ERROR = (1068);

        public const Int32 D_SLP_PARSE_ERROR = (1069);
        public const Int32 D_SLP_INTERNAL_ERROR = (1070);
        public const Int32 D_SLP_TOO_MANY_SERVERS_ERROR = (1071);

        public const Int32 D_INVALID_SERVER_VERSION = (1072);

        public const Int32 D_GENERATE_PKCS12_ERROR = (1073);
        public const Int32 D_SET_LOAD_BALANCE_LIST_ERROR = (1074);

        public const Int32 D_OATH_BLOB_UPDATE = (1075);


        /* Server errors */

        public const Int32 D_KEEP_ALIVE_ERROR = (3001);
        public const Int32 D_RECEIVE_LOG_ERROR = (3002);
        public const Int32 D_ERROR_NOTIFY = (3003);

        /* Server returned errors */

        public const Int32 D_ERR_UNKNOWN = (5000);
        public const Int32 D_ERR_NET_FAIL = (5001);
        public const Int32 D_ERR_ACCESS_DENIED = (5002);
        public const Int32 D_ERR_CANNOT_CREATE_OBJ = (5003);
        public const Int32 D_ERR_CANNOT_OPEN_OBJ = (5004);
        public const Int32 D_ERR_CANNOT_DEL_OBJ = (5005);
        public const Int32 D_ERR_CANNOT_ALLOC_RES = (5006);
        public const Int32 D_ERR_INVALID_CTX = (5007);
        public const Int32 D_ERR_INVALID_OPERATION = (5008);
        public const Int32 D_ERR_INVALID_KEY = (5009);
        public const Int32 D_ERR_NO_TLS_USED = (5010);
        public const Int32 D_ERR_CANNOT_CHANGE_PWD = (5011);
        public const Int32 D_ERR_OBJ_NOT_EXPORTABLE = (5012);
        public const Int32 D_ERR_USR_ALREADY_EXISTS = (5013);
        public const Int32 D_ERR_INVALID_USR_NAME = (5014);
        public const Int32 D_ERR_CANNOT_CREATE_USR = (5015);
        public const Int32 D_ERR_NO_MORE_LOG_SLOTS = (5016);
        public const Int32 D_ERR_CANNOT_DELETE_USR = (5017);
        public const Int32 D_ERR_CANNOT_DELETE_MASTER = (5018);
        public const Int32 D_ERR_NOT_IMPLEMENTED = (5019);
        public const Int32 D_ERR_USR_NOT_FOUND = (5020);
        public const Int32 D_ERR_INVALID_PAYLOAD = (5021);
        public const Int32 D_ERR_OBJ_ALREADY_EXISTS = (5022);
        public const Int32 D_ERR_INVALID_OBJ_NAME = (5023);
        public const Int32 D_ERR_OBJ_IN_USE = (5024);
        public const Int32 D_ERR_CANNOT_WRITE_BACKUP_BLOB = (5025);
        public const Int32 D_ERR_CANNOT_OPEN_BACKUP_BLOB = (5026);
        public const Int32 D_ERR_CANNOT_RESTORE_BACKUP_BLOB = (5027);
        public const Int32 D_ERR_INVALID_BACKUP_PIN_OR_LEN = (5028);
        public const Int32 D_ERR_INVALID_XML_SIGNATURE = (5029);
        public const Int32 D_ERR_INVALID_CERTIFICATE = (5030);
        public const Int32 D_ERR_VERIFY_XML_FAILED = (5031);
        public const Int32 D_ERR_INVALID_XML = (5032);
        public const Int32 D_ERR_SIGN_XML_FAILED = (5033);
        public const Int32 D_ERR_UPACK_VERIFY_FAILED = (5034);
        public const Int32 D_ERR_CANNOT_TRUNCATE_LOG = (5035);
        public const Int32 D_ERR_CANNOT_BACKUP_OLD_LOG = (5036);
        public const Int32 D_ERR_CERTIFICATE_EXPIRED = (5037);
        public const Int32 D_ERR_CERTIFICATE_FAILED = (5038);
        public const Int32 D_ERR_CERTIFICATE_NOT_FOUND = (5039);
        public const Int32 D_ERR_CERTIFICATE_REVOKED = (5040);
        public const Int32 D_ERR_CERTIFICATE_ISSUER_FAILED = (5041);
        public const Int32 D_ERR_CERTIFICATE_NOT_YET_VALID = (5042);
        public const Int32 D_ERR_CERT_EXPIRED_SIGN_VALID = (5043);
        public const Int32 D_ERR_CRL_EXPIRED = (5044);
        public const Int32 D_ERR_INVALID_CRL_SIGN = (5045);
        public const Int32 D_ERR_CRL_CERT_MISMATCH = (5046);
        public const Int32 D_ERR_CERT_REVOKED = D_ERR_CERTIFICATE_REVOKED;	/* deprecated. 5047. */
        public const Int32 D_ERR_ACCESS_DENIED_NO_TOKEN = (5048);
        public const Int32 D_ERR_ACCESS_DENIED_TOKEN_NEEDED = (5049);
        public const Int32 D_ERR_CERT_REVOKED_CRL_VAL_UNUSED = (5050);
        public const Int32 D_ERR_CERT_VALID_CRL_VAL_UNUSED = (5051);
        public const Int32 D_ERR_CANNOT_PARSE_XML = (5052);
        public const Int32 D_ERR_CANNOT_CREATE_XML_SIG_TEMPL = (5053);
        public const Int32 D_ERR_CANNOT_ADD_XML_SIG_TEMPL_REF = (5054);
        public const Int32 D_ERR_CANNOT_ADD_XML_SIG_TEMPL_TRANS = (5055);
        public const Int32 D_ERR_CANNOT_ADD_XML_SIG_KEY_INFO = (5056);
        public const Int32 D_ERR_CANNOT_ADD_XML_SIG_KEY_CERT = (5057);
        public const Int32 D_ERR_CANNOT_ALLOC_XML_SIG_CTX = (5058);
        public const Int32 D_ERR_CANNOT_PARSE_DER_PRIV_KEY = (5059);
        public const Int32 D_ERR_XML_CANNOT_LOAD_PRIV_KEY = (5060);
        public const Int32 D_ERR_XML_CANNOT_LOAD_CERT = (5061);
        public const Int32 D_ERR_XML_CANNOT_CREATE_KEY_MNG = (5062);
        public const Int32 D_ERR_XML_CANNOT_INIT_KEY_MNG = (5063);
        public const Int32 D_ERR_XML_CANNOT_LOAD_TRUSTED_CERTS = (5064);
        public const Int32 D_ERR_XML_SIG_NODE_NOT_FOUND = (5065);
        public const Int32 D_ERR_XML_CERT_NODE_NOT_FOUND = (5066);
        public const Int32 D_ERR_XML_CANNOT_DECODE_CERT_NODE = (5067);
        public const Int32 D_ERR_CANNOT_PARSE_DER_CERT = (5068);
        public const Int32 D_ERR_CANNOT_DECODE_XML_COMPRESS = (5069);
        public const Int32 D_ERR_INVALID_CERTIFICATE_NULL_RES = (5070);
        public const Int32 D_ERR_CANNOT_RECREATE_MASTER = (5071);
        public const Int32 D_ERR_CANNOT_CREATE_USR_STORAGE1 = (5072);
        public const Int32 D_ERR_CANNOT_CREATE_USR_STORAGE2 = (5073);
        public const Int32 D_ERR_CANNOT_CREATE_USR_DEFAULT_ACL = (5074);
        public const Int32 D_ERR_CANNOT_ALLOC_CTX = (5075);
        public const Int32 D_ERR_CANNOT_LOAD_PRIV_KEY = (5076);
        public const Int32 D_ERR_CANNOT_DECODE_PUB_KEY = (5077);
        public const Int32 D_ERR_CANNOT_GENERATE_RND_DATA = (5078);
        public const Int32 D_ERR_CACHE_LAYER_EXHAUSTED = (5079);
        public const Int32 D_ERR_RSA_POWER_SIGN_FAILED = (5080);
        public const Int32 D_ERR_CANNOT_GET_SYS_INFO = (5100);
        public const Int32 D_ERR_CANNOT_ALLOC_UPACK_ID = (5101);
        public const Int32 D_ERR_CANNOT_ALLOC_UPACK_PATH = (5102);
        public const Int32 D_ERR_CANNOT_WRITE_UPACK_OBJ = (5103);
        public const Int32 D_ERR_INVALID_CRL = (5104);
        public const Int32 D_ERR_OPERATION_FAILED = (5105);
        public const Int32 D_ERR_GET_USR_ACL_FAILED = (5106);
        public const Int32 D_ERR_INVALID_SIGNATURE = (5107);
        public const Int32 D_ERR_CANNOT_GENERATE_SOFT_TOKEN = (5108);
        public const Int32 D_ERR_INVALID_SECRET = (5109);
        public const Int32 D_ERR_ACCESS_DENIED_USR_BLOCKED = (5120);
        public const Int32 D_ERR_INVALID_IMEI = (5121);
        public const Int32 D_ERR_REPLAY_DETECTED = (5122);
        public const Int32 D_ERR_NON_APPROVED_FIPS_OPERATION = (5123);
        public const Int32 D_ERR_ACCESS_DENIED_OBJ_BLOCKED = (5124);
        public const Int32 D_ERR_FIPS_DRBG_CONTINUOUS_TEST = (5125);
        public const Int32 D_ERR_FIPS_RSA_CONTINUOUS_TEST = (5126);
        public const Int32 D_ERR_FIPS_ECC_CONTINUOUS_TEST = (5127);
        public const Int32 D_ERR_FIPS_DES_CONTINUOUS_TEST = (5128);
        public const Int32 D_ERR_FIPS_AES_CONTINUOUS_TEST = (5129);
        public const Int32 D_ERR_CANNOT_UPDATE_OBJ = (5175);
        public const Int32 D_ERR_CANNOT_GET_PWD_POLICY = (5176);
        public const Int32 D_ERR_PWD_BLOCKED_BY_POLICY = (5177);
        public const Int32 D_ERR_PWD_EXPIRED = (5178);
        public const Int32 D_ERR_CERT_VALID_CRL_VAL_UNUSED_CRL_EXPIRED = (5179);
        public const Int32 D_ERR_CERT_VALID_CRL_EXPIRED = (5180);
        public const Int32 D_ERR_INVALID_CERT_SIGN = (5181);
        public const Int32 D_ERR_CANNOT_LOAD_CORRUPTED_OBJ = (5200);
        public const Int32 D_ERR_INVALID_CERT_ISPB_MISMATCH = (5230);
        public const Int32 D_ERR_INVALID_CA = (5231);
        public const Int32 D_ERR_DEPRECATED_FUNCTION = (5303);

        public const Int32 D_ERR_SERVER_BUSY = (5304);
        public const Int32 D_ERR_SL_BE_BUSY = (5305);
        public const Int32 D_ERR_SVMK_MISMATCH = (5306);
        public const Int32 D_ERR_INVALID_CERT_SN_MISMATCH = (5307);
        public const Int32 D_ERR_CANNOT_DEC_SYM_KEY = (5308);
        public const Int32 D_ERR_CANNOT_REC_SYM_KEY = (5309);

        public const Int32 D_SUCCESS_CANNOT_OPEN_OBJ_AT_REPL = (5401);
        public const Int32 D_ERR_CANNOT_OPEN_INVALID_OBJ_AT_REPL = (5402);


        //
        // p2p errors;
        //
        public const Int32 D_ERR_REPLICATION_BUSY = (36000);
        public const Int32 D_ERR_REPLICATION_D_BUSY = (36001);
        public const Int32 D_ERR_REPLICATION_S_BUSY = (36002);
        public const Int32 D_ERR_REPLICATION_STORAGE_LAYER_BUSY = (36003);
        public const Int32 D_ERR_REPLICATION_SEC_LAYER_BUSY = (36004);


        public const Int32 D_ERR_REPLICATION_PEER_NOT_SYNCED = (36500);

        public const Int32 D_ERR_REPLICATION_CANNOT_PREPARE_TRANS = (37001);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_HANDSHAKE = (37002);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_FIND = (37003);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_CONNECT = (37004);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_SEND = (37005);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_RECV = (37006);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_SEND_ALL = (37007);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_RECV_ALL = (37008);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_SCONNECT = (37009);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_SSEND = (37010);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_SRECV = (37011);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_SSEND_ALL = (37012);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_SRECV_ALL = (37013);
        public const Int32 D_ERR_REPLICATION_CANNOT_P2P_WORK = (37014);
        public const Int32 D_ERR_REPLICATION_NOT_FOUND = (37015);
        public const Int32 D_ERR_REPLICATION_ACK_NOT_FOUND = (37016);
        public const Int32 D_ERR_REPLICATION_INVALID_OPERATION = (37017);
        public const Int32 D_ERR_REPLICATION_INVALID_EVENT = (37018);
        public const Int32 D_ERR_REPLICATION_OPERATION_FAILED = (37019);
        public const Int32 D_ERR_REPLICATION_COMMIT_FAILED = (37020);
        public const Int32 D_ERR_REPLICATION_ERASE_FAILED = (37021);
        public const Int32 D_ERR_REPLICATION_INQUIRE_FAILED = (37022);
        public const Int32 D_ERR_REPLICATION_UPDATE_ACK_FAILED = (37023);
        public const Int32 D_ERR_REPLICATION_DISPATCH_FAILED = (37024);
        public const Int32 D_ERR_REPLICATION_CANNOT_SL_BE_TRANSP = (37025);
        public const Int32 D_ERR_REPLICATION_CANNOT_PRUNE_LOG = (37026);
        public const Int32 D_ERR_REPLICATION_CANNOT_LOAD_LOG = (37027);
        public const Int32 D_ERR_REPLICATION_CANNOT_WORK = (37028);
        public const Int32 D_ERR_REPLICATION_CANNOT_VALIDATE_EVENT = (37029);
        public const Int32 D_ERR_REPLICATION_TRANS_MISMATCH = (37030);
        public const Int32 D_ERR_REPLICATION_CANNOT_SYNC_POINT = (37031);
        public const Int32 D_ERR_REPLICATION_UNDEFINED_LIVE_SYNC = (37032);
        public const Int32 D_ERR_REPLICATION_CONNECTED_LIVE_SYNC = (37033);
        public const Int32 D_ERR_REPLICATION_SELF_LIVE_SYNC = (37034);
        public const Int32 D_ERR_REPLICATION_OBJ_IN_USE = (37035);


        public const Int32 NOT_LISTED_ERROR = (-999999);

        /* OpenSession - Options/parameters */

        /* dwParam */
        public const Int32 SS_ANONYMOUS = (0x00000001);  /*pbData == NULL*/
        public const Int32 SS_USER_PWD = (0x00000002);  /*pbData == SS_USER_PWD*/
        public const Int32 SS_CERTIFICATE = (0x00000004);  /*pbData == SS_MEDIA_FILE*/
        public const Int32 SS_CLUSTER = (0x00000008);  /*pbData == NULL*/
        public const Int32 SS_USR_PWD_EX = (0x00000010);  /*pbData == AUTH_PWD_EX*/

        /* dwFlags */
        public const Int32 ENCRYPTED_CONN = (0x00000001);  /* Encrypted communication */
        public const Int32 USER_INTERACTIVE = (0x00000002);  /* User interactive. Not implemented. */
        public const Int32 CLEAR_CONN = (0x00000004);  /* Not encrypted communication */
        public const Int32 LB_BYPASS = (0x00000008);  /* Load balance bypass */
        public const Int32 CACHE_BYPASS = (0x00000010);  /* Session Cache bypass */

        /* Strong authentication */

        public const Int32 SA_AUTH_NONE = (0x00000000);	/* No strong authentication */
        public const Int32 SA_AUTH_OTP = (0x00000001);	/* OTP authentication */

        /* SetSessionParam/GetSessionParam */

        /* dwParam */
        public const Int32 SP_SESSION_TIMEOUT = (0x00000001);  /* Time-out sessao pbData == dwTimeout = (ms); */
        public const Int32 SP_SEND_TIMEOUT = (0x00000002);  /* Time-out send pbData == dwTimeout = (ms); */
        public const Int32 SP_RECV_TIMEOUT = (0x00000004);  /* Time-out recv pbData == dwTimeout = (ms); */
        public const Int32 SP_ENCRYPTED = (0x00000008);  /* Read-only pbData == bSessionEncrypted = (TRUE/FALSE); */
        public const Int32 SP_SESSION_ID = (0x00000010);  /* Read-only pbData == dwSessionId */


        /* CloseSession */

        /* dwFlags */
        public const Int32 WAIT_OPERATIONS = (0x00000004);  /* Wait the end of all operations in progress. Not implemented. */
        public const Int32 CLOSE_PHYSICALLY = (0x00000008);  /* Force the end of the connection with the HSM. Session will not be cached. */

        /* Backup */

        public const Int32 MAKE_BACKUP = (0);
        public const Int32 MAKE_RESTORE = (1);				/* Deprecated. Only defined for backward compatibility. */
        public const Int32 MAKE_RESTORE_WITH_NET_CONFIG = MAKE_RESTORE;
        public const Int32 MAKE_RESTORE_WITHOUT_NET_CONFIG = (2);

        /* GetHsmData/SetHsmData */

        /* dwParam */
        public const Int32 HD_AUDIT_START = (0x00000001);  /* Indicate that the connection will be used to retrieve logs. */
        public const Int32 HD_AUDIT_RECV = (0x00000002);  /* Receive logs from server. */

        /* dwFlags */
        public const Int32 DATA_ONLY = (0x00000008);  /* Backup/Restore only data */
        public const Int32 CONFIG_ONLY = (0x00000010);  /* Backup/Restore only configurations*/


        /* GetHsmConfig/SetHsmConfig */

        /* dwParam*/
        public const Int32 HC_PASS_PORT_VALUE = (0x00000001);  /* Monitoring port. pbData == wPortNumber */
        public const Int32 HC_PASS_PORT_ENABLE = (0x00000002);  /* Enable/disable monitoring port. pbData == bEnable */
        public const Int32 HC_MAX_CONNECT = (0x00000004);  /* Maximum connections = (processing);. pbData == dwMaxConnections */
        public const Int32 HC_MAX_MONITORING = (0x00000008);  /* Maximum connections = (monitoring);. pbData == dwMaxConnections */
        public const Int32 HC_PERMISSION_IP = (0x00000010);  /* Clients IP list. pbData == szIPList = (xxx.xxx.xxx.xxx;xxx...); */

        /* dwFlags */
        public const Int32 ENABLE_VALUES = (0x00000020);  /* Enable values indicated by pbData. */
        public const Int32 DISABLE_VALUES = (0x00000040);  /* Disable values indicated by pbData. */


        /* DAdmOperation */

        /* dwParam */
        public const Int32 AO_SHUTDOWN = (0x00000001);  /* Shutdown HSM. pbData == NULL */
        public const Int32 AO_RESTART = (0x00000002);  /* Restart HSM services. pbData == NULL */
        public const Int32 AO_KEEPALIVE = (0x00000004);  /* Keep session alive. */
        public const Int32 AO_SET_DATE_TIME = (0x00000008);  /* Set the HSM's time and date. pbData == struct tm = (time.h); */
        public const Int32 AO_ADD_CLUSTER_LIST = (0x00000010);  /* DEPRECATED! */
        public const Int32 AO_DEL_CLUSTER_LIST = (0x00000012);  /* DEPRECATED! */
        public const Int32 AO_GET_CLUSTER_LIST = (0x00000014);  /* DEPRECATED! */
        public const Int32 AO_RST_CLUSTER_LIST = (0x00000018);  /* DEPRECATED! */
        public const Int32 AO_SET_PWD_SEC_POLICY = (0x00000019);  /* Define password security policies. */
        public const Int32 AO_GET_PWD_SEC_POLICY = (0x00000020);  /* Recover password security policies. */
        public const Int32 AO_REPL_UPDATE = (0x00000021);  /* Process an update replication command. pbData == NULL */
        public const Int32 AO_REPL_NODE_MESSAGE = (0x00000022);  /* Send comands to the HSM's replication subsystem. pbData == *REPL_NODE_MSG */

        public const Int32 AO_KEEPALIVE_FLAG_NOISELESS = (-2371);

        //
        // Replication operation messages
        // to be used with AO_REPL_NODE_MESSAGE.
        //
        public const Int32 RNM_PROBE = (1);
        public const Int32 RNM_DOWN = (2);
        public const Int32 RNM_SLP_BYPASS_ADD = (3);
        public const Int32 RNM_SLP_BYPASS_DEL = (4);

        /* SetUserParam/GetUserParam */

        /* dwParam */
        public const Int32 UP_USER_NAME = (0x00000001);  /* User name. pbData == szUserName */
        public const Int32 UP_AUTH_MASK = (0x00000002);  /* Authorization mask. pdData == dwAuthMask */
        public const Int32 UP_ACCESS_TYPE = (0x00000004);  /* Access type mask. pbData == dwAccessType */
        public const Int32 UP_CERTIFICATE = (0x00000008);  /* User certificate. pbData == pbCertificate */
        public const Int32 UP_PASSWORD = (0x00000010);  /* User password. pbData == pwd */
        public const Int32 UP_INVALID_LOGIN_ATTEMPTS = (0x00000020);  /* Amount of invalid login attempts. pbData == DWORD */
        public const Int32 UP_BLOCK_USR = (0x00000040);  /* Block user. == szUserName */
        public const Int32 UP_UNBLOCK_USR = (0x00000080);  /* Unblock user. == szUserName */
        public const Int32 UP_USR_PASSWORD = (0x00000100);  /* Re-define user password. == USER_INFO */

        /* FindUser */

        /* dwFindType */
        public const Int32 FU_USER_ID = (0x00000001);  /* User ID pvFindParam == szUserId */
        public const Int32 FU_USER_NAME = (0x00000002);  /* User ID pvFindParam == szUserName */
        public const Int32 FU_AUTH_MASK = (0x00000004);  /* Authorization mask. pvFindParam == dwAuthMask */
        public const Int32 FU_ACCESS_TYPE = (0x00000008);  /* Access type. pvFindParam == dwAccessType */
        public const Int32 FU_ROOT_ID = (0x00000010);  /* Root certificate issuer. pvFindParam == szRootCN */

        /* dwFlags */
        public const Int32 PARTIAL_VALUE = (0x00000080);  /* pvFindParam contains part of the search value. */


        public const Int32 INVALID_OBJ_TYPE = (0);


        public const Int32 MAX_REPL_DOMAIN_NAME = GET_INFO_MAX_REPL_DOMAIN_NAME;
        public const Int32 MAX_REPL_NODES = GET_INFO_MAX_REPL_NODES;


        //Replication states returned by SYS_REPL_INFO structure.
        public const Int32 REPL_STATE_TWOPC_VIRTUAL = (1);
        public const Int32 REPL_STATE_TWOPC_PREPARED = (2);
        public const Int32 REPL_STATE_TWOPC_COMMITTED = (3);
        public const Int32 REPL_STATE_TWOPC_COMMITTED_TM = (4);

        //Replication events returned by SYS_REPL_INFO structure.
        public const Int32 REPL_EVENT_ET_NULL = (1);
        public const Int32 REPL_EVENT_ET_CREATE_USR = (2);
        public const Int32 REPL_EVENT_ET_DELETE_USR = (3);
        public const Int32 REPL_EVENT_ET_CREATE_OBJ = (4);
        public const Int32 REPL_EVENT_ET_DELETE_OBJ = (5);
        public const Int32 REPL_EVENT_ET_DELETE_USR_OTP_AUTH_INFO = (6);
        public const Int32 REPL_EVENT_ET_WRITE_USR_OTP_AUTH_INFO = (7);
        public const Int32 REPL_EVENT_ET_UPDATE_USR_OTP_AUTH_INFO = (8);
        public const Int32 REPL_EVENT_ET_CHANGE_USR_PWD = (9);
        public const Int32 REPL_EVENT_ET_SET_USR_LOCK_COUNT = (10);
        public const Int32 REPL_EVENT_ET_SET_GLOBAL_SEC_POLICY = (11);
        public const Int32 REPL_EVENT_ET_SET_SYS_DATE_TIME = (12);
        public const Int32 REPL_EVENT_ET_UPDATE_ACL = (13);
        public const Int32 REPL_EVENT_ET_BLOCK_OBJ = (14);
        public const Int32 REPL_EVENT_ET_UPDATE_OBJ = (15);
        public const Int32 REPL_EVENT_ET_SET_USR_NS_AUTH_COOKIE = (16);
        public const Int32 REPL_EVENT_ET_SET_USR_OTP_MOV_FACTOR = (17);

        /* DListUserTrusts */

        public const Int32 OP_LST_USR_TRUSTERS = (0x01); /* List users that permits the current logged user to access it's partition. */
        public const Int32 OP_LST_USR_TRUSTEES = (0x02); /* List users that have permission to access the current logged user's partition. */


        /* DAssignToken/DUnassignToken */

        public const Int32 AT_GO3_TOKEN = (1); /* DEPRECATED! */
        public const Int32 AT_OATH_TOKEN = (2); /* Assign a OATH EVENT OTP token */
        public const Int32 AT_OATH_TOKEN_TOTP = (3); /* Assign a OATH TIME OTP token */

        //
        // mod_OATH's NEW_SA; use with structure OATH_SA_v1.
        //
        public const Int32 MAX_OATH_HMAC_LEN = (128);   // up to hmac-sha512, in bytes

        public const Int32 OATH_SA_v1_type_SHA1 = (0x01);
        public const Int32 OATH_SA_v1_HOTP_DYN_TRUNC_OFF = (16);
        public const Int32 OATH_SA_v2_default_TIME_STEP = (30);
        public const Int32 OATH_SA_v2_default_T0_Epoch = (0);


        /* DOATHResync */

        public const Int32 OATH_MIN_HOTP_LEN = (6 + 1); //plus 1 for the null terminator
        public const Int32 OATH_MAX_HOTP_LEN = (16 + 1); //plus 1 for the null terminator

        /* DOATHGetBlobInfo */

        public const Int32 OATH_ISSUE_OATH_BLOB_t = (1);
        public const Int32 OATH_ISSUE_OATH_INFO_t = (2);


        /* DPKCS7Sign - Sign using PKCS#7 */

        public const Int32 TAC_MOD_CORE_P7_TEXT = 0x0001;
        public const Int32 TAC_MOD_CORE_P7_NOCERTS = 0x0002;
        public const Int32 TAC_MOD_CORE_P7_NOSIGS = 0x0004;
        public const Int32 TAC_MOD_CORE_P7_NOCHAIN = 0x0008;
        public const Int32 TAC_MOD_CORE_P7_NOINTERN = 0x0010;
        public const Int32 TAC_MOD_CORE_P7_NOVERIFY = 0x0020;
        public const Int32 TAC_MOD_CORE_P7_DETACHED = 0x0040;
        public const Int32 TAC_MOD_CORE_P7_BINARY = 0x0080;
        public const Int32 TAC_MOD_CORE_P7_NOATTR = 0x0100;
        public const Int32 TAC_MOD_CORE_P7_NOSMIMECAP = 0x0200;
        public const Int32 TAC_MOD_CORE_P7_NOOLDMIMETYPE = 0x0400;
        public const Int32 TAC_MOD_CORE_P7_CRLFEOL = 0x0800;
        public const Int32 TAC_MOD_CORE_P7_NOCRL = 0x2000;




        /* HASH algorithms */

        public const Int32 ALG_MD5 = (1);
        public const Int32 ALG_SHA1 = (2);
        public const Int32 ALG_SSL_SHA1_MD5 = (3);
        public const Int32 ALG_SHA2_256 = (4);
        public const Int32 ALG_SHA2_384 = (5);
        public const Int32 ALG_SHA2_512 = (6);


        /*
	        DSignXML/DSignXML2/DPIXSign hash mode options.
        */
        public const Int32 ALG_MD5_InclC14N = (1);
        public const Int32 ALG_SHA1_InclC14N = (2);
        public const Int32 ALG_SHA256_InclC14N = (3);
        public const Int32 ALG_SHA384_InclC14N = (4);
        public const Int32 ALG_SHA512_InclC14N = (5);
        public const Int32 ALG_SHA224_InclC14N = (6);
        public const Int32 ALG_MD5_ExclC14N = (31);
        public const Int32 ALG_SHA1_ExclC14N = (32);
        public const Int32 ALG_MD5_InclC14NWithComments = (33);
        public const Int32 ALG_SHA1_InclC14NWithComments = (34);
        public const Int32 ALG_MD5_ExclC14NWithComments = (35);
        public const Int32 ALG_SHA1_ExclC14NWithComments = (36);
        public const Int32 ALG_SHA256_ExclC14N = (37);
        public const Int32 ALG_SHA256_InclC14NWithComments = (38);
        public const Int32 ALG_SHA256_ExclC14NWithComments = (39);
        public const Int32 ALG_SHA384_ExclC14N = (40);
        public const Int32 ALG_SHA384_InclC14NWithComments = (41);
        public const Int32 ALG_SHA384_ExclC14NWithComments = (42);
        public const Int32 ALG_SHA512_ExclC14N = (43);
        public const Int32 ALG_SHA512_InclC14NWithComments = (44);
        public const Int32 ALG_SHA512_ExclC14NWithComments = (45);
        public const Int32 ALG_SHA224_ExclC14N = (46);
        public const Int32 ALG_SHA224_InclC14NWithComments = (47);
        public const Int32 ALG_SHA224_ExclC14NWithComments = (48);

        /* 
	        DSignXML2 flags
        */

        public const Int32 XML_SIGN_FLAGS_NOL = (1 << 31);

        /*
            DSignXML/DSignXML2 filter options
        */

        public const String XML_FILTER_NULL_URI = "''";

        /* DPIXPost/DPIXGet/DPIXDelete */

        public const Int32 PIX_VERIFY_HOST_NAME = (1);

        /*
	        DPIXJWSSign
        */
        public const Int32 PIX_JWS_GEN_MAX_LEN = (8 * 1024);

        public const Int32 MD5_LEN = (16);
        public const Int32 SHA1_LEN = (20);
        public const Int32 SSL_SHA1_MD5_LEN = (36);
        public const Int32 SHA2_256_LEN = (32);
        public const Int32 SHA2_384_LEN = (48);
        public const Int32 SHA2_512_LEN = (64);

        public const Int32 MAX_HASH_LEN = SHA2_512_LEN;

        /* Digital signature */

        public const Int32 NO_HASH_OID = (1);
        public const Int32 MD5_HASH_OID = (2);
        public const Int32 SHA_HASH_OID = (3);
        public const Int32 SHA256_HASH_OID = (4);
        public const Int32 SHA384_HASH_OID = (5);
        public const Int32 SHA512_HASH_OID = (6);

        public const Int32 MD5_HASH_OID_LEN = (18);
        public const Int32 SHA_HASH_OID_LEN = (15);
        public const Int32 SHA256_HASH_OID_LEN = (19);
        public const Int32 SHA384_HASH_OID_LEN = (19);
        public const Int32 SHA512_HASH_OID_LEN = (19);

        /* Symmetric cryptography algorithms */

        public const Int32 ALG_DES = (1);
        public const Int32 ALG_3DES_112 = (2);  /* EDE */
        public const Int32 ALG_3DES_168 = (3);  /* EDE */
        public const Int32 ALG_DESX = (91);

        public const Int32 ALG_AES_128 = (7);
        public const Int32 ALG_AES_192 = (8);
        public const Int32 ALG_AES_256 = (9);

        public const Int32 ALG_ARC4 = (10);

        /* Symmetric key sizes = (bytes); */

        public const Int32 ALG_DES_LEN = (8);
        public const Int32 ALG_DES3_112_LEN = (16);
        public const Int32 ALG_DES3_168_LEN = (24);

        //Deprecated
        public const Int32 DES_LEN = (ALG_DES_LEN);
        public const Int32 DES3_112_LEN = (ALG_DES3_112_LEN);
        public const Int32 DES3_168_LEN = (ALG_DES3_168_LEN);

        public const Int32 ALG_DESX_LEN = (24);

        public const Int32 ALG_AES_128_LEN = (16);
        public const Int32 ALG_AES_192_LEN = (24);
        public const Int32 ALG_AES_256_LEN = (32);

        public const Int32 ALG_ARC4_LEN = (16);

        /* Block sizes */

        public const Int32 DES_BLOCK = (8);
        public const Int32 DES3_BLOCK = (8);
        public const Int32 DESX_BLOCK = (8);
        public const Int32 AES_BLOCK = (16);
        public const Int32 AES_128_BLOCK = (16);
        public const Int32 AES_192_BLOCK = (16);
        public const Int32 AES_256_BLOCK = (16);

        /* Operation modes */

        public const Int32 MODE_NONE = (0);
        public const Int32 MODE_ECB = (1 << 0);
        public const Int32 MODE_CBC = (1 << 1);
        public const Int32 MODE_CFB = (1 << 2);
        public const Int32 MODE_OFB = (1 << 3);

        /* Operation directions */

        public const Int32 D_ENCRYPT = (0 << 7);
        public const Int32 D_DECRYPT = (1 << 7);

        /* Asymmetric algorithms */

        public const Int32 ALG_RSA_512 = (4);
        public const Int32 ALG_RSA_1024 = (5);
        public const Int32 ALG_RSA_2048 = (6);
        public const Int32 ALG_RSA_4096 = (11);
        public const Int32 ALG_RSA_1152 = (121);
        public const Int32 ALG_RSA_1408 = (122);
        public const Int32 ALG_RSA_1984 = (123);
        public const Int32 ALG_RSA_8192 = (124);
        public const Int32 ALG_RSA_2304 = (126);
        public const Int32 ALG_RSA_2560 = (127);
        public const Int32 ALG_RSA_2816 = (128);
        public const Int32 ALG_RSA_3072 = (129);

        public const Int32 ALG_ECC_SECP112R1 = (18); // SECG/WTLS curve over a 112 bit prime field
        public const Int32 ALG_ECC_SECP112R2 = (19); // SECG curve over a 112 bit prime field
        public const Int32 ALG_ECC_SECP128R1 = (20); // SECG curve over a 128 bit prime field
        public const Int32 ALG_ECC_SECP128R2 = (21); // SECG curve over a 128 bit prime field
        public const Int32 ALG_ECC_SECP160K1 = (22); // SECG curve over a 160 bit prime field
        public const Int32 ALG_ECC_SECP160R1 = (23); // SECG curve over a 160 bit prime field
        public const Int32 ALG_ECC_SECP160R2 = (24); // SECG/WTLS curve over a 160 bit prime field
        public const Int32 ALG_ECC_SECP192K1 = (25); // SECG curve over a 192 bit prime field
        public const Int32 ALG_ECC_SECP192R1 = (26); // NIST/X9.62/SECG curve over a 192 bit prime field
        public const Int32 ALG_ECC_SECP224K1 = (27); // SECG curve over a 224 bit prime field
        public const Int32 ALG_ECC_SECP224R1 = (28); // NIST/SECG curve over a 224 bit prime field
        public const Int32 ALG_ECC_SECP256K1 = (29); // SECG curve over a 256 bit prime field
        public const Int32 ALG_ECC_SECP256R1 = (30); // X9.62/SECG curve over a 256 bit prime field
        public const Int32 ALG_ECC_SECP384R1 = (31); // NIST/SECG curve over a 384 bit prime field
        public const Int32 ALG_ECC_SECP521R1 = (32); // NIST/SECG curve over a 521 bit prime field
        public const Int32 ALG_ECC_X9_62_PRIME192V1 = (ALG_ECC_SECP192R1);
        public const Int32 ALG_ECC_X9_62_PRIME192V2 = (33); // X9.62 curve over a 192 bit prime field
        public const Int32 ALG_ECC_X9_62_PRIME192V3 = (34); // X9.62 curve over a 192 bit prime field
        public const Int32 ALG_ECC_X9_62_PRIME239V1 = (35); // X9.62 curve over a 239 bit prime field
        public const Int32 ALG_ECC_X9_62_PRIME239V2 = (36); // X9.62 curve over a 239 bit prime field
        public const Int32 ALG_ECC_X9_62_PRIME239V3 = (37); // X9.62 curve over a 239 bit prime field
        public const Int32 ALG_ECC_X9_62_PRIME256V1 = (ALG_ECC_SECP256R1);

        public const Int32 ALG_ECC_BRAINPOOL_P160R1 = (38); // RFC 5639 standard curves
        public const Int32 ALG_ECC_BRAINPOOL_P160T1 = (39);
        public const Int32 ALG_ECC_BRAINPOOL_P192R1 = (40);
        public const Int32 ALG_ECC_BRAINPOOL_P192T1 = (41);
        public const Int32 ALG_ECC_BRAINPOOL_P224R1 = (42);
        public const Int32 ALG_ECC_BRAINPOOL_P224T1 = (43);
        public const Int32 ALG_ECC_BRAINPOOL_P256R1 = (44);
        public const Int32 ALG_ECC_BRAINPOOL_P256T1 = (45);
        public const Int32 ALG_ECC_BRAINPOOL_P320R1 = (46);
        public const Int32 ALG_ECC_BRAINPOOL_P320T1 = (47);
        public const Int32 ALG_ECC_BRAINPOOL_P384R1 = (48);
        public const Int32 ALG_ECC_BRAINPOOL_P384T1 = (49);
        public const Int32 ALG_ECC_BRAINPOOL_P512R1 = (50);
        public const Int32 ALG_ECC_BRAINPOOL_P512T1 = (51);


        /* blobs */
        public const Int32 BLOB_TYPE = (12);
        public const Int32 ALG_OBJ_BLOB = (12);
        public const Int32 ALG_OBJ_BLOB_X509 = (13);
        public const Int32 ALG_OBJ_BLOB_PKCS7 = (14);
        public const Int32 ALG_OBJ_BLOB_CRL = (15);
        public const Int32 ALG_OBJ_BLOB_HOTP = (16);
        public const Int32 ALG_OBJ_BLOB_DPGO3 = (17); /* TAC-PASS = (Vasco Digipass GO3 Compatible); */
        public const Int32 ALG_OBJ_MAP = (90);
        public const Int32 ALG_OBJ_EXT_MAP_2_OBJ = (125);

        /* HMAC objects */

        public const Int32 ALG_HMAC_MD5 = (92);
        public const Int32 ALG_HMAC_SHA1 = (93);
        public const Int32 ALG_HMAC_SHA2_256 = (94);
        public const Int32 ALG_HMAC_SHA2_384 = (95);
        public const Int32 ALG_HMAC_SHA2_512 = (96);

        /* PKCS11 objects */

        public const Int32 ALG_PKCS11_MAP = (120); // pkcs11 shell obj



        public const Int32 MAX_ALG_ID = (ALG_OBJ_EXT_MAP_2_OBJ);


        /* Public keys -> most significant bit of the DWORD must be set. */

        public const Int32 ALG_RSA_512_PUB = (ALG_RSA_512 | 1 << 31);
        public const Int32 ALG_RSA_1024_PUB = (ALG_RSA_1024 | 1 << 31);
        public const Int32 ALG_RSA_2048_PUB = (ALG_RSA_2048 | 1 << 31);
        public const Int32 ALG_RSA_4096_PUB = (ALG_RSA_4096 | 1 << 31);
        public const Int32 ALG_RSA_1152_PUB = (ALG_RSA_1152 | 1 << 31);
        public const Int32 ALG_RSA_1408_PUB = (ALG_RSA_1408 | 1 << 31);
        public const Int32 ALG_RSA_1984_PUB = (ALG_RSA_1984 | 1 << 31);
        public const Int32 ALG_RSA_8192_PUB = (ALG_RSA_8192 | 1 << 31);
        public const Int32 ALG_RSA_2304_PUB = (ALG_RSA_2304 | 1 << 31);
        public const Int32 ALG_RSA_2560_PUB = (ALG_RSA_2560 | 1 << 31);
        public const Int32 ALG_RSA_2816_PUB = (ALG_RSA_2816 | 1 << 31);
        public const Int32 ALG_RSA_3072_PUB = (ALG_RSA_3072 | 1 << 31);


        public const Int32 ALG_ECC_SECP112R1_PUB = (ALG_ECC_SECP112R1 | (1 << 31));
        public const Int32 ALG_ECC_SECP112R2_PUB = (ALG_ECC_SECP112R2 | (1 << 31));
        public const Int32 ALG_ECC_SECP128R1_PUB = (ALG_ECC_SECP128R1 | (1 << 31));
        public const Int32 ALG_ECC_SECP128R2_PUB = (ALG_ECC_SECP128R2 | (1 << 31));
        public const Int32 ALG_ECC_SECP160K1_PUB = (ALG_ECC_SECP160K1 | (1 << 31));
        public const Int32 ALG_ECC_SECP160R1_PUB = (ALG_ECC_SECP160R1 | (1 << 31));
        public const Int32 ALG_ECC_SECP160R2_PUB = (ALG_ECC_SECP160R2 | (1 << 31));
        public const Int32 ALG_ECC_SECP192K1_PUB = (ALG_ECC_SECP192K1 | (1 << 31));
        public const Int32 ALG_ECC_SECP192R1_PUB = (ALG_ECC_SECP192R1 | (1 << 31));
        public const Int32 ALG_ECC_SECP224K1_PUB = (ALG_ECC_SECP224K1 | (1 << 31));
        public const Int32 ALG_ECC_SECP224R1_PUB = (ALG_ECC_SECP224R1 | (1 << 31));
        public const Int32 ALG_ECC_SECP256K1_PUB = (ALG_ECC_SECP256K1 | (1 << 31));
        public const Int32 ALG_ECC_SECP256R1_PUB = (ALG_ECC_SECP256R1 | (1 << 31));
        public const Int32 ALG_ECC_SECP384R1_PUB = (ALG_ECC_SECP384R1 | (1 << 31));
        public const Int32 ALG_ECC_SECP521R1_PUB = (ALG_ECC_SECP521R1 | (1 << 31));
        public const Int32 ALG_ECC_X9_62_PRIME192V1_PUB = (ALG_ECC_SECP192R1_PUB);
        public const Int32 ALG_ECC_X9_62_PRIME192V2_PUB = (ALG_ECC_X9_62_PRIME192V2 | (1 << 31));
        public const Int32 ALG_ECC_X9_62_PRIME192V3_PUB = (ALG_ECC_X9_62_PRIME192V3 | (1 << 31));
        public const Int32 ALG_ECC_X9_62_PRIME239V1_PUB = (ALG_ECC_X9_62_PRIME239V1 | (1 << 31));
        public const Int32 ALG_ECC_X9_62_PRIME239V2_PUB = (ALG_ECC_X9_62_PRIME239V2 | (1 << 31));
        public const Int32 ALG_ECC_X9_62_PRIME239V3_PUB = (ALG_ECC_X9_62_PRIME239V3 | (1 << 31));
        public const Int32 ALG_ECC_X9_62_PRIME256V1_PUB = (ALG_ECC_SECP256R1_PUB);

        public const Int32 ALG_ECC_BRAINPOOL_P160R1_PUB = (ALG_ECC_BRAINPOOL_P160R1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P160T1_PUB = (ALG_ECC_BRAINPOOL_P160T1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P192R1_PUB = (ALG_ECC_BRAINPOOL_P192R1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P192T1_PUB = (ALG_ECC_BRAINPOOL_P192T1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P224R1_PUB = (ALG_ECC_BRAINPOOL_P224R1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P224T1_PUB = (ALG_ECC_BRAINPOOL_P224T1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P256R1_PUB = (ALG_ECC_BRAINPOOL_P256R1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P256T1_PUB = (ALG_ECC_BRAINPOOL_P256T1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P320R1_PUB = (ALG_ECC_BRAINPOOL_P320R1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P320T1_PUB = (ALG_ECC_BRAINPOOL_P320T1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P384R1_PUB = (ALG_ECC_BRAINPOOL_P384R1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P384T1_PUB = (ALG_ECC_BRAINPOOL_P384T1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P512R1_PUB = (ALG_ECC_BRAINPOOL_P512R1 | (1 << 31));
        public const Int32 ALG_ECC_BRAINPOOL_P512T1_PUB = (ALG_ECC_BRAINPOOL_P512T1 | (1 << 31));

        /* Binary objects */

        public const Int32 ALG_OBJ_INVALID_TYPE = (0);
        public const Int32 ALG_OBJ_NULL = (ALG_OBJ_INVALID_TYPE);
        public const Int32 ALG_OBJ = (12);
        public const Int32 OBJ_BLOCK = (1);


        /* RSA module sizes */
        public const Int32 RSA_512_LEN = (64);
        public const Int32 RSA_1024_LEN = (128);
        public const Int32 RSA_2048_LEN = (256);
        public const Int32 RSA_4096_LEN = (512);
        public const Int32 RSA_1152_LEN = (144);
        public const Int32 RSA_1408_LEN = (176);
        public const Int32 RSA_1984_LEN = (248);
        public const Int32 RSA_8192_LEN = (1024);


        /*
        *	Sizes only valid for default public key
        *	exportations.
        */
        public const Int32 RSA_512_PUB_LEN = (74);
        public const Int32 RSA_1024_PUB_LEN = (140);
        public const Int32 RSA_2048_PUB_LEN = (270);
        public const Int32 RSA_4096_PUB_LEN = (526);
        public const Int32 RSA_1152_PUB_LEN = (156);
        public const Int32 RSA_1408_PUB_LEN = (188);
        public const Int32 RSA_1984_PUB_LEN = (261);
        public const Int32 RSA_8192_PUB_LEN = (1024 + 128);


        public const Int32 MAX_RSA_LEN = RSA_8192_LEN;
        public const Int32 MAX_RSA_PUB_LEN = RSA_8192_PUB_LEN;

        /* ECC key sizes = (bits); */
        public const Int32 ECC_SECP112R1_LEN = (112);
        public const Int32 ECC_SECP112R2_LEN = (112);
        public const Int32 ECC_SECP128R1_LEN = (128);
        public const Int32 ECC_SECP128R2_LEN = (128);
        public const Int32 ECC_SECP160K1_LEN = (160);
        public const Int32 ECC_SECP160R1_LEN = (160);
        public const Int32 ECC_SECP160R2_LEN = (160);
        public const Int32 ECC_SECP192K1_LEN = (192);
        public const Int32 ECC_SECP192R1_LEN = (192);
        public const Int32 ECC_SECP224K1_LEN = (224);
        public const Int32 ECC_SECP224R1_LEN = (224);
        public const Int32 ECC_SECP256K1_LEN = (256);
        public const Int32 ECC_SECP256R1_LEN = (256);
        public const Int32 ECC_SECP384R1_LEN = (384);
        public const Int32 ECC_SECP521R1_LEN = (521);
        public const Int32 ECC_X9_62_PRIME192V1_LEN = (ECC_SECP192R1_LEN);
        public const Int32 ECC_X9_62_PRIME192V2_LEN = (192);
        public const Int32 ECC_X9_62_PRIME192V3_LEN = (192);
        public const Int32 ECC_X9_62_PRIME239V1_LEN = (239);
        public const Int32 ECC_X9_62_PRIME239V2_LEN = (239);
        public const Int32 ECC_X9_62_PRIME239V3_LEN = (239);
        public const Int32 ECC_X9_62_PRIME256V1_LEN = (ECC_SECP256R1_LEN);

        public const Int32 ECC_BRAINPOOL_P160R1_LEN = (160); // RFC 5639 standard curves
        public const Int32 ECC_BRAINPOOL_P160T1_LEN = (160);
        public const Int32 ECC_BRAINPOOL_P192R1_LEN = (192);
        public const Int32 ECC_BRAINPOOL_P192T1_LEN = (192);
        public const Int32 ECC_BRAINPOOL_P224R1_LEN = (224);
        public const Int32 ECC_BRAINPOOL_P224T1_LEN = (224);
        public const Int32 ECC_BRAINPOOL_P256R1_LEN = (256);
        public const Int32 ECC_BRAINPOOL_P256T1_LEN = (256);
        public const Int32 ECC_BRAINPOOL_P320R1_LEN = (320);
        public const Int32 ECC_BRAINPOOL_P320T1_LEN = (320);
        public const Int32 ECC_BRAINPOOL_P384R1_LEN = (384);
        public const Int32 ECC_BRAINPOOL_P384T1_LEN = (384);
        public const Int32 ECC_BRAINPOOL_P512R1_LEN = (512);
        public const Int32 ECC_BRAINPOOL_P512T1_LEN = (512);

        /* Initialization vector sizes */

        public const Int32 DES_IV_LEN = (8);
        public const Int32 AES_IV_LEN = (16);

        public const Int32 D_FORCE_ACTUAL_RSA = (4);

        /* Padding */

        public const Int32 D_NO_PADDING = (0);
        public const Int32 D_PKCS5_PADDING = (1);
        public const Int32 D_ZERO_PADDING = (2);
        public const Int32 D_NO_RSA_PADDING = (3);
        public const Int32 D_PKCS1_PADDING = (4);

        /* Key Blobs */
        public const Int32 PRIVATEKEY_BLOB = (1);
        public const Int32 PUBLICKEY_BLOB = (2);
        public const Int32 SIMPLE_BLOB = (3);
        public const Int32 PLAINTEXTKEY_BLOB = (4);
        public const Int32 RAW_BLOB = (5);
        public const Int32 HOTP_BLOB = (6);
        public const Int32 SIMPLE_BLOB_OAEP = (7);
        public const Int32 SIMPLE_BLOB_PKCS1 = (SIMPLE_BLOB);
        public const Int32 PUBLICKEY_BLOB_X509 = (8);
        public const Int32 SYM_WRAPPED_KEY_BLOB = (9);


        /* Pkcs11 Blobs */
        public const Int32 P11_BLOB = (1);

        /* Pkcs11 Update Flags */

        public const Int32 UPDATE_P11_target = (1 << 0);
        public const Int32 UPDATE_P11_associate = (1 << 1);
        public const Int32 UPDATE_P11_Class = (1 << 2);
        public const Int32 UPDATE_P11_App = (1 << 3);
        public const Int32 UPDATE_P11_Id = (1 << 4);
        public const Int32 UPDATE_P11_Label = (1 << 5);
        public const Int32 UPDATE_P11_Trusted = (1 << 6);
        public const Int32 UPDATE_P11_WrapWithTrusted = (1 << 7);
        public const Int32 UPDATE_P11_Local = (1 << 8);
        public const Int32 UPDATE_P11_CertificateCategory = (1 << 9);
        public const Int32 UPDATE_P11_JavaMidpSecDomain = (1 << 10);
        public const Int32 UPDATE_P11_KeyGenMechanism = (1 << 11);

        /* Key types */

        /* Flags */
        public const Int32 NONEXPORTABLE_KEY = (0x00000000);  /* Mark the key as non exportable. */
        public const Int32 EXPORTABLE_KEY = (0x00000001);  /* Mark the key as exportable. */
        public const Int32 NO_CRYPTO = (0x00000002);  /* The key will not be encrypted inside the HSM. Deprecated in newer versions. */
        public const Int32 TEMPORARY_KEY = (0x00000004);  /* Mark key as temporary. Key will exist while the session exists. = (default in ImportKey);. */
        public const Int32 PERMANENT_KEY = (0x00000008);  /* The key will be persistent in the HSM. = (default in GenerateKey and ImportKeyPart);. */
        public const Int32 DESTROY_KEY = (0x00000010);  /* Destroy key handle after function use. */
        public const Int32 REMOVE_FROM_HSM = (0x00000020);  /* Erase a key from the HSM and destroys it's handle. */
        public const Int32 REMOVE_FROM_HCM = (REMOVE_FROM_HSM);  /* DEPRECATED. use REMOVE_FROM_HSM */
        public const Int32 REMOVE_ATTRIBUTE = (0x00000040);
        public const Int32 RSA_PUB_EXP3 = (0x00000800);  /* Use exponent 0x03 when generating a RSA key pair */
        public const Int32 MOD_SPB_RELATED = (0x00001000);  /* Mark as mod_SPB related object */

        /* SetKeyParam/GetKeyParam */

        public const Int32 DKP_ALGID = (1);  /* Key algorithm ID. pbData == nAlgId */
        public const Int32 DKP_IV = (2);  /* Initialization Vector. pbData == pbIV */
        public const Int32 DKP_PADDING = (3);  /* Padding format. pbData == dwPadding */
        public const Int32 DKP_MODE = (4);  /* Operation mode. pbData == dwOpMode */
        public const Int32 DKP_OWNER = (5);  /* Key owner. pbData == szUserId = (separated by ";" ); */
        public const Int32 DKP_USER = (6);  /* Key user. pbData == szUserId = (separated by ";" );*/
        public const Int32 DKP_READ_LOCK = (7);  /* Key read lock status. pbData == NULL */
        public const Int32 DKP_ENCRYPTED = (8);  /* Encrypted object. */
        public const Int32 DKP_KEYLEN = (9);  /* Key size = (bytes);. */
        public const Int32 DKP_TEMPORARY_KEY = (10); /* Temporary key. pbData == dwTempKey */
        public const Int32 DKP_MAP_VALUE = (11); /* Values of a MAP object.pbData == MAP_2_OBJ_INFO*/
        public const Int32 DKP_BLOCKED = (12); /* Block object. pbData == nBlocked = (TRUE|FALSE);*/
        public const Int32 DKP_CERT_X509_INFO = (13); /* Returns information of a x.509 certificate. pbData == CERT_X509_INFO */
        public const Int32 DKP_SESSION = (14); /* Session associated to the key handle. pbData == HSESSIONCTX */
        public const Int32 DKP_KEY_ID = (15); /* Key name associated to the key handle. pbData == szKeyId */
        public const Int32 DKP_PUB_KEY_EXP = (16); /* Public exponent for the key. pbData == DBLOB */


        /* SetHashParam/GetHashParam */

        public const Int32 DHP_ALGID = (1);  /* Hash algorithm. */
        public const Int32 DHP_HASH_VALUE = (2);  /* Hash value. */
        public const Int32 DHP_HASH_SIZE = (4);  /* Hash size = (bytes);. */

        /* HashSessionKey */

        public const Int32 DHS_LITTLE_ENDIAN = (1);

        /* DSetObjParam */
        public const Int32 OP_OBJ_BLOCKED = (1);  /* User blocked */
        public const Int32 OP_OBJ_UNBLOCKED = (2);  /* Used unblocked */

        /* LogParam */

        public const Int32 LP_LOG_PATH = (0x00000001);  /* Log file full path. */
        public const Int32 LP_LOG_LEVEL = (0x00000002); /* Log level. */

        public const Int32 LOG_ERROR_LEVEL = (0); /*default*/
        public const Int32 LOG_WARNING_LEVEL = (1);
        public const Int32 LOG_INFO_LEVEL = (2);
        public const Int32 LOG_DEBUG_LEVEL = (3);

        public const Int32 GET_LOG_START_FULL = (0x00000000);
        public const Int32 GET_LOG_END_FULL = (0x00000000);

        /* Permissions */

        public const Int32 ACL_NOP = (0x00000000);       // "may the Force be with ya'!"
        public const Int32 ACL_OBJ_DEL = (ACL_NOP + 1);      // delete objects
        public const Int32 ACL_OBJ_READ = (ACL_OBJ_DEL << 1); // read obj content
        public const Int32 ACL_OBJ_LIST = (ACL_OBJ_READ);     // list usr objs
        public const Int32 ACL_OBJ_CREATE = (ACL_OBJ_DEL << 2); // create obj
        public const Int32 ACL_OBJ_UPDATE = (ACL_OBJ_DEL << 3); // update obj = (hdr and alike);
        public const Int32 ACL_OBJ_WRITE = (ACL_OBJ_UPDATE);   // update obj
        public const Int32 ACL_USR_CREATE = (ACL_OBJ_DEL << 4); // create usr
        public const Int32 ACL_USR_DELETE = (ACL_USR_CREATE);   // makes no sense only to create
        public const Int32 ACL_USR_REMOTE_LOG = (ACL_OBJ_DEL << 5); // can usr use remote log/info?
        public const Int32 ACL_USR_LIST = (ACL_OBJ_DEL << 6); // can usr get user-list?
        public const Int32 ACL_SYS_OPERATOR = (ACL_OBJ_DEL << 7); // operate as master = (adm mode);
        public const Int32 ACL_SYS_BACKUP = (ACL_OBJ_DEL << 8); // extract full appliance backup
        public const Int32 ACL_SYS_RESTORE = (ACL_SYS_BACKUP);   // restore full appliance backup
        public const Int32 ACL_SYS_UDATE_HSM = (ACL_OBJ_DEL << 9); // firmware and stuff like that
        public const Int32 ACL_NS_AUTHORIZATION = (ACL_OBJ_DEL << 10); // user must be authorized with "m of n"
        public const Int32 ACL_VIRTUAL_OTP_AUTH = (ACL_OBJ_DEL << 29); // presence means SA = (user must use 2-F OTP);
        public const Int32 ACL_CHANGE_PWD_NEXT_TIME = (ACL_OBJ_DEL << 30); // can force usrs to change pwd on next login


        public const Int32 ACL_DEFAULT_OWNER = (ACL_OBJ_DEL | ACL_OBJ_READ | ACL_OBJ_CREATE | ACL_OBJ_UPDATE | ACL_OBJ_WRITE);

        /* DGenerateCVV/DVerifyCVV */

        public const Int32 MIN_CVV_LEN = (3 + 1);
        public const Int32 MAX_PAN_LEN = (24 + 1);
        public const Int32 MAX_EXP_DATE_LEN = (4 + 1);
        public const Int32 MAX_SVC_LEN = (3 + 1);

        /* DGeneratePVV */

        public const Int32 EFT_MIN_PVKI = (0x00);
        public const Int32 EFT_MAX_PVKI = (0x06);
        public const Int32 EFT_PVV_LEN = (4);

        /* DGeneratePIN */

        public const Int32 GP_DEFAULT_PIN = (1);
        public const Int32 GP_USER_DEF_PIN = (2);
        public const Int32 GP_RANDOM_PIN = (3);

        /* DEFTExportKey/DEFTKeKImport */

        public const Int32 EK_EFT_KEK_EXPORT_RAW = (1); // BLOB= (); == envelope + checksum[3];
        public const Int32 EK_EFT_KEK_EXPORT_VISA1 = (2); // Variant-1 ZCMK, BLOB= (); == envelope + checksum[3];
        public const Int32 EK_EFT_KEK_EXPORT_LMK = (3); // BLOB= (); == 3DES_CBC= (SVMK, Key);

        /* DPINBlockTranslate */

        // translate types
        public const Int32 TP_TRANSLATE_TYPE_AUTO = (0xFF);
        public const Int32 TP_TRANSLATE_TYPE_IBM_3624 = (0x36);
        public const Int32 TP_TRANSLATE_TYPE_ISO_0 = (1); // == VISA 1; HSM default
        public const Int32 TP_TRANSLATE_TYPE_ISO_1 = (2);
        public const Int32 TP_TRANSLATE_TYPE_ISO_3 = (3);

        /* Other constants */

        public const Int32 MAX_USR_PWD = (16);
        public const Int32 MAX_USR_LEN = (16);
        public const Int32 MAX_CN_LEN = (256);
        public const Int32 MAX_PATH_LEN = (256);
        public const Int32 MAX_MODULE_NAME_LEN = (128);
        public const Int32 MAX_MODULE_VERSION_LEN = (32);
        public const Int32 MAX_ADDR_LEN = (128);
        public const Int32 MIN_PIN_LEN = (8);
        public const Int32 MIN_BACKUP_PIN_LEN = (16);
        public const Int32 MAX_BACKUP_PIN_LEN = (32);
        public const Int32 MAX_OBJ_NAME_LEN = (32);
        public const Int32 MAX_PIN_LEN = (6);
        public const Int32 MAX_MODULE_NAME_VERSION_LEN = (1024);
        public const Int32 MAX_IP_LEN = (15);
        public const Int32 MAX_NET_NAME = (16);
        public const Int32 MAX_HOTP_PIN = (4);
        public const Int32 MAX_HOTP_IMEI = (24);
        public const Int32 MAX_HOTP_APP_NAME = (13);
        public const Int32 MAX_HOTP_LOGO_LEN = (1632);
        public const Int32 MAX_P11_OBJ_ID = (128);
        public const Int32 MAX_OBJ_ID_BIN_LEN = (32 + 1);
        public const Int32 MAX_OBJ_ID = MAX_OBJ_ID_BIN_LEN;
        public const Int32 MAX_OBJ_ID_LEN = (MAX_USR_LEN + 1 + MAX_OBJ_ID);
        public const Int32 MAX_OBJ_ID_FQN_LEN = (MAX_OBJ_ID_LEN);
        public const Int32 MAX_P11_DATE_TXT = (8);
        public const Int32 MIN_EFT_PIN_LEN = (4);
        public const Int32 MAX_EFT_PIN_LEN = (12);
        public const Int32 MIN_KSI_LEN = (5);
        public const Int32 MIN_CTR_LEN = (5);


        /* MOD EFT*/

        public const Int32 EFT_VISA_KEY_CHECKSUM_LEN = (3);
        public const Int32 EFT_EXP_DATE_LEN = (4);

        public const Int32 EFT_EMV_SDA_SEQ_LEN = (2);
        public const Int32 EFT_EMV_SDA_DAC_LEN = (2);

        public const Int32 EFT_EMV_IDN_LEN = (2);
        public const Int32 EFT_EMV_IDN_ATC_LEN = (2);
        public const Int32 EFT_EMV_IDN_UN_LEN = (4);

        public const Int32 EFT_EMV_CSR_VISA_TRACK_NUM_LEN = (3);
        public const Int32 EFT_EMV_CSR_VISA_SERVICE_ID_LEN = (4);
        public const Int32 EFT_EMV_CSR_VISA_ISSUER_ID_LEN = (4);
        public const Int32 EFT_EMV_CSR_VISA_PUB_KEY_INDEX_LEN = (3);

        public const Int32 EFT_EMV_CSR_VISA_HASH_SIZE = (20);
        public const Int32 EFT_EMV_CSR_MASTER_HASH_SIZE = (28);



        /* DGenerateICCMK */

        public const Int32 EFT_EMV_GEN_ICC_MK_OP_CBC_EXP = (0x01);
        public const Int32 EFT_EMV_GEN_ICC_MK_OP_ECB_EXP = (0x02);

        /* DMAC_ISO9797_1_Met2*/

        public const Int32 EMV_MAC_TYPE_ALG1 = (1);
        public const Int32 EMV_MAC_TYPE_ALG3 = (2);

        /* DGenerateEMV_MAC/DGenerateEMV_HMAC */

        public const Int32 EMV_OP_ISO_9797_1_M2_COMMON = (0x01);
        public const Int32 EMV_OP_ISO_9797_1_M2_MCHIP = (0x02);
        public const Int32 EMV_OP_ISO_9797_1_M2_VISA = (0x03);
        public const Int32 EMV_OP_ISO_9797_1_M2_VISA_CRYPTOGRAM = (0x04);
        public const Int32 EMV_OP_ISO_9797_1_M2_VISA_ICC_V1_4_PAN_AUTO = (0x05);
        public const Int32 EMV_OP_ISO_9797_1_M2_RAW = (0x06);
        public const Int32 EMV_OP_ISO_9797_1_M1_VISA_CRYPTOGRAM_PADD_V10 = (0x7F);
        public const Int32 EMV_OP_ISO_9797_1_M2_ELO = (0x07);

        /* DGenerateDDA_ICCCert */

        public const Int32 EFT_EMV_DDA_OP_RSA_SIGN1 = (0x01); // rsa + sha1

        /* DGenerateEMV_CSR */

        public const Int32 EFT_EMV_OP_CSR_VISA = (0x01);
        public const Int32 EFT_EMV_OP_CSR_MASTER = (0x02);
        public const Int32 EFT_EMV_OP_CSR_ELO = (0x03);


        /* DGenerateISO9796Cert2 */

        public const Int32 CORE_P_ISO_9796_USER_ID_LEN = (32);
        public const Int32 CORE_P_ISO_9796_USER_NAME_LEN = (32);
        public const Int32 CORE_P_ISO_9796_KEY_LEN = (512); // 128
        public const Int32 CORE_P_ISO_9796_MIN_KEY_LEN = (64);
        public const Int32 CORE_P_ISO_9796_EXPONENT_LEN = (8);
        public const Int32 CORE_P_ISO_9796_MIN_EXPONENT_LEN = (1);


        /* DGenerateEMV_PinBlock */

        public const Int32 PBC_EMV_PIN_BLOCK_OP_COMMON = (EMV_OP_ISO_9797_1_M2_COMMON);
        public const Int32 PBC_EMV_PIN_BLOCK_OP_MCHIP = (EMV_OP_ISO_9797_1_M2_MCHIP);
        public const Int32 PBC_EMV_PIN_BLOCK_OP_VISA = (EMV_OP_ISO_9797_1_M2_VISA);
        public const Int32 PBC_EMV_PIN_BLOCK_OP_VISA_CRYPTOGRAM = (EMV_OP_ISO_9797_1_M2_VISA_CRYPTOGRAM);
        public const Int32 PBC_EMV_PIN_BLOCK_OP_ELO = (EMV_OP_ISO_9797_1_M2_ELO);

        public const Int32 PBC_EMV_PIN_BLOCK_MAX_OUTPUT = (64);


        /* DDeriveKeyFromBuffer */

        public const Int32 EMV_DERIVE_KEY_OP_XOR = (0x01);
        public const Int32 EMV_DERIVE_KEY_OP_ECB = (0x02);


        /* DGeneratePKCS10CSR */

        public const Int32 CORE_P10_CSR_VERSION1 = (0x00);
        public const Int32 CORE_P10_CSR_DN_MAX_LEN = (2048);

        public const Int32 P10_CSR_DER = (1);
        public const Int32 P10_CSR_PEM = (2);

        public const Int32 CORE_P10_HASH_SHA1 = (0x01);
        public const Int32 CORE_P10_HASH_SHA224 = (0x02);
        public const Int32 CORE_P10_HASH_SHA256 = (0x03);
        public const Int32 CORE_P10_HASH_SHA384 = (0x04);
        public const Int32 CORE_P10_HASH_SHA512 = (0x05);

        /* DPKCS8ExportKey */

        // ASCII
        public const Int32 CORE_P8_EXPORT_PWD_LEN = (16);

        /* SPB */

        public const Int32 ND_SPB_MSG_HEADER_V2_LEN = (588);
        public const Int32 ND_SPB_MAX_NOTIFY_DATA_SEG = (32 * 1024);
        public const uint ND_SPB_USE_CIP1 = (0x80000000);
        public const uint ND_SPB_USE_ANY = (0x40000000);

        /* DSPBEncode */

        public const Int32 ND_SPB_HASH_MODE_SHA1 = (0x02);
        public const Int32 ND_SPB_HASH_MODE_SHA256 = (0x03);

        /* DSPBDecode */

        public const Int32 ND_SPB_REMOVE_PADDING = (0x01);

        public const Int32 ND_SPB_OUT_NO_PADDING = (0x01);
        public const Int32 ND_SPB_OUT_WITH_PADDING = (0x02);

        public const Int32 ND_SPB_ISPB_LEN = (8);
        public const Int32 ND_SPB_CA_LEN = (2);
        public const Int32 ND_SPB_DOMAIN_MAX_LEN = (5);
        public const Int32 ND_SPB_SN_MAX_LEN = (32);
        public const Int32 ND_SPB_ID_MAX_LEN = (ND_SPB_SN_MAX_LEN + 1 + ND_SPB_CA_LEN + 1);
        public const Int32 ND_SPB_MAX_SUBJECT = (1024);
        public const Int32 ND_SPB_MAX_ISSUER = (1024);
        public const Int32 ND_SPB_MAX_ALG_ID = (256);

        //strong auth
        public const Int32 SA_TP_MAX_DES_LEN = (16 + 1);
        public const Int32 SA_TP_MAX_OFFSET_LEN = (6 + 1);
        public const Int32 SA_TP_MAX_SERIAL_LEN = (10 + 1);
        public const Int32 SA_TP_MAX_MKEY_LEN = (32 + 1);
        public const Int32 SA_TP_MAX_OTP_LEN = (6 + 1);


        /* Module OATH */

        /* DOATHIssueHOTPBlob */
        public const Int32 ISSUE_OATH_MIN_OTP_LEN = (6);
        public const Int32 ISSUE_OATH_MAX_OTP_LEN = (16);
        public const Int32 ISSUE_OATH_MAX_OTP_RETRY = (129);

        //bSeedLen
        public const Int32 ISSUE_OATH_SHA1_LEN = (20);
        public const Int32 ISSUE_OATH_SHA256_LEN = (32);
        public const Int32 ISSUE_OATH_SHA512_LEN = (64);

        //bTruncationOffset
        public const Int32 ISSUE_OATH_DYN_TRUNC = (OATH_SA_v1_HOTP_DYN_TRUNC_OFF);

        //wTimeStep
        public const Int32 ISSUE_OATH_DEFAULT_TIME_STEP = (OATH_SA_v2_default_TIME_STEP);
        public const Int32 ISSUE_OATH_HOTP_TS = (0);

        //otT0
        public const Int32 ISSUE_OATH_HOTP_T0 = (OATH_SA_v2_default_T0_Epoch);

        //otMovingFactor
        public const Int32 ISSUE_OATH_INIT_MF = (0);

        public const Int32 ISSUE_OATH_OUTPUT_BLOB_V1_LEN = (160);
        public const Int32 ISSUE_OATH_OUTPUT_BLOB_V2_LEN = (180);
        public const Int32 ISSUE_OATH_OUTPUT_BLOB_LEN = (ISSUE_OATH_OUTPUT_BLOB_V1_LEN);
        public const Int32 ISSUE_OATH_OUTPUT_MAX_BLOB_LEN = (ISSUE_OATH_OUTPUT_BLOB_V2_LEN);


        public const Int32 OATH_MAX_PSK_LEN = (255);



        public const Int32 DEFAULT_PORT = (4433);

        public const Int32 ISSUE_OATH_GENERATE_HOTP = (1);
        public const Int32 ISSUE_OATH_GENERATE_TOTP = (2);
        public const Int32 ISSUE_OATH_IMPORT_HOTP = (3);
        public const Int32 ISSUE_OATH_IMPORT_TOTP = (4);

        public const Int32 OATH_UPDATE_BLOB = (1 << 31);

        public const Int32 ISSUE_OATH_BLOB_V2_IV_LEN = (AES_BLOCK);
        public const Int32 ISSUE_OATH_BLOB_V2_TAG_LEN = (AES_BLOCK);

        /* DListObjsFilter */

        public const Int32 LST_NO_FILTER = (1);
        public const Int32 LST_FILTER = (2);

        /* DSPBCalculateObjectId */

        public const Int32 SPB_GENERATE_KEY_NAME = (1);
        public const Int32 SPB_GENERATE_CER_NAME = (2);


        /* DIPFilterOperation */

        public const Int32 D_IPF_ENABLE = (1);
        public const Int32 D_IPF_DISABLE = (2);
        public const Int32 D_IPF_LIST = (33);
        public const Int32 D_IPF_ADD = (44);
        public const Int32 D_IPF_DEL = (55);


        /* DCert2CertInfo */

        public const Int32 P2C_SPB_CERT_INFO = (1);


        /* DGenerateDUKPT */

        // flags/modes; duk, pek, and mek are mutually exclusive;
        public const Int32 NEW_DUKPT_MODE_DUK = (0x00000000);
        public const Int32 NEW_DUKPT_MODE_EXP = (1 << 31);
        public const Int32 NEW_DUKPT_MODE_DE = (1 << 30);
        public const Int32 NEW_DUKPT_MODE_PEK = (1 << 29);
        public const Int32 NEW_DUKPT_MODE_MEK = (1 << 28);
        public const Int32 NEW_DUKPT_MODE_TMP = (1 << 27);
        public const Int32 NEW_DUKPT_MODE_IPEK = (1 << 26);


        /* DCertEncodingConvert */

        public const Int32 CERT_OUT_DER = 1;
        public const Int32 CERT_OUT_PEM = 2;


        /* DBatchSign */

        public const Int32 DN_BATCH_SIGN_BLOCK_HEADER = ((sizeof(Int32) * 2) + MAX_OBJ_ID_FQN_LEN);



        //-----------------------------------------------------------------


        //DOATHIssueHOTPBlob
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ISSUE_OTP_BLOB
        {
            public byte bSeedLen; //Lenght of the seed. Can be ISSUE_OATH_SHA1_LEN, ... for generation.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_OATH_HMAC_LEN)]
            public byte[] pbSeed;  //Only used when importing
            public byte bTruncationOffset; //Can be ISSUE_OATH_DYN_TRUNC,...
            public Int16 wTimeStep; //Time step in seconds. Use ISSUE_OATH_HOTP_TS for HOTP
            public UInt64 otT0; //t0 default value ISSUE_OATH_HOTP_T0
            public byte bUseDefaultMovingFactor; //Set to FALSE to define a moving factor in otMovingFactor or set to TRUE for default
            public UInt64 otMovingFactor; //Client increments BEFORE using
        };

        /*
         * This structure is deprecated.
         *
         * Use AUTH_PWD_EX_2 instead.
         *
         * There's a bug in using 16chars passwords.
         * Remove from code, as soon as nobody is using
         * this anymore.
         *
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct AUTH_PWD
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_ADDR_LEN)]
            public string szAddr;
            public Int32 nPort;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_USR_LEN)]
            public string szUserId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_USR_PWD)]
            public string szPassword;
        };

        /*
         * This structure is deprecated.
         *
         * Use AUTH_PWD_EX_2 instead.
         *
         * There's a bug in using 16chars passwords.
         * Remove from code, as soon as nobody is using
         * this anymore.
         *
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct AUTH_PWD_EX
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_ADDR_LEN)]
            public string szAddr;
            public Int32 nPort;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_USR_LEN)]
            public string szUserId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_USR_PWD)]
            public string szPassword;
            public UInt32 dwAuthType;
            public IntPtr pbStrongAuth;
            public Int32 nStrongAuthLen;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct AUTH_PWD_EX_2
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_ADDR_LEN)]
            public string szAddr;
            public Int32 nPort;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_USR_LEN)]
            public string szUserId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_USR_PWD)]
            public byte[] pbPassword;
            public UInt32 dwAuthType;
            public IntPtr pbStrongAuth;
            public Int32 nStrongAuthLen;
        };


        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SPB_CERT_X509_INFO
        {
            Int32 lVersion;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ND_SPB_MAX_ALG_ID)]
            public string szAlgId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ND_SPB_ISPB_LEN + 1)]
            public string szISPB;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ND_SPB_CA_LEN + 1)]
            public string szCA;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ND_SPB_SN_MAX_LEN + 1)]
            public string szSN;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ND_SPB_MAX_SUBJECT)]
            public string szSubject;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ND_SPB_MAX_ISSUER)]
            public string szIssuer;
            public tm tmNotBefore;
            public tm tmNotAfter;
            public DBLOB dbPublicKey;

        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct OBJ_HDR_V1
        {
            public Int32 version;
            public Int32 type;
            public Int32 attrib;
            public Int32 len;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct OBJ_LIST_FILTER_OUT_DATA
        {
            public OBJ_HDR_V1 stObjectHeader;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_OBJ_ID_FQN_LEN)]
            public string szObjName;
            public OBJ_HDR_V1 stSlot1Header;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_OBJ_ID_FQN_LEN)]
            public string szSlot1ObjName;
            public OBJ_HDR_V1 stSlot2Header;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_OBJ_ID_FQN_LEN)]
            public string szSlot2ObjName;
            public byte bBlockedStatus;
            public UInt64 stCreationTime;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct OATH_SA_v1
        {
            public byte type;
            public byte key_len;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_OATH_HMAC_LEN)]
            public byte[] key;
            public byte truncation_offset;

        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct OATH_SA_v2
        {
            public OATH_SA_v1 sa_v1;
            public Int16 time_step; // seconds
            public UInt64 T0;        // Unix time_t

        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ISSUE_OATH_BLOB
        {
            public byte seed_len;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_OATH_HMAC_LEN)]
            public byte[] seed;
            UInt64 moving_factor;
            byte truncation_offset;
            Int16 time_step; // seconds; > 0 == TOTP blob
            UInt64 T0;        // Unix time_t
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            Int32[] pad_cks_tag;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ISSUE_OATH_INFO_t
        {
            public byte seed_len;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_OATH_HMAC_LEN)]
            public byte[] seed;
            UInt64 moving_factor;
            byte truncation_offset;
            Int16 time_step; // seconds; > 0 == TOTP blob
            UInt64 T0;        // Unix time_t
        };



        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct OATH_PSKC_TRANSLATE_OUTPUT
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 160)]
            public byte[] stOATHBlob;   // encripted buffer
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = OATH_MAX_PSK_LEN + 1)]
            public string szKeyId;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IP_FILTER_INFO
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_USR_LEN + 1)]
            public string szUser;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_USR_LEN + 1)]
            public string szIp;
        };

        public enum AttributeFilter
        {
            MOD_SPB_RELATED = (0x00001000)
        }

        public enum FilterType
        {
            LST_NO_FILTER = 1,
            LST_FILTER = 2
        }

        public enum Verb
        {
            OBJ_LIST_VERB_VERSION = (1 << 0),
            OBJ_LIST_VERB_TYPE = (1 << 1),
            OBJ_LIST_VERB_ATTRIB = (1 << 2),
            OBJ_LIST_OBJS_OR = (1 << 31)
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct OBJ_LIST_FILTER
        {
            public Int32 verb;
            public OBJ_HDR_V1 header;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct USER_INFO
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_USR_LEN + 1)]
            public string szUserId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_USR_PWD + 1)]
            public string szPassword;
            public Int32 dwAuthMask;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct MAP_2_OBJ_INFO
        {
            public Int32 dwObj1AlgId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_OBJ_NAME_LEN + 1)]
            public string szObj1Id;
            public Int32 dwObj2AlgId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_OBJ_NAME_LEN + 1)]
            public string szObj2Id;
        };

        public const Int32 MAP_2_OBJ_INFO_LEN = 2 * (sizeof(Int32) + MAX_OBJ_NAME_LEN + 1);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct DBLOB
        {
            public IntPtr pvData;
            public Int32 dwDataLen;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct HOTP_INFO_EX
        {
            public Int32 dwStructId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_OBJ_NAME_LEN + 1)]
            public string szObjId;
            public Int32 dwObjAttr;
            public Int32 dwObjHotpFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_HOTP_PIN + 1)]
            public string szStPin;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_HOTP_IMEI + 1)]
            public string szStIMEI;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_HOTP_APP_NAME + 1)]
            public string szStAppName;
            public IntPtr pdbStLogoImage;	// type: DBLOB
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct tm
        {
            public Int32 tm_sec;     /* seconds after the minute - [0,59] */
            public Int32 tm_min;     /* minutes after the hour - [0,59] */
            public Int32 tm_hour;    /* hours since midnight - [0,23] */
            public Int32 tm_mday;    /* day of the month - [1,31] */
            public Int32 tm_mon;     /* months since January - [0,11] */
            public Int32 tm_year;    /* years since 1900 */
            public Int32 tm_wday;    /* days since Sunday - [0,6] */
            public Int32 tm_yday;    /* days since January 1 - [0,365] */
            public Int32 tm_isdst;   /* daylight savings time flag */
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct USER_BLOCK
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_USR_LEN + 1)]
            public string szUserId;
            public int nBlocked;
            public Int32 dwAttempts;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct EXT_MAP_2_OBJ_INFO
        {
            public Int32 dwObjAlgId1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_OBJ_ID_FQN_LEN)]
            public string szObjId1;
            public Int32 dwObjAlgId2;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_OBJ_ID_FQN_LEN)]
            public string szObjId2;
        }

        public const Int32 SA_HOTP_CHAP_LEN = 10;
        public const Int32 SA_ST_ID_HOTP_CHAP = 1;
        public const Int32 SA_ST_ID_HOTP_CHAP_OUT = (2); /* HOTP_CHAP_OUT */

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct HOTP_CHAP
        {
            public Int32 dwStructId;							//Structure Id -> SA_ST_ID_HOTP_CHAP
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SA_HOTP_CHAP_LEN + 1)]
            public string szChallenge;		//Server created challenge
        }

        /* DGetHsmInfo */

        public const Int32 HI_BATTERY_LIFE = (0x00000001);  /* Battery remaining life time. pbData == tLife (time_t) */
        public const Int32 HI_PERFOMANCE_COUNT = (0x00000002);  /* Use percentage: CPU, Memory e disk. pbData == * PERFOMANCE_COUNT */
        public const Int32 HI_MODULE_INFO = (0x00000004);  /* Existing modules. pbData == * MODULE_INFO */
        public const Int32 HI_HSM_INFO = (0x00000008);  /* HSM's model and version. pbData == szHsmInfo */
        public const Int32 HI_OPERATIONS_COUNT = (0x00000010);  /* Operation counter. pbData == * OPERATIONS_INFO */
        public const Int32 HI_SYS_HEALTH = (0x00000020);  /* Elapsed time since last update and battery check. pbData == * SYS_HEALTH */
        public const Int32 HI_FIPS_MODE = (0x00000040);  /* Recover HSM's operation mode. pbData == *DWORD */
        public const Int32 HI_DISK_INFO = (0x00000080);  /* Recover HSM's disk usage information. pbData == *SYS_DISK_INFO */
        public const Int32 HI_REPL_INFO = (0x00000100);  /* Recover HSM's replication information. pbData == *SYS_REPL_INFO */
        public const Int32 HI_CURRENT_DATE = (0x00000200);  /* Recover HSM's date and time. pbData == *QWORD */
        public const Int32 HI_HW_STR = (0x00000400);  /* Recover HSM's date and time. pbData == *SYS_HW_STR_INFO */
        public const Int32 HI_NTP_INFO = (0x00000800);  /* Recover HSM's date and time. pbData == *SYS_NTP_INFO */
        public const Int32 HI_STATS_INFO = (0x00001000);  /* Recover HSM's statistics info. pbData == *SYS_STATUS_INFO */
        public const Int32 HI_COUNTER_INFO = (0x00002000);  /* Recover HSM's counter info. pbData == *SYS_COUNTER_INFO */
        public const Int32 HI_FIPS_RCODE_INFO = (0x00004000);  /* Recover HSM's FIPS auto-test return code. pbData == *DWORD */
        public const Int32 HI_PENDING_INFO = (0x00008000);  /* Recover HSM's pending info. pbData == *SYS_PENDING_INFO */
        public const Int32 HI_ALL_INFO = (0x00010000);  /* Recover HSM's ALL info. pbData == *SYS_ALL_INFO */

        public const Int32 GET_INFO_MAX_REPL_DOMAIN_NAME = (1024);
        public const Int32 GET_INFO_MAX_REPL_NODES = (255);
        public const Int32 GET_INFO_MAX_SN_LEN = (255);
        public const Int32 GET_INFO_MAX_HW_STR_LEN = (255);
        public const Int32 GET_INFO_MAX_TPKEY_LEN = (16);
        public const Int32 GET_INFO_MAX_NTP_SVRS = (16);
        public const Int32 GET_INFO_MAX_NTPQ_LEN = (256);
        public const Int32 GET_INFO_MAX_NTP_KT_LEN = (16);
        public const Int32 GET_INFO_MAX_NTP_KM_LEN = (64);




        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYS_HW_STR_INFO
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = GET_INFO_MAX_SN_LEN + 1)]
            public string szSerialNumber;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = GET_INFO_MAX_SN_LEN + 1)]
            public string szHardwareString;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = GET_INFO_MAX_TPKEY_LEN + 1)]
            public string szTpKey;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYS_COUNTER_INFO
        {
            public UInt64 qwUsers;
            public UInt64 qwObjects;
            public UInt64 qwSLBeFileSize;
            public UInt64 qwTasks;
            public UInt64 qwVMSize;
        };

        public struct HOTP_CHAP_OUT
        {
            public Int32 dwStructId;							                //Structure Id -> SA_ST_ID_HOTP_CHAP_OUT
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SA_HOTP_CHAP_LEN + 1)]
            public string szChallenge;		                                     //Server created challenge
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SA_TP_MAX_OTP_LEN)]
            public string szTokenResponse;                                  	//Expected response from HOTPToken
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SA_TP_MAX_OTP_LEN)]
            public string szCountResponse;	                                    //Server Counter Response
        }


        public struct HOTP_SYNC
        {
            public Int32 dwStructId;				                            	//Structure Id -> SA_ST_ID_HOTP_SYNC
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_OBJ_NAME_LEN + 1)]
            public string szObjId;	                                                //HOTPToken to synchronize
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SA_TP_MAX_OTP_LEN)]
            public string szOTP1;		                                            //Expected response from HOTPToken
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SA_TP_MAX_OTP_LEN)]
            public string szOTP2;	                                            	//Server Counter Response
        }

        public delegate Int32 ListIpFilterCallback(IntPtr pInData, Int32 dwInDataLen, IntPtr pParam, Int32 bFinal);
        public delegate Int32 ListCallback(string szName, ref object pParam, Int32 bFinal);
        public delegate Int32 ListCallbackFilter(IntPtr pvIn, IntPtr pParam, Int32 bFinal);
        public delegate Int32 WriteLocalFileCallback(IntPtr pbData, Int32 cbData, ref object pParam, Int32 bFinal);
        public delegate Int32 ReadLocalFileCallback(IntPtr pbData, ref Int32 pcbData, ref object pParam, out Int32 pbFinal);
        public delegate Int32 ListUserTrustsCallback(string szUserName, Int32 dwACL, ref object pParam, Int32 bFinal);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DInitialize(Int32 dwReserved);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DFinalize();

        /*
         * This API is deprecated.
         *
         * Use AUTH_PWD_EX_2 overload instead.
         *
         * There's a bug in using 16chars passwords.
         * Remove from code, as soon as nobody is using
         * this anymore.
         *
         */
        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOpenSession(out IntPtr phSession, Int32 dwParam, ref AUTH_PWD pbData, Int32 dwDataLen, Int32 dwFlags);

        /*
         * This API is deprecated.
         *
         * Use AUTH_PWD_EX_2 overload instead.
         *
         * There's a bug in using 16chars passwords.
         * Remove from code, as soon as nobody is using
         * this anymore.
         *
         */
        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOpenSession(out IntPtr phSession, Int32 dwParam, ref AUTH_PWD_EX pbData, Int32 dwDataLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOpenSession(out IntPtr phSession, Int32 dwParam, ref AUTH_PWD_EX_2 pbData, Int32 dwDataLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DCloseSession(out IntPtr phSession, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DAdmOperation(IntPtr hSession, Int32 dwParam, IntPtr pbData, Int32 dwDataLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DCreateHash(IntPtr hSession, Int32 nAlgId, IntPtr hKey, Int32 dwFlags, out IntPtr hHash);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DDestroyHash(ref IntPtr phHash);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetUserKey(IntPtr hSession, string szKeyId, Int32 dwFlags, out IntPtr phKey);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DListUserTrusts(IntPtr hSession, string szUserId, byte bType, ListUserTrustsCallback listObjCallback, ref object pParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSignXml(IntPtr hKey, IntPtr hHash, string szCertId, Int32 dwSizeUnsignedXml, byte[] pbUnsignedXml, Int32 dwFilterLen, byte[] pbFilter, out Int32 pdwSizeSignedXml, out IntPtr ppbSignedXml);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSignXml2(IntPtr hSession,
                                            byte bHashMode,
                                            Int32 dwFlags,
                                            string szKeyId,
                                            string szCertId,
                                            Int32 dwSizeUnsignedXml,
                                            byte[] pbUnsignedXml,
                                            Int32 dwFilterLen,
                                            byte[] pbFilter,
                                            out Int32 pdwSizeSignedXml,
                                            out IntPtr ppbSignedXml);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DVerifySignedXml(IntPtr hSession, string szCertsId, Int32 dwSizeSignedXml, byte[] pbSignedXml, Int32 dwFilterLen, byte[] pbFilter);
        //TODO Implementar o VerifySignedXmlEx

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DPIXSign(IntPtr hSession, string szKeyId, string szCertId, Int32 dwSizeUnsignedXml, byte[] pbUnsignedXml, out Int32 pdwSizeSignedXml, out IntPtr ppbSignedXml);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DPIXVerify(IntPtr hSession, string szCertsId, string szCRL, Int32 dwSizeSignedXml, byte[] pbSignedXml);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DPIXJWSSign(IntPtr hSession, string szKeyId, Int32 dwFlags, Int32 dwHeaderLen, byte[] pbHeader, Int32 dwPayloadLen, byte[] pbPayload, out Int32 pdwJWSLen, byte[] pbJWS);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DPIXJWSCheck(IntPtr hSession, string szChain, string szCRL, Int32 dwJWSLen, byte[] pbJWS, Int32 dwFlags, out Int32 pdwHeaderLen, byte[] pbHeader, out Int32 pdwPayloadLen, byte[] pbPayload);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DPIXPost(IntPtr hSession,
        string szKeyId,
        string szCertChainId,
        string szPIXCertChainId,
        string szURL,
        Int32 dwCountRequestHeaderList,
        string[] pszRequestHeaderList,
        Int32 dwSizeRequestData,
        byte[] pbRequestData,
        Int32 dwTimeOut,
        out Int32 pdwSizeResponseHeaders,
        out IntPtr ppbResponseHeaders,
        out Int32 pdwSizeResponseBody,
        out IntPtr ppbResponseBody,
        Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DPIXGet(IntPtr hSession,
        string szKeyId,
        string szCertChainId,
        string szPIXCertChainId,
        string szURL,
        Int32 dwCountRequestHeaderList,
        string[] pszRequestHeaderList,
        Int32 dwTimeOut,
        out Int32 pdwSizeResponseHeaders,
        out IntPtr ppbResponseHeaders,
        out Int32 pdwSizeResponseBody,
        out IntPtr ppbResponseBody,
        Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DPIXDelete(IntPtr hSession,
        string szKeyId,
        string szCertChainId,
        string szPIXCertChainId,
        string szURL,
        Int32 dwCountRequestHeaderList,
        string[] pszRequestHeaderList,
        Int32 dwTimeOut,
        out Int32 pdwSizeResponseHeaders,
        out IntPtr ppbResponseHeaders,
        out Int32 pdwSizeResponseBody,
        out IntPtr ppbResponseBody,
        Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DDestroyKey(ref IntPtr phKey, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern void DFree(IntPtr p);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetObjInfo(IntPtr hSession, string szObjId, Int32 nAlgId, ref EXT_MAP_2_OBJ_INFO data, ref Int32 pdwDataLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DCreateUser(IntPtr hSession, USER_INFO userInfo);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DRemoveUser(IntPtr hSession, string szUserId);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSetUserParam(IntPtr hSession, Int32 dwParam, IntPtr pbData, Int32 dwDataLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetUserParam(IntPtr hSession, Int32 dwParam, ref USER_BLOCK pbData, ref Int32 pdwDataLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGenerateMapObj(IntPtr hSession, string szMapId, string szObj1Id, Int32 nObj1AlgId, string szObj2Id, Int32 nObj2AlgId);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DRemoveObj(IntPtr hSession, string szObjId);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DBackupData(IntPtr hSession, string szBackupFile, string szPin, Int32 nDirection);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetStatLogSize(IntPtr hSession, out Int32 pdwLogLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DTruncateLog(IntPtr hSession);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetStatLog(IntPtr hSession, Int32 dwStart, Int32 dwOffSet, out Int32 pdwLogSize, out IntPtr ppbLog);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DEncrypt(IntPtr hKey, IntPtr hHash, Int32 bFinal, Int32 dwFlags, byte[] pbData, ref Int32 pdwDataLen, Int32 dwBufLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DDecrypt(IntPtr hKey, IntPtr hHash, Int32 bFinal, Int32 dwFlags, byte[] pbData, ref Int32 pdwDataLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGenerateKey(IntPtr hSession, string szKeyId, Int32 nAlgId, Int32 dwFlags, out IntPtr phKey);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DListUsers(IntPtr hSession, ListCallback listUsersCallback, ref object pParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DReadFile(IntPtr hSession, string FileId, WriteLocalFileCallback writeLocalFileCallback, ref object pParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DWriteFile(IntPtr hSession, string FileId, Int32 FileSize, ReadLocalFileCallback readLocalFileCallback, ref object pParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetKeyParam(IntPtr hKey, Int32 dwParam, byte[] pbData, ref Int32 pdwDataLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSetKeyParam(IntPtr hKey, Int32 dwParam, byte[] pbData, Int32 dwDataLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DImportKey(IntPtr hSession, string szKeyId, IntPtr hKEKey, Int32 dwBlobType, Int32 nAlgId, Int32 dwFlags, byte[] pbData, Int32 dwDataLen, out IntPtr phKey);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DExportKey(IntPtr hKey, IntPtr hKEKey, Int32 dwBlobType, Int32 dwFlags, byte[] pbData, ref Int32 pdwDataLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSignHash(IntPtr hHash, IntPtr hKey, Int32 dwFlags, byte[] pbSignature, ref Int32 pdwSigLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DBatchSign(IntPtr hKey, byte[] pbBlock, Int32 dwBlockCount, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DVerifySignature(IntPtr hHash, byte[] pbSignature, Int32 dwSigLen, IntPtr hPubKey, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DHashData(IntPtr hHash, byte[] pbData, Int32 dwDataLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSetHashParam(IntPtr hHash, Int32 dwParam, byte[] pbData, Int32 dwDataLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetHashParam(IntPtr hHash, Int32 dwParam, byte[] pbData, ref Int32 pdwDataLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DPKCS7Sign(IntPtr hSession, string szKeyName, string szKeyCert, string szCerts, UInt32 dwAttrib, byte[] pbContent, Int32 dwContentLen, out Int32 pdwSignatureLen, out IntPtr ppbSignature, Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        [System.Obsolete("Use DOATHIssueBlob")]
        public static extern Int32 DOATHIssueHOTPBlob(IntPtr hSession, string szMasterKeyId, byte[] pbOutPwdEnvelope, byte[] pbOutEncMobileSeed, byte[] pbOutEncSeedBlob, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOATHIssueBlob(IntPtr hSession, string szMasterKeyId,
            UInt32 dwParamBlobType, IntPtr pvParamBlob, Int32 dwParamBlobLen, byte[] pbOTPBlob, ref Int32 pdwOTPBlobLen, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DListObjs(IntPtr hSession, ListCallback listObjCallback, ref object pParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DListObjsFilter(IntPtr hSession, FilterType filter, ref DinamoApi.OBJ_LIST_FILTER pvFilter, ListCallbackFilter listObjCallback, IntPtr pParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetUserAcl(IntPtr hSession, string szUser, out Int32 pdwUserAcl);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DIPFilterOperation(IntPtr hSession, byte bOP, string szUser, string szIP,
                        ListIpFilterCallback listIpFilterCallback, IntPtr pParam, out Int32 pdwStatus, Int32 dwReserved);

        // SPB

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBMapInfo(IntPtr hSession, string sIdCert, ref DinamoApi.EXT_MAP_2_OBJ_INFO pstExtMap, Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBGenerateKey(IntPtr hSession, string sID, IntPtr szPrivateKeyName, Int32 dwKeyParam, Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBGenerateCSR(IntPtr hSession, string sPrivateKeyName, byte bVersion, string sSPBSubject, Int32 dwOutType,
            ref Int32 pdwCSRLen, out IntPtr ppbCSR, Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGeneratePKCS10CSR(IntPtr hSession, string szKeyName,
                                    byte bVersion, string szDN, Int32 dwOutType,
                                    ref Int32 pdwCSRLen, out IntPtr ppbCSR, Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DPKCS8ImportKey(IntPtr hSession, string szKeyId, string szSecret,
                                   Int32 dwKeyAlg, Int32 dwAttrib,
                                   IntPtr pbKeyEnvelope, Int32 dwKeyEnvelopeLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DPKCS8ExportKey(IntPtr hSession, string szKeyId, string szSecret,
                                    out IntPtr ppbKeyEnvelope, out Int32 ppbKeyEnvelopeLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBImportPKCS12(IntPtr hSession, byte bActivate, string szReserved, string szPkcs12File, string szPkcs12Pwd, string szDomain, Int32 dwKeyAttr);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBExportPKCS12(IntPtr hSession, string szPkcs12Pwd, string szISPB, string szReserved, out IntPtr pPkcs12File, out Int32 pdwPkcs12Len, Int32 dwReserved);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DImportPKCS12(IntPtr hSession, string szPkcs12File, string szPkcs12Pwd, string szKeyId, Int32 dwKeyAttr, string szCertId);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DExportPKCS12(IntPtr hSession, string szPkcs12Pwd, string szKeyId, string szCertId,
                            string szReserved, out IntPtr pPkcs12, out Int32 pdwPkcs12Len, Int32 dwReserved);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBImportCertificate(IntPtr hSession, byte bActivate, string szReserved, IntPtr pCertificate, Int32 dwCertificateLen, string szDomain, uint dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBActivateCertificate(IntPtr hSession, string szIdCert,
                                            string szDomain, uint dwParam);
        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBGetCertificate(IntPtr hSession, string szIdCert,
                                        ref byte[] ppbCertificate, ref Int32 pdwCertificateLen, Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBGetCertificateList(IntPtr hSession, string szDomain,
                                            Int32 bActive, ref DBLOB pdbList,
                                            ref Int32 pdwListLen, Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBSetISPBMap(IntPtr hSession, string szISPB,
                                    string szKeyId, string szCertId, Int32 dwParam);

        //[DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        //public static extern Int32 DSPBEncode (	IntPtr hSession, string szSrcISPB, string szDstISPB,
        //                        byte[] pbMsgIn,Int32 dwMsgInLen, byte bErrorCode,
        //                        byte bSpecialTreatment,ref byte[] pbMsgOut,ref Int32 pdwMsgOutLen, Int32 dwFlags);

        //[DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        //public static extern Int32 DSPBDecode (	IntPtr hSession, string szSrcISPB,string szDstISPB, byte[] pbMsgIn,Int32 dwMsgInLen, byte bAcceptExpiredCert,
        //                        byte bAutoUpdateCert, ref byte[] pbMsgOut, ref Int32 pdwMsgOutLen,Int32 dwFlags);
        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBEncodeInit(IntPtr hSession, string szSrcISPB, string szDstISPB,
                                Int32 dwTotalDataLen, byte bErrorCode, byte bSpecialTreatment, out IntPtr hSPBCtx,
                                Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBEncodeCont(IntPtr hSPBCtx, IntPtr pbDataIn, Int32 dwDataInLen,
                                 IntPtr pbDataOut, out Int32 pdwDataOutLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBEncodeEnd(out IntPtr hSPBCtx, IntPtr pbSPBHeader, out Int32 pdwSPBHeaderLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBDecodeInit(IntPtr hSession, string szSrcISPB, string szDstISPB,
                                IntPtr pbHeader, Int32 dwHeaderLen, byte bAcceptExpiredCert, byte bAutoUpdateCert,
                                Int32 dwMessageDataLen, out IntPtr hSPBCtx, Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBDecodeCont(IntPtr hSPBCtx, IntPtr pbDataIn, Int32 dwDataInLen,
                                out IntPtr ppbDataOut, out Int32 pdwDataOutLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBDecodeEnd(out IntPtr hSPBCtx);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetErrorString(Int32 code, IntPtr szCod, IntPtr szMsg);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DCert2CertInfo(byte[] pbCert, Int32 dwCertLen, Int32 dwOutType,
                            out SPB_CERT_X509_INFO pvCertInfo, Int32 dwFlags);


        //OATH SA
        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOATHGetNextOTP(IntPtr hSession, string szMasterKeyId, byte bOTPLen, byte[] pbOATHBlob, Int32 dwOATHBlobLen, IntPtr szOTP, Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOATHResync(IntPtr hSession, string szUser, string szOTP1, string szOTP2, Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DUnassignToken(IntPtr hSession, Int32 dwParam, string szUserId);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DAssignToken(IntPtr hSession, string szUserId, Int32 dwParam, IntPtr pbData, Int32 dwDataLen);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSPBCalculateObjectId(string szISPB, string szDomain, Int32 dwKeyType, IntPtr szOutObjName, Int32 dwParam);

        //OATH
        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOATHIssueHOTPBlob(IntPtr hSession,
            string szMasterKeyId,
            Int32 dwParamBlobType,
            IntPtr pvParamBlob,
            Int32 dwParamBlobLen,
            byte[] pbOTPBlob,
            ref Int32 pdwOTPBlobLen,
            Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOATHGetBlobInfo(IntPtr hSession,
                                string szMasterKey,
                                byte[] pbInBlob,
                                Int32 dwInBlobLen,
                                Int32 dwOutBlobType,
                                byte[] pbOutInfo,
                                ref Int32 pdwOutInfoLen,
                                Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOATHBlobResync(IntPtr hSession,
                                        string szMasterKeyId,
                                        string szOTP1,
                                        string szOTP2,
                                        byte[] pbOATHBlob,
                                        ref Int32 pdwOATHBlobLen,
                                        Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOATHPskcTranslate(IntPtr hSession,
                                string szMasterKey,
                                byte[] pbPSK,
                                byte bPSKLen,
                                byte[] pbPSKC,
                                Int32 dwPSKCLen,
                                out IntPtr pvBlobList,
                                out Int32 pdwBlobListQuantity,
                                Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DOATHCheckOTP(IntPtr hSession,
            string szMasterKeyId,
            string szOTP,
            byte[] pbOutData,
            ref Int32 pdwOutDataLen,
            Int32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetRandom(IntPtr hSession, byte[] pbData, Int32 dwDataLen);

        /* Statistics */

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetHsmInfo(IntPtr hSession,
                                                ref byte pbFinal,
                                                UInt32 dwParam,
                                                ref DinamoApi.SYS_HW_STR_INFO pbData,
                                                ref UInt32 pdwDataLen,
                                                UInt32 dwFlags);
        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetHsmInfo(IntPtr hSession,
                                                ref byte pbFinal,
                                                UInt32 dwParam,
                                                ref UInt64 pbData,
                                                ref UInt32 pdwDataLen,
                                                UInt32 dwFlags);
        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetHsmInfo(IntPtr hSession,
                                                ref byte pbFinal,
                                                UInt32 dwParam,
                                                IntPtr pbData,
                                                ref UInt32 pdwDataLen,
                                                UInt32 dwFlags);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGenerateDUKPT(IntPtr hSession,
                                                byte[] pbKSI,
                                                byte[] pbDID_CTR,
                                                IntPtr szDUKPT,
                                                UInt32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGenerateBDKName(byte[] pbKSI,
                                                    IntPtr szBDKName,
                                                    UInt32 dwParam);


        public const Int32 MNG_OBJ_META_A_KEY_TYPE = (1);
        public const Int32 MNG_OBJ_META_A_CLASS = (2);
        public const Int32 MNG_OBJ_META_A_EXTRACTABLE = (3);
        public const Int32 MNG_OBJ_META_A_SENSITIVE = (4);
        public const Int32 MNG_OBJ_META_A_N_EXTRACTABLE = (5);
        public const Int32 MNG_OBJ_META_A_LOCAL = (6);
        public const Int32 MNG_OBJ_META_A_CERT_TYPE = (7);
        public const Int32 MNG_OBJ_META_A_RSA_MODULUS = (8);
        public const Int32 MNG_OBJ_META_A_RSA_PUB_EXP = (9);
        public const Int32 MNG_OBJ_META_A_PUB_KEY_INFO = (10);
        public const Int32 MNG_OBJ_META_A_EC_PARAMS = (11);
        public const Int32 MNG_OBJ_META_A_SUBJECT = (12);
        public const Int32 MNG_OBJ_META_A_ISSUER = (13);
        public const Int32 MNG_OBJ_META_A_SN = (14);
        public const Int32 MNG_OBJ_META_A_TOKEN = (15);
        public const Int32 MNG_OBJ_META_A_MODIFIABLE = (16);
        public const Int32 MNG_OBJ_META_A_DERIVE = (17);
        public const Int32 MNG_OBJ_META_A_WRAP = (18);
        public const Int32 MNG_OBJ_META_A_UNWRAP = (19);
        public const Int32 MNG_OBJ_META_A_SIGN = (20);
        public const Int32 MNG_OBJ_META_A_VERIFY = (21);
        public const Int32 MNG_OBJ_META_A_ENCRYPT = (22);
        public const Int32 MNG_OBJ_META_A_DECRYPT = (23);
        public const Int32 MNG_OBJ_META_A_OBJ_ID = (24);
        public const Int32 MNG_OBJ_META_A_MODULUS_BITS = (25);
        public const Int32 MNG_OBJ_META_A_PRIVATE = (26);
        public const Int32 MNG_OBJ_META_A_LABEL = (27);
        public const Int32 MNG_OBJ_META_A_ID = (28);
        public const Int32 MNG_OBJ_META_A_APPLICATION = (29);
        public const Int32 MNG_OBJ_META_A_TRUSTED = (30);
        public const Int32 MNG_OBJ_META_A_JMIDP_SEC_DOMAIN = (31);
        public const Int32 MNG_OBJ_META_A_CERT_CATEGORY = (32);
        public const Int32 MNG_OBJ_META_A_KEY_GEN_MECHANISM = (33);
        public const Int32 MNG_OBJ_META_A_WRAP_WITH_TRUSTED = (34);
        public const Int32 MNG_OBJ_META_A_HSM_ASSOCIATE = (35);
        public const Int32 MNG_OBJ_META_A_SIGN_RECOVER = (36);
        public const Int32 MNG_OBJ_META_A_VERIFY_RECOVER = (37);

        public const Int32 MNG_OBJ_META_A_HSM_OBJ_VERSION = (502);
        public const Int32 MNG_OBJ_META_A_HSM_OBJ_TYPE = (503);
        public const Int32 MNG_OBJ_META_A_HSM_OBJ_ATTR = (504);
        public const Int32 MNG_OBJ_META_A_HSM_OBJ_LEN = (505);
        public const Int32 MNG_OBJ_META_A_HSM_OBJ_ID = (506);
        public const Int32 MNG_OBJ_META_A_HSM_OBJ_PVALUE = (507);


        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DCreateObjMetadata(ref IntPtr hmUpdateMetaCtx, Int32 dwFlag);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DSetObjMetadata(IntPtr hInMeta,
                                                    Int32 dwOption,
                                                    ref Int32 pvOptionData,
                                                    Int32 dwOptionDataLen,
                                                    Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DGetObjMetadata(IntPtr hInMeta,
                                                    Int32 dwOption,
                                                    byte[] pvOptionData,
                                                    ref Int32 pdwOptionDataLen,
                                                    Int32 dwParam);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DFindObjMetadataInit(IntPtr hSession, IntPtr hmSearchInfoCtx, out IntPtr hmSearchCtx, Int32 dwFlag);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DFindObjMetadataCont(IntPtr hmSearchCtx, IntPtr[] hmSearchResult, Int32 lenSearchResult, out Int32 dwOutCount, Int32 dwFlag);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DFindObjMetadataEnd(ref IntPtr hmSearchCtx, Int32 dwFlag);

        [DllImport("tacndlib", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 DDestroyObjMetadata(ref IntPtr hmSearchCtx, Int32 dwFlag);

    }
}
