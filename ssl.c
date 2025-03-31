/****************************************************************************************
 * 文 件 名 : dpi_ssl.c
 * 项目名称 :
 * 模 块 名 :
 * 功    能 :
 * 操作系统 : LINUX
 * 修改记录 : 无
 * 版    本 : Rev 0.1.0
 *- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 设计: wangy         2018/07/06
 编码: licl          2018/12/04
 修改:
 *- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * 公司介绍及版权说明
 *
 *           (C)Copyright 2018 YView    Corporation All Rights Reserved.
 *- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

 *****************************************************************************************/
#include <stdlib.h>
#include <glib.h>
#include <arpa/inet.h>
#include <rte_mbuf.h>

#include "dpi_proto_ids.h"
#include "dpi_tbl_log.h"
#include "dpi_tcp_reassemble.h"
#include "dpi_log.h"
#include "dpi_common.h"
#include "dpi_dissector.h"
#include "dpi_ssl.h"
#include "dpi_utils.h"
#include "openssl/x509v3.h"
#include "openssl/sha.h"
#include "openssl/md5.h"


GHashTable  *https_filter_table = NULL;
GAsyncQueue *sslh_encrypted_pcap = NULL;
extern struct global_config g_config;
extern struct rte_mempool *tbl_log_mempool;


#define KEX_DHE_DSS     0x10
#define KEX_DHE_PSK     0x11
#define KEX_DHE_RSA     0x12
#define KEX_DH_ANON     0x13
#define KEX_DH_DSS      0x14
#define KEX_DH_RSA      0x15
#define KEX_ECDHE_ECDSA 0x16
#define KEX_ECDHE_PSK   0x17
#define KEX_ECDHE_RSA   0x18
#define KEX_ECDH_ANON   0x19
#define KEX_ECDH_ECDSA  0x1a
#define KEX_ECDH_RSA    0x1b
#define KEX_KRB5        0x1c
#define KEX_PSK         0x1d
#define KEX_RSA         0x1e
#define KEX_RSA_PSK     0x1f
#define KEX_SRP_SHA     0x20
#define KEX_SRP_SHA_DSS 0x21
#define KEX_SRP_SHA_RSA 0x22
#define KEX_IS_DH(n)    ((n) >= KEX_DHE_DSS && (n) <= KEX_ECDH_RSA)
#define KEX_TLS13       0x23
#define KEX_ECJPAKE     0x24

#define KEX_ECDHE_SM2   0x25
#define KEX_ECC_SM2     0x26
#define KEX_IBSDH_SM9   0x27
#define KEX_IBC_SM9     0x28

/* Order is significant, must match "ciphers" array in packet-tls-utils.c */

#define ENC_START       0x30
#define ENC_DES         0x30
#define ENC_3DES        0x31
#define ENC_RC4         0x32
#define ENC_RC2         0x33
#define ENC_IDEA        0x34
#define ENC_AES         0x35
#define ENC_AES256      0x36
#define ENC_CAMELLIA128 0x37
#define ENC_CAMELLIA256 0x38
#define ENC_SEED        0x39
#define ENC_CHACHA20    0x3A
#define ENC_NULL        0x3B
#define ENC_SM1         0x3C
#define ENC_SM4         0x3D

#define DIG_MD5         0x40
#define DIG_SHA         0x41
#define DIG_SHA256      0x42
#define DIG_SHA384      0x43
#define DIG_NA          0x44 /* Not Applicable */
#define DIG_SM3         0x45

#define SSL_HND_HELLO_EXT_SERVER_NAME                   0
#define SSL_HND_HELLO_EXT_MAX_FRAGMENT_LENGTH           1
#define SSL_HND_HELLO_EXT_CLIENT_CERTIFICATE_URL        2
#define SSL_HND_HELLO_EXT_TRUSTED_CA_KEYS               3
#define SSL_HND_HELLO_EXT_TRUNCATED_HMAC                4
#define SSL_HND_HELLO_EXT_STATUS_REQUEST                5
#define SSL_HND_HELLO_EXT_USER_MAPPING                  6
#define SSL_HND_HELLO_EXT_CLIENT_AUTHZ                  7
#define SSL_HND_HELLO_EXT_SERVER_AUTHZ                  8
#define SSL_HND_HELLO_EXT_CERT_TYPE                     9
#define SSL_HND_HELLO_EXT_SUPPORTED_GROUPS              10 /* renamed from "elliptic_curves" (RFC 7919 / TLS 1.3) */
#define SSL_HND_HELLO_EXT_EC_POINT_FORMATS              11
#define SSL_HND_HELLO_EXT_SRP                           12
#define SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS          13
#define SSL_HND_HELLO_EXT_USE_SRTP                      14
#define SSL_HND_HELLO_EXT_HEARTBEAT                     15
#define SSL_HND_HELLO_EXT_ALPN                          16
#define SSL_HND_HELLO_EXT_STATUS_REQUEST_V2             17
#define SSL_HND_HELLO_EXT_SIGNED_CERTIFICATE_TIMESTAMP  18
#define SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE              19
#define SSL_HND_HELLO_EXT_SERVER_CERT_TYPE              20
#define SSL_HND_HELLO_EXT_PADDING                       21
#define SSL_HND_HELLO_EXT_ENCRYPT_THEN_MAC              22
#define SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET        23
#define SSL_HND_HELLO_EXT_TOKEN_BINDING                 24
#define SSL_HND_HELLO_EXT_CACHED_INFO                   25
#define SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS     26 /* Not yet assigned by IANA (QUIC-TLS Draft04) */
/* 26-34  Unassigned*/
#define SSL_HND_HELLO_EXT_SESSION_TICKET_TLS            35
/* TLS 1.3 draft */
#define SSL_HND_HELLO_EXT_KEY_SHARE_OLD                 40
#define SSL_HND_HELLO_EXT_PRE_SHARED_KEY                41
#define SSL_HND_HELLO_EXT_EARLY_DATA                    42
#define SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS            43
#define SSL_HND_HELLO_EXT_COOKIE                        44
#define SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES        45
#define SSL_HND_HELLO_EXT_TICKET_EARLY_DATA_INFO        46 /* draft-ietf-tls-tls13-18 (removed in -19) */
#define SSL_HND_HELLO_EXT_CERTIFICATE_AUTHORITIES       47
#define SSL_HND_HELLO_EXT_OID_FILTERS                   48
#define SSL_HND_HELLO_EXT_POST_HANDSHAKE_AUTH           49
#define SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS_CERT     50
#define SSL_HND_HELLO_EXT_KEY_SHARE                     51
#define SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS_V1  57
#define SSL_HND_HELLO_EXT_GREASE_0A0A                   2570
#define SSL_HND_HELLO_EXT_GREASE_1A1A                   6682
#define SSL_HND_HELLO_EXT_GREASE_2A2A                   10794
#define SSL_HND_HELLO_EXT_NPN                           13172 /* 0x3374 */
#define SSL_HND_HELLO_EXT_GREASE_3A3A                   14906
#define SSL_HND_HELLO_EXT_GREASE_4A4A                   19018
#define SSL_HND_HELLO_EXT_GREASE_5A5A                   23130
#define SSL_HND_HELLO_EXT_GREASE_6A6A                   27242
#define SSL_HND_HELLO_EXT_CHANNEL_ID_OLD                30031 /* 0x754f */
#define SSL_HND_HELLO_EXT_CHANNEL_ID                    30032 /* 0x7550 */
#define SSL_HND_HELLO_EXT_GREASE_7A7A                   31354
#define SSL_HND_HELLO_EXT_GREASE_8A8A                   35466
#define SSL_HND_HELLO_EXT_GREASE_9A9A                   39578
#define SSL_HND_HELLO_EXT_GREASE_AAAA                   43690
#define SSL_HND_HELLO_EXT_GREASE_BABA                   47802
#define SSL_HND_HELLO_EXT_GREASE_CACA                   51914
#define SSL_HND_HELLO_EXT_GREASE_DADA                   56026
#define SSL_HND_HELLO_EXT_GREASE_EAEA                   60138
#define SSL_HND_HELLO_EXT_GREASE_FAFA                   64250
#define SSL_HND_HELLO_EXT_RENEGOTIATION_INFO            65281 /* 0xFF01 */
#define SSL_HND_HELLO_EXT_DRAFT_VERSION_TLS13           65282 /* 0xFF02 */
enum
{
    EM_CONTENTTYPE             ,
    EM_VERSION                 ,
    EM_RECORDLAYERLENGTH       ,
    EM_CHANGECIPHERSPEC        ,
    EM_ALERTLEN                ,
    EM_ALERTLEVEL              ,
    EM_ALERTDESCRIPTION        ,
    EM_HANDSHAKETYPE           ,
    EM_CLIENTHELLOLENGTH       ,
    EM_CLIENTPROTOCOLVERSION   ,
    EM_CLIENTGMTUNIXTIME       ,
    EM_CLIENTRANDOMBYTES       ,
    EM_CLIENTSESSIONIDLENGTH   ,
    EM_CLIENTSESSIONID         ,
    EM_CLIENTCIPHERSUITESLENGTH,
    EM_CLIENTCIPHERSUITES      ,
    EM_CLIENTCIPHERSUITE_CNT,
    EM_CLTCOMPRESSIONMETHODSLEN,
    EM_CLIENTCOMPRESSIONMETHODS,
    EM_CLIENTEXTENSIONSLENGTH  ,
    EM_CLIENTEXTENSIONS        ,
    EM_SERVERHELLOLENGTH       ,
    EM_SERVERPROTOCOLVERSION   ,
    EM_SERVERGMTUNIXTIME       ,
    EM_SERVERRANDOMBYTES       ,
    EM_SERVERSESSIONIDLENGTH   ,
    EM_SERVERSESSIONID         ,
    EM_SERVERCIPHERSUITE       ,
    EM_SERVERCOMPRESSIONMETHOD ,
    EM_SERVEREXTENSIONSLENGTH  ,
    EM_SERVEREXTENSIONS        ,
    EM_CLIENT_CERTIFICATESLENGTH,
    EM_CLIENT_CERTIFICATESNUMS,
    EM_SERVER_CERTIFICATESLENGTH,
    EM_SERVER_CERTIFICATESNUMS,
    EM_CERTIFICATESLENGTH      ,
    EM_CERTIFICATESNUMS        ,
    EM_SERVERKEYEXDHGEN_g	   ,
    EM_SERVERKEYEXDHMOD_p      ,
    EM_SERVERKEXLENGTH            ,
    EM_ECDHCURVETYPE              ,
    EM_ECDHNAMEDCURVE             ,
    EM_ECDHPUBKEYLENGTH           ,
    EM_ECDHPUBKEY                 ,
    EM_ECDHSIGNATUREHASHALGORITHM ,
    EM_ECDHSIGNATURESIGALGORITHM  ,
    EM_ECDHSIGNATURELENGTH        ,
    EM_ECDHSIGNATURE              ,
    EM_RSAMODULUSLENGTH           ,
    EM_RSAMODULUS                 ,
    EM_RSAEXPONENTLENGTH          ,
    EM_RSAEXPONENT                ,
    EM_RSASIGNATUREHASHALGORITHM  ,
    EM_RSASIGNATURESIGALGORITHM   ,
    EM_RSASIGNATURELENGTH         ,
    EM_RSASIGNATURE               ,
    EM_DHEPLENGTH                 ,
    EM_DHEP                       ,
    EM_DHEGLENGTH                 ,
    EM_DHEG                       ,
    EM_DHEPUBKEYLENGTH            ,
    EM_DHEPUBKEY                  ,
    EM_DHESIGNATUREHASHALGORITHM  ,
    EM_DHESIGNATURESIGALGORITHM   ,
    EM_DHESIGNATURELENGTH         ,
    EM_DHESIGNATURE               ,
    EM_SERVERKEXDATA              ,
    EM_CLIENTKEXLENGTH            ,
    EM_ENCRYPEDPUBKEY             ,
    EM_ENCRYPEDPUBKEYLENGTH       ,
    EM_CERTIFICATEREQUESTLENGTH   ,
    EM_CLIENTCERTIFICATETYPESCOUNT,
    EM_CLIENTCERTIFICATETYPES     ,
    EM_DISTINGUISHEDNAMELENGTH    ,
    EM_DISTINGUISHEDNAME          ,
    EM_CERTIFICATEVERIFYLENGTH    ,
    EM_CLIENTCERTIFICATESIGNATURE ,
    EM_CLTCERTSIGNATURELENGTH     ,
    EM_SERVERCERTSIGNATURE,
    EM_CERTPATH,
    EM_SERVERNAME                 ,
    EM_SERVERNAMEATTR			  ,
    EM_RSAPRESHAREDKEY            ,
    EM_CLIENT_CERTIFICATE_ISSUER_NAME,
    EM_CLIENT_CERTIFICATE_SEQUENCE,
    EM_CLIENT_CERTIFICATE_LENGTH,
    EM_CLIENT_CLIENTECDHCURVETYPE,
    EM_CLIENT_CLIENTECDHNAMEDCURVE,
    EM_CLIENT_CLIENTECDHPUBKEY,
    EM_EXT_TYPE,
    EM_CLIENT_EXT_TYPE_CNT,
    EM_CLIENT_EXT_TYPES,
    EM_SERVER_EXT_TYPE_CNT,
    EM_SERVER_EXT_TYPES,
    EM_EXT_SESSION_TICKET,
    EM_EXT_SESSION_TICKET_DATA,
    EM_NEW_SESSION_TICKET_DATA,
    EM_CLIENT_SESSION_TICKET,
    EM_SERVER_SESSION_TICKET,
    EM_EXT_GREASE,
    EM_EXT_HEART_BEAT,
    EM_EXT_RENEGOTIATE,
    EM_CLIENT_EC_POINT_FORMAT,
    EM_SERVER_EC_POINT_FORMAT,
    EM_CLIENT_GREASE,
    EM_CLIENT_SUPPORT_GROUP,
    EM_SERVER_SUPPORT_GROUP,
    EM_IS_AUTH_TAG,
    EM_CLIENT_CERT_HASHES,
    EM_SERVER_CERT_HASHES,
    EM_SSL_JA3C,
    EM_SSL_JA3S,
    EM_SSL_ENCRYPTED_PCAP,
    EM_SSL_IS_LEGAL,
    EM_SSL_UNLEGAL_REASON,
    EM_SSL_BEGINTIME,
    EM_SSL_ENDTIME,
    EM_SERVER_CERT_CHAINS,
    EM_SRVEXT_EC_POIFOR,
    EM_SRVEXT_EC_GROUPS,
    EM_SSL_MAX,
};

static dpi_field_table  ssl_field_array[] = {
    DPI_FIELD_D(EM_CONTENTTYPE                 , YV_FT_BYTES,                 "ContentType"),
    DPI_FIELD_D(EM_VERSION                     , YV_FT_BYTES,                 "Version"),
    DPI_FIELD_D(EM_RECORDLAYERLENGTH           , YV_FT_UINT32,                "RecordLayerLength"),
    DPI_FIELD_D(EM_CHANGECIPHERSPEC            , YV_FT_UINT32,                "ChangeCipherSpec"),
    DPI_FIELD_D(EM_ALERTLEN                    , YV_FT_UINT32,                "AlertLen"),
    DPI_FIELD_D(EM_ALERTLEVEL                  , YV_FT_UINT64,                "AlertLevel"),
    DPI_FIELD_D(EM_ALERTDESCRIPTION            , YV_FT_UINT64,                "AlertDescription"),
    DPI_FIELD_D(EM_HANDSHAKETYPE               , YV_FT_UINT32,                "HandshakeType"),
    DPI_FIELD_D(EM_CLIENTHELLOLENGTH           , YV_FT_UINT32,                "ClientHelloLength"),
    DPI_FIELD_D(EM_CLIENTPROTOCOLVERSION       , YV_FT_UINT32,                "ClientProtocolVersion"),
    DPI_FIELD_D(EM_CLIENTGMTUNIXTIME           , YV_FT_BYTES,                 "ClientGMTUnixTime"),
    DPI_FIELD_D(EM_CLIENTRANDOMBYTES           , YV_FT_BYTES,                 "ClientRandomBytes"),
    DPI_FIELD_D(EM_CLIENTSESSIONIDLENGTH       , YV_FT_UINT16,                "ClientSessionIDLength"),
    DPI_FIELD_D(EM_CLIENTSESSIONID             , YV_FT_BYTES,                 "ClientSessionID"),
    DPI_FIELD_D(EM_CLIENTCIPHERSUITESLENGTH    , YV_FT_UINT16,                "ClientCipherSuitesLength"),
    DPI_FIELD_D(EM_CLIENTCIPHERSUITES          , YV_FT_BYTES,                 "ClientCipherSuites"),
    DPI_FIELD_D(EM_CLIENTCIPHERSUITE_CNT       , YV_FT_UINT16,                "ClientCipherSuiteCnt"),
    DPI_FIELD_D(EM_CLTCOMPRESSIONMETHODSLEN    , YV_FT_UINT16,                "CltCompressionMethodsLen"),
    DPI_FIELD_D(EM_CLIENTCOMPRESSIONMETHODS    , YV_FT_BYTES,                 "ClientCompressionMethods"),
    DPI_FIELD_D(EM_CLIENTEXTENSIONSLENGTH      , YV_FT_UINT8,                 "ClientExtensionsLength"),
    DPI_FIELD_D(EM_CLIENTEXTENSIONS            , YV_FT_BYTES,                 "ClientExtensions"),
    DPI_FIELD_D(EM_SERVERHELLOLENGTH           , YV_FT_UINT32,                "ServerHelloLength"),
    DPI_FIELD_D(EM_SERVERPROTOCOLVERSION       , YV_FT_UINT32,                "ServerProtocolVersion"),
    DPI_FIELD_D(EM_SERVERGMTUNIXTIME           , YV_FT_BYTES,                 "ServerGMTUnixTime"),
    DPI_FIELD_D(EM_SERVERRANDOMBYTES           , YV_FT_BYTES,                 "ServerRandomBytes"),
    DPI_FIELD_D(EM_SERVERSESSIONIDLENGTH       , YV_FT_UINT16,                "ServerSessionIDLength"),
    DPI_FIELD_D(EM_SERVERSESSIONID             , YV_FT_BYTES,                 "ServerSessionID"),
    DPI_FIELD_D(EM_SERVERCIPHERSUITE           , YV_FT_BYTES,                 "ServerCipherSuite"),
    DPI_FIELD_D(EM_SERVERCOMPRESSIONMETHOD     , YV_FT_BYTES,                 "ServerCompressionMethod"),
    DPI_FIELD_D(EM_SERVEREXTENSIONSLENGTH      , YV_FT_UINT8,                 "ServerExtensionsLength"),
    DPI_FIELD_D(EM_SERVEREXTENSIONS            , YV_FT_BYTES,                 "ServerExtensions"),
    DPI_FIELD_D(EM_CLIENT_CERTIFICATESLENGTH   , YV_FT_UINT32,                "ClientCertificatesLength"),
    DPI_FIELD_D(EM_CLIENT_CERTIFICATESNUMS     , YV_FT_UINT8,                 "ClientCertificatesNums"),
    DPI_FIELD_D(EM_SERVER_CERTIFICATESLENGTH   , YV_FT_UINT32,                "ServerCertificatesLength"),
    DPI_FIELD_D(EM_SERVER_CERTIFICATESNUMS     , YV_FT_UINT8,                 "ServerCertificatesNums"),
    DPI_FIELD_D(EM_CERTIFICATESLENGTH          , YV_FT_UINT32,                "CertificatesLength"),
    DPI_FIELD_D(EM_CERTIFICATESNUMS            , YV_FT_UINT8,                 "CertificatesNums"),
    DPI_FIELD_D(EM_SERVERKEYEXDHGEN_g           , YV_FT_STRING,                 "ServerKeyExDHGen_g"),
    DPI_FIELD_D(EM_SERVERKEYEXDHMOD_p           , YV_FT_STRING,                 "ServerKeyExDHMod_p"),
    DPI_FIELD_D(EM_SERVERKEXLENGTH             , YV_FT_UINT32,                "ServerKexLength"),
    DPI_FIELD_D(EM_ECDHCURVETYPE               , YV_FT_BYTES,                 "ECDHCurveType"),
    DPI_FIELD_D(EM_ECDHNAMEDCURVE              , YV_FT_BYTES,                 "ECDHNamedCurve"),
    DPI_FIELD_D(EM_ECDHPUBKEYLENGTH            , YV_FT_UINT32,                "ECDHPUbKeyLength"),
    DPI_FIELD_D(EM_ECDHPUBKEY                  , YV_FT_BYTES,                 "ECDHPubkey"),
    DPI_FIELD_D(EM_ECDHSIGNATUREHASHALGORITHM  , YV_FT_BYTES,                 "ECDHSignatureHashAlgorithm"),
    DPI_FIELD_D(EM_ECDHSIGNATURESIGALGORITHM   , YV_FT_BYTES,                 "ECDHSignatureSigAlgorithm"),
    DPI_FIELD_D(EM_ECDHSIGNATURELENGTH         , YV_FT_UINT32,                "ECDHSignatureLength"),
    DPI_FIELD_D(EM_ECDHSIGNATURE               , YV_FT_BYTES,                 "ECDHSignature"),
    DPI_FIELD_D(EM_RSAMODULUSLENGTH            , YV_FT_UINT32,                  "RSAModulusLength"),
    DPI_FIELD_D(EM_RSAMODULUS                  , YV_FT_UINT32,                  "RSAModulus"),
    DPI_FIELD_D(EM_RSAEXPONENTLENGTH           , YV_FT_UINT32,                  "RSAExponentLength"),
    DPI_FIELD_D(EM_RSAEXPONENT                 , YV_FT_UINT32,                  "RSAExponent"),
    DPI_FIELD_D(EM_RSASIGNATUREHASHALGORITHM   , YV_FT_UINT32,                  "RSASignatureHashAlgorithm"),
    DPI_FIELD_D(EM_RSASIGNATURESIGALGORITHM    , YV_FT_UINT32,                  "RSASignatureSigAlgorithm"),
    DPI_FIELD_D(EM_RSASIGNATURELENGTH          , YV_FT_UINT32,                  "RSASignatureLength"),
    DPI_FIELD_D(EM_RSASIGNATURE                , YV_FT_UINT32,                  "RSASignature"),
    DPI_FIELD_D(EM_DHEPLENGTH                  , YV_FT_UINT32,                  "DHEpLength"),
    DPI_FIELD_D(EM_DHEP                        , YV_FT_UINT32,                  "DHEp"),
    DPI_FIELD_D(EM_DHEGLENGTH                  , YV_FT_UINT32,                  "DHEgLength"),
    DPI_FIELD_D(EM_DHEG                        , YV_FT_UINT32,                  "DHEg"),
    DPI_FIELD_D(EM_DHEPUBKEYLENGTH             , YV_FT_UINT32,                  "DHEPubKeyLength"),
    DPI_FIELD_D(EM_DHEPUBKEY                   , YV_FT_BYTES,                  "DHEPubkey"),
    DPI_FIELD_D(EM_DHESIGNATUREHASHALGORITHM   , YV_FT_UINT32,                  "DHESignatureHashAlgorithm"),
    DPI_FIELD_D(EM_DHESIGNATURESIGALGORITHM    , YV_FT_UINT32,                  "DHESignatureSigAlgorithm"),
    DPI_FIELD_D(EM_DHESIGNATURELENGTH          , YV_FT_UINT32,                  "DHESignatureLength"),
    DPI_FIELD_D(EM_DHESIGNATURE                , YV_FT_UINT32,                  "DHESignature"),
    DPI_FIELD_D(EM_SERVERKEXDATA               , YV_FT_UINT32,                  "ServerKexData"),
    DPI_FIELD_D(EM_CLIENTKEXLENGTH             , YV_FT_UINT32,                  "ClientKexLength"),
    DPI_FIELD_D(EM_ENCRYPEDPUBKEY              , YV_FT_BYTES,                 "EncrypedPubkey"),
    DPI_FIELD_D(EM_ENCRYPEDPUBKEYLENGTH        , YV_FT_UINT32,                "EncrypedPubkeyLength"),
    DPI_FIELD_D(EM_CERTIFICATEREQUESTLENGTH    , YV_FT_UINT32,                "CertificateRequestLength"),
    DPI_FIELD_D(EM_CLIENTCERTIFICATETYPESCOUNT , YV_FT_UINT32,                  "ClientCertificateTypesCount"),
    DPI_FIELD_D(EM_CLIENTCERTIFICATETYPES      , YV_FT_UINT32,                  "ClientCertificateTypes"),
    DPI_FIELD_D(EM_DISTINGUISHEDNAMELENGTH     , YV_FT_UINT32,                  "DistinguishedNameLength"),
    DPI_FIELD_D(EM_DISTINGUISHEDNAME           , YV_FT_UINT32,                  "DistinguishedName"),
    DPI_FIELD_D(EM_CERTIFICATEVERIFYLENGTH     , YV_FT_UINT32,                  "CertificateVerifyLength"),
    DPI_FIELD_D(EM_CLIENTCERTIFICATESIGNATURE  , YV_FT_BYTES,                  "ClientCertificateSignature"),
    DPI_FIELD_D(EM_CLTCERTSIGNATURELENGTH      , YV_FT_BYTES,                  "CltCertSignatureLength"),
    DPI_FIELD_D(EM_SERVERCERTSIGNATURE         , YV_FT_BYTES,                  "ServerCertificateSignature"),
    DPI_FIELD_D(EM_CERTPATH                    , YV_FT_BYTES,                  "certPath"),
    DPI_FIELD_D(EM_SERVERNAME                  , YV_FT_BYTES,                 "ServerName"),
    DPI_FIELD_D(EM_SERVERNAMEATTR              , YV_FT_BYTES,                   "ServerNameAttr"),
    DPI_FIELD_D(EM_RSAPRESHAREDKEY             , YV_FT_BYTES,                 "RSAPreSharedKey"),                  //Client key exchange RSA  |
    DPI_FIELD_D(EM_CLIENT_CERTIFICATE_ISSUER_NAME,YV_FT_UINT64,               "Client_Certificate_issuer_name"),   //                         |
    DPI_FIELD_D(EM_CLIENT_CERTIFICATE_SEQUENCE , YV_FT_UINT64,                "Client_Certificate_sequence"),      //                         |
    DPI_FIELD_D(EM_CLIENT_CERTIFICATE_LENGTH   , YV_FT_UINT64,                "Client_Certificate_length"),        //                         |
    DPI_FIELD_D(EM_CLIENT_CLIENTECDHCURVETYPE  , YV_FT_BYTES,                 "ClientECDHCurveType"),              //                         |
    DPI_FIELD_D(EM_CLIENT_CLIENTECDHNAMEDCURVE , YV_FT_BYTES,                 "ClientECDHNamedCurve"),             //                         |
    DPI_FIELD_D(EM_CLIENT_CLIENTECDHPUBKEY     , YV_FT_UINT64,                "ClientECDHPubkey"),                 //Client key exchange ECDH |
    DPI_FIELD_D(EM_EXT_TYPE                    , YV_FT_UINT8,                 "ext_type"),
    DPI_FIELD_D(EM_CLIENT_EXT_TYPE_CNT         , YV_FT_UINT8,                 "ClientExtTypeCnt"),
    DPI_FIELD_D(EM_CLIENT_EXT_TYPES            , YV_FT_BYTES,                 "ClientExtType"),
    DPI_FIELD_D(EM_SERVER_EXT_TYPE_CNT         , YV_FT_UINT8,                 "ServerExtTypeCnt"),
    DPI_FIELD_D(EM_SERVER_EXT_TYPES            , YV_FT_BYTES,                 "ServerExtType"),
    DPI_FIELD_D(EM_EXT_SESSION_TICKET          , YV_FT_UINT8,                 "extSessTick"),
    DPI_FIELD_D(EM_EXT_SESSION_TICKET_DATA       , YV_FT_BYTES,                   "extSessTicketData"),
    DPI_FIELD_D(EM_NEW_SESSION_TICKET_DATA       , YV_FT_BYTES,                   "newSessTicketData"),
    DPI_FIELD_D(EM_CLIENT_SESSION_TICKET       , YV_FT_BYTES,                 "ClientSessionTick"),
    DPI_FIELD_D(EM_SERVER_SESSION_TICKET       , YV_FT_BYTES,                 "ServerSessionTick"),
    DPI_FIELD_D(EM_EXT_GREASE                  , YV_FT_UINT32,                "extGrease"),
    DPI_FIELD_D(EM_EXT_HEART_BEAT              , YV_FT_BYTES,                 "ExtHeartBeat"),
    DPI_FIELD_D(EM_EXT_RENEGOTIATE             , YV_FT_BYTES,                 "ExtRenegotiate"),
    DPI_FIELD_D(EM_CLIENT_EC_POINT_FORMAT      , YV_FT_BYTES,                 "ClientEcPointFormat"),
    DPI_FIELD_D(EM_SERVER_EC_POINT_FORMAT      , YV_FT_BYTES,                 "ServerEcPointFormat"),
    DPI_FIELD_D(EM_CLIENT_GREASE               , YV_FT_UINT32,                "ClientGrease"),
    DPI_FIELD_D(EM_CLIENT_SUPPORT_GROUP        , YV_FT_BYTES,                 "ClientSupportGroups"),
    DPI_FIELD_D(EM_SERVER_SUPPORT_GROUP        , YV_FT_BYTES,                 "ServerSupportGroups"),
    DPI_FIELD_D(EM_IS_AUTH_TAG                 , YV_FT_UINT8,                 "IsAuthTag"),
    DPI_FIELD_D(EM_CLIENT_CERT_HASHES          , YV_FT_BYTES,                 "ClientCertHashes"),
    DPI_FIELD_D(EM_SERVER_CERT_HASHES          , YV_FT_BYTES,                 "ServerCertHashes"),
    DPI_FIELD_D(EM_SSL_JA3C                    , YV_FT_BYTES,                 "JA3C"),
    DPI_FIELD_D(EM_SSL_JA3S                    , YV_FT_BYTES,                 "JA3S"),
    DPI_FIELD_D(EM_SSL_ENCRYPTED_PCAP          , YV_FT_BYTES,                 "EncryptedAppData"),
    DPI_FIELD_D(EM_SSL_IS_LEGAL                , YV_FT_UINT16,                "is_legal"),
    DPI_FIELD_D(EM_SSL_UNLEGAL_REASON          , YV_FT_BYTES,                 "unlegal_reason"),
    DPI_FIELD_D(EM_SSL_BEGINTIME               , YV_FT_BYTES,                 "begintime"),
    DPI_FIELD_D(EM_SSL_ENDTIME                 , YV_FT_BYTES,                 "endtime"),
    DPI_FIELD_D(EM_SERVER_CERT_CHAINS          , YV_FT_BYTES,                 "cert_chains"),
    DPI_FIELD_D(EM_SRVEXT_EC_POIFOR            , YV_FT_BYTES,                 "srvExtECPoiFor"),
    DPI_FIELD_D(EM_SRVEXT_EC_GROUPS            , YV_FT_BYTES,                 "srvExtECGroups"),
};

enum SSL_UNLEGAL_TYPE{
    SSL_INITIALIZED_BY_SERVER = 1,  /*是否为服务器发起连接*/
    SSL_NO_HANDSHAKE,               /*无握手*/
    SSL_CERT_NOT_EFFECTIVE,         /*证书未生效*/
    SSL_CERT_EXPIRED,               /*证书过期*/
    SSL_CERT_BAD,                   /*签名是否有效*/
    SSL_CERT_LONG,                  /*证书是否过期*/
    SSL_CERT_SELF_SIGNED,           /*是否为单证书自签名*/
    SSL_CERT_NONE,                  /*无证书交换*/
    SSL_CERT_TOO_MANY,              /*证书链太长*/
    SSL_PORT_UNSTANTARD,            /*是否为非标准端口*/
    SSL_WEAK_DIGEST,
    SSL_WEAK_CERT_KEY,
    SSL_DUAL_VERIFY,

    SSL_UNLEGAL_MAX
};

static const char* ssl_unlegal_reson[] =
{
    NULL,
    "initialized_by_server",
    "has_no_handshake",
    "certificate_not_yet_effective",
    "certificate_expired",
    "certificate_authenticate_fail",
    "certificate_self_signed",
    "certificate_none",
    "certification_too_many",
    "port_not_443",
    "weak_digest_algorithm",
    "weak_certificate_secret_key",
    "verify_dual_direction"
};

enum KEY_EXCHANGE_ALG{
    KEY_EXCHANGE_NULL = 0,
    KEY_EXCHANGE_ECDH,
    KEY_EXCHANGE_RSA,
};

/* VALUE TO STRING MATCHING */
typedef struct _value_string {
    uint32_t      value;
    const char*   strptr;
} value_string;

static const value_string ssl_curve_types[] = {
    { 1, "explicit_prime" },
    { 2, "explicit_char2" },
    { 3, "named_curve" },
    { 0x00, NULL }
};

static const value_string ssl_31_content_type[] = {
    { 20, "Change Cipher Spec" },
    { 21, "Alert" },
    { 22, "Handshake" },
    { 23, "Application Data" },
    { 24, "Heartbeat" },
    { 0x00, NULL }
};

static const value_string ssl_extension_curves[] = {
    {  1, "sect163k1" },
    {  2, "sect163r1" },
    {  3, "sect163r2" },
    {  4, "sect193r1" },
    {  5, "sect193r2" },
    {  6, "sect233k1" },
    {  7, "sect233r1" },
    {  8, "sect239k1" },
    {  9, "sect283k1" },
    { 10, "sect283r1" },
    { 11, "sect409k1" },
    { 12, "sect409r1" },
    { 13, "sect571k1" },
    { 14, "sect571r1" },
    { 15, "secp160k1" },
    { 16, "secp160r1" },
    { 17, "secp160r2" },
    { 18, "secp192k1" },
    { 19, "secp192r1" },
    { 20, "secp224k1" },
    { 21, "secp224r1" },
    { 22, "secp256k1" },
    { 23, "secp256r1" },
    { 24, "secp384r1" },
    { 25, "secp521r1" },
    { 26, "brainpoolP256r1" }, /* RFC 7027 */
    { 27, "brainpoolP384r1" }, /* RFC 7027 */
    { 28, "brainpoolP512r1" }, /* RFC 7027 */
    { 29, "x25519" }, /* https://tools.ietf.org/html/draft-ietf-tls-tls13 https://tools.ietf.org/html/draft-ietf-tls-rfc4492bis */
    { 30, "x448" }, /* https://tools.ietf.org/html/draft-ietf-tls-tls13 https://tools.ietf.org/html/draft-ietf-tls-rfc4492bis */
    { 256, "ffdhe2048" }, /* RFC 7919 */
    { 257, "ffdhe3072" }, /* RFC 7919 */
    { 258, "ffdhe4096" }, /* RFC 7919 */
    { 259, "ffdhe6144" }, /* RFC 7919 */
    { 260, "ffdhe8192" }, /* RFC 7919 */
    { 2570, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 6682, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 10794, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 14906, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 19018, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 23130, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 27242, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 31354, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 35466, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 39578, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 43690, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 47802, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 51914, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 56026, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 60138, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 64250, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 0xFF01, "arbitrary_explicit_prime_curves" },
    { 0xFF02, "arbitrary_explicit_char2_curves" },
    { 0x00, NULL }
};

#define SSLV2_VERSION          0x0002
#define SSLV3_VERSION          0x0300
#define TLSV1_VERSION          0x0301
#define TLSV1DOT1_VERSION      0x0302
#define TLSV1DOT2_VERSION      0x0303
#define TLSV1DOT3_VERSION      0x0304
#define DTLSV1DOT0_VERSION     0xfeff
#define DTLSV1DOT2_VERSION     0xfefd
static const value_string ssl_versions_lsit[] = {
    { SSLV2_VERSION,        "SSL 2.0"  },
    { SSLV3_VERSION,        "SSL 3.0"  },
    { TLSV1_VERSION,        "TLS 1.0"  },
    { TLSV1DOT1_VERSION,    "TLS 1.1"  },
    { TLSV1DOT2_VERSION,    "TLS 1.2"  },
    { TLSV1DOT3_VERSION,    "TLS 1.3"  },
    { DTLSV1DOT0_VERSION,   "DTLS 1.0" },
    { DTLSV1DOT2_VERSION,   "DTLS 1.2" },
    { 0x00, NULL }
};

static const value_string wtls_vals_handshake_type[] = {
    {  0, "Hello Request" },
    {  1, "Client Hello" },
    {  2, "Server Hello" },
    {  4, "New Session Ticket" },
    { 11, "Certificate" },
    { 12, "Server Key Exchange" },
    { 13, "Certificate Request" },
    { 14, "Server Hello Done" },
    { 15, "Certificate Verify" },
    { 16, "Client Key Exchange" },
    { 20, "Finished" },
    { 0,  NULL }
};


/* http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml */
/* Note: sorted by ascending value so value_string_ext fcns can do a binary search */
static const value_string ssl_31_ciphersuite[] = {
    /* RFC 2246, RFC 4346, RFC 5246 */
    { 0x0000, "" },
    { 0x0001, "TLS_RSA_WITH_NULL_MD5" },
    { 0x0002, "TLS_RSA_WITH_NULL_SHA" },
    { 0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
    { 0x0004, "TLS_RSA_WITH_RC4_128_MD5" },
    { 0x0005, "TLS_RSA_WITH_RC4_128_SHA" },
    { 0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
    { 0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0009, "TLS_RSA_WITH_DES_CBC_SHA" },
    { 0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
    { 0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
    { 0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
    { 0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
    { 0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
    { 0x0018, "TLS_DH_anon_WITH_RC4_128_MD5" },
    { 0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA" },
    { 0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA" },
    { 0x001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA" },
    /* RFC 2712 */
    { 0x001E, "TLS_KRB5_WITH_DES_CBC_SHA" },
    { 0x001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
    { 0x0020, "TLS_KRB5_WITH_RC4_128_SHA" },
    { 0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
    { 0x0022, "TLS_KRB5_WITH_DES_CBC_MD5" },
    { 0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
    { 0x0024, "TLS_KRB5_WITH_RC4_128_MD5" },
    { 0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
    { 0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
    { 0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
    { 0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
    { 0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
    { 0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },
    /* RFC 4785 */
    { 0x002C, "TLS_PSK_WITH_NULL_SHA" },
    { 0x002D, "TLS_DHE_PSK_WITH_NULL_SHA" },
    { 0x002E, "TLS_RSA_PSK_WITH_NULL_SHA" },
    /* RFC 5246 */
    { 0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
    { 0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
    { 0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
    { 0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
    { 0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
    { 0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
    { 0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
    { 0x003B, "TLS_RSA_WITH_NULL_SHA256" },
    { 0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },
    /* RFC 4132 */
    { 0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
    /* 0x00,0x60-66 Reserved to avoid conflicts with widely deployed implementations  */
    /* --- ??? --- */
    { 0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
    { 0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
    /* draft-ietf-tls-56-bit-ciphersuites-01.txt */
    { 0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    /* --- ??? ---*/
    { 0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
    { 0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },
    /* draft-chudov-cryptopro-cptls-04.txt */
    { 0x0080,  "TLS_GOSTR341094_WITH_28147_CNT_IMIT" },
    { 0x0081,  "TLS_GOSTR341001_WITH_28147_CNT_IMIT" },
    { 0x0082,  "TLS_GOSTR341094_WITH_NULL_GOSTR3411" },
    { 0x0083,  "TLS_GOSTR341001_WITH_NULL_GOSTR3411" },
    /* RFC 4132 */
    { 0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    /* RFC 4279 */
    { 0x008A, "TLS_PSK_WITH_RC4_128_SHA" },
    { 0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA" },
    { 0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA" },
    { 0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
    { 0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
    { 0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
    { 0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },
    /* RFC 4162 */
    { 0x0096, "TLS_RSA_WITH_SEED_CBC_SHA" },
    { 0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
    { 0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
    { 0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
    { 0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
    { 0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA" },
    /* RFC 5288 */
    { 0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
    { 0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },
    /* RFC 5487 */
    { 0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B0, "TLS_PSK_WITH_NULL_SHA256" },
    { 0x00B1, "TLS_PSK_WITH_NULL_SHA384" },
    { 0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256" },
    { 0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384" },
    { 0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256" },
    { 0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384" },
    /* From RFC 5932 */
    { 0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
    /* From RFC 5746 */
    { 0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
    /* https://tools.ietf.org/html/draft-ietf-tls-grease */
    { 0x0A0A, "Reserved (GREASE)" },
    /* https://tools.ietf.org/html/draft-ietf-tls-tls13 */
    { 0x1301, "TLS_AES_128_GCM_SHA256" },
    { 0x1302, "TLS_AES_256_GCM_SHA384" },
    { 0x1303, "TLS_CHACHA20_POLY1305_SHA256" },
    { 0x1304, "TLS_AES_128_CCM_SHA256" },
    { 0x1305, "TLS_AES_128_CCM_8_SHA256" },
    /* https://tools.ietf.org/html/draft-ietf-tls-grease */
    { 0x1A1A, "Reserved (GREASE)" },
    { 0x2A2A, "Reserved (GREASE)" },
    { 0x3A3A, "Reserved (GREASE)" },
    { 0x4A4A, "Reserved (GREASE)" },
    /* From RFC 7507 */
    { 0x5600, "TLS_FALLBACK_SCSV" },
    /* https://tools.ietf.org/html/draft-ietf-tls-grease */
    { 0x5A5A, "Reserved (GREASE)" },
    { 0x6A6A, "Reserved (GREASE)" },
    { 0x7A7A, "Reserved (GREASE)" },
    { 0x8A8A, "Reserved (GREASE)" },
    { 0x9A9A, "Reserved (GREASE)" },
    { 0xAAAA, "Reserved (GREASE)" },
    { 0xBABA, "Reserved (GREASE)" },
    /* From RFC 4492 */
    { 0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
    { 0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
    { 0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA" },
    { 0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
    { 0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
    { 0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
    { 0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
    { 0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
    { 0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0xc015, "TLS_ECDH_anon_WITH_NULL_SHA" },
    { 0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
    { 0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
    { 0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },
    /* RFC 5054 */
    { 0xC01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
    { 0xC01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
    { 0xC01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
    { 0xC020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
    { 0xC021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
    { 0xC022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },
    /* RFC 5589 */
    { 0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
    { 0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
    { 0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },
    /* RFC 5489 */
    { 0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA" },
    { 0xC034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0xC036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0xC037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0xC038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA" },
    { 0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256" },
    { 0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384" },
    /* RFC 6209 */
    { 0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC03E, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256" },
    { 0xC03F, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384" },
    { 0xC040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256" },
    { 0xC043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384" },
    { 0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256" },
    { 0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384" },
    { 0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256" },
    { 0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384" },
    { 0xC058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256" },
    { 0xC059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC06A, "TLS_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06B, "TLS_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC06C, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06D, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC06E, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06F, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384" },
    /* RFC 6367 */
    { 0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC07C, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07D, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC07E, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07F, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08C, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08D, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08E, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08F, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC09A, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC09B, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    /* RFC 6655 */
    { 0xC09C, "TLS_RSA_WITH_AES_128_CCM" },
    { 0xC09D, "TLS_RSA_WITH_AES_256_CCM" },
    { 0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM" },
    { 0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM" },
    { 0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8" },
    { 0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8" },
    { 0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8" },
    { 0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8" },
    { 0xC0A4, "TLS_PSK_WITH_AES_128_CCM" },
    { 0xC0A5, "TLS_PSK_WITH_AES_256_CCM" },
    { 0xC0A6, "TLS_DHE_PSK_WITH_AES_128_CCM" },
    { 0xC0A7, "TLS_DHE_PSK_WITH_AES_256_CCM" },
    { 0xC0A8, "TLS_PSK_WITH_AES_128_CCM_8" },
    { 0xC0A9, "TLS_PSK_WITH_AES_256_CCM_8" },
    { 0xC0AA, "TLS_PSK_DHE_WITH_AES_128_CCM_8" },
    { 0xC0AB, "TLS_PSK_DHE_WITH_AES_256_CCM_8" },
    /* RFC 7251 */
    { 0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM" },
    { 0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM" },
    { 0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" },
    { 0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8" },
    /* https://tools.ietf.org/html/draft-ietf-tls-grease */
    { 0xCACA, "Reserved (GREASE)" },
    { 0xCC13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCC14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCC15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    /* RFC 7905 */
    { 0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    /* https://tools.ietf.org/html/draft-ietf-tls-ecdhe-psk-aead */
    { 0xD001, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0xD002, "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0xD003, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256" },
    { 0xD005, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256" },
    /* https://tools.ietf.org/html/draft-ietf-tls-grease */
    { 0xDADA, "Reserved (GREASE)" },
    /* http://tools.ietf.org/html/draft-josefsson-salsa20-tls */
    { 0xE410, "TLS_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE411, "TLS_RSA_WITH_SALSA20_SHA1" },
    { 0xE412, "TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE413, "TLS_ECDHE_RSA_WITH_SALSA20_SHA1" },
    { 0xE414, "TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE415, "TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1" },
    { 0xE416, "TLS_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE417, "TLS_PSK_WITH_SALSA20_SHA1" },
    { 0xE418, "TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE419, "TLS_ECDHE_PSK_WITH_SALSA20_SHA1" },
    { 0xE41A, "TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE41B, "TLS_RSA_PSK_WITH_SALSA20_SHA1" },
    { 0xE41C, "TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE41D, "TLS_DHE_PSK_WITH_SALSA20_SHA1" },
    { 0xE41E, "TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE41F, "TLS_DHE_RSA_WITH_SALSA20_SHA1" },
    /* https://tools.ietf.org/html/draft-ietf-tls-grease */
    { 0xEAEA, "Reserved (GREASE)" },
    { 0xFAFA, "Reserved (GREASE)" },
    { 0xfefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0xfeff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0xffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0xffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* note that ciphersuites 0xff00 - 0xffff are private */
    { 0x00, NULL }
};


static const value_string ssl_extension_ec_point_formats[] = {
    { 0, "uncompressed" },
    { 1, "ansiX962_compressed_prime" },
    { 2, "ansiX962_compressed_char2" },
    { 0x00, NULL }
};


/* To assist in parsing client/server key exchange messages
   0 indicates unknown */
static int ssl_get_keyex_alg(int cipher) {
	/* Map Cipher suite number to Key Exchange algorithm {{{ */
	switch (cipher) {
	case 0x0017:
	case 0x0018:
	case 0x0019:
	case 0x001a:
	case 0x001b:
	case 0x0034:
	case 0x003a:
	case 0x0046:
	case 0x006c:
	case 0x006d:
	case 0x0089:
	case 0x009b:
	case 0x00a6:
	case 0x00a7:
	case 0x00bf:
	case 0x00c5:
	case 0xc084:
	case 0xc085:
		return KEX_DH_ANON;
	case 0x000b:
	case 0x000c:
	case 0x000d:
	case 0x0030:
	case 0x0036:
	case 0x003e:
	case 0x0042:
	case 0x0068:
	case 0x0085:
	case 0x0097:
	case 0x00a4:
	case 0x00a5:
	case 0x00bb:
	case 0x00c1:
	case 0xc082:
	case 0xc083:
		return KEX_DH_DSS;
	case 0x000e:
	case 0x000f:
	case 0x0010:
	case 0x0031:
	case 0x0037:
	case 0x003f:
	case 0x0043:
	case 0x0069:
	case 0x0086:
	case 0x0098:
	case 0x00a0:
	case 0x00a1:
	case 0x00bc:
	case 0x00c2:
	case 0xc07e:
	case 0xc07f:
		return KEX_DH_RSA;
	case 0x0011:
	case 0x0012:
	case 0x0013:
	case 0x0032:
	case 0x0038:
	case 0x0040:
	case 0x0044:
	case 0x0063:
	case 0x0065:
	case 0x0066:
	case 0x006a:
	case 0x0087:
	case 0x0099:
	case 0x00a2:
	case 0x00a3:
	case 0x00bd:
	case 0x00c3:
	case 0xc080:
	case 0xc081:
		return KEX_DHE_DSS;
	case 0x002d:
	case 0x008e:
	case 0x008f:
	case 0x0090:
	case 0x0091:
	case 0x00aa:
	case 0x00ab:
	case 0x00b2:
	case 0x00b3:
	case 0x00b4:
	case 0x00b5:
	case 0xc090:
	case 0xc091:
	case 0xc096:
	case 0xc097:
	case 0xc0a6:
	case 0xc0a7:
	case 0xc0aa:
	case 0xc0ab:
	case 0xccad:
	case 0xe41c:
	case 0xe41d:
		return KEX_DHE_PSK;
	case 0x0014:
	case 0x0015:
	case 0x0016:
	case 0x0033:
	case 0x0039:
	case 0x0045:
	case 0x0067:
	case 0x006b:
	case 0x0088:
	case 0x009a:
	case 0x009e:
	case 0x009f:
	case 0x00be:
	case 0x00c4:
	case 0xc07c:
	case 0xc07d:
	case 0xc09e:
	case 0xc09f:
	case 0xc0a2:
	case 0xc0a3:
	case 0xccaa:
	case 0xe41e:
	case 0xe41f:
		return KEX_DHE_RSA;
	case 0xc015:
	case 0xc016:
	case 0xc017:
	case 0xc018:
	case 0xc019:
		return KEX_ECDH_ANON;
	case 0xc001:
	case 0xc002:
	case 0xc003:
	case 0xc004:
	case 0xc005:
	case 0xc025:
	case 0xc026:
	case 0xc02d:
	case 0xc02e:
	case 0xc074:
	case 0xc075:
	case 0xc088:
	case 0xc089:
		return KEX_ECDH_ECDSA;
	case 0xc00b:
	case 0xc00c:
	case 0xc00d:
	case 0xc00e:
	case 0xc00f:
	case 0xc029:
	case 0xc02a:
	case 0xc031:
	case 0xc032:
	case 0xc078:
	case 0xc079:
	case 0xc08c:
	case 0xc08d:
		return KEX_ECDH_RSA;
	case 0xc006:
	case 0xc007:
	case 0xc008:
	case 0xc009:
	case 0xc00a:
	case 0xc023:
	case 0xc024:
	case 0xc02b:
	case 0xc02c:
	case 0xc072:
	case 0xc073:
	case 0xc086:
	case 0xc087:
	case 0xc0ac:
	case 0xc0ad:
	case 0xc0ae:
	case 0xc0af:
	case 0xcca9:
	case 0xe414:
	case 0xe415:
		return KEX_ECDHE_ECDSA;
	case 0xc033:
	case 0xc034:
	case 0xc035:
	case 0xc036:
	case 0xc037:
	case 0xc038:
	case 0xc039:
	case 0xc03a:
	case 0xc03b:
	case 0xc09a:
	case 0xc09b:
	case 0xccac:
	case 0xe418:
	case 0xe419:
		return KEX_ECDHE_PSK;
	case 0xc010:
	case 0xc011:
	case 0xc012:
	case 0xc013:
	case 0xc014:
	case 0xc027:
	case 0xc028:
	case 0xc02f:
	case 0xc030:
	case 0xc076:
	case 0xc077:
	case 0xc08a:
	case 0xc08b:
	case 0xcca8:
	case 0xe412:
	case 0xe413:
		return KEX_ECDHE_RSA;
	case 0x001e:
	case 0x001f:
	case 0x0020:
	case 0x0021:
	case 0x0022:
	case 0x0023:
	case 0x0024:
	case 0x0025:
	case 0x0026:
	case 0x0027:
	case 0x0028:
	case 0x0029:
	case 0x002a:
	case 0x002b:
		return KEX_KRB5;
	case 0x002c:
	case 0x008a:
	case 0x008b:
	case 0x008c:
	case 0x008d:
	case 0x00a8:
	case 0x00a9:
	case 0x00ae:
	case 0x00af:
	case 0x00b0:
	case 0x00b1:
	case 0xc064:
	case 0xc065:
	case 0xc08e:
	case 0xc08f:
	case 0xc094:
	case 0xc095:
	case 0xc0a4:
	case 0xc0a5:
	case 0xc0a8:
	case 0xc0a9:
	case 0xccab:
	case 0xe416:
	case 0xe417:
		return KEX_PSK;
	case 0x0001:
	case 0x0002:
	case 0x0003:
	case 0x0004:
	case 0x0005:
	case 0x0006:
	case 0x0007:
	case 0x0008:
	case 0x0009:
	case 0x000a:
	case 0x002f:
	case 0x0035:
	case 0x003b:
	case 0x003c:
	case 0x003d:
	case 0x0041:
	case 0x0060:
	case 0x0061:
	case 0x0062:
	case 0x0064:
	case 0x0084:
	case 0x0096:
	case 0x009c:
	case 0x009d:
	case 0x00ba:
	case 0x00c0:
	case 0xc07a:
	case 0xc07b:
	case 0xc09c:
	case 0xc09d:
	case 0xc0a0:
	case 0xc0a1:
	case 0xe410:
	case 0xe411:
	case 0xfefe:
	case 0xfeff:
	case 0xffe0:
	case 0xffe1:
		return KEX_RSA;
	case 0x002e:
	case 0x0092:
	case 0x0093:
	case 0x0094:
	case 0x0095:
	case 0x00ac:
	case 0x00ad:
	case 0x00b6:
	case 0x00b7:
	case 0x00b8:
	case 0x00b9:
	case 0xc092:
	case 0xc093:
	case 0xc098:
	case 0xc099:
	case 0xccae:
	case 0xe41a:
	case 0xe41b:
		return KEX_RSA_PSK;
	case 0xc01a:
	case 0xc01d:
	case 0xc020:
		return KEX_SRP_SHA;
	case 0xc01c:
	case 0xc01f:
	case 0xc022:
		return KEX_SRP_SHA_DSS;
	case 0xc01b:
	case 0xc01e:
	case 0xc021:
		return KEX_SRP_SHA_RSA;
	case 0xc0ff:
		return KEX_ECJPAKE;
	default:
		break;
	}

	return 0;
	/* }}} */
}

static const SslCipherSuite cipher_suites[] = {
	{0x0001,KEX_RSA,            ENC_NULL,       DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_MD5 */
	{0x0002,KEX_RSA,            ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA */
	{0x0003,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
	{0x0004,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_MD5 */
	{0x0005,KEX_RSA,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_SHA */
	{0x0006,KEX_RSA,            ENC_RC2,        DIG_MD5,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
	{0x0007,KEX_RSA,            ENC_IDEA,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_IDEA_CBC_SHA */
	{0x0008,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
	{0x0009,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_DES_CBC_SHA */
	{0x000A,KEX_RSA,            ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
	{0x000B,KEX_DH_DSS,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
	{0x000C,KEX_DH_DSS,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_DES_CBC_SHA */
	{0x000D,KEX_DH_DSS,         ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA */
	{0x000E,KEX_DH_RSA,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
	{0x000F,KEX_DH_RSA,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_DES_CBC_SHA */
	{0x0010,KEX_DH_RSA,         ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA */
	{0x0011,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
	{0x0012,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_DES_CBC_SHA */
	{0x0013,KEX_DHE_DSS,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
	{0x0014,KEX_DHE_RSA,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
	{0x0015,KEX_DHE_RSA,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_DES_CBC_SHA */
	{0x0016,KEX_DHE_RSA,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
	{0x0017,KEX_DH_ANON,        ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
	{0x0018,KEX_DH_ANON,        ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_WITH_RC4_128_MD5 */
	{0x0019,KEX_DH_ANON,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
	{0x001A,KEX_DH_ANON,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_DES_CBC_SHA */
	{0x001B,KEX_DH_ANON,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
	{0x002C,KEX_PSK,            ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA */
	{0x002D,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA */
	{0x002E,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA */
	{0x002F,KEX_RSA,            ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA */
	{0x0030,KEX_DH_DSS,         ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA */
	{0x0031,KEX_DH_RSA,         ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA */
	{0x0032,KEX_DHE_DSS,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */
	{0x0033,KEX_DHE_RSA,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
	{0x0034,KEX_DH_ANON,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA */
	{0x0035,KEX_RSA,            ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA */
	{0x0036,KEX_DH_DSS,         ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA */
	{0x0037,KEX_DH_RSA,         ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA */
	{0x0038,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */
	{0x0039,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
	{0x003A,KEX_DH_ANON,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA */
	{0x003B,KEX_RSA,            ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA256 */
	{0x003C,KEX_RSA,            ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
	{0x003D,KEX_RSA,            ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
	{0x003E,KEX_DH_DSS,         ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA256 */
	{0x003F,KEX_DH_RSA,         ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA256 */
	{0x0040,KEX_DHE_DSS,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 */
	{0x0041,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
	{0x0042,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA */
	{0x0043,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA */
	{0x0044,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA */
	{0x0045,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA */
	{0x0046,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA */
	{0x0060,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
	{0x0061,KEX_RSA,            ENC_RC2,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
	{0x0062,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
	{0x0063,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
	{0x0064,KEX_RSA,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
	{0x0065,KEX_DHE_DSS,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
	{0x0066,KEX_DHE_DSS,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_WITH_RC4_128_SHA */
	{0x0067,KEX_DHE_RSA,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
	{0x0068,KEX_DH_DSS,         ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA256 */
	{0x0069,KEX_DH_RSA,         ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA256 */
	{0x006A,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 */
	{0x006B,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */
	{0x006C,KEX_DH_ANON,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA256 */
	{0x006D,KEX_DH_ANON,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA256 */
	{0x0084,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
	{0x0085,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA */
	{0x0086,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA */
	{0x0087,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA */
	{0x0088,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA */
	{0x0089,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA */
	{0x008A,KEX_PSK,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_RC4_128_SHA */
	{0x008B,KEX_PSK,            ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_3DES_EDE_CBC_SHA */
	{0x008C,KEX_PSK,            ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA */
	{0x008D,KEX_PSK,            ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA */
	{0x008E,KEX_DHE_PSK,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_RC4_128_SHA */
	{0x008F,KEX_DHE_PSK,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA */
	{0x0090,KEX_DHE_PSK,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA */
	{0x0091,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA */
	{0x0092,KEX_RSA_PSK,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_RC4_128_SHA */
	{0x0093,KEX_RSA_PSK,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA */
	{0x0094,KEX_RSA_PSK,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA */
	{0x0095,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA */
	{0x0096,KEX_RSA,            ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_SEED_CBC_SHA */
	{0x0097,KEX_DH_DSS,         ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_SEED_CBC_SHA */
	{0x0098,KEX_DH_RSA,         ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_SEED_CBC_SHA */
	{0x0099,KEX_DHE_DSS,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_SEED_CBC_SHA */
	{0x009A,KEX_DHE_RSA,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_SEED_CBC_SHA */
	{0x009B,KEX_DH_ANON,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_SEED_CBC_SHA */
	{0x009C,KEX_RSA,            ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
	{0x009D,KEX_RSA,            ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
	{0x009E,KEX_DHE_RSA,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 */
	{0x009F,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */
	{0x00A0,KEX_DH_RSA,         ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_128_GCM_SHA256 */
	{0x00A1,KEX_DH_RSA,         ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_256_GCM_SHA384 */
	{0x00A2,KEX_DHE_DSS,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 */
	{0x00A3,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 */
	{0x00A4,KEX_DH_DSS,         ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_128_GCM_SHA256 */
	{0x00A5,KEX_DH_DSS,         ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_256_GCM_SHA384 */
	{0x00A6,KEX_DH_ANON,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_128_GCM_SHA256 */
	{0x00A7,KEX_DH_ANON,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_256_GCM_SHA384 */
	{0x00A8,KEX_PSK,            ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_AES_128_GCM_SHA256 */
	{0x00A9,KEX_PSK,            ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_AES_256_GCM_SHA384 */
	{0x00AA,KEX_DHE_PSK,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 */
	{0x00AB,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 */
	{0x00AC,KEX_RSA_PSK,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 */
	{0x00AD,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 */
	{0x00AE,KEX_PSK,            ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA256 */
	{0x00AF,KEX_PSK,            ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA384 */
	{0x00B0,KEX_PSK,            ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA256 */
	{0x00B1,KEX_PSK,            ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA384 */
	{0x00B2,KEX_DHE_PSK,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 */
	{0x00B3,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 */
	{0x00B4,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA256 */
	{0x00B5,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA384 */
	{0x00B6,KEX_RSA_PSK,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 */
	{0x00B7,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 */
	{0x00B8,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA256 */
	{0x00B9,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA384 */
	{0x00BA,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{0x00BB,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
	{0x00BC,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{0x00BD,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
	{0x00BE,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{0x00BF,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 */
	{0x00C0,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
	{0x00C1,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
	{0x00C2,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
	{0x00C3,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
	{0x00C4,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
	{0x00C5,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 */

	/* NOTE: TLS 1.3 cipher suites are incompatible with TLS 1.2. */
	{0x1301,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_AES_128_GCM_SHA256 */
	{0x1302,KEX_TLS13,          ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_AES_256_GCM_SHA384 */
	{0x1303,KEX_TLS13,          ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_CHACHA20_POLY1305_SHA256 */
	{0x1304,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_CCM   },   /* TLS_AES_128_CCM_SHA256 */
	{0x1305,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_CCM_8 },   /* TLS_AES_128_CCM_8_SHA256 */

	{0xC001,KEX_ECDH_ECDSA,     ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
	{0xC002,KEX_ECDH_ECDSA,     ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
	{0xC003,KEX_ECDH_ECDSA,     ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */
	{0xC004,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */
	{0xC005,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
	{0xC006,KEX_ECDHE_ECDSA,    ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
	{0xC007,KEX_ECDHE_ECDSA,    ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA */
	{0xC008,KEX_ECDHE_ECDSA,    ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */
	{0xC009,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
	{0xC00A,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
	{0xC00B,KEX_ECDH_RSA,       ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_NULL_SHA */
	{0xC00C,KEX_ECDH_RSA,       ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
	{0xC00D,KEX_ECDH_RSA,       ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA */
	{0xC00E,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */
	{0xC00F,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */
	{0xC0FF,KEX_ECJPAKE,        ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_ECJPAKE_WITH_AES_128_CCM_8 */
	{0xC010,KEX_ECDHE_RSA,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_NULL_SHA */
	{0xC011,KEX_ECDHE_RSA,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
	{0xC012,KEX_ECDHE_RSA,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
	{0xC013,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
	{0xC014,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
	{0xC015,KEX_ECDH_ANON,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_NULL_SHA */
	{0xC016,KEX_ECDH_ANON,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_RC4_128_SHA */
	{0xC017,KEX_ECDH_ANON,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
	{0xC018,KEX_ECDH_ANON,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
	{0xC019,KEX_ECDH_ANON,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
	{0xC01A,KEX_SRP_SHA,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA */
	{0xC01B,KEX_SRP_SHA_RSA,    ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA */
	{0xC01C,KEX_SRP_SHA_DSS,    ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA */
	{0xC01D,KEX_SRP_SHA,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_WITH_AES_128_CBC_SHA */
	{0xC01E,KEX_SRP_SHA_RSA,    ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA */
	{0xC01F,KEX_SRP_SHA_DSS,    ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA */
	{0xC020,KEX_SRP_SHA,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_WITH_AES_256_CBC_SHA */
	{0xC021,KEX_SRP_SHA_RSA,    ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA */
	{0xC022,KEX_SRP_SHA_DSS,    ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA */
	{0xC023,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
	{0xC024,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
	{0xC025,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */
	{0xC026,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */
	{0xC027,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
	{0xC028,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
	{0xC029,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */
	{0xC02A,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */
	{0xC02B,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
	{0xC02C,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
	{0xC02D,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */
	{0xC02E,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */
	{0xC02F,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
	{0xC030,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
	{0xC031,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */
	{0xC032,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */
	{0xC033,KEX_ECDHE_PSK,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_RC4_128_SHA */
	{0xC034,KEX_ECDHE_PSK,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA */
	{0xC035,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA */
	{0xC036,KEX_ECDHE_PSK,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA */
	{0xC037,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 */
	{0xC038,KEX_ECDHE_PSK,      ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
	{0xC039,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA */
	{0xC03A,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA256 */
	{0xC03B,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA384 */
	{0xC072,KEX_ECDHE_ECDSA,    ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{0xC073,KEX_ECDHE_ECDSA,    ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
	{0xC074,KEX_ECDH_ECDSA,     ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{0xC075,KEX_ECDH_ECDSA,     ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
	{0xC076,KEX_ECDHE_RSA,      ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{0xC077,KEX_ECDHE_RSA,      ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
	{0xC078,KEX_ECDH_RSA,       ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{0xC079,KEX_ECDH_RSA,       ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
	{0xC07A,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC07B,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC07C,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC07D,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC07E,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC07F,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC080,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC081,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC082,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC083,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC084,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC085,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC086,KEX_ECDHE_ECDSA,    ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC087,KEX_ECDHE_ECDSA,    ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC088,KEX_ECDH_ECDSA,     ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC089,KEX_ECDH_ECDSA,     ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC08A,KEX_ECDHE_RSA,      ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC08B,KEX_ECDHE_RSA,      ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC08C,KEX_ECDH_RSA,       ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC08D,KEX_ECDH_RSA,       ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC08E,KEX_PSK,            ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC08F,KEX_PSK,            ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC090,KEX_DHE_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC091,KEX_DHE_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC092,KEX_RSA_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
	{0xC093,KEX_RSA_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
	{0xC094,KEX_PSK,            ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
	{0xC095,KEX_PSK,            ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
	{0xC096,KEX_DHE_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
	{0xC097,KEX_DHE_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
	{0xC098,KEX_RSA_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
	{0xC099,KEX_RSA_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
	{0xC09A,KEX_ECDHE_PSK,      ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
	{0xC09B,KEX_ECDHE_PSK,      ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
	{0xC09C,KEX_RSA,            ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_128_CCM */
	{0xC09D,KEX_RSA,            ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_256_CCM */
	{0xC09E,KEX_DHE_RSA,        ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_128_CCM */
	{0xC09F,KEX_DHE_RSA,        ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_256_CCM */
	{0xC0A0,KEX_RSA,            ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_128_CCM_8 */
	{0xC0A1,KEX_RSA,            ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_256_CCM_8 */
	{0xC0A2,KEX_DHE_RSA,        ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_128_CCM_8 */
	{0xC0A3,KEX_DHE_RSA,        ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_256_CCM_8 */
	{0xC0A4,KEX_PSK,            ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_128_CCM */
	{0xC0A5,KEX_PSK,            ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_256_CCM */
	{0xC0A6,KEX_DHE_PSK,        ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_128_CCM */
	{0xC0A7,KEX_DHE_PSK,        ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_256_CCM */
	{0xC0A8,KEX_PSK,            ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_128_CCM_8 */
	{0xC0A9,KEX_PSK,            ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_256_CCM_8 */
	{0xC0AA,KEX_DHE_PSK,        ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_128_CCM_8 */
	{0xC0AB,KEX_DHE_PSK,        ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_256_CCM_8 */
	{0xC0AC,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
	{0xC0AD,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM */
	{0xC0AE,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
	{0xC0AF,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 */
	{0xCCA8,KEX_ECDHE_RSA,      ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
	{0xCCA9,KEX_ECDHE_ECDSA,    ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
	{0xCCAA,KEX_DHE_RSA,        ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
	{0xCCAB,KEX_PSK,            ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 */
	{0xCCAC,KEX_ECDHE_PSK,      ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
	{0xCCAD,KEX_DHE_PSK,        ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
	{0xCCAE,KEX_RSA_PSK,        ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 */
	/* GM */
	{0xe001,KEX_ECDHE_SM2,      ENC_SM1,        DIG_SM3,    MODE_CBC},        /* ECDHE_SM1_SM3 */
	{0xe003,KEX_ECC_SM2,        ENC_SM1,        DIG_SM3,    MODE_CBC},        /* ECC_SM1_SM3 */
	{0xe005,KEX_IBSDH_SM9,      ENC_SM1,        DIG_SM3,    MODE_CBC},        /* IBSDH_SM1_SM3 */
	{0xe007,KEX_IBC_SM9,        ENC_SM1,        DIG_SM3,    MODE_CBC},        /* IBC_SM1_SM3 */
	{0xe009,KEX_RSA,            ENC_SM1,        DIG_SM3,    MODE_CBC},        /* RSA_SM1_SM3 */
	{0xe00a,KEX_RSA,            ENC_SM1,        DIG_SHA,    MODE_CBC},        /* RSA_SM1_SHA1 */
	{0xe011,KEX_ECDHE_SM2,      ENC_SM4,        DIG_SM3,    MODE_CBC},        /* ECDHE_SM4_SM3 */
	{0xe013,KEX_ECC_SM2,        ENC_SM4,        DIG_SM3,    MODE_CBC},        /* ECC_SM4_SM3 */
	{0xe015,KEX_IBSDH_SM9,      ENC_SM4,        DIG_SM3,    MODE_CBC},        /* IBSDH_SM4_SM3 */
	{0xe017,KEX_IBC_SM9,        ENC_SM4,        DIG_SM3,    MODE_CBC},        /* IBC_SM4_SM3 */
	{0xe019,KEX_RSA,            ENC_SM4,        DIG_SM3,    MODE_CBC},        /* RSA_SM4_SM3 */
	{0xe01a,KEX_RSA,            ENC_SM4,        DIG_SHA,    MODE_CBC},        /* RSA_SM4_SHA1 */
	{-1,    0,                  0,              0,          MODE_STREAM}
};

#define SSL_CLIENT_RANDOM       (1<<0)
#define SSL_SERVER_RANDOM       (1<<1)
#define SSL_CIPHER              (1<<2)
#define SSL_HAVE_SESSION_KEY    (1<<3)
#define SSL_VERSION             (1<<4)
#define SSL_MASTER_SECRET       (1<<5)
#define SSL_PRE_MASTER_SECRET   (1<<6)
#define SSL_CLIENT_EXTENDED_MASTER_SECRET (1<<7)
#define SSL_SERVER_EXTENDED_MASTER_SECRET (1<<8)
#define SSL_NEW_SESSION_TICKET  (1<<10)
#define SSL_ENCRYPT_THEN_MAC    (1<<11)
#define SSL_SEEN_0RTT_APPDATA   (1<<12)
#define SSL_QUIC_RECORD_LAYER   (1<<13) /* For QUIC (draft >= -13) */

static const value_string ssl_31_compression_method[] = {
    {  0, "null" },
    {  1, "DEFLATE" },
    { 64, "LZS" },
    { 0x00, NULL }
};

const value_string dpi_tls_hash_algorithm[] = {
    { 0, "None" },
    { 1, "MD5" },
    { 2, "SHA1" },
    { 3, "SHA224" },
    { 4, "SHA256" },
    { 5, "SHA384" },
    { 6, "SHA512" },
    { 0, NULL }
};

const value_string dpi_tls_signature_algorithm[] = {
    { 0, "Anonymous" },
    { 1, "RSA" },
    { 2, "DSA" },
    { 3, "ECDSA" },
    { 0, NULL }
};
const value_string dpi_x509af_Version_vals[] = {
    {   0, "v1" },
    {   1, "v2" },
    {   2, "v3" },
    { 0, NULL }
};

const value_string dpi_tls_hello_ext_server_name_type_vs[] = {
	{ 0, "host_name" },
	{ 0, NULL }
};


static int BetweenAnd(size_t number, size_t Left, size_t Right)
{
    if ((Left <= number) && (number <= Right))
    {
        return 0;
    }
    return 1;
}


static inline const char* value2String(size_t value, const value_string *KVList)
{
    while(KVList->strptr)
    {
        if(value ==  KVList->value)
            return KVList->strptr;
        KVList++;
    }
    return "";
}



static void
network_to_hex_with_space(const char * network_stream, size_t length,
                          char * hex_str, uint8_t step)
{
  size_t i;
  int  j, k;
  unsigned char byte;

  if (length % 2 != 0) {
    length = length - 1;
  }

  for (i = 0, j = 0; i < length; i+=k) {

    for (k = 0; k < step; ++k) {
      byte = network_stream[i + k];
      hex_str[j++] = "0123456789ABCDEF"[byte >> 4];
      hex_str[j++] = "0123456789ABCDEF"[byte & 0x0F];
    }

    // byte = network_stream[i + k];
    // hex_str[j++] = "0123456789ABCDEF"[byte >> 4];
    // hex_str[j++] = "0123456789ABCDEF"[byte & 0x0F];
    // byte = network_stream[i+1];
    // hex_str[j++] = "0123456789ABCDEF"[byte >> 4];
    // hex_str[j++] = "0123456789ABCDEF"[byte & 0x0F];
    if (i != length - 1) {
      hex_str[j++] = ' ';
    }
  }
  hex_str[j] = '\0';
}

void dpi_get_x509_chain_str(ST_SSLInfo* pst_sslinfo,char* to_str,int max_str_len){
  int ret = 0;
  for (int i = 0; i < pst_sslinfo->cert_chain_num; i++) {
    struct dpi_x509_chain_st *p = pst_sslinfo->cert_chain[i];
    while (NULL != p) {
      if (p->subject == NULL) {
        break;
      }
      p = p->subject;
    }

    while (p!= NULL) {
      ret += snprintf(to_str+ret, max_str_len - strlen(to_str), "%s", p->desc);
      p = p->iss;
      if(p){
      strcat(to_str, "->");
      ret+=2;
      }
    }
    strcat(to_str, ";");
    ret++;
  }
}
void dpi_free_x509_chain(struct dpi_x509_chain_st * chain){
    struct dpi_x509_chain_st *p = chain;
    struct dpi_x509_chain_st *next = chain->iss;

    if (NULL == p) {
        return;
    }
    while (p->subject != NULL) {
        p = p->subject;
        free(p->iss);
        p->iss = NULL;
    }
    free(p);
    while (next != NULL) {
        next = p->iss;
        free(p->subject);
        p->subject = NULL;
    }
    free(next);
}

static inline void free_ssl_result(struct flow_info *flow _U_, ST_SSLInfo* pst_sslinfo)
{
    uint16_t i;
    struct SslCertInfo  *pcert_info;

    for (i = 0; i < array_length(pst_sslinfo->cert_infos); i++)
    {
        pcert_info = &pst_sslinfo->cert_infos[i];

        if (pcert_info->CertificatesNums) {
            free_x509(pcert_info->cert, pcert_info->CertificatesNums);
            pcert_info->CertificatesNums = 0;
        }
    }

    if(pst_sslinfo->ECDHPubkey_free){
        free(pst_sslinfo->ECDHPubkey_ptr);
        pst_sslinfo->ECDHPubkey_ptr = 0;
    }
    for(int i =0;i<pst_sslinfo->cert_chain_num;i++){
        dpi_free_x509_chain(pst_sslinfo->cert_chain[i]);
        pst_sslinfo->cert_chain[i] = NULL;
    }
    pst_sslinfo->cert_chain_num =0;
}

static int write_ssl_result(struct flow_info *flow, int direction, ST_SSLInfo *pst_sslinfo) {
    if (pst_sslinfo->ContentType == 22 && pst_sslinfo->HandshakeType == 0)
        return 0;

    struct SslCertInfo *pcert_info;
    struct tbl_log     *log_ptr = NULL;
    int                 idx = 0;
    int                 i;
    int                 ret;
    char                _str[2048] = {0};

    if (rte_mempool_get(tbl_log_mempool, (void **)&log_ptr) < 0) {
        DPI_LOG(DPI_LOG_WARNING, "not enough memory: tbl_log_mempool");
        return PKT_OK;
    }

    init_log_ptr_data(log_ptr, flow, EM_TBL_LOG_ID_BY_DEFAULT);
    dpi_precord_new_record(log_ptr->record, NULL, NULL);
    write_tbl_log_common(flow, direction, log_ptr, &idx, TBL_LOG_MAX_LEN, NULL);

#ifndef DPI_SDT_ZDY
    player_t *layer = precord_layer_put_new_layer(log_ptr->record, "ssl_n");
#else
    player_t *layer = precord_layer_put_new_layer(log_ptr->record, "ssl");
#endif

    for (i = 0; i < EM_SSL_MAX; i++) {
        ret = 0;
        switch (ssl_field_array[i].index) {
            case EM_CONTENTTYPE:
                write_one_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ContentType);
                break;
            case EM_VERSION:
                write_string_reconds(
                    log_ptr->record, &idx, TBL_LOG_MAX_LEN, value2String(pst_sslinfo->Version, ssl_versions_lsit));
                break;
            case EM_RECORDLAYERLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->RecordLayerLength);
                break;
            case EM_CHANGECIPHERSPEC:
                write_one_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ChangeCipherSpec);
                break;
            case EM_ALERTLEN:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->AlertLen);
                break;
            case EM_HANDSHAKETYPE:
                {
                  if (pst_sslinfo->ContentType == 22) {
                    write_one_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->HandshakeType);
                  } else
                    write_n_empty_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, 1);
                }
                break;
            case EM_CLIENTHELLOLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientHelloLength);
                break;
            case EM_CLIENTPROTOCOLVERSION:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientProtocolVersion);
                break;
            case EM_CLIENTGMTUNIXTIME:
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientGMTUnixTime,
                    strlen(pst_sslinfo->ClientGMTUnixTime));  // GMT Time
                break;
            case EM_CLIENTRANDOMBYTES:
                if (0x00 != *(size_t *)&pst_sslinfo->ClientRandomBytes)  //判断Random非空
                  write_multi_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientRandomBytes, 28);  // Radnom
                else
                  write_n_empty_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, 1);
                break;
            case EM_CLIENTSESSIONIDLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientSessionID_val_len);
                break;
            case EM_CLIENTSESSIONID:
                write_multi_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientSessionID_val_ptr,
                    pst_sslinfo->ClientSessionID_val_len);  // Session
                break;
            case EM_CLIENTCIPHERSUITE_CNT:
                if (pst_sslinfo->ClientCipherSuites_val_len)
                  write_one_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientCipherSuites_val_len / 2);
                else
                  write_n_empty_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, 1);
                break;
            case EM_CLTCOMPRESSIONMETHODSLEN:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientCompressionMethods_val_len);
                break;
            case EM_CLIENTCIPHERSUITES:
                {
                  memset(_str, 0, sizeof(_str));
                  network_to_hex_with_space(
                      pst_sslinfo->ClientCipherSuites_val_ptr, pst_sslinfo->ClientCipherSuites_val_len, _str, 2);
                  write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, strlen(_str));  // Version
                }
                break;
            case EM_CLIENTCOMPRESSIONMETHODS:
                for (int j = 0; j < pst_sslinfo->ClientCompressionMethods_val_len; j++) {
                  if (j > 0)
                    _str[ret++] = ' ';
                  ret += sprintf(_str + ret, "%02x", pst_sslinfo->ClientCompressionMethods_val_ptr[j]);
                }
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                break;
            case EM_CLIENTEXTENSIONSLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientExtensions_val_len);
                break;
            case EM_CLIENTEXTENSIONS:
                  //YV_FT_UINT64,                  "ClientExtensions"
                  ret = 0;
                  if (pst_sslinfo->cli_exts_num > 0)
                  {
                      for (int j=0; j<pst_sslinfo->cli_exts_num; j++) {
                          ret += sprintf(_str + ret, "%04x ", pst_sslinfo->cli_exts_id[j]);
                      }
                      ret -= 1;
                  }
                  write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                  break;
          case EM_SERVERHELLOLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ServerHelloLength);
                break;
            case EM_SERVERPROTOCOLVERSION:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ServerProtocolVersion);
                break;

            case EM_SERVERGMTUNIXTIME:
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ServerGMTUnixTime,
                    strlen(pst_sslinfo->ServerGMTUnixTime));  // Time
                break;
                    //YV_FT_BYTES,                   "ServerGMTUnixTime"
            case EM_SERVERRANDOMBYTES:
                if (0x00 != *(size_t *)&pst_sslinfo->ServerRandomBytes)  //判断Random非空
                  write_multi_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ServerRandomBytes, 28);  // Random
                else
                  write_n_empty_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, 1);
                break;
            case EM_SERVERSESSIONIDLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ServerSessionID_val_len);
                break;
            case EM_SERVERSESSIONID:
                write_multi_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ServerSessionID_val_ptr,
                    pst_sslinfo->ServerSessionID_val_len);  // SessionID
                break;
            case EM_SERVERCIPHERSUITE:
                if (pst_sslinfo->ServerCipherSuite > 0) {
                  ret = sprintf(_str, "%04x", (uint16_t)pst_sslinfo->ServerCipherSuite);
                  write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                } else
                  write_n_empty_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, 1);
                break;
            case EM_SERVERCOMPRESSIONMETHOD:
                if (pst_sslinfo->ContentType == SSL_HND_SERVER_HELLO) {
                  sprintf(_str, "%02x", pst_sslinfo->ServerCompressionMethod);
                  write_string_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str);
                } else {
                  write_n_empty_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, 1);
                }
                break;
            case EM_SERVEREXTENSIONSLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ServerExtensions_val_len);
                break;
            case EM_SERVEREXTENSIONS:
                if (pst_sslinfo->srv_exts_num > 0) {
                  for (int j = 0; j < pst_sslinfo->srv_exts_num; j++) {
                    ret += sprintf(_str + ret, "%04x ", pst_sslinfo->srv_exts_id[j]);
                  }
                  ret -= 1;
                }
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                break;
            case EM_SERVERCERTSIGNATURE:
                if (pst_sslinfo->cert_infos[SERVER_CERT].cert[0].signature_alg != NULL) {
                  write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->cert_infos[SERVER_CERT].cert[0].signature_alg, strlen(pst_sslinfo->cert_infos[SERVER_CERT].cert[0].signature_alg));
                } else {
                  write_n_empty_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, 1);
                }
                break;
            case EM_CERTPATH:
                {
                  char str[102400] = {0};
                  dpi_get_x509_chain_str(pst_sslinfo, str, sizeof(str));
                  write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, str, strlen(str));
                  break;
                }
            case EM_SERVERNAME:
                write_one_str_reconds(
                    log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ServerName, strlen(pst_sslinfo->ServerName));
                break;
            case EM_SERVERNAMEATTR:
                if (pst_sslinfo->server_name_type == 0xff)
                  write_n_empty_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, 1);
                else
                  write_one_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, (uint32_t)pst_sslinfo->server_name_type);
                break;
            case EM_CLIENT_CERTIFICATESLENGTH:
                write_one_no_zero_num_reconds(
                    log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->cert_infos[CLIENT_CERT].CertificatesLength);
                break;
            case EM_CLIENT_CERTIFICATESNUMS:
                write_one_no_zero_num_reconds(
                    log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->cert_infos[CLIENT_CERT].CertificatesNums);
                break;
            case EM_SERVER_CERTIFICATESLENGTH:
                write_one_no_zero_num_reconds(
                    log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->cert_infos[SERVER_CERT].CertificatesLength);
                break;
            case EM_SERVER_CERTIFICATESNUMS:
                write_one_no_zero_num_reconds(
                    log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->cert_infos[SERVER_CERT].CertificatesNums);
                break;
            case EM_CERTIFICATESLENGTH:
                pcert_info = &pst_sslinfo->cert_infos[SERVER_CERT];
                if (pcert_info->CertificatesNums) {
                  for (int k = 0; k < pcert_info->CertificatesNums; k++)
                    ret += sprintf(_str + ret, "%u,", pcert_info->cert[k].length);
                  ret -= 1;
                }
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                break;
            case EM_CLIENTCERTIFICATETYPESCOUNT:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->cert_request.cert_types_count);
                break;
            case EM_CLIENTCERTIFICATETYPES:
                if (pst_sslinfo->cert_request.cert_types_count) {
                  for (int k = 0; k < pst_sslinfo->cert_request.cert_types_count; k++) {
                    ret += sprintf(_str + ret, "%u,", pst_sslinfo->cert_request.cert_types_array[k]);
                  }
                  ret -= 1;
                }
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                break;
            // case EM_CERTIFICATEREQUESTLENGTH:
            //   break;
            case EM_ENCRYPEDPUBKEY:
                write_multi_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, (const uint8_t *)pst_sslinfo->EncrypedPubkey_ptr,
                    pst_sslinfo->EncrypedPubkey_len);
                if (pst_sslinfo->EncrypedPubkey_free && pst_sslinfo->EncrypedPubkey_len) {
                  pst_sslinfo->EncrypedPubkey_free(pst_sslinfo->EncrypedPubkey_ptr);
                }
                break;
            case EM_ENCRYPEDPUBKEYLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->EncrypedPubkey_len);
                break;
            case EM_SERVERKEYEXDHMOD_p:
                write_coupler_log(log_ptr->record, &idx, TBL_LOG_MAX_LEN, ssl_field_array[i].type,
                    (uint8_t *)pst_sslinfo->ServerKeyExDHMod_p,
                    pst_sslinfo->ServerKeyExDHMod_p_length);  // ServerKexExDHMod_p
                break;
            case EM_SERVERKEYEXDHGEN_g:
                write_coupler_log(log_ptr->record, &idx, TBL_LOG_MAX_LEN, ssl_field_array[i].type,
                    (uint8_t *)pst_sslinfo->ServerKeyExDHGen_g,
                    pst_sslinfo->ServerKeyExDHGen_g_length);  // ServerKexExDHGen_g
                break;
            case EM_DHEPUBKEY:
                write_coupler_log(log_ptr->record, &idx, TBL_LOG_MAX_LEN, ssl_field_array[i].type,
                    (uint8_t *)pst_sslinfo->ServerKeyExDHYs,
                    pst_sslinfo->ServerKeyExDHYs_length);  // DHEPubkey
                break;
            case EM_CLIENT_CERTIFICATE_LENGTH:
                pcert_info = &pst_sslinfo->cert_infos[CLIENT_CERT];
                if (pcert_info->CertificatesNums) {
                  for (int k = 0; k < pcert_info->CertificatesNums; k++) {
                    ret += sprintf(_str + ret, "%u,", pcert_info->cert[k].length);
                  }
                  ret -= 1;
                }
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                break;
            case EM_CLIENT_CLIENTECDHCURVETYPE:
                if (pst_sslinfo->ClientECFormats[0] > 0) {
                  for (int j = 0; j < pst_sslinfo->ClientECFormats[0]; j++) {
                    ret += snprintf(_str + ret, sizeof(_str) - ret, "%s,",
                        value2String(pst_sslinfo->ClientECFormats[j + 1], ssl_extension_ec_point_formats));
                  }
                  ret -= 1;
                }
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                break;
            case EM_CLIENT_CLIENTECDHNAMEDCURVE:
                if (get_uint16_ntohs(pst_sslinfo->ClientECGroups, 0) > 0) {
                  for (int j = 0; j < get_uint16_ntohs(pst_sslinfo->ClientECGroups, 0); j += 2) {
                    ret += sprintf(_str + ret, "%04x ", get_uint16_ntohs(pst_sslinfo->ClientECGroups + 2, j));
                  }
                  ret -= 1;
                }
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                break;
            case EM_CLIENT_CLIENTECDHPUBKEY:
                if (pst_sslinfo->ClientKeyExchangeSuites.type == KEY_EXCHANGE_ECDH) {
                  write_multi_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientKeyExchangeSuites.ptr,
                      pst_sslinfo->ClientKeyExchangeSuites.len);
                } else
                  write_n_empty_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, 1);
                break;
            case EM_ECDHCURVETYPE:
                write_string_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ECDHCurveType);
                break;
            case EM_SERVERKEXLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ServerKexLength);
                break;
            case EM_ECDHNAMEDCURVE:
                write_string_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ECDHNamedCurve);
                break;
            case EM_ECDHPUBKEY:
                write_multi_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, (const uint8_t *)pst_sslinfo->ECDHPubkey_ptr,
                    pst_sslinfo->ECDHPubkey_len);
                if (pst_sslinfo->ECDHPubkey_free && pst_sslinfo->ECDHPubkey_len) {
                  pst_sslinfo->ECDHPubkey_free(pst_sslinfo->ECDHPubkey_ptr);
                }
                break;
            case EM_ECDHSIGNATUREHASHALGORITHM:
                write_string_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ECDHSignatureHashAlgorithm);
                break;
            case EM_ECDHSIGNATURELENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ECDHSignature_len);
                break;
            case EM_ECDHSIGNATURE:
                write_multi_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, (const uint8_t *)pst_sslinfo->ECDHSignature_ptr,
                    pst_sslinfo->ECDHSignature_len);
                if (pst_sslinfo->ECDHSignature_free && pst_sslinfo->ECDHSignature_len) {
                  pst_sslinfo->ECDHSignature_free(pst_sslinfo->ECDHSignature_ptr);
                }
                break;
            case EM_ECDHSIGNATURESIGALGORITHM:
                write_string_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ECDHSignatureSigAlgorithm);
                break;
            case EM_ECDHPUBKEYLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ECDHPubkey_len);
                break;
            case EM_EXT_GREASE:
                write_one_num_reconds(
                    log_ptr->record, &idx, TBL_LOG_MAX_LEN, !!(pst_sslinfo->ext_grease & (1 << FLOW_DIR_SRC2DST)));
                break;
            // case EM_SSL_JA3C:
            //   break;
            // case EM_SSL_JA3S:
            //   break;
            // case EM_EXT_SESSION_TICKET:
            //   break;
            case EM_CLIENTCIPHERSUITESLENGTH:
                write_one_no_zero_num_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->ClientCipherSuites_val_len);
                break;
            // case EM_CLIENTCERTIFICATESIGNATURE:
            //   break;
            case EM_SERVER_CERT_CHAINS:
              // 服务端证书链
              if (pst_sslinfo->svr_cert_chain[(int)strlen(pst_sslinfo->svr_cert_chain) - 1] == ',')
                  pst_sslinfo->svr_cert_chain[(int)strlen(pst_sslinfo->svr_cert_chain) - 1] = '\0';
              write_one_str_reconds(
                  log_ptr->record, &idx, TBL_LOG_MAX_LEN, pst_sslinfo->svr_cert_chain, strlen(pst_sslinfo->svr_cert_chain));
              break;
            case EM_SRVEXT_EC_POIFOR:
                if (pst_sslinfo->ServerECFormats[0] > 0) {
                  for (int j = 0; j < pst_sslinfo->ServerECFormats[0]; j++) {
                    ret += sprintf(
                        _str + ret, "%s,", value2String(pst_sslinfo->ServerECFormats[j + 1], ssl_extension_ec_point_formats));
                  }
                  ret -= 1;
                }
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                break;
            case EM_SRVEXT_EC_GROUPS:
                if (get_uint16_ntohs(pst_sslinfo->ServerECGroups, 0) > 0) {
                  for (int j = 0; j < get_uint16_ntohs(pst_sslinfo->ServerECGroups, 0); j += 2) {
                    ret += sprintf(_str + ret, "%04x ", get_uint16_ntohs(pst_sslinfo->ServerECGroups + 2, j));
                  }
                  ret -= 1;
                }
                write_one_str_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, _str, ret);
                break;
            default:
                write_n_empty_reconds(log_ptr->record, &idx, TBL_LOG_MAX_LEN, 1);
                break;
        }
    }
    log_ptr->log_type           = TBL_LOG_SSL;
    log_ptr->thread_id          = flow->thread_id;
    log_ptr->log_len            = idx;
    log_ptr->content_len        = 0;
    log_ptr->content_ptr        = NULL;
    log_ptr->flow               = flow;

    if (write_tbl_log(log_ptr) != 1)
    {
        sdt_precord_destroy(log_ptr->record);
        log_ptr->record = NULL;
        rte_mempool_put(tbl_log_mempool, (void *)log_ptr);
    }
    //写证书信息并释放
    for (i = 0; i < 2; i++) {
        pcert_info = &pst_sslinfo->cert_infos[i];
        if (pcert_info->CertificatesNums) {
            for (int k = 0; k < pcert_info->CertificatesNums; k++) {
                write_x509_log(flow, direction, &pcert_info->cert[k], NULL);
            }
            free_x509(pcert_info->cert, pcert_info->CertificatesNums);
            pcert_info->CertificatesNums = 0;
        }
    }
    for(int i =0;i<pst_sslinfo->cert_chain_num;i++){
        dpi_free_x509_chain(pst_sslinfo->cert_chain[i]);
        pst_sslinfo->cert_chain[i] = NULL;
    }
    pst_sslinfo->cert_chain_num =0;
    return 0;
}

static int GetNumBy3Byte(const char* RAW)
{
    unsigned char num[4];
    num[3] = 0;
    num[2] = (unsigned char)RAW[0];
    num[1] = (unsigned char)RAW[1];
    num[0] = (unsigned char)RAW[2];
    return *(int*)(&num);
}

static int SSL_hello_ext_server_name(const uint8_t *payload, const uint32_t payload_len, ST_SSLInfo* pst_sslinfo)
{
    if(NULL == payload || NULL == pst_sslinfo || payload_len <=0 )
    {
        return -1;
    }

    int list_length    = get_uint16_ntohs(payload, 0);                // Server Name List length : 2 Byte
    payload+=2;
    if((unsigned)list_length > payload_len)
    {
        return -1;
    }

    pst_sslinfo->server_name_type = payload[0];

    uint16_t  name_len = get_uint16_ntohs(payload, 1);              // Server Name length      : 2 Byte
    name_len = DPI_MIN(name_len, sizeof(pst_sslinfo->ServerName) - 1);
    memcpy(pst_sslinfo->ServerName, payload+3, name_len);
    pst_sslinfo->ServerName[name_len] = 0;

    return 0;
}






static void dissect_ext_ticket_data(const uint8_t *payload, const uint32_t payload_len _U_, ST_SSLInfo *pst_sslinfo) {

	int offset = 0;
	int i;

	for (i = 0; i < pst_sslinfo->ext_ticket_length; i++) {
		if (i >= (int)sizeof(pst_sslinfo->ext_ticket_data)) {
			break;
		}
		pst_sslinfo->ext_ticket_data[i] = payload[offset + i];
	}

	offset += pst_sslinfo->ext_ticket_length;

}

static int SSL_Extensions(const uint8_t *payload, const uint32_t payload_len, int direction, ST_SSLInfo* pst_sslinfo, char* JA3, int* JA3_Len)
{
    if(NULL == pst_sslinfo || NULL == payload || payload_len < 4 )
    {
        return -1;
    }

    const uint8_t* pData   = payload;
    int DataLen            = payload_len;
    int group_flag         = 0;
    uint16_t i;
    while(DataLen >= 4) /* 每个扩展项的 Type 2字节, Length 2字节 */
    {
        uint32_t Type = get_uint16_ntohs(pData, 0);
        uint16_t Leng = get_uint16_ntohs(pData, 2);
        pData+=4;
        DataLen-=4;

        if(Leng > DataLen)
            return -1;

        if (direction == FLOW_DIR_SRC2DST && pst_sslinfo->cli_exts_num < EXT_TYPE_MAX_SIZE) {
            pst_sslinfo->cli_exts_id[pst_sslinfo->cli_exts_num++] = Type;
        }
        else if (direction == FLOW_DIR_DST2SRC && pst_sslinfo->srv_exts_num < EXT_TYPE_MAX_SIZE) {
            pst_sslinfo->srv_exts_id[pst_sslinfo->srv_exts_num++] = Type;
        }

        switch(Type)
        {
            case SSL_HND_HELLO_EXT_SERVER_NAME: // 当前字段的 HandShark 扩展只关心这一项
                SSL_hello_ext_server_name(pData, DataLen, pst_sslinfo);
                break;
            case SSL_HND_HELLO_EXT_SESSION_TICKET_TLS:
                pst_sslinfo->ext_session_ticket = 1;
                pst_sslinfo->ext_ticket_length = Leng;
                dissect_ext_ticket_data(pData, DataLen, pst_sslinfo); // add by hongll
                break;
            case SSL_HND_HELLO_EXT_HEARTBEAT:
                pst_sslinfo->ext_heartbeat = 1;
                break;
            case SSL_HND_HELLO_EXT_SUPPORTED_GROUPS:
                {
                    if(JA3){
                        if(get_uint16_ntohs(pData, 0) < 30 && get_uint16_ntohs(pData, 0) + 2 == Leng){
                            memcpy(pst_sslinfo->ClientECGroups, pData, Leng);
                            *JA3_Len += snprintf(JA3 + (*JA3_Len) , 256, "10-%u-%u", Leng, Leng -2);
                            for(i=0; i<Leng-2; i+=2){
                            if(*JA3_Len < 256)
                                *JA3_Len += snprintf(JA3 + (*JA3_Len) , 256 - (*JA3_Len), "-%u", pData[i]);
                            }
                            JA3[(*JA3_Len)++] = ',';
                            group_flag = 1;
                        }
                    } else {
                        if(get_uint16_ntohs(pData, 0) < 30 && get_uint16_ntohs(pData, 0) + 2 == Leng)
                            memcpy(pst_sslinfo->ServerECGroups, pData, Leng);
                    }

                }

                break;
            case SSL_HND_HELLO_EXT_EC_POINT_FORMATS:
                {
                    if(JA3){
                        if(pData[0]<3 && pData[0] + 1 == Leng)
                            memcpy(pst_sslinfo->ClientECFormats, pData, Leng);
                        if(group_flag == 0)
                            JA3[(*JA3_Len)++] = ',';
                        if(JA3 && Leng == 2 && pData[0] == 1){
                            *JA3_Len += snprintf(JA3 + (*JA3_Len) , 256, "11-2-1-%u", pData[1]);
                        }
                    }
                    else{
                        if(pData[0]<array_length(pst_sslinfo->ServerECFormats) && pData[0] + 1 == Leng)
                            memcpy(pst_sslinfo->ServerECFormats, pData, Leng);
                    }
                    if(pst_sslinfo->ServerECFormats[0]){
                        for(i=0; i<pst_sslinfo->ServerECFormats[0]; i++)
                            snprintf(pst_sslinfo->ec_point_format + strlen(pst_sslinfo->ec_point_format),
                                    32, "0x%02x,", pst_sslinfo->ServerECFormats[i+1]);
                    }
                }
                break;
            case SSL_HND_HELLO_EXT_RENEGOTIATION_INFO:
                pst_sslinfo->ext_renegotiate = 1;
                break;
            case SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS:
            case SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS_V1:
                pst_sslinfo->client_grease = 1;
                break;
            case SSL_HND_HELLO_EXT_GREASE_0A0A:
            case SSL_HND_HELLO_EXT_GREASE_1A1A:
            case SSL_HND_HELLO_EXT_GREASE_2A2A:
            case SSL_HND_HELLO_EXT_GREASE_3A3A:
            case SSL_HND_HELLO_EXT_GREASE_4A4A:
            case SSL_HND_HELLO_EXT_GREASE_5A5A:
            case SSL_HND_HELLO_EXT_GREASE_6A6A:
            case SSL_HND_HELLO_EXT_GREASE_7A7A:
            case SSL_HND_HELLO_EXT_GREASE_8A8A:
            case SSL_HND_HELLO_EXT_GREASE_9A9A:
            case SSL_HND_HELLO_EXT_GREASE_AAAA:
            case SSL_HND_HELLO_EXT_GREASE_BABA:
            case SSL_HND_HELLO_EXT_GREASE_CACA:
            case SSL_HND_HELLO_EXT_GREASE_DADA:
            case SSL_HND_HELLO_EXT_GREASE_EAEA:
            case SSL_HND_HELLO_EXT_GREASE_FAFA:
              pst_sslinfo->ext_grease |= (1 << direction);
              break;
        }
        pData += Leng;
        DataLen -= Leng;
    }

    if(JA3 && group_flag == 0)
        JA3[(*JA3_Len)++] = ',';

    return 0;
}

static int Handshake_ClientHello(const uint8_t *payload, const uint32_t payload_len, ST_SSLInfo* pst_sslinfo )
{
    if(NULL == pst_sslinfo || NULL == payload || payload_len < 4)
    {
        return -1;
    }

    uint32_t       element_length, i;
    const uint8_t* pData   = payload;
    uint32_t       DataLen = payload_len;

    /* 偏移掉 Handshake Type [1 Byte] */
    pData++;
    DataLen--;

    /* 偏移掉 Handshake Length [3 Byte] */
    int hc_len = GetNumBy3Byte((const char*)pData);
    if(hc_len < 64 || hc_len > 2048)
    {
        return -1; // ERROR ON Handshake Length
    }

    pData+=3;
    DataLen-=3;

    pst_sslinfo->ClientProtocolVersion =  get_uint16_ntohs(pData, 0); /* Version 2字节 */
    pData+=2;
    DataLen-=2;

    char JA3C[2048];
    int  JA3C_Len = 0;

    JA3C_Len = snprintf(JA3C, 256, "%u,", pst_sslinfo->ClientProtocolVersion);

    time_t t =  get_uint32_ntohl(pData, 0) + 28800; /* GMT TIME 4字节 */
    struct tm tm_tmp;
    gmtime_r(&t, &tm_tmp);
    //localtime_r(&t, &tm_tmp);
    snprintf(pst_sslinfo->ClientGMTUnixTime, sizeof(pst_sslinfo->ClientGMTUnixTime), "%04d-%02d-%02d %02d:%02d:%02d",
                        tm_tmp.tm_year + 1900,
                        tm_tmp.tm_mon + 1,
                        tm_tmp.tm_mday,
                        tm_tmp.tm_hour,
                        tm_tmp.tm_min,
                        tm_tmp.tm_sec);
    pData+=4;
    DataLen-=4;

    memcpy(pst_sslinfo->ClientRandomBytes, pData, 28); /* Random 28 Byte */
    pData+=28;
    DataLen-=28;

    /* GET SessionID */
    element_length = pData[0];
    if(element_length > 64)                //一般情况，Session数据长度不大于 64
    {
        return -1;                         // 过滤坏包
    }
    pst_sslinfo->ClientSessionID_val_len = DPI_MIN(element_length, 32); /* Session ID  Length Byte:1 */
    pData+=1;
    DataLen-=1;
    memcpy(pst_sslinfo->ClientSessionID_val_ptr, pData, pst_sslinfo->ClientSessionID_val_len);

    if(element_length > DataLen)
      return -1;
    pData += element_length;
    DataLen -= element_length;

    /* GET CipherSuites */
	element_length = get_uint16_ntohs(pData, 0);

  if(element_length > DataLen)
      return -1;

	pst_sslinfo->ClientCipherSuites_val_len = element_length;
    if(element_length > 128)                //一般情况， 加密套件数据长度不大于 64
    {
        return -1;                         // 过滤坏包
    }

    for(i=0; i<element_length; i+=2){
        JA3C_Len += snprintf(JA3C + JA3C_Len, 256, "%u-", get_uint16_ntohs(pData, i + 2));
    }
    JA3C[JA3C_Len - 1] = ',';

	  pst_sslinfo->ClientCipherSuites_val_len = element_length;
    pData+=2;
    DataLen-=2;
    memcpy(pst_sslinfo->ClientCipherSuites_val_ptr, pData, pst_sslinfo->ClientCipherSuites_val_len);
    pData += element_length;
    DataLen -= element_length;

    /* GET CompressionMethods */
    element_length = pData[0];
    pst_sslinfo->ClientCompressionMethods_val_len = DPI_MIN(element_length, 8); /* CompressionMethods 1字节 */
    pData+=1;
    DataLen-=1;
    memcpy(pst_sslinfo->ClientCompressionMethods_val_ptr, pData, pst_sslinfo->ClientCompressionMethods_val_len);
    pData += element_length;
    DataLen -= element_length;

    if(DataLen < 2)
        return 0;

    /* GET Extensions */
    element_length = get_uint16_ntohs(pData, 0);
    pst_sslinfo->ClientExtensions_val_len = element_length;/* Extensions Length 2 字节 */
    pData+=2;
    DataLen-=2;

    JA3C_Len += snprintf(JA3C + JA3C_Len, 256, "%u,", element_length);


    if(pst_sslinfo->ClientExtensions_val_len > DataLen)
        return 0;

    pst_sslinfo->ClientExtensions_val_ptr = pData; /* 指针指向这片数据域 */
    pData += element_length;
    DataLen -= element_length;

    int ret = SSL_Extensions(pst_sslinfo->ClientExtensions_val_ptr, pst_sslinfo->ClientExtensions_val_len,
                                FLOW_DIR_SRC2DST, pst_sslinfo, JA3C, &JA3C_Len);
    if(ret < 0)
        return ret;

    pst_sslinfo->JA3C_flag = 1;
    MD5((unsigned char*)JA3C, JA3C_Len, pst_sslinfo->JA3C);
    return 0;
}


static const SslCipherSuite * ssl_find_cipher(int num) {
	const SslCipherSuite *c;
	for (c = cipher_suites; c->number != -1; c++) {
		if (c->number == num) {
			return c;
		}
	}

	return NULL;
}

static void ssl_set_cipher(SSL_Session *ssl, uint16_t cipher) {
	/* store selected cipher suite for decryption */
	ssl->cipher = cipher;

	const SslCipherSuite *cs = ssl_find_cipher(cipher);
	if (!cs) {
		ssl->cipher_suite = NULL;
		ssl->state &= ~SSL_CIPHER;
	}
	else if (ssl->version == SSLV3_VERSION && !(cs->dig == DIG_MD5 || cs->dig == DIG_SHA)) {
		/* A malicious packet capture contains a SSL 3.0 session using a TLS 1.2
		 * cipher suite that uses for example MACAlgorithm SHA256. Reject that
		 * to avoid a potential buffer overflow in ssl3_check_mac. */
		ssl->cipher_suite = NULL;
		ssl->state &= ~SSL_CIPHER;
		//ssl_debug_printf("%s invalid SSL 3.0 cipher suite 0x%04X\n", G_STRFUNC, cipher);
	}
	else {
		/* Cipher found, save this for the delayed decoder init */
		ssl->cipher_suite = cs;
		ssl->state |= SSL_CIPHER;
//		ssl_debug_printf("%s found CIPHER 0x%04X %s -> state 0x%02X\n", G_STRFUNC, cipher,
//			val_to_str_ext_const(cipher, &ssl_31_ciphersuite_ext, "unknown"), ssl->state);
	}
}


static int Handshake_ServerHello(const uint8_t *payload, const uint32_t payload_len, SSL_Session *ssl_session, ST_SSLInfo* pst_sslinfo)
{
    if(NULL == payload || payload_len < 4)
    {
        return -1;
    }

    SSL_Session   *sess = ssl_session;
    uint32_t       element_length = 0;
    const uint8_t* pData   = payload;
    uint32_t       DataLen = payload_len;

    /* 偏移掉 Handshake Type [1 Byte] */
    pData++;
    DataLen--;

    /* 偏移掉 Handshake Length [3 Byte] */
    int hs_len = GetNumBy3Byte((const char*)pData);
    if(hs_len < 50 || hs_len > 2048)
    {
        return -1; // ERROR ON Handshake Length
    }

    pData+=3;
    DataLen-=3;

    pst_sslinfo->ServerProtocolVersion =  get_uint16_ntohs(pData, 0); /* GET Server Version 2Byte*/
    pData+=2;
    DataLen-=2;

    char JA3S[256];
    int  JA3S_Len = 0;
    JA3S_Len = snprintf(JA3S, 256, "%u,", pst_sslinfo->ServerProtocolVersion);

    time_t t =  get_uint32_ntohl(pData, 0) + 28800; /* GET GMT Time 4Byte*/
    struct tm tm_tmp;
    gmtime_r(&t, &tm_tmp);
    //localtime_r(&t, &tm_tmp);
    snprintf(pst_sslinfo->ServerGMTUnixTime, sizeof(pst_sslinfo->ServerGMTUnixTime), "%04d-%02d-%02d %02d:%02d:%02d",
                        tm_tmp.tm_year + 1900,
                        tm_tmp.tm_mon + 1,
                        tm_tmp.tm_mday,
                        tm_tmp.tm_hour,
                        tm_tmp.tm_min,
                        tm_tmp.tm_sec);
    pData+=4;
    DataLen-=4;

    memcpy(pst_sslinfo->ServerRandomBytes, pData, 28); /* GET Random 28 Byte*/
    pData+=28;
    DataLen-=28;

    /* GET SessionID */
    element_length = pData[0];                         /* GET Session ID len 1 Byte */
    pst_sslinfo->ServerSessionID_val_len = DPI_MIN(element_length, 32);
    pData+=1;
    DataLen-=1;
    memcpy(pst_sslinfo->ServerSessionID_val_ptr, pData, pst_sslinfo->ServerSessionID_val_len);
    pData += element_length;
    DataLen -= element_length;

    /* GET CipherSuite */                             /* GET CipherSuite*/
    pst_sslinfo->ServerCipherSuite = get_uint16_ntohs(pData, 0);
    pData+=2;
    DataLen-=2;

    if (sess) {
      ssl_set_cipher(sess, pst_sslinfo->ServerCipherSuite);
    }
    JA3S_Len += snprintf(JA3S+ JA3S_Len, 256, "%u,", pst_sslinfo->ServerCipherSuite);

    /* GET CompressionMethods */      /* GET  CompressionMethods 1 Byte*/
    pst_sslinfo->ServerCompressionMethod = get_uint8_t(pData, 0);
    pData+=1;
    DataLen-=1;

    if(DataLen < 2)
        return 0;

    /* GET Extensions */
    element_length = get_uint16_ntohs(pData, 0); /* GET Extensions Len 2 Byte */
    pst_sslinfo->ServerExtensions_val_len = element_length;
    pData+=2;
    DataLen-=2;

    JA3S_Len += snprintf(JA3S + JA3S_Len, 256, "%u", element_length);
    pst_sslinfo->JA3S_flag = 1;
    MD5((unsigned char*)JA3S, JA3S_Len, pst_sslinfo->JA3S);

    if(pst_sslinfo->ServerExtensions_val_len > DataLen)
        return 0;

    pst_sslinfo->ServerExtensions_val_ptr = pData;/* Point to Extensions */
    pData += element_length;
    DataLen -= element_length;

    return SSL_Extensions(pst_sslinfo->ServerExtensions_val_ptr, pst_sslinfo->ServerExtensions_val_len,
                            FLOW_DIR_DST2SRC, pst_sslinfo, NULL, NULL);
}

static void Handshake_NewSessionTicket(const uint8_t *payload, const uint32_t payload_len, ST_SSLInfo *pst_sslinfo) {

	if (!payload_len || payload_len < 4)
		return;

	int offset = 0;
	int i;
	int len;

	offset += 1;  // Type
	len = GetNumBy3Byte((const char *)(payload + offset));
	if (len <= 0)
		return;

	offset += 3;

	pst_sslinfo->new_sess_ticket.lifetime_hint = get_uint32_ntohl(payload, offset);
	offset += 4;

	pst_sslinfo->new_sess_ticket.ticket_len = get_uint16_ntohs(payload, offset);
	offset += 2;

	for (i = 0; i < pst_sslinfo->new_sess_ticket.ticket_len; i++) {
		if (i >= (int)sizeof(pst_sslinfo->new_sess_ticket.ticket_data)-1) {
			break;
		}
		pst_sslinfo->new_sess_ticket.ticket_data[i] = payload[offset + i];
	}

	offset += pst_sslinfo->new_sess_ticket.ticket_len;

}

static int Handshake_ServeKeyExchangeNamedCurve(const uint8_t *payload, const uint32_t payload_len, ST_SSLInfo* pst_sslinfo,SSL_Session *session )
{
    int type;

    int DataLength    = payload_len;
    const char* pData = (const char*)payload;

    if(DataLength < 4)
    {
        return -1;
    }

    /* Get Curve Type */
    type = pData[0];
    pst_sslinfo->ECDHCurveType = value2String(type, ssl_curve_types);
    pData++;
    DataLength--;

    /* Get Name Curve */
    type = get_uint16_ntohs(pData, 0);
    pst_sslinfo->ECDHNamedCurve = value2String(type, ssl_extension_curves);
    pData+=2;
    DataLength-=2;

    /* Get Pubkey Length */
    pst_sslinfo->ECDHPubkey_len  = get_uint8_t(pData, 0);
    pData++;
    DataLength--;

    if(pst_sslinfo->ECDHPubkey_len > (unsigned)DataLength) /* 如果公钥数据的长度 大于实际数据的长度， 就是无效的 */
    {
        return -1;
    }

    /* Get Public Key */
    if(g_config.ssl_flow_mode){
        if( (pst_sslinfo->ECDHPubkey_ptr = malloc(pst_sslinfo->ECDHPubkey_len)) ){
            memcpy(pst_sslinfo->ECDHPubkey_ptr, pData, pst_sslinfo->ECDHPubkey_len);
            pst_sslinfo->ECDHPubkey_free = free;
        }
    }
    else if(pst_sslinfo->ECDHPubkey_len)
    {
        pst_sslinfo->ECDHPubkey_ptr = (char*)alloc_memdup(session->flow->memAc, pData, pst_sslinfo->ECDHPubkey_len);
        pst_sslinfo->ECDHPubkey_free = NULL;
    }

    pData+=pst_sslinfo->ECDHPubkey_len; /* SKIP */
    DataLength-=pst_sslinfo->ECDHPubkey_len;

    /* Get Signature Hash Algorithm Hash */
    type = pData[0];
    pData++;
    DataLength--;
    pst_sslinfo->ECDHSignatureHashAlgorithm = value2String(type, dpi_tls_hash_algorithm);

    /* Get Signature Hash Algorithm Signature */
    type = pData[0];
    pData++;
    DataLength--;
    pst_sslinfo->ECDHSignatureSigAlgorithm = value2String(type, dpi_tls_signature_algorithm);

    /* Get Signature */
    pst_sslinfo->ECDHSignature_len  = get_uint16_ntohs(pData, 0);
    pData+=2;
    DataLength+=2;

    pst_sslinfo->ECDHSignature_free  = NULL;

    return 0;
}

static int Handshake_Client_Key_Exchange(const uint8_t *payload, const uint32_t payload_len, ST_SSLInfo* pst_sslinfo )
{

    int32_t Exchange_Len = (0x00FFFFFF & get_uint32_ntohl(payload, 0));
    if(((uint32_t)Exchange_Len + 4 > payload_len) || (Exchange_Len < 32))
        return 0;

    payload += 4;
    if(payload[0] + 1 == Exchange_Len){ //DH
        pst_sslinfo->ClientKeyExchangeSuites.type = KEY_EXCHANGE_ECDH;
        pst_sslinfo->ClientKeyExchangeSuites.ptr  = payload + 1;
        pst_sslinfo->ClientKeyExchangeSuites.len  = payload[0];
    }
    else if(get_uint16_ntohs(payload, 0) + 2 == Exchange_Len){//RSA
        pst_sslinfo->ClientKeyExchangeSuites.type = KEY_EXCHANGE_RSA;
        pst_sslinfo->ClientKeyExchangeSuites.ptr  = payload + 2;
        pst_sslinfo->ClientKeyExchangeSuites.len  = Exchange_Len - 2;
    }

    return 0;

}

static void dissect_ssl3_hnd_srv_keyex_dhe(const uint8_t *payload, int offset, int version _U_, uint8_t anon, ST_SSLInfo *pst_sslinfo) {

	if (!payload || (!pst_sslinfo))
		return;

	int i;

	/* p */
	pst_sslinfo->ServerKeyExDHMod_p_length = get_uint16_ntohs(payload, offset);
	offset += 2;

	for (i = 0; i < (int)pst_sslinfo->ServerKeyExDHMod_p_length; i++) {
		if (i >= 1024)
			break;

		pst_sslinfo->ServerKeyExDHMod_p[i] = payload[offset + i];
	}

	offset += pst_sslinfo->ServerKeyExDHMod_p_length;

	/* g */
	pst_sslinfo->ServerKeyExDHGen_g_length = get_uint16_ntohs(payload, offset);
	offset += 2;

	for (i = 0; i < (int)pst_sslinfo->ServerKeyExDHGen_g_length; i++) {
		if (i >= 1024)
			break;

		pst_sslinfo->ServerKeyExDHGen_g[i] = payload[offset + i];
	}

	offset += pst_sslinfo->ServerKeyExDHGen_g_length;

	/* Ys */
	pst_sslinfo->ServerKeyExDHYs_length = get_uint16_ntohs(payload, offset);
	offset += 2;

	for (i = 0; i < (int)pst_sslinfo->ServerKeyExDHYs_length; i++) {
		if (i >= 1024)
			break;

		pst_sslinfo->ServerKeyExDHYs[i] = payload[offset + i];
	}

	offset += pst_sslinfo->ServerKeyExDHYs_length;

	/* Signature (if non-anonymous KEX) */
	if (!anon) {

	}
}

static int Handshake_Serve_Key_Exchange(const uint8_t *payload, const uint32_t payload_len, SSL_Session *ssl_session, ST_SSLInfo *pst_sslinfo)
{
	SSL_Session *sess = ssl_session;

	int offset = 0;

	switch (ssl_get_keyex_alg(sess->cipher)) {
	case KEX_DH_ANON: /* RFC 5246; ServerDHParams */
		dissect_ssl3_hnd_srv_keyex_dhe(payload, offset, sess->version, TRUE, pst_sslinfo);
		break;
	case KEX_DH_DSS: /* RFC 5246; not allowed */
	case KEX_DH_RSA:
		/* XXX: add error on not allowed KEX */
		break;
	case KEX_DHE_DSS: /* RFC 5246; dhe_dss, dhe_rsa: ServerDHParams, Signature */
	case KEX_DHE_RSA:
		dissect_ssl3_hnd_srv_keyex_dhe(payload, offset+4, sess->version, FALSE, pst_sslinfo);
		break;
	case KEX_DHE_PSK: /* RFC 4279; diffie_hellman_psk: psk_identity_hint, ServerDHParams */
		/* XXX: implement support for DHE_PSK */
		break;
	case KEX_ECDH_ANON: /* RFC 4492; ec_diffie_hellman: ServerECDHParams (without signature for anon) */
//		dissect_ssl3_hnd_srv_keyex_ecdh(hf, tvb, pinfo, tree, offset, offset_end, session->version, TRUE);
		break;
	case KEX_ECDHE_PSK: /* RFC 5489; psk_identity_hint, ServerECDHParams */
		/* XXX: implement support for ECDHE_PSK */
		break;
	case KEX_ECDH_ECDSA: /* RFC 4492; ec_diffie_hellman: ServerECDHParams, Signature */
	case KEX_ECDH_RSA:
	case KEX_ECDHE_ECDSA:
	case KEX_ECDHE_RSA:
//		dissect_ssl3_hnd_srv_keyex_ecdh(hf, tvb, pinfo, tree, offset, offset_end, session->version, FALSE);
		break;
	case KEX_KRB5: /* RFC 2712; not allowed */
		/* XXX: add error on not allowed KEX */
		break;
	case KEX_PSK: /* RFC 4279; psk, rsa: psk_identity*/
	case KEX_RSA_PSK:
//		dissect_ssl3_hnd_srv_keyex_psk(hf, tvb, tree, offset, offset_end - offset);
		break;
	case KEX_RSA: /* only allowed if the public key in the server certificate is longer than 512 bits*/
//		dissect_ssl3_hnd_srv_keyex_rsa(hf, tvb, pinfo, tree, offset, offset_end, session->version);
		break;
	case KEX_SRP_SHA: /* RFC 5054; srp: ServerSRPParams, Signature */
	case KEX_SRP_SHA_DSS:
	case KEX_SRP_SHA_RSA:
		/* XXX: implement support for SRP_SHA* */
		break;
	case KEX_ECJPAKE: /* https://tools.ietf.org/html/draft-cragie-tls-ecjpake-01 used in Thread Commissioning */
//		dissect_ssl3_hnd_srv_keyex_ecjpake(hf, tvb, tree, offset, offset_end);
		break;
	default:
		/* XXX: add info message for not supported KEX algo */
		break;
	}

    const char *pData = (const char *)payload;
    int Exchange_Len = 0;

    Exchange_Len = (0x00FFFFFF & get_uint32_ntohl(pData, 0));
    pData    += 4;                                               // Shift Handshake_type, Legth  4 Byte
    if((unsigned)Exchange_Len > payload_len)
    {
        return -1; // ERR
    }

    pst_sslinfo->ServerKexLength = Exchange_Len;

    if(0x03 == pData[0]) /* pData[0] -> Type  */
    {
        Handshake_ServeKeyExchangeNamedCurve((const uint8_t *)pData, Exchange_Len, pst_sslinfo,sess);
    }

    return 0;
}


static int Handshake_certificate_request(const uint8_t *payload, const uint32_t payload_len, SSL_Session *ssl_session _U_, ST_SSLInfo *pst_sslinfo)
{
    int ele_length;
    int offset = 0;

    int length = GetNumBy3Byte((const char *)payload + 1);
    offset += 4;

    if (length > (int)payload_len - offset)
        return 0;

    // certificate types
    ele_length = get_uint8_t(payload, offset);
    offset += 1;

    if (ele_length > 0) {
        pst_sslinfo->cert_request.cert_types_count = ele_length;
        memcpy(pst_sslinfo->cert_request.cert_types_array, payload+offset, ele_length);
        offset += ele_length;
    }

    // Signature Hash Algorithms
    ele_length =get_uint16_ntohs(payload, offset);
    offset += 2;

    offset += ele_length;

    return  offset;
}

static int dissect_Handshake(struct flow_info *flow, int C2S, const uint8_t *payload, const uint32_t payload_len, ST_SSLInfo* pst_sslinfo)
{
    if(NULL == pst_sslinfo ||NULL == payload || payload_len < 3)
    {
        return 0;
    }

    uint8_t type = payload[0];
    pst_sslinfo->HandshakeType = type;
    switch(type)
    {
        case SSL_HND_CLIENT_HELLO        : /* 完成 */
            if(flow->ack_tcp_session[C2S] || flow->init_tcp_session[!C2S])
                pst_sslinfo->unlegal_flag |= 1 << SSL_INITIALIZED_BY_SERVER;
            pst_sslinfo->ClientHelloLength = 0x00FFFFFF &  get_uint32_ntohl(payload, 0);
            if(pst_sslinfo->ClientHelloDissectedFlag == 0 && Handshake_ClientHello(payload, payload_len, pst_sslinfo) < 0)
                return -1;
            pst_sslinfo->ClientHelloDissectedFlag = 1;
            break;

        case SSL_HND_SERVER_HELLO        : /* 完成 */
            if(flow->init_tcp_session[C2S] || flow->ack_tcp_session[!C2S])
                pst_sslinfo->unlegal_flag |= 1 << SSL_INITIALIZED_BY_SERVER;
            pst_sslinfo->ServerHelloLength = 0x00FFFFFF & get_uint32_ntohl(payload, 0);
            if(pst_sslinfo->ServerHelloDissectedFlag == 0)
                Handshake_ServerHello(payload, payload_len, flow->app_session, pst_sslinfo);
            pst_sslinfo->ServerHelloDissectedFlag = 1;
            break;

        case SSL_HND_NEWSESSION_TICKET:
          if (flow->ack_tcp_session[C2S] || flow->init_tcp_session[!C2S])
            pst_sslinfo->unlegal_flag |= 1 << SSL_INITIALIZED_BY_SERVER;
          if (pst_sslinfo->NewTicketDissectedFlag == 0)
            Handshake_NewSessionTicket(payload, payload_len, pst_sslinfo);
          pst_sslinfo->NewTicketDissectedFlag = 1;
          break;

        case SSL_HND_CERTIFICATE         : /* 完成 */
        {
            if(flow->init_tcp_session[C2S] || flow->ack_tcp_session[!C2S])
                pst_sslinfo->unlegal_flag |= 1 << SSL_INITIALIZED_BY_SERVER;

            // direction: 区分是客户端证书 还是 服务端证书
            if (dissect_x509(flow, C2S, payload, payload_len, pst_sslinfo) < 0)
                return 0;
        }
            break;
        case SSL_HND_SERVER_KEY_EXCHG    : /* 完成 */
            if(flow->init_tcp_session[C2S] || flow->ack_tcp_session[!C2S])
                pst_sslinfo->unlegal_flag |= 1 << SSL_INITIALIZED_BY_SERVER;
            if(pst_sslinfo->ServerKexDissectedFlag == 0)
                Handshake_Serve_Key_Exchange(payload, payload_len, flow->app_session, pst_sslinfo);
            pst_sslinfo->ServerKexDissectedFlag = 1;
            break;

        case SSL_HND_CLIENT_KEY_EXCHG    : /* 完成 */
            if(flow->ack_tcp_session[C2S] || flow->init_tcp_session[!C2S])
                pst_sslinfo->unlegal_flag |= 1 << SSL_INITIALIZED_BY_SERVER;
            if(pst_sslinfo->ClientKexDissectedFlag == 0)
                Handshake_Client_Key_Exchange(payload, payload_len, pst_sslinfo);
            pst_sslinfo->ClientKexDissectedFlag = 1;
            break;
        case SSL_HND_CERT_REQUEST:
            Handshake_certificate_request(payload, payload_len, flow->app_session, pst_sslinfo);
            break;
        // case SSL_HND_SVR_HELLO_DONE:
        //    break;
        default:
            return 0;
    }
    return 0 ;
}

static int dissect_Handshake_full(struct flow_info *flow, int direction,
                                const uint8_t *payload, const uint32_t payload_len,
                                ST_SSLInfo *pst_sslinfo)
{
    uint8_t *pData = (uint8_t*)payload;     //tls.handshake.type
    int DataLen = (int)payload_len;         //tls.record.length

    while (DataLen > 0)
    {
        int handshakeLen = GetNumBy3Byte((const char*)pData+1);
        if (handshakeLen > DataLen -4) {
            uint8_t type = payload[0];
            pst_sslinfo->HandshakeType = type;
            return 0;
        }

        handshakeLen+=4;//补上tls.handshake.type与tls.handshake.length的字段长度
        dissect_Handshake(flow, direction, pData, handshakeLen,
                                    pst_sslinfo); /* 指向 Handshake 数据域 */
        DataLen -= handshakeLen;
        pData += handshakeLen;
    }
    return 0;
}
//检验 SSL 数据的有效长度
static int SSL_is_complete(const uint8_t *payload, const uint32_t payload_len)
{
    const char *pCurrent = NULL;
    int         CurrentLen = 0;

    pCurrent = (const char *)payload;
    CurrentLen = payload_len;

    while(CurrentLen > 5) //至少需要5字节
    {
        /* 解析最前面的 5个字节 */
        int RecordLayer_ContentType = pCurrent[0];
        int RecordLayer_Version = get_uint16_ntohs(pCurrent, 1);
        int RecordLayer_Length = get_uint16_ntohs(pCurrent, 3);
        pCurrent += 5;
        CurrentLen -= 5;

        if(0 != BetweenAnd(RecordLayer_ContentType, 20, 24) || 0 != BetweenAnd(RecordLayer_Version, 0x0301, 0x0304))
        {
            return 0 ; // Bad Packet, 找不到有效的数据长度
        }

        if(RecordLayer_Length > CurrentLen)   // 如果 SSL层Length长度, 大于当前报文的长度
        {                                     // 需要更多数据, 需要重组
            return 0 ; // 总长度减去剩余长度， 就是已经验证的长度 ,5 TLV:[TL]
        }

        pCurrent += RecordLayer_Length;
        CurrentLen -= RecordLayer_Length;
        if(0 == CurrentLen)
        {
            return 1; //数据包完整，返回全部长度
        }
    }

    /* 少于5字节的未知数据 不知道是什么东西, 需要重组  */
    return 0;


}

static int ssl_is_v2_client_hello(const uint8_t *payload, const uint32_t offset) {
	uint8_t byte;

	byte = payload[offset];
	if (byte != 0x80)           /* v2 client hello should start this way */
	{
		return 0;
	}

	byte = payload[offset+2];
	if (byte != 0x01)           /* v2 client hello msg type */
	{
		return 0;
	}

	/* 1 in 2^16 of being right; improve later if necessary */
	return 1;
}


static ST_SSLInfo* st_sslInfo_get(struct flow_info *flow)
{
    SSL_Session     *psslSession = (SSL_Session*)flow->app_session;
    ST_SSLInfo      *psslInfo = NULL;

    if (psslSession == NULL)
    {
        if( (psslSession = dpi_malloc(sizeof(SSL_Session))) ){
            memset(psslSession, 0, sizeof(SSL_Session));
            flow->app_session = psslSession;
        }
        else{
            DPI_LOG(DPI_LOG_WARNING, "no memory for malloc SSL_Session");
            return NULL;
        }
    }

    psslInfo = &psslSession->ssl_info;

    return psslInfo;
}

static int dissect_ssl_process(struct flow_info *flow, int direction, const uint8_t *payload, const uint32_t payload_len)
{
    const uint8_t * pData   = payload;
    size_t          DataLen = payload_len;
    int             rc      = 0;
    ST_SSLInfo      *psslInfo;

    psslInfo = st_sslInfo_get(flow);

    if (psslInfo == NULL){
        return PKT_DROP;
    }

	psslInfo->server_name_type = 0xff; // default

    /* 可能会有很多个 TLS Recoder Layer
       单帧中存在多个 TLS Recoder Layer时，每条Layer单独输出为一条tbl
    */
    while(DataLen > 5) /* Type:1, Version:2, Length:2 */
    {
        if (!g_config.ssl_flow_mode)
        {
            memset(psslInfo, 0,  sizeof(ST_SSLInfo));
        }

        /* 采集数据 */
        psslInfo->ContentType       = get_uint8_t(pData, 0);      // 1字节
        psslInfo->Version           = get_uint16_ntohs(pData, 1); // 2字节
        psslInfo->RecordLayerLength = get_uint16_ntohs(pData, 3); // 2字节

        if(psslInfo->RecordLayerLength > (1024 *8)) // 限制在 8K内
        {
            return -1;
        }

        if(psslInfo->ContentType == 20){
            psslInfo->ChangeCipherSpec = 1;
            goto next;
        }
        else if(psslInfo->ContentType == 21){
            psslInfo->AlertLen = psslInfo->RecordLayerLength;
            goto next;
        }
        else if (psslInfo->ContentType == 23) {
            psslInfo->Application_Data = 1;
            goto next;
        }
        else if(psslInfo->ContentType != 22)
        {
            return -1;;
        }

        /* 只解析以下几种SSL版本 */
        switch(psslInfo->Version)
        {
            case TLSV1_VERSION:
            case TLSV1DOT1_VERSION:
            case TLSV1DOT2_VERSION:
            case TLSV1DOT3_VERSION:
              if (DataLen < 5)
                break;

              if (ssl_is_v2_client_hello(pData, 0)) {

                // 解析 sslv2 reocrd
              }
              else {
      //					DataLen -= dissect_ssl3_record();
              }
                break; // 符合条件则跳出，否则不处理
            default:
                return -1;
        }

        /* 解析当前层 Handshake */
        rc = dissect_Handshake_full(flow, direction, pData + 5, psslInfo->RecordLayerLength, psslInfo); /* 指向 Handshake 数据域 */
        //如白名单开关打开,servername有数据,检测是否属于白名单,如不是,则flow黑名单标志置1
        const char *servername;
        if(g_config.ssl_or_x509)
            servername = psslInfo->ServerName[0] ? psslInfo->ServerName : NULL ;
        else
            servername = psslInfo->cert_infos[SERVER_CERT].cert[0].subject_name[DPI_X509_NAME_COMMON];

        if( servername && (!flow->whitelist_flag) && (g_config.https_whitelist_switch || g_config.https_blacklist_switch) ){
            long ret = (long)white_filter(servername, strlen(servername), https_filter_table);
            if(ret == 0){
                if(g_config.https_default_switch){
                    flow->blacklist_flag = 1;
                    free_ssl_result(flow, psslInfo);
                    return -1;
                }
                else{
                    flow->whitelist_flag = 1;
                }
            }
            else if(ret == 1){
                flow->whitelist_flag = 1;
            }
            else if(ret == 2){
                flow->blacklist_flag = 1;
                free_ssl_result(flow, psslInfo);
                return -1;
            }
        }

        if(rc < 0)
        {
            free_ssl_result(flow, psslInfo);
            return rc; // ERROR
        }

next:
        if (!g_config.ssl_flow_mode)
            write_ssl_result(flow, direction, psslInfo);
        /* 数据向前 步进, 指向下一层 Recoder Layer */
        pData   += 5;                                             // Jump to Handshake Type
        DataLen -= 5;
        DataLen  = DataLen - psslInfo->RecordLayerLength;
        pData    = pData + psslInfo->RecordLayerLength;
    }

    return payload_len;
}


static int dissect_ssl_Layer(struct flow_info *flow, uint8_t C2S, const uint8_t *payload, uint32_t payload_len)
{
    if(payload_len <= 5)
        return 0;

    int i, ret, rc;
    const uint8_t * pData   = payload;
    size_t          DataLen = payload_len;


    //创建sesion
    if(NULL == flow->app_session)
    {
        flow->app_session = malloc(sizeof( SSL_Session));
        memset(flow->app_session, 0, sizeof( SSL_Session));
    }

    //Cache
     SSL_Session          *pSession = ( SSL_Session*)flow->app_session;
    struct ssl_cache_t   *sslCache = pSession->cache + C2S;

    pSession->flow = flow;

    // 如果存在 缓存 将后续报文载入缓存
    if(sslCache->cache)
    {
        if(payload_len > (uint32_t)(sslCache->cache_size - sslCache->cache_hold))
        {
            // 缓存撑爆前, 解析数据
            dissect_ssl_process(flow, C2S,(const uint8_t*)sslCache->cache, (uint32_t)sslCache->cache_hold);
            goto SSL_DROP;
        }

        //载入缓存
        memcpy(sslCache->cache + sslCache->cache_hold, payload, payload_len);
        sslCache->cache_hold  += payload_len;

        // 更新 payload payload_len
        payload = (const uint8_t*)sslCache->cache;
        payload_len = sslCache->cache_hold;
    }

    //完整性探测
    int ssl_len = 0;
    if(SSL_is_complete(payload, payload_len)) //返回可以解析的长度
    {
        ssl_len = dissect_ssl_process(flow, C2S, payload, payload_len);  // 有效数据 有多长就解析多长
    }

    // 有没有剩料?
    if(ssl_len>=0 && ssl_len < (int)payload_len)
    {
        //已开启缓存, 直接将剩料挪到前面
        if(sslCache->cache)
        {
            memmove(sslCache->cache, sslCache->cache + ssl_len, sslCache->cache_hold - ssl_len);
            sslCache->cache_hold  -= ssl_len;
        }
        else
        //未开启缓存, 创建缓存, 把剩料装进去
        if(NULL == sslCache->cache)
        {
            sslCache->cache_size = g_config.http.http_strip_cache_size;//借用一下吧
            sslCache->cache      = dpi_malloc(sslCache->cache_size);
            memcpy(sslCache->cache, payload + ssl_len, payload_len - ssl_len);
            sslCache->cache_hold = payload_len - ssl_len; //持有数据等于 总长减去已耗用
        }
        goto SSL_NEED_MORE_PKT;
    }

SSL_DROP:
    if(NULL != sslCache->cache)
    {
        free(sslCache->cache);
        sslCache->cache = NULL;
        sslCache->cache_hold = 0;
        sslCache->cache_size = 0;
    }
    return 0;

SSL_NEED_MORE_PKT:
    return 0;

}

// 已缓存的数据直接输出
static int ssl_miss(struct flow_info *flow, uint8_t C2S, uint32_t len)
{
    SSL_Session           *ssl_session     = NULL;
    struct   ssl_cache_t  *ssl_cache       = NULL;
    int      miss_len    = len;

    if(NULL == flow->app_session)
    {
        return 0;
    }

    ssl_session = ( SSL_Session*)flow->app_session;
    ssl_cache   = ssl_session->cache + C2S;

    if(ssl_cache->cache)
    {
        dissect_ssl_process(flow, C2S, (const uint8_t*)ssl_cache->cache, (uint32_t)ssl_cache->cache_hold);
        free(ssl_cache->cache);
        ssl_cache->cache      = NULL;
        ssl_cache->cache_hold = 0;
        ssl_cache->cache_size = 0;
    }
    return 0;
}

static void flow_ssl_finish(struct flow_info *flow)
{
    SSL_Session           *ssl_session     = NULL;
    struct   ssl_cache_t  *ssl_cache_C2S   = NULL;
    struct   ssl_cache_t  *ssl_cache_S2C   = NULL;

    if(flow->app_session)
    {
        ssl_session = (SSL_Session *)flow->app_session;
        ssl_cache_C2S = ssl_session->cache + 1;
        ssl_cache_S2C = ssl_session->cache + 0;

        if(ssl_cache_C2S->cache)
        {
            dissect_ssl_process(flow, 1/*C2S*/, (const uint8_t*)ssl_cache_C2S->cache, (uint32_t)ssl_cache_C2S->cache_hold);
            free(ssl_cache_C2S->cache);
            ssl_cache_C2S->cache        = NULL;
            ssl_cache_C2S->cache_hold   = 0;
            ssl_cache_C2S->cache_size   = 0;
        }

        if(ssl_cache_S2C->cache)
        {
            dissect_ssl_process(flow, 0/*S2C*/, (const uint8_t*)ssl_cache_S2C->cache, (uint32_t)ssl_cache_S2C->cache_hold);
            free(ssl_cache_C2S->cache);
            ssl_cache_S2C->cache        = NULL;
            ssl_cache_S2C->cache_hold   = 0;
            ssl_cache_S2C->cache_size   = 0;
        }

        if (g_config.ssl_flow_mode && ssl_session)
        {
            ST_SSLInfo      *ssl_info;
            ssl_info = &ssl_session->ssl_info;
            ssl_info->ContentType = 0;
            write_ssl_result(flow, flow->direction, ssl_info);
        }

        free(flow->app_session);
        flow->app_session = NULL;
    }
}

/*****************************************************************
 *Function    : identify_ssl
 *Description : ssl 协议识别接口
 *Input       : flow, payload, payload_len
 *Output      : none
 *Return      : void
 *Others      : none
 *****************************************************************/
static int identify_ssl(struct flow_info *flow, uint8_t C2S, const uint8_t *payload, uint32_t payload_len)
{
    /* 协议的开关检查 */
    if (g_config.protocol_switch[PROTOCOL_SSL] == 0)
    {
        return PROTOCOL_UNKNOWN;
    }

    UNUSED(flow);
    const uint8_t  *pData;
    uint16_t  DataLen;

    pData = NULL;
    DataLen = 0;

    pData = payload;
    DataLen = payload_len;

    /* 至少要有9字节， 才有效[第1层TLV=5字节][第2层TLV4字节] */
    if(DataLen < 9)
    {
        DPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTOCOL_SSL);
        return PROTOCOL_UNKNOWN;
    }

    {
        /** 第1层 SSL **/

        /* 1 GET Secure Sockets Layer */
        uint8_t  SSL_ContentType = get_uint8_t(pData, 0);
        uint16_t SSL_Version     = get_uint16_ntohs(pData, 1);
        uint16_t SSL_Length      = get_uint16_ntohs(pData, 3);
        pData+=5;
        DataLen-=5;

        // 判断 Type， Version 有效性
        if(0 != BetweenAnd(SSL_ContentType, 20, 24) || 0 != BetweenAnd(SSL_Version, 0x0301, 0x0304))
        {
            DPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTOCOL_SSL);
            return PROTOCOL_UNKNOWN;
        }

        if(SSL_Length > payload_len) //长度有效性
        {
            return PROTOCOL_UNKNOWN;
        }

        if(SSL_ContentType == 23 && SSL_Length + 5 == (int)payload_len)
        {
            flow->real_protocol_id = PROTOCOL_SSL;
            flow->slave_protocol_id = PROTOCOL_X509;
            return PROTOCOL_SSL;
        }
    }
    {
        /** 2 进入 Recoder Layer  **/
        uint8_t RecoderLayer_ContentType = get_uint8_t(pData, 0);
        // 判断 Type， Version的长度 有效性
        if(0 != BetweenAnd(RecoderLayer_ContentType, 1, 20))/* type 的有效范围 */
        {
            DPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTOCOL_SSL);
            return PROTOCOL_UNKNOWN;
        }
    }

    /* 通过了所有的检测， 就是SSL/TLS协议了*/
    flow->real_protocol_id = PROTOCOL_SSL;
    flow->slave_protocol_id = PROTOCOL_X509;
    return PROTOCOL_SSL;
}

extern struct decode_t decode_ssl;
static int ssl_initial(struct decode_t *decode)
{
    decode_on_port_tcp(443, &decode_ssl);

#ifndef DPI_SDT_ZDY
    dpi_register_proto_schema(ssl_field_array, EM_SSL_MAX, "ssl_n");
    map_fields_info_register(ssl_field_array, PROTOCOL_SSL, EM_SSL_MAX, "ssl_n");
    register_tbl_array(TBL_LOG_SSL, 0, "ssl_n", NULL);
#else
    dpi_register_proto_schema(ssl_field_array, EM_SSL_MAX, "ssl");
    map_fields_info_register(ssl_field_array, PROTOCOL_SSL, EM_SSL_MAX, "ssl");
    register_tbl_array(TBL_LOG_SSL, 0, "ssl", NULL);
#endif
    return 0;
}

static int ssl_destroy(struct decode_t *decode)
{
    return 0;
}

struct decode_t decode_ssl = {
#ifndef DPI_SDT_ZDY
    .name           =   "ssl_n",
#else
    .name           =   "ssl",
#endif
    .decode_initial =   ssl_initial,
    .pkt_identify   =   identify_ssl,
    .pkt_dissect    =   dissect_ssl_Layer,
    .pkt_miss       =   ssl_miss,
    .flow_finish    =   flow_ssl_finish,
    .decode_destroy =   ssl_destroy,
};





