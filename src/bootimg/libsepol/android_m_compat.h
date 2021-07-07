/*
 * On Android 6.0, even though the policy version is POLICYDB_VERSION_XPERMS_IOCTL, it has a
 * different implementation than the standard one.
 * In the standard implementation, extended attributes are treated with the same set of avtab
 * specifications. What the data specifies is stored in an additional entry. This makes sure the
 * data structure won't need to change when more extended attributes are added in the future.
 * On Android 6.0, IOCTLDRIVER or IOCTLFUNCTION has separate sets of avtab specifications, and
 * the extended sections do not have the additional entry to specify the feature.
 * Here our goal is to add a compatibility layer, so that the rest of the library can treat
 * Android 6.0 policies as standard POLICYDB_VERSION_XPERMS_IOCTL implementations.
 */

#define AVTAB_OPTYPE_ALLOWED	0x1000
#define AVTAB_OPTYPE_AUDITALLOW	0x2000
#define AVTAB_OPTYPE_DONTAUDIT	0x4000
#define AVTAB_OPTYPE		(AVTAB_OPTYPE_ALLOWED | AVTAB_OPTYPE_AUDITALLOW | AVTAB_OPTYPE_DONTAUDIT)
#define AVTAB_XPERMS_OPTYPE	4

#define avtab_xperms_to_optype(x) (x << AVTAB_XPERMS_OPTYPE)
#define avtab_optype_to_xperms(x) (x >> AVTAB_XPERMS_OPTYPE)

// Global indication whether an Android M policy is detected
extern unsigned avtab_android_m_compat;
