#include "../DCE_Perl.h"

MODULE = DCE::UUID PACKAGE = DCE::UUID

void
uuid_create()

  PPCODE:
  {
    unsigned_char_t *	uuid;
    error_status_t	status, dummy;
    uuid_t	uuid_struct;

    uuid_create(&uuid_struct, &status);
    uuid_to_string(&uuid_struct, &uuid, &dummy);

    XPUSH_pv(uuid);
    DCESTATUS;
  }


void
uuid_hash(uuid, status)
  unsigned_char_t *	uuid

  CODE:
  {
    uuid_t	uuid_struct;
    unsigned16  hash;
    error_status_t	status;

    uuid_from_string(uuid, &uuid_struct, &status);
    hash = uuid_hash(&uuid_struct, &status);
    XPUSHs_iv(hash);
    DCESTATUS;
  }
