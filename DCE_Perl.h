#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <dce/sec_login.h>
#include <dce/binding.h>
#include <dce/pgo.h>
#include <dce/uuid.h>
#include <dce/rgynbase.h>
#include <dce/acct.h>
#include <dce/policy.h>
#include <dce/dce_error.h>

/* $Id: DCE_Perl.h,v 1.10 1996/08/13 19:59:06 dougm Exp dougm $ */

#define iniHV 	hv = (HV*)sv_2mortal((SV*)newHV())
#define iniAV 	av = (AV*)sv_2mortal((SV*)newAV())
#define iniSV 	sv = (SV*)sv_2mortal((SV*)newSV(0))

#define PUSHs_pv(pv) PUSHs(sv_2mortal((SV*)newSVpv(pv,0)));
#define PUSHs_iv(iv) PUSHs(sv_2mortal((SV*)newSViv(iv)));
#define XPUSHs_pv(pv) XPUSHs(sv_2mortal((SV*)newSVpv(pv,0)));
#define XPUSHs_iv(iv) XPUSHs(sv_2mortal((SV*)newSViv(iv)));

typedef  sec_rgy_handle_t * DCE__Registry;
typedef  sec_rgy_cursor_t * DCE__cursor;
typedef  uuid_t * DCE__UUID;

#define BLESS_UUID \
    uuid = sv_newmortal(); \
    sv_setref_pv(uuid, "DCE::UUID", (void*)uuid_struct)

/* 
 * Not sure this is a good idea, so for now users
 * must ask for this magic ala 'tie $status => DCE::Status'
 */
#define STATUS_MAGIC \
   if(status != sec_rgy_status_ok) { \
      int error_stat; \
      unsigned char error_string[dce_c_error_string_len]; \
      SV *sv = perl_get_sv("DCE::status",TRUE); \
      sv_setnv(sv, (double)status); \
      dce_error_inq_text(status, error_string, &error_stat); \
      sv_setpv(sv, error_string); \
      SvNOK_on(sv); \
   } 

#define DCESTATUS \
   XPUSHs_iv(status)  



