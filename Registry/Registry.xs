#include "../DCE_Perl.h"

/* $Id: Registry.xs,v 1.14 1996/11/18 15:33:45 dougm Exp $ */

#define FETCH_AUTH_INFO \
  info = (HV*)SvRV(hash_ref);  \
  auth_info.info_type = sec_rgy_bind_auth_none; \
  svp = hv_fetch((HV*)SvRV(hash_ref), "info_type", 9, 1); \
  if(SvTRUE(*svp)) \
    auth_info.info_type = (sec_rgy_bind_auth_info_type_t )SvPV(*svp,len); \
  svp = hv_fetch(info, "authn_level", 11, 1); \
  auth_info.tagged_union.dce_info.authn_level =  (unsigned32 )SvIV(*svp); \
  svp = hv_fetch(info, "authn_svc", 9, 1); \
  auth_info.tagged_union.dce_info.authn_svc = (unsigned32 )SvIV(*svp); \
  svp = hv_fetch(info, "authz_svc", 9, 1); \
  auth_info.tagged_union.dce_info.authz_svc = (unsigned32 )SvIV(*svp); \
  svp = hv_fetch(info, "identity", 8, 1); \
  auth_info.tagged_union.dce_info.identity = (sec_login_handle_t )SvPV(*svp,len)

#define BLESS_RGY_CONTEXT \
  sv = sv_newmortal(); \
  sv_setref_pv(sv,package,(void*)rgy_context); \
  XPUSHs(sv); \
  DCESTATUS

#define FETCH_LOGIN_NAME \
   hv = (HV*)SvRV(login_name_ref); \
   svp = hv_fetch(hv, "pname", 5, 1); \
   strcpy(login_name.pname, (char *)SvPV(*svp,len)); \
   svp = hv_fetch(hv, "gname", 5, 1); \
   strcpy(login_name.gname, (char *)SvPV(*svp,len)); \
   svp = hv_fetch(hv, "oname", 5, 1)   

#define FETCH_ADMIN_PART \
   hv = (HV*)SvRV(admin_part_ref); \
   svp = hv_fetch(hv, "expiration_date", 15, 1); \
   admin_part.expiration_date = SvIV(*svp); \
   svp = hv_fetch(hv, "good_since_date", 15, 1); \
   admin_part.good_since_date = SvIV(*svp); \
   svp = hv_fetch(hv, "flags", 5, 1); \
   admin_part.flags = SvIV(*svp); \
   svp = hv_fetch(hv, "authentication_flags", 20, 1); \
   admin_part.authentication_flags = SvIV(*svp)

#define FETCH_USER_PART \
    hv = (HV*)SvRV(user_part_ref); \
    svp = hv_fetch(hv, "gecos", 5, 1); \
    strncpy(user_part.gecos, (char *)SvPV(*svp,len), 257); \
    svp = hv_fetch(hv, "homedir", 7, 1); \
    strncpy(user_part.homedir, (char *)SvPV(*svp,len), 257); \
    svp = hv_fetch(hv, "shell", 5, 1); \
    strncpy(user_part.shell, (char *)SvPV(*svp,len), 257); \
    svp = hv_fetch(hv, "passwd", 6, 1); \
    strncpy(user_part.passwd, (char *)SvPV(*svp,len), 16); \
    svp = hv_fetch(hv, "passwd_version_number", 21, 1); \
    user_part.passwd_version_number = SvIV(*svp); \
    svp = hv_fetch(hv, "flags", 5, 1); \
    user_part.flags = SvIV(*svp)

/*  pgo_item.id = uuid_struct; \ */

#define FETCH_PGO_ITEM \
  info = (HV*)SvRV(hash_ref);  \
  svp = hv_fetch(info, "unix_num", 8, 1); \
  pgo_item.unix_num = (signed32 )SvIV(*svp); \
  svp = hv_fetch(info, "quota", 5, 1); \
  pgo_item.quota = (signed32 )SvIV(*svp); \
  svp = hv_fetch(info, "flags", 5, 1); \
  pgo_item.flags = (sec_rgy_pgo_flags_t )SvIV(*svp); \
  svp = hv_fetch(info, "fullname", 8, 1); \
  strncpy(pgo_item.fullname, (char *)SvPV(*svp,na), 256); \
  svp = hv_fetch(info, "uuid", 4, 1); \
  UUIDmagic_sv(pgo_item.id, *svp);  

/*   BLESS_UUID(pgo_item.id); \   */

#define STORE_PGO_ITEM \
   iniHV; \
   hv_store(hv,"quota",5,newSViv((IV)pgo_item.quota),0); \
   hv_store(hv,"unix_num",8,newSViv((IV)pgo_item.unix_num),0); \
   hv_store(hv,"flags",5,newSViv((IV)pgo_item.flags),0); \
   hv_store(hv,"fullname", 8, newSVpv(pgo_item.fullname,0),0); \
   {\
       unsigned_char_t *uuid_str; \
       error_status_t  uuid_str_status; \
       uuid_to_string(&pgo_item.id, &uuid_str, &uuid_str_status); \
       uuid_sv = newSVpv((unsigned_char_t *)uuid_str, 0); \
       hv_store(hv, "id", 2, (SV*)uuid_sv, 0); \
   } \
   rv = newRV((SV*)hv)

#define STORE_POLICY_DATA \
   iniHV; \
   hv_store(hv,"passwd_min_len",14,newSViv(policy_data.passwd_min_len),0); \
   hv_store(hv,"passwd_lifetime",15,newSViv(policy_data.passwd_lifetime),0); \
   hv_store(hv,"passwd_exp_date",15,newSViv(policy_data.passwd_exp_date),0); \
   hv_store(hv,"acct_lifespan",13,newSViv(policy_data.acct_lifespan),0); \
   hv_store(hv,"passwd_flags",12,newSViv(policy_data.passwd_flags),0); \
   XPUSHs(newRV((SV*)hv)); \
   DCESTATUS

typedef sec_rgy_login_name_t * DCE__login_name;

MODULE = DCE::Registry  PACKAGE = DCE::Registry  PREFIX = sec_rgy_
PROTOTYPES: DISABLE

void
sec_rgy_DESTROY(rgy_context)
   DCE::Registry	rgy_context
   
  PPCODE:
  {
    error_status_t	status;
    sec_rgy_site_close(rgy_context, &status);
    DCESTATUS;
  }

void
sec_rgy_site_bind(package="DCE::Registry",site_name="",hash_ref=&sv_undef)
  char *	package
  char *	site_name
  SV *	hash_ref

  PPCODE:
  {
  sec_rgy_handle_t	rgy_context; 
  error_status_t	status; 
  STRLEN len; 
  sec_rgy_bind_auth_info_t	auth_info; 
  SV *sv; 
  SV **svp;
  HV *stash, *info; 
  
  FETCH_AUTH_INFO;
  sec_rgy_site_bind(site_name, &auth_info, &rgy_context, &status);
  BLESS_RGY_CONTEXT;
  }

void
sec_rgy_cell_bind(package="DCE::Registry",cell_name="",hash_ref=&sv_undef)
  char *	package
  char *	cell_name
  SV *	hash_ref

  PPCODE:
  {
  sec_rgy_handle_t	rgy_context; 
  error_status_t	status; 
  STRLEN len; 
  sec_rgy_bind_auth_info_t	auth_info; 
  SV *sv; 
  SV **svp;
  HV *stash, *info; 
  
  FETCH_AUTH_INFO;
  sec_rgy_site_bind(cell_name, &auth_info, &rgy_context, &status);
  BLESS_RGY_CONTEXT;
  }


void
sec_rgy_site_bind_query(package="DCE::Registry",site_name="",hash_ref=&sv_undef)
  char *	package
  char *	site_name
  SV *	hash_ref

  PPCODE:
  {
  sec_rgy_handle_t	rgy_context; 
  error_status_t	status; 
  STRLEN len; 
  sec_rgy_bind_auth_info_t	auth_info; 
  SV *sv; 
  SV **svp;
  HV *stash, *info; 
  
  FETCH_AUTH_INFO;
  sec_rgy_site_bind_query(site_name, &auth_info, &rgy_context, &status);
  BLESS_RGY_CONTEXT;
  }

void
sec_rgy_site_bind_update(package="DCE::Registry",site_name="",hash_ref=&sv_undef)
  char *	package
  char *	site_name
  SV *	hash_ref

  PPCODE:
  {
  sec_rgy_handle_t	rgy_context; 
  error_status_t	status; 
  STRLEN len; 
  sec_rgy_bind_auth_info_t	auth_info; 
  SV *sv; 
  SV **svp;
  HV *stash, *info; 
  
  FETCH_AUTH_INFO;
  sec_rgy_site_bind_update(site_name, &auth_info, &rgy_context, &status);
  BLESS_RGY_CONTEXT;
  }


void
sec_rgy_site_open(package="DCE::Registry",site_name="")
  char *	package
  char *	site_name

  PPCODE:
  {
    sec_rgy_handle_t	rgy_context; 
    error_status_t	status; 
    HV *stash;
    SV *sv;

    sec_rgy_site_open(site_name, &rgy_context, &status);
    BLESS_RGY_CONTEXT;
  }

void
sec_rgy_site_open_query(package="DCE::Registry",site_name="")
  char *	package
  char *	site_name

  PPCODE:
  {
    sec_rgy_handle_t	rgy_context; 
    error_status_t	status; 
    HV *stash;
    SV *sv;

    sec_rgy_site_open_query(site_name, &rgy_context, &status);
    BLESS_RGY_CONTEXT;
  }

void
sec_rgy_site_open_update(package="DCE::Registry",site_name="")
  char *	package
  char *	site_name

  PPCODE:
  {
    sec_rgy_handle_t	rgy_context; 
    error_status_t	status; 
    HV *stash;
    SV *sv;

    sec_rgy_site_open_update(site_name, &rgy_context, &status); 
    BLESS_RGY_CONTEXT;
  }

void
sec_rgy_site_binding_get_info(rgy_context)
  DCE::Registry	rgy_context

  PPCODE:
  {
    sec_rgy_bind_auth_info_t auth_info;
    unsigned_char_t *	cell_name;
    unsigned_char_t *	server_name;
    unsigned_char_t *	string_binding;
    error_status_t	status;
    STRLEN len;

    sec_rgy_site_binding_get_info(rgy_context, &cell_name, 
		&server_name, &string_binding, &auth_info, &status);

    CHK_STS(3);

    if(WANTARRAY) {
	EXTEND(sp, 3);
	PUSHs_pv(cell_name);
	PUSHs_pv(server_name);
	PUSHs_pv(string_binding);
	DCESTATUS;
    }
    else
	PUSHs_pv(cell_name);
  }

unsigned_char_t *
sec_rgy_site_get(rgy_context)
  DCE::Registry		rgy_context

  PPCODE:
  {
    unsigned_char_t * site_name;
    error_status_t status;

    sec_rgy_site_get(rgy_context, &site_name, &status);

    XPUSHs_pv(site_name);
    if(WANTARRAY)
	DCESTATUS;
  }

void
sec_rgy_site_close(rgy_context)
  DCE::Registry	rgy_context

  PPCODE:
  {
    error_status_t	status;
    sec_rgy_site_close(rgy_context, &status);
    DCESTATUS;
  }

boolean32
sec_rgy_site_is_readonly(rgy_context)
  DCE::Registry	rgy_context

  CODE:
  {
    RETVAL=sec_rgy_site_is_readonly(rgy_context);
  }

  OUTPUT:
  RETVAL

void
sec_rgy_pgo_unix_num_to_id(rgy_context, domain, unix_num)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  long	unix_num

  PPCODE:
  {
   uuid_t uuid_struct;
   error_status_t status;
   SV *uuid_sv;

   sec_rgy_pgo_unix_num_to_id(rgy_context, domain, unix_num, 
			       &uuid_struct, &status);

   BLESS_UUID_mortal(uuid_struct);
   XPUSHs(uuid_sv); 

    if(WANTARRAY) 
	DCESTATUS;
  }

void
sec_rgy_pgo_unix_num_to_name(rgy_context, domain, unix_num)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  long	unix_num

  PPCODE:
  {
    char *	name;
    error_status_t	status;
    name = (char *) malloc(sizeof(char)* 1025);
    sec_rgy_pgo_unix_num_to_name(rgy_context, domain, unix_num, name, &status);
    XPUSHs_pv(name);

    if(WANTARRAY) 
	DCESTATUS;
  }

void
sec_rgy_pgo_id_to_unix_num(rgy_context, domain, uuid)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  SV  *uuid

  PPCODE:
  {
    uuid_t  uuid_struct;
    error_status_t	uuid_status;
    signed32	unix_id;
    error_status_t	status;

    UUIDmagic_sv(uuid_struct, uuid);
    sec_rgy_pgo_id_to_unix_num(rgy_context, domain, &uuid_struct, 
			       &unix_id, &status);
    XPUSHs_iv(unix_id);

    if(WANTARRAY) 
	DCESTATUS;
  }

void
sec_rgy_pgo_id_to_name(rgy_context, domain, item_id)
  DCE::Registry		rgy_context
  sec_rgy_domain_t	domain
  SV *item_id

  PPCODE:
  {
    error_status_t	status;
    uuid_t              uuid;
    sec_rgy_name_t	pgo_name;
    sec_rgy_name_t      retval;

    UUIDmagic_sv(uuid, item_id);
    sec_rgy_pgo_id_to_name(rgy_context, domain, &uuid, pgo_name, &status);
    strncpy(retval, pgo_name, 1024); 

    XPUSHs_pv(retval);
    if(WANTARRAY) 
	DCESTATUS;	
  }

void
sec_rgy_pgo_name_to_unix_num(rgy_context, domain, name)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	name

  PPCODE:
  {
    signed32	unix_id;
    error_status_t	status;

    sec_rgy_pgo_name_to_unix_num(rgy_context, domain, name, &unix_id, &status);

    XPUSHs(newSViv(unix_id));
    if(WANTARRAY) 
	DCESTATUS;
  }

void
sec_rgy_pgo_name_to_id(rgy_context, domain, name)
  DCE::Registry		rgy_context
  sec_rgy_domain_t	domain
  char *	name

  PPCODE:
  {
    uuid_t	uuid_struct;
    error_status_t	status;
    SV *uuid_sv;
    sec_rgy_pgo_name_to_id(rgy_context, domain, name, &uuid_struct, &status);

    BLESS_UUID_mortal(uuid_struct);
    XPUSHs(uuid_sv); 
    if(WANTARRAY) 
	DCESTATUS;
  }

void
sec_rgy_pgo_add(rgy_context, domain, name, hash_ref)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	name
  SV *hash_ref

  PPCODE:
  {
    error_status_t	status;
    sec_rgy_pgo_item_t  pgo_item;
    SV **svp;     
    HV *info; 

    FETCH_PGO_ITEM;
    sec_rgy_pgo_add(rgy_context, domain, name, &pgo_item, &status);
    DCESTATUS;
  }

void
sec_rgy_pgo_replace(rgy_context, domain, name, hash_ref)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	name
  SV *hash_ref

  PPCODE:
  {
    error_status_t	status;
    sec_rgy_pgo_item_t  pgo_item;
    SV **svp;     
    HV *info; 

    FETCH_PGO_ITEM;
    sec_rgy_pgo_replace(rgy_context, domain, name, &pgo_item, &status);
    DCESTATUS;
  }

void
sec_rgy_pgo_rename(rgy_context, domain, old_name, new_name)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	old_name
  char *	new_name

  PPCODE:
  {
    sec_rgy_name_t  old_pgo_name, new_pgo_name;
    error_status_t	status;    

    strncpy(old_pgo_name, old_name, 1024);
    strncpy(new_pgo_name, new_name, 1024);

    sec_rgy_pgo_rename(rgy_context,domain,old_pgo_name,new_pgo_name,&status);
    DCESTATUS;
  }

void
sec_rgy_pgo_delete(rgy_context, domain, name)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	name

  PPCODE:
  {
    error_status_t	status;

    sec_rgy_pgo_delete(rgy_context, domain, name, &status);
    DCESTATUS;
  }

void
sec_rgy_pgo_add_member(rgy_context, domain, name, person)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	name
  char *	person

  PPCODE:
  {
    sec_rgy_name_t	go_name;
    sec_rgy_name_t	person_name;
    error_status_t	status;

    strncpy(go_name, name, 1025);
    strncpy(person_name, person, 1025);

    sec_rgy_pgo_add_member(rgy_context, domain, go_name, person_name, &status);
    DCESTATUS;
  }

void
sec_rgy_pgo_delete_member(rgy_context, domain, name, person)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	name
  char *	person

  PPCODE:
  {
    sec_rgy_name_t	go_name;
    sec_rgy_name_t	person_name;
    error_status_t	status;

    strncpy(go_name, name, 1025);
    strncpy(person_name, person, 1025);

    sec_rgy_pgo_delete_member(rgy_context, domain, go_name, person_name, &status);
    DCESTATUS;
  }

void
sec_rgy_cursor_reset(rgy_context, cursor)
  DCE::Registry	rgy_context
  DCE::RegistryCursor	cursor

  CODE:
  {
    sec_rgy_cursor_reset(cursor);
  }

void
sec_rgy_create_cursor(rgy_context, cursor)
  DCE::Registry	rgy_context
  SV *	cursor

  CODE:
  {
    sec_rgy_cursor_t *rgy_cursor;
    rgy_cursor = malloc(sizeof(sec_rgy_cursor_t));
    sv_setref_pv((SV*)cursor, "DCE::RegistryCursor", (void *)rgy_cursor);
  }

DCE::RegistryCursor
sec_rgy_cursor(rgy_context)
  SV *	rgy_context

  CODE:
  {
    sec_rgy_cursor_t *rgy_cursor;
    rgy_cursor = malloc(sizeof(sec_rgy_cursor_t));
    RETVAL = rgy_cursor;
  }

  OUTPUT:
  RETVAL

void
sec_rgy_pgo_get_next(rgy_context, domain, scope, item_cursor)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	scope
  DCE::RegistryCursor	item_cursor

  PPCODE:
  {
    error_status_t	status;
    sec_rgy_pgo_item_t  pgo_item;
    uuid_t  uuid_struct;
    sec_rgy_name_t	pgo_name;
    SV *rv, *uuid_sv;
    HV *hv;

    sec_rgy_pgo_get_next(rgy_context, domain, scope, item_cursor, &pgo_item, pgo_name, &status);

    STORE_PGO_ITEM;

    EXTEND(sp, 2);
    PUSHs((SV*)rv);
    PUSHs_pv(pgo_name); 
    DCESTATUS;
  }

void
sec_rgy_pgo_is_member(rgy_context, domain, name, person)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	name
  char *	person

  PPCODE:
  {
    sec_rgy_name_t	go_name;
    sec_rgy_name_t	person_name;
    boolean32           is_mem;
    error_status_t	status;

    strncpy(go_name, name, 1025);
    strncpy(person_name, person, 1025);

    is_mem = sec_rgy_pgo_is_member(rgy_context, domain, 
				   go_name, person_name, &status);
    XPUSHs_iv(is_mem);
    DCESTATUS;
  }

void
sec_rgy_pgo_get_by_name(rgy_context, domain, name, item_cursor)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	name
  DCE::RegistryCursor 	item_cursor

  PPCODE:
  {
    error_status_t	status;
    sec_rgy_pgo_item_t  pgo_item;
    uuid_t  uuid_struct;
    SV *rv, *uuid_sv;
    HV *hv;

    sec_rgy_pgo_get_by_name(rgy_context, domain, name, (sec_rgy_cursor_t *)item_cursor, &pgo_item, &status);

    STORE_PGO_ITEM;

    XPUSHs((SV*)rv);
    DCESTATUS;
  }

void
sec_rgy_pgo_get_by_unix_num(rgy_context, domain, scope, unix_id, allow_aliases, cursor)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	scope
  signed32	unix_id
  boolean32	allow_aliases
  DCE::RegistryCursor 	cursor

  PPCODE:
  {
    error_status_t	status;
    sec_rgy_pgo_item_t  pgo_item;
    uuid_t  uuid_struct;
    char *name;
    SV *rv, *uuid_sv;
    HV *hv;

    sec_rgy_pgo_get_by_unix_num(rgy_context, domain, scope, unix_id, 
				allow_aliases, (sec_rgy_cursor_t *)cursor, 
				&pgo_item, name, &status);

    STORE_PGO_ITEM;

    XPUSHs((SV*)rv);
    XPUSHs_pv(name);
    DCESTATUS;
  }

void
sec_rgy_pgo_get_by_id(rgy_context, domain, scope, id, allow_aliases, cursor)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	scope
  SV *	id
  boolean32	allow_aliases
  DCE::RegistryCursor	cursor

  PPCODE:
  {
    sec_rgy_pgo_item_t  pgo_item;
    uuid_t  uuid_struct;
    error_status_t status;
    char *name; 
    SV *rv, *uuid_sv;
    HV *hv;

    UUIDmagic_sv(uuid_struct, id);
    sec_rgy_pgo_get_by_id(rgy_context, domain, scope, &uuid_struct, 
			   allow_aliases, (sec_rgy_cursor_t *)cursor, 
			   &pgo_item, name, &status);

    STORE_PGO_ITEM;

    XPUSHs((SV*)rv);
    XPUSHs_pv(name);
    DCESTATUS;
  }

void
sec_rgy_pgo_get_members(rgy_context, domain, name, member_cursor, max_members = 20)
  DCE::Registry	rgy_context
  sec_rgy_domain_t	domain
  char *	name
  DCE::RegistryCursor	member_cursor
  long	 max_members

  PPCODE:
  {
    error_status_t	status;
    sec_rgy_member_t *member_list;
    signed32 number_supplied, number_members, i;
    AV *av;

    member_list = (sec_rgy_member_t *)malloc(sizeof(sec_rgy_member_t) * max_members);

    sec_rgy_pgo_get_members(rgy_context, domain, name, 
			    (sec_rgy_cursor_t *)member_cursor, max_members, 
			    member_list, &number_supplied, &number_members, 
			    &status);

    if(status == sec_rgy_no_more_entries)

    if((status != 0) && (status != sec_rgy_no_more_entries)) { 
      ST(0) = &sv_undef;
      free(member_list);
      PUTBACK;
      return;
    }
    
    iniAV;

    for(i=0; i<number_supplied; i++) {
      av_push(av, newSVpv(member_list[i], strlen(member_list[i]))); 
    }
    free(member_list);    

    EXTEND(sp, 3);

    PUSHs(newRV((SV*)av));
    PUSHs(newSViv((long)number_supplied));
    PUSHs(newSViv((long)number_members));
    DCESTATUS;
  }


void
sec_rgy_acct_lookup(rgy_context, login_name_ref, cursor)
  DCE::Registry	rgy_context
  SV	*login_name_ref
  DCE::RegistryCursor	cursor

  PPCODE:
  {
    char *pname_result, *gname_result, *oname_result;
    sec_rgy_acct_key_t	key_parts;
    sec_timeval_sec_t	creation_date;
    error_status_t	status;
  
    sec_rgy_login_name_t login_name, name_result;
    sec_rgy_sid_t id_sid;
    sec_rgy_unix_sid_t unix_sid;
    sec_rgy_acct_user_t user_part;
    sec_rgy_acct_admin_t admin_part;
    error_status_t uuid_status;
    STRLEN len;
    HV *hv, *nhv;
    SV **svp, *uuid_sv;

    FETCH_LOGIN_NAME;
    strcpy(login_name.oname, (char *)SvPV(*svp,len));
    sec_rgy_acct_lookup(rgy_context, &login_name, (sec_rgy_cursor_t *)cursor,
			&name_result, &id_sid, &unix_sid, &key_parts, 
			&user_part, &admin_part, &status);
    
    CHK_STS(4);

    iniHV;
    hv_store(hv, "pname", 5, newSVpv(name_result.pname,0),0);
    hv_store(hv, "gname", 5, newSVpv(name_result.gname,0),0);
    hv_store(hv, "oname", 5, newSVpv(name_result.oname,0),0);
    /* DCE_TIEHASH(&name_result, "DCE::login_name", hv); */
    sv_setsv(ST(1), newRV((SV*)hv));

    EXTEND(sp, 4);
    iniHV;
    BLESS_UUID(id_sid.person); 
    hv_store(hv,"person", 6, uuid_sv,0);
    BLESS_UUID(id_sid.group); 
    hv_store(hv,"group", 5, uuid_sv,0);
    BLESS_UUID(id_sid.org); 
    hv_store(hv,"org", 3, uuid_sv,0);
    PUSHs(newRV((SV*)hv));  

    iniHV;
    hv_store(hv, "person", 6, newSViv(unix_sid.person),0);
    hv_store(hv, "group", 5, newSViv(unix_sid.group),0);
    hv_store(hv, "org", 3, newSViv(unix_sid.org),0);
    PUSHs(newRV((SV*)hv));  

    iniHV;
    hv_store(hv, "gecos", 5, newSVpv(user_part.gecos,0),0);
    hv_store(hv, "homedir", 7, newSVpv(user_part.homedir,0),0);
    hv_store(hv, "shell", 5, newSVpv(user_part.shell,0),0);
    hv_store(hv, "passwd", 6, newSVpv(user_part.passwd,0),0);
    hv_store(hv, "passwd_version_number", 21,
	     newSViv(user_part.passwd_version_number),0);
    hv_store(hv, "passwd_dtm", 10, newSViv((IV)user_part.passwd_dtm),0);
    hv_store(hv, "flags", 5, newSViv(user_part.flags),0);
    PUSHs(newRV((SV*)hv));  

    iniHV;
    nhv = (HV*)sv_2mortal((SV*)newHV());
    BLESS_UUID(admin_part.creator.principal);
    hv_store(nhv, "principal", 9, uuid_sv, 0);
    BLESS_UUID(admin_part.creator.cell);
    hv_store(nhv, "cell", 4, uuid_sv, 0);      
    hv_store(hv, "creator", 7, newRV((SV*)nhv), 0); 

    nhv = (HV*)sv_2mortal((SV*)newHV());
    BLESS_UUID(admin_part.last_changer.principal);
    hv_store(nhv, "principal", 9, uuid_sv, 0);
    BLESS_UUID(admin_part.last_changer.cell);
    hv_store(nhv, "cell", 4, uuid_sv, 0);      
    hv_store(hv, "last_changer", 12, newRV((SV*)nhv), 0); 

    hv_store(hv, "creation_date", 13, newSViv(admin_part.creation_date),0);
    hv_store(hv, "change_date", 11, newSViv(admin_part.change_date),0);
    hv_store(hv, "expiration_date", 15, newSViv(admin_part.expiration_date),0);
    hv_store(hv, "good_since_date", 15, newSViv(admin_part.good_since_date),0);
    hv_store(hv, "flags", 5, newSViv(admin_part.flags),0);
    hv_store(hv, "authentication_flags", 20, newSViv(admin_part.authentication_flags),0);
    PUSHs(newRV((SV*)hv));  

    DCESTATUS;
  }

void
sec_rgy_acct_replace_all(rgy_context, login_name_ref, key_parts, user_part_ref, admin_part_ref, set_passwd, caller_key, new_key, new_keytype)
  DCE::Registry	rgy_context
  SV	*login_name_ref
  sec_rgy_acct_key_t	key_parts
  SV	*user_part_ref
  boolean32	set_passwd
  SV	*admin_part_ref
  char *	caller_key
  char *	new_key
  sec_passwd_type_t	new_keytype

  PPCODE:
  {
    sec_passwd_version_t	new_key_version;
    sec_rgy_login_name_t	login_name;
    sec_rgy_acct_user_t	user_part;
    sec_rgy_acct_admin_t admin_part;
    sec_passwd_rec_t	caller_key_rec, new_key_rec;
    char caller_key_arr[BUFSIZ], new_key_arr[BUFSIZ];
    error_status_t	status;
    SV **svp;
    HV *hv;
    STRLEN len;

    FETCH_LOGIN_NAME;
    strcpy(login_name.oname, (char *)SvPV(*svp,len));
    FETCH_USER_PART;
    FETCH_ADMIN_PART;
 
    /* load encryption key struct */
    caller_key_rec.version_number = sec_passwd_c_version_none;
    caller_key_rec.pepper = NULL;
    caller_key_rec.key.key_type = sec_passwd_plain;
    strcpy(caller_key_arr, caller_key);
    caller_key_rec.key.tagged_union.plain = caller_key_arr;

    /* load password struct */
    new_key_rec.version_number = sec_passwd_c_version_none;
    new_key_rec.key.key_type = sec_passwd_plain;
    new_key_rec.pepper = NULL;
    strcpy(new_key_arr, new_key);
    new_key_rec.key.tagged_union.plain = new_key_arr;

    sec_rgy_acct_replace_all(rgy_context, &login_name, &key_parts, 
		     &user_part, &admin_part, set_passwd,
		     &caller_key_rec, &new_key_rec, new_keytype, 
		     &new_key_version, &status);

    EXTEND(sp, 2);
    PUSHs_iv(key_parts);
    PUSHs_iv(new_key_version);
    DCESTATUS;
  }

void
sec_rgy_acct_user_replace(rgy_context, login_name_ref, user_part_ref, set_passwd, caller_key, new_key, new_keytype)
  DCE::Registry	rgy_context
  SV	*login_name_ref
  SV	*user_part_ref
  boolean32	set_passwd
  char *	caller_key
  char *	new_key
  sec_passwd_type_t	new_keytype

  PPCODE:
  {
    sec_passwd_version_t	new_key_version;
    sec_rgy_login_name_t	login_name;
    sec_rgy_acct_user_t	user_part;
    sec_passwd_rec_t	caller_key_rec, new_key_rec;
    char caller_key_arr[BUFSIZ], new_key_arr[BUFSIZ];
    error_status_t	status;
    SV **svp;
    HV *hv;
    STRLEN len;

    FETCH_LOGIN_NAME;
    strcpy(login_name.oname, (char *)SvPV(*svp,len));
    FETCH_USER_PART;
 
    /* load encryption key struct */
    caller_key_rec.version_number = sec_passwd_c_version_none;
    caller_key_rec.pepper = NULL;
    caller_key_rec.key.key_type = sec_passwd_plain;
    strcpy(caller_key_arr, caller_key);
    caller_key_rec.key.tagged_union.plain = caller_key_arr;

    /* load password struct */
    new_key_rec.version_number = sec_passwd_c_version_none;
    new_key_rec.key.key_type = sec_passwd_plain;
    new_key_rec.pepper = NULL;
    strcpy(new_key_arr, new_key);
    new_key_rec.key.tagged_union.plain = new_key_arr;

    sec_rgy_acct_user_replace(rgy_context, &login_name, 
		     &user_part, set_passwd, 
		     &caller_key_rec, &new_key_rec, new_keytype, 
		     &new_key_version, &status);

    XPUSHs_iv(new_key_version);
    DCESTATUS;
  }

void
sec_rgy_acct_add(rgy_context, login_name_ref, key_parts, user_part_ref, admin_part_ref, caller_key, new_key, new_keytype)
  DCE::Registry	rgy_context
  SV	*login_name_ref
  sec_rgy_acct_key_t	key_parts
  SV	*user_part_ref
  SV	*admin_part_ref
  char *	caller_key
  char *	new_key
  sec_passwd_type_t	new_keytype

  PPCODE:
  {
    sec_passwd_version_t	new_key_version;
    sec_rgy_login_name_t	login_name;
    sec_rgy_acct_user_t	user_part;
    sec_rgy_acct_admin_t admin_part;
    sec_passwd_rec_t	caller_key_rec, new_key_rec;
    char caller_key_arr[BUFSIZ], new_key_arr[BUFSIZ];
    error_status_t	status;
    SV **svp;
    HV *hv;
    STRLEN len;

    FETCH_LOGIN_NAME;
    strcpy(login_name.oname, (char *)SvPV(*svp,len));
    FETCH_USER_PART;
    FETCH_ADMIN_PART;
 
    /* load encryption key struct */
    caller_key_rec.version_number = sec_passwd_c_version_none;
    caller_key_rec.pepper = NULL;
    caller_key_rec.key.key_type = sec_passwd_plain;
    strcpy(caller_key_arr, caller_key);
    caller_key_rec.key.tagged_union.plain = caller_key_arr;

    /* load password struct */
    new_key_rec.version_number = sec_passwd_c_version_none;
    new_key_rec.key.key_type = sec_passwd_plain;
    new_key_rec.pepper = NULL;
    strcpy(new_key_arr, new_key);
    new_key_rec.key.tagged_union.plain = new_key_arr;

    sec_rgy_acct_add(rgy_context, &login_name, &key_parts, 
		     &user_part, &admin_part, 
		     &caller_key_rec, &new_key_rec, new_keytype, 
		     &new_key_version, &status);

    EXTEND(sp, 2);
    PUSHs_iv(key_parts);
    PUSHs_iv(new_key_version);
    DCESTATUS;
  }

void
sec_rgy_acct_passwd(rgy_context, login_name_ref, caller_key, new_key, new_keytype)
  DCE::Registry	rgy_context
  SV	*login_name_ref
  char *	caller_key
  char *	new_key
  sec_passwd_type_t	new_keytype

  PPCODE:
  {
    sec_passwd_version_t	new_key_version;
    sec_rgy_login_name_t	login_name;
    sec_passwd_rec_t	caller_key_rec, new_key_rec;
    char caller_key_arr[BUFSIZ], new_key_arr[BUFSIZ];
    error_status_t	status;
    SV **svp;
    HV *hv;
    STRLEN len;

    FETCH_LOGIN_NAME;
    strcpy(login_name.oname, (char *)SvPV(*svp,len));
 
    /* load encryption key struct */
    caller_key_rec.version_number = sec_passwd_c_version_none;
    caller_key_rec.pepper = NULL;
    caller_key_rec.key.key_type = sec_passwd_plain;
    strcpy(caller_key_arr, caller_key);
    caller_key_rec.key.tagged_union.plain = caller_key_arr;

    /* load password struct */
    new_key_rec.version_number = sec_passwd_c_version_none;
    new_key_rec.key.key_type = sec_passwd_plain;
    new_key_rec.pepper = NULL;
    strcpy(new_key_arr, new_key);
    new_key_rec.key.tagged_union.plain = new_key_arr;

    sec_rgy_acct_passwd(rgy_context, &login_name, 
			&caller_key_rec, &new_key_rec, new_keytype, 
			&new_key_version, &status);

    XPUSHs_iv(new_key_version);
    DCESTATUS;
  }

void
sec_rgy_acct_admin_replace(rgy_context, login_name_ref, key_parts, admin_part_ref)
  DCE::Registry	rgy_context
  SV	*login_name_ref
  sec_rgy_acct_key_t	key_parts
  SV	*admin_part_ref

  PPCODE:
  {
    sec_rgy_login_name_t	login_name;
    sec_rgy_acct_admin_t admin_part;
    sec_passwd_rec_t	caller_key_rec, new_key_rec;
    char caller_key_arr[BUFSIZ], new_key_arr[BUFSIZ];
    error_status_t	status;
    SV **svp;
    HV *hv;
    STRLEN len;

    FETCH_LOGIN_NAME;
    strcpy(login_name.oname, (char *)SvPV(*svp,len));
    FETCH_ADMIN_PART;
 
    sec_rgy_acct_admin_replace(rgy_context, &login_name, &key_parts, 
			       &admin_part, &status);

    DCESTATUS;
  }

void
sec_rgy_acct_delete(rgy_context, login_name_ref)
  DCE::Registry	rgy_context
  SV	*login_name_ref

  PPCODE:
  {
    sec_rgy_login_name_t	login_name;
    error_status_t	status;
    SV **svp;
    HV *hv;
    STRLEN len;

    FETCH_LOGIN_NAME;
    strcpy(login_name.oname, (char *)SvPV(*svp,len));
    sec_rgy_acct_delete(rgy_context, &login_name, &status);
    DCESTATUS;
  }


void
sec_rgy_acct_rename(rgy_context, old_login_name_ref, new_login_name_ref, new_key_parts)
  DCE::Registry	rgy_context
  SV *old_login_name_ref
  SV *new_login_name_ref
  sec_rgy_acct_key_t	new_key_parts

  CODE:
  {
    sec_rgy_login_name_t old_login_name, new_login_name;
    error_status_t	status;
    SV **svp;
    HV *hv;
    STRLEN len;
    
    hv = (HV*)SvRV(old_login_name_ref); 
    svp = hv_fetch(hv, "pname", 5, 1); 
    strcpy(old_login_name.pname, (char *)SvPV(*svp,len)); 
    svp = hv_fetch(hv, "gname", 5, 1); 
    strcpy(old_login_name.gname, (char *)SvPV(*svp,len)); 
    svp = hv_fetch(hv, "oname", 5, 1);   
    strcpy(old_login_name.oname, (char *)SvPV(*svp,len));

    hv = (HV*)SvRV(new_login_name_ref); 
    svp = hv_fetch(hv, "pname", 5, 1); 
    strcpy(new_login_name.pname, (char *)SvPV(*svp,len)); 
    svp = hv_fetch(hv, "gname", 5, 1); 
    strcpy(new_login_name.gname, (char *)SvPV(*svp,len)); 
    svp = hv_fetch(hv, "oname", 5, 1);   
    strcpy(new_login_name.oname, (char *)SvPV(*svp,len));

    sec_rgy_acct_rename(rgy_context, &old_login_name, &new_login_name, 
			&new_key_parts, &status);
    XPUSHs_iv(new_key_parts);
    DCESTATUS;
  }

void
sec_rgy_plcy_get_info(rgy_context, organization)
  DCE::Registry	rgy_context
  char *	organization

  PPCODE:
  {
    sec_rgy_plcy_t policy_data;
    error_status_t	status;
    HV *hv;

    sec_rgy_plcy_get_info(rgy_context, organization, &policy_data, &status);
    STORE_POLICY_DATA;
  }

void
sec_rgy_plcy_set_info(rgy_context, organization, policy_data_ref)
  DCE::Registry	rgy_context
  char	 *organization
  SV	*policy_data_ref

  PPCODE:
  {
    sec_rgy_plcy_t policy_data;
    error_status_t	status;
    HV *hv;
    SV **svp;

    hv = (HV*)SvRV(policy_data_ref);
    svp = hv_fetch(hv,"passwd_min_len",14,1);
    policy_data.passwd_min_len = (signed32 )SvIV(*svp);

    svp = hv_fetch(hv,"passwd_lifetime",15,1);
    policy_data.passwd_lifetime = (sec_timeval_period_t )SvIV(*svp);

    svp = hv_fetch(hv,"passwd_exp_date",15,1);
    policy_data.passwd_exp_date = (sec_timeval_sec_t )SvIV(*svp);

    svp = hv_fetch(hv,"acct_lifespan",13,1);
    policy_data.acct_lifespan = (sec_timeval_period_t )SvIV(*svp);

    svp = hv_fetch(hv,"passwd_flags",12,1);
    policy_data.passwd_flags = (sec_rgy_plcy_pwd_flags_t )SvIV(*svp);

    sec_rgy_plcy_set_info(rgy_context, organization, &policy_data, &status);
    DCESTATUS;
  }

void
sec_rgy_plcy_get_effective(rgy_context, organization)
  DCE::Registry	rgy_context
  char *	organization

  PPCODE:
  {
    sec_rgy_plcy_t policy_data;
    error_status_t	status;
    HV *hv;

    sec_rgy_plcy_get_effective(rgy_context, organization, &policy_data, &status);
    STORE_POLICY_DATA;
  }


MODULE = DCE::Registry  PACKAGE = DCE::cursor

void
new(package)
  char	*package
     
  PPCODE:
  {
    SV *cursor;
    sec_rgy_cursor_t *rgy_cursor;
    rgy_cursor = malloc(sizeof(sec_rgy_cursor_t));
    cursor = sv_newmortal();
    warn("Don't call DCE::cursor->new, use DCE::Registry->cursor instead!!!");
    sv_setref_pv((SV*)cursor, "DCE::RegistryCursor", (void *)rgy_cursor);
    XPUSHs(cursor);
  }

MODULE = DCE::Registry  PACKAGE = DCE::RegistryCursor

void
DESTROY(cursor)
DCE::RegistryCursor   cursor

   CODE:
   {
     free(cursor);
   }

void
reset(cursor)
DCE::RegistryCursor	cursor

  CODE:
  {
    sec_rgy_cursor_reset(cursor);
  }

void
new(package)
  char	*package
     
  PPCODE:
  {
    SV *cursor;
    sec_rgy_cursor_t *rgy_cursor;
    rgy_cursor = malloc(sizeof(sec_rgy_cursor_t));
    cursor = sv_newmortal();
    sv_setref_pv((SV*)cursor, package, (void *)rgy_cursor);
    XPUSHs(cursor);
  }

MODULE = DCE::Registry		PACKAGE = DCE::login_name

char *
FETCH(id, key)
DCE::login_name id
char *key

    CODE:
    {
    SV *uuid_sv;
    
    if(strEQ(key, "pname"))
	RETVAL = id->pname;
    else if(strEQ(key, "gname")) 
	RETVAL = id->gname;
    else if(strEQ(key, "oname")) 
	RETVAL = id->oname;
    else 
	RETVAL = NULL;
    }
    printf("DCE::login_name->FETCH %s, %s\n", key, RETVAL); 
    OUTPUT:
    RETVAL

void
STORE(id, key, val)
DCE::login_name id
char *key
char *val

    CODE:
    if(strEQ(key, "pname")) printf("STORE %s %s", key, val);
       /*id->pname = val;*/
    
char *
FIRSTKEY(id)
DCE::login_name id

    CODE:
    {
    MAGIC *mg;
    /* mg = mg_find(SvRV(id), '~'); */
    }
