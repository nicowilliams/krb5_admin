/*  */

/* Blame: Roland Dowdeswell <elric@imrryr.org> */

/*
 * XXXrcd: nice comments here.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Kerberos includes */

#include <krb5.h>
#include <kadm5/admin.h>

#define BAIL(x, y)	do {						\
		ret = x;						\
		if (ret) {						\
			snprintf(croakstr, sizeof(croakstr),		\
			    "%s: %s", #x, y);				\
			ret = 1;					\
			goto done;					\
		}							\
	} while (0)

#define K5BAIL(x)	do {						\
		ret = x;						\
		if (ret) {						\
			const char	*tmp;				\
									\
			tmp = krb5_get_error_message(ctx, ret);		\
			if (tmp) {					\
				snprintf(croakstr, sizeof(croakstr),	\
				    "%s: %s", #x, tmp);			\
				krb5_free_error_message(ctx, tmp);	\
			} else {					\
				snprintf(croakstr, sizeof(croakstr),	\
				    "%s: unknown error", #x);		\
			}						\
			ret = 1;					\
			goto done;					\
		}							\
	} while (0)

typedef	void *kadm5_handle;

struct _key {
	char		*princ;
	krb5_timestamp	 timestamp;
	int	 	 kvno;
	int		 enctype;
	int		 length;
	char		 data[1024];
	struct _key	*next;
};

typedef struct _key *key;

#include "C.h"

kadm5_handle
krb5_get_kadm5_hndl(krb5_context ctx, char *dbname)
{
	kadm5_config_params	 params;
	kadm5_ret_t		 ret;
	kadm5_handle		 hndl;
	const char		*princstr = "root";
	char			 croakstr[2048] = "";

	memset((char *) &params, 0, sizeof(params));	

	if (dbname) {
		params.mask   = KADM5_CONFIG_DBNAME;
		params.dbname = dbname;
	}

	K5BAIL(KADM5_INIT_WITH_PASSWORD(ctx, princstr, &params, &hndl));

done:
	if (ret)
		croak("%s", croakstr);

	return hndl;
}

kadm5_principal_ent_rec
krb5_query_princ(krb5_context ctx, kadm5_handle hndl, char *in)
{
	kadm5_principal_ent_rec	 dprinc;
	krb5_principal		 princ = NULL;
	kadm5_ret_t		 ret;
	char			 croakstr[2048] = "";

	memset(&dprinc, 0, sizeof(dprinc));

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_get_principal(hndl, princ, &dprinc, 
	    KADM5_PRINCIPAL_NORMAL_MASK));

done:
	if (princ)
		krb5_free_principal(ctx, princ);
	/* XXXrcd: free dprinc */

	if (ret)
		croak("%s", croakstr);

	return dprinc;
}

/*
 * random_passwd() will return a random string which is designed to
 * be a passwd in most circumstances.  We choose characters from a
 * subset that is easy to recognise in most fonts, i.e. we avoid zero
 * and capital O because many fonts do not adequately distinguish them.
 * The return value is a char * which has been malloc(3)ed, it is the
 * caller's responsibility to free it.  random_passwd() can croak()
 * and so should be called only at the beginning of functions.
 */

#define HUMAN_PASSWD_SIZE	10
#define PROID_PASSWD_SIZE	15
char c_num[]	= "2345679";
char c_low[]	= "qwertyuipasdfghjkzxcvbnm";
char c_cap[]	= "QWERTYUPASDFGHJKLZXCVNM";
char c_all[] =	"2345679"      "2345679"
		"QWERTYUPASDFGHJKLZXCVNM"
		"qwertyuipasdfghjkzxcvbnm"
		"qwertyuipasdfghjkzxcvbnm"
		"!@#$%^&*()-+=[]{};:,.<>?"
		;

static char *
random_passwd(krb5_context ctx, int len)
{
	krb5_keyblock	 key;
	krb5_error_code	 ret;
	char		 croakstr[2048] = "";
	char		*passwd = NULL;
	unsigned char	*tmp;
	int		 i;

	passwd = malloc(len + 1);
	if (!passwd) {
		snprintf(croakstr, sizeof(croakstr), "Out of memory");
		ret = errno;
		goto done;
	}

	/* We lamely convert a key into a string for the passwd */
	K5BAIL(krb5_c_make_random_key(ctx, 18, &key));

	/*
	 * We are contructing what we presume to be a relatively good
	 * passwd here.  First, we select a single character from each
	 * of three character classes.  We do this up front to ensure
	 * that all passwds contain at least 3 character classes.  We
	 * could generate and then test, but we don't.  We looking to
	 * weight things a little away from the symbols and towards
	 * simplicity.  So, let's say that lower or upper case characters
	 * have about 4.5 bits of strength given that we've selected
	 * 23 of them.  The numbers have about 2.2 or so.  Our c_all[]
	 * is also a little skewed.  We have 79 possible characters but
	 * we're skewing towards lower case to make it easier to type.
	 * So, we're not really getting over 6 bits out of it.  Still,
	 * let's say that we're getting 5.5, then our 10 char passwd
	 * is:
	 *
	 *	2.2 + 4.5 + 4.5 + 7 * 5.5 = 49 bits.
	 *
	 * XXXrcd:
	 * Also note that because of our use of simple modulo arith,
	 * we're slightly biasing results towards the fronts of each
	 * of these character classes...
	 *
	 * Good enough.  Certainly better than the users will choose for
	 * themselves.
	 */

	tmp = KEYBLOCK_CONTENTS(key);
	passwd[0] = c_low[tmp[0] % (sizeof(c_low) - 1)];
	passwd[1] = c_cap[tmp[1] % (sizeof(c_cap) - 1)];
	passwd[2] = c_num[tmp[2] % (sizeof(c_num) - 1)];
	for (i=3; i < len; i++)
		passwd[i] = c_all[tmp[i] % (sizeof(c_all) - 1)];

	krb5_free_keyblock_contents(ctx, &key);
	passwd[i] = '\0';

done:
	if (ret) {
		free(passwd);
		croak("%s", croakstr);
	}

	return passwd;
}

char *
krb5_createprinc(krb5_context ctx, kadm5_handle hndl,
		 kadm5_principal_ent_rec p, long mask,
		 int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
		 char *passwd)
{
	kadm5_ret_t	 ret;
	char		 croakstr[2048] = "";

	if (passwd)
		passwd = strdup(passwd);
	else
		passwd = random_passwd(ctx, HUMAN_PASSWD_SIZE);

	if (!passwd)
		croak("Out of memory.");

	mask |= KADM5_PRINCIPAL;
	K5BAIL(kadm5_create_principal_3(hndl, &p, mask, n_ks_tuple, ks_tuple,
	    passwd));

done:
	if (ret) {
		free(passwd);
		croak("%s", croakstr);
	}

	return passwd;
}

void
krb5_modprinc(krb5_context ctx, kadm5_handle hndl, kadm5_principal_ent_rec p,
              long mask)
{
	kadm5_ret_t	ret;
	char		croakstr[256] = "";

	K5BAIL(kadm5_modify_principal(hndl, &p, mask));

done:
	if (ret)
		croak("%s", croakstr);
}

void
krb5_deleteprinc(krb5_context ctx, kadm5_handle hndl, char *in)
{
	krb5_principal	princ = NULL;
	kadm5_ret_t	ret;
	char		croakstr[2048] = "";

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_delete_principal(hndl, princ));

done:
	/* XXXrcd: free the princ. */
	if (ret)
		croak("%s", croakstr);
}

static char *
encode_curve_string(uint8_t *key)
{
	int	 i;
	char	*result;

	result = malloc(65);
	if (!result)
		return NULL;

	for (i=0; i < 32; i++)
		sprintf(&result[2*i], "%02x", key[i]);

	return result;
}

static char **
encode_curve_strings(uint8_t *secret, uint8_t *public)
{
	char	**result;

	result = calloc(3, sizeof(*result));
	if (!result)
		return NULL;

	result[0] = encode_curve_string(secret);
	result[1] = encode_curve_string(public);

	if (!result[0] || !result[1]) {
		free(result[0]);
		free(result[1]);
		return NULL;
	}

	return result;
}

static void
decode_curve_string(uint8_t *key, char *keystr)
{
	int	i;
	char	c;

	for (i=0; i < 32; i++) {
		c = keystr[2*i];
		if ('0' <= c && c <= '9')
			c -= '0';
		else
			c = c - 'a' + 10;
		key[i] = (c & 0xf) << 4;

		c = keystr[2*i + 1];
		if ('0' <= c && c <= '9')
			c -= '0';
		else
			c = c - 'a' + 10;
		key[i] |= (c & 0xf);
	}
}

char **
curve25519_pass1(krb5_context ctx)
{
	krb5_keyblock	  key;
	krb5_error_code	  ret;
	uint8_t		  basepoint[32] = {9};
	uint8_t		  mypublic[32];
	uint8_t		 *mysecret;
	char		**result;
	char		  croakstr[2048] = "";

	/*
	 * get 32 bytes of randomness for mysecret by generating an
	 * 256 bit AES key.
	 */
	K5BAIL(krb5_c_make_random_key(ctx, 18, &key));

	mysecret = KEYBLOCK_CONTENTS(key);

	mysecret[0] &= 248;
	mysecret[31] &= 127;
	mysecret[31] |= 64;

	curve25519_donna(mypublic, mysecret, basepoint);

	result = encode_curve_strings(mysecret, mypublic);

done:
	if (ret)
		croak("%s", croakstr);

	krb5_free_keyblock_contents(ctx, &key);

	if (!result)
		croak("malloc failed");

	return result;
}

char *
curve25519_pass2(krb5_context ctx, char *mysecretstr, char *theirpublicstr)
{
	uint8_t	 shared_key[32];
	uint8_t	 mysecret[32];
	uint8_t	 theirpublic[32];
	char	*ret;
	int	 i;

	if (!mysecretstr || !theirpublicstr)
		croak("mysecret and theirpublic must not be undef");

	if (strlen(mysecretstr) != 64 || strlen(theirpublicstr) != 64)
		croak("Strings must be 64 characters");

	decode_curve_string(mysecret, mysecretstr);
	decode_curve_string(theirpublic, theirpublicstr);

	curve25519_donna(shared_key, mysecret, theirpublic);

	ret = encode_curve_string(shared_key);

	if (!ret)
		croak("malloc(3) failed");

	return ret;
}

key
krb5_getkey(krb5_context ctx, kadm5_handle hndl, char *in)
{
	kadm5_principal_ent_rec	 dprinc;
	krb5_principal		 princ = NULL;
	krb5_keyblock		 kb;
	kadm5_config_params	 params;
	kadm5_ret_t		 ret;
	int			 i;
	int			 des_done = 0;
	char			 croakstr[2048] = "";
	key			 k;
	key			 ok = NULL;
	key			 first = NULL;

	memset((char *) &params, 0, sizeof(params));	
	memset(&dprinc, 0, sizeof(dprinc));

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_get_principal(hndl, princ, &dprinc, 
	    KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA));

	for (i=0; i < dprinc.n_key_data; i++) {
		krb5_key_data	*kd = &dprinc.key_data[i];

		k = calloc(sizeof(struct _key), 1);
		if (!first)
			first = k;
		if (ok)
			ok->next = k;
		ok = k;

		/*
		 * Here we elide both duplicated DES keys and
		 * keys with invalid encryption types.
		 */

		if (kd->key_data_type[0] == ENCTYPE_NULL)
		    continue;
		if (kd->key_data_type[0] == ENCTYPE_DES_CBC_CRC ||
		    kd->key_data_type[0] == ENCTYPE_DES_CBC_MD5 ||
		    kd->key_data_type[0] == ENCTYPE_DES_CBC_MD4) {
		    if (des_done)
			continue;
		    des_done = 1;
		}

		k->princ = in;
		k->timestamp = dprinc.last_pwd_change;
		k->kvno = kd->key_data_kvno;
#ifdef HAVE_MIT
		ret = kadm5_decrypt_key(hndl, &dprinc, kd->key_data_type[0],
		    -1 /*salt*/, kd->key_data_kvno, &kb, NULL, NULL);

		/* XXXrcd: assert that we have enough space */
		k->enctype = kb.enctype;
		k->length = kb.length;
		memcpy(k->data, kb.contents, kb.length);
		krb5_free_keyblock_contents(ctx, &kb);
#else
		k->enctype = kd->key_data_type[0];
		k->length = kd->key_data_length[0];
		memcpy(k->data, kd->key_data_contents[0], k->length);
#endif
	}

done:
	/* XXXrcd: free up used data structures! */

	if (princ)
		krb5_free_principal(ctx, princ);

	if (ret) {
#if 0 /* XXXrcd: clean up */
		key_free(ok);
#endif
		croak("%s", croakstr);
	}

	return first;
}

void
krb5_createkey(krb5_context ctx, kadm5_handle hndl, char *in)
{
	kadm5_principal_ent_rec	 dprinc;
	krb5_key_salt_tuple	 enctypes[8];
	kadm5_config_params	 params;
	krb5_principal		 princ = NULL;
	kadm5_ret_t		 ret;
	size_t			 i;
	char			 croakstr[2048] = "";
	char			 dummybuf[256];

	memset((char *) &params, 0, sizeof(params));	
	memset(dummybuf, 0x0, sizeof(dummybuf));
	memset(&dprinc, 0, sizeof(dprinc));

	K5BAIL(krb5_parse_name(ctx, in, &princ));

	for (i=0; i < sizeof(dummybuf); i++)
		dummybuf[i] = 32 + (i % 80);

	dummybuf[i] = '\0';

	dprinc.principal = princ;
	dprinc.attributes = KRB5_KDB_DISALLOW_ALL_TIX;
	K5BAIL(kadm5_create_principal(hndl, &dprinc, KADM5_PRINCIPAL|
	     KADM5_ATTRIBUTES, dummybuf));

#if HAVE_MIT
	/*
	 * XXXrcd: for now, hardcode AES, DES3 and RC4, we'll take this
	 *         out later, when we can update the configuration.
	 *
	 *         We should set supported_enctypes to avoid having to
	 *         do this.
	 */
	enctypes[0].ks_enctype  = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	enctypes[0].ks_salttype = 0;
	enctypes[1].ks_enctype  = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
	enctypes[1].ks_salttype = 0;
	enctypes[2].ks_enctype  = ENCTYPE_ARCFOUR_HMAC;
	enctypes[2].ks_salttype = 0;
	enctypes[3].ks_enctype  = ENCTYPE_DES3_CBC_SHA1;
	enctypes[3].ks_salttype = 0;

	K5BAIL(kadm5_randkey_principal_3(hndl, dprinc.principal, 0,
	    4, enctypes, NULL, NULL));

	/* MIT's kadm5_create_princ() does NOT set a default policy */
	dprinc.policy = "default";
	K5BAIL(kadm5_modify_principal(hndl, &dprinc, KADM5_POLICY));
#else
	K5BAIL(kadm5_randkey_principal_3(hndl, dprinc.principal, 0,
	    0, 0, NULL, NULL));
#endif

	dprinc.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
	K5BAIL(kadm5_modify_principal(hndl, &dprinc, KADM5_ATTRIBUTES));

done:
	/* XXXrcd: free up used data structures! */

	if (princ)
		krb5_free_principal(ctx, princ);

	if (ret)
		croak("%s", croakstr);
	return;
}

static int
max_kvno(kadm5_principal_ent_rec dprinc)
{
	int	 i;
	int	 max_kvno = 0;

	for (i=0; i < dprinc.n_key_data; i++) {
		krb5_key_data	*kd = &dprinc.key_data[i];

		if (max_kvno < kd->key_data_kvno)
			max_kvno = kd->key_data_kvno;
	}

	return max_kvno;
}

static int
is_next_kvno(krb5_context ctx, kadm5_handle hndl, krb5_principal princ,
	     int kvno, char *errstr, int errlen)
{
	kadm5_principal_ent_rec	dprinc;
	int			ret;
	char			croakstr[2048] = "";

	memset(&dprinc, 0, sizeof(dprinc));

	if (kvno < 2)
		return 1;

	K5BAIL(kadm5_get_principal(hndl, princ, &dprinc, 
	    KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA));

	if (max_kvno(dprinc) != (kvno - 1)) {
		snprintf(errstr, errlen, "not the next key");
		return 0;
	}

done:
	if (ret) {
		strncpy(errstr, croakstr, errlen);
		errstr[errlen - 1] = '\0';
		return 0;
	}

	return 1;
}

void
krb5_setkey(krb5_context ctx, kadm5_handle hndl, char *in, int kvno,
	    krb5_keyblock *keys)
{
	kadm5_config_params	 params;
	krb5_principal		 princ = NULL;
	kadm5_ret_t		 ret;
	int			 n_keys;
	int			 locked = 0;
	char			 croakstr[2048] = "";

	memset((char *) &params, 0, sizeof(params));	

	/*
	 * We expect that our typemap will give us an array of keys that
	 * is terminated with an extra invalid entry.
	 */

#ifdef HAVE_HEIMDAL
	for (n_keys = 0; KEYBLOCK_CONTENTS(keys[n_keys]) != NULL; n_keys++)
		;
#else
#ifdef HAVE_MIT
	for (n_keys = 0; keys[n_keys].magic == KV5M_KEYBLOCK; n_keys++)
		;
#endif /* HAVE_MIT */
#endif /* HAVE_HEIMDAL */

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_lock(hndl));
	locked = 1;

	if (!is_next_kvno(ctx, hndl, princ, kvno, croakstr, sizeof(croakstr))) {
		ret = 1;
		goto done;
	}

	K5BAIL(kadm5_setkey_principal_3(hndl, princ, TRUE, 0, NULL,
	    keys, n_keys));

done:
	/* XXXrcd: free up used data structures! */

	if (princ)
		krb5_free_principal(ctx, princ);
	if (locked) {
		/*
		 * Strangely, writes are tossed if you do not unlock before
		 * destroying the DB.  Also, don't flush while you have a
		 * lock.  That tosses writes...
		 */
		kadm5_unlock(hndl);
	}

	if (ret)
		croak("%s", croakstr);
	return;
}

char *
krb5_randpass(krb5_context ctx, kadm5_handle hndl, char *in, int n_ks_tuple,
	      krb5_key_salt_tuple *ks_tuple)
{
	krb5_principal		 princ = NULL;
	kadm5_ret_t		 ret;
	char			 croakstr[2048] = "";
	char			*passwd = NULL;

	passwd = random_passwd(ctx, PROID_PASSWD_SIZE);
	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_chpass_principal_3(hndl, princ, FALSE, n_ks_tuple,
	    ks_tuple, passwd));

done:
	if (princ)
		krb5_free_principal(ctx, princ);

	if (ret) {
		free(passwd);
		croak("%s", croakstr);
	}
	return passwd;
}

void
krb5_setpass(krb5_context ctx, kadm5_handle hndl, char *in, int kvno,
	     int n_ks_tuple, krb5_key_salt_tuple *ks_tuple, char *passwd)
{
	krb5_principal		princ = NULL;
	kadm5_ret_t		ret;
	int			locked = 0;
	char			croakstr[2048] = "";

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_lock(hndl));
	locked = 1;

	if (!is_next_kvno(ctx, hndl, princ, kvno, croakstr, sizeof(croakstr))) {
		ret = 1;
		goto done;
	}

	K5BAIL(kadm5_chpass_principal_3(hndl, princ, FALSE, n_ks_tuple,
	    ks_tuple, passwd));

done:
	if (princ)
		krb5_free_principal(ctx, princ);
	if (locked) {
		/*
		 * Strangely, writes are tossed if you do not unlock before
		 * destroying the DB.  Also, don't flush while you have a
		 * lock.  That tosses writes...
		 */
		kadm5_unlock(hndl);
	}

	if (ret)
		croak("%s", croakstr);
	return;
}

void
krb5_randkey(krb5_context ctx, kadm5_handle hndl, char *in)
{
	krb5_principal		princ = NULL;
	krb5_key_salt_tuple	enctypes[1];
	kadm5_ret_t		ret;
	char			croakstr[2048] = "";

	K5BAIL(krb5_parse_name(ctx, in, &princ));

	/*
	 * Random keys are hardcoded to AES for now: we're only actually
	 * using them for proids...
	 */
#if HAVE_MIT
	enctypes[0].ks_enctype  = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	enctypes[0].ks_salttype = 0;

	K5BAIL(kadm5_randkey_principal_3(hndl, princ, FALSE, 1, enctypes,
	    NULL, NULL));
#else
	K5BAIL(kadm5_randkey_principal_3(hndl, princ, FALSE, 0, NULL,
	    NULL, NULL));
#endif

done:
	if (princ)
		krb5_free_principal(ctx, princ);

	if (ret)
		croak("%s", croakstr);
	return;
}

krb5_keyblock
get_kte(krb5_context ctx, char *kt, char *in)
{
	krb5_principal		princ = NULL;
	krb5_keytab		keytab = NULL;
	krb5_keytab_entry	e;
	krb5_error_code		ret;
	char			croakstr[2048] = "";

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	if (kt)
		K5BAIL(krb5_kt_resolve(ctx, kt, &keytab));
	else
		K5BAIL(krb5_kt_default(ctx, &keytab));

	K5BAIL(krb5_kt_get_entry(ctx, keytab, princ, 0, 0, &e));

done:
	/* XXXrcd: free up keytab and stuff */
	if (ret)
		croak("%s", croakstr);
	return KEYTABENT_KEYBLOCK(e);
}

void
kt_remove_entry(krb5_context ctx, char *kt, krb5_keytab_entry *e)
{
	krb5_keytab		keytab = NULL;
	krb5_error_code		ret;
	char			croakstr[2048] = "";

	if (kt)
		K5BAIL(krb5_kt_resolve(ctx, kt, &keytab));
	else
		K5BAIL(krb5_kt_default(ctx, &keytab));

	K5BAIL(krb5_kt_remove_entry(ctx, keytab, e));

done:
	if (keytab)
		krb5_kt_close(ctx, keytab);

	if (ret) {
		croak("%s", croakstr);
	}
}

key
read_kt(krb5_context ctx, char *ktname)
{
	krb5_keytab		 kt = NULL;
	krb5_keytab_entry	 e;
	krb5_kt_cursor		 c;
	key			 k;
	key			 first = NULL;
	key			 ok = NULL;
	krb5_error_code		 ret;
	char			 croakstr[2048] = "";

	if (ktname)
		K5BAIL(krb5_kt_resolve(ctx, ktname, &kt));
	else
		K5BAIL(krb5_kt_default(ctx, &kt));

	K5BAIL(krb5_kt_start_seq_get(ctx, kt, &c));

	while (!(ret = krb5_kt_next_entry(ctx, kt, &e, &c))) {
		k = calloc(sizeof(*k), 1);
		if (!first)
			first = k;
		if (ok)
			ok->next = k;
		ok = k;

		K5BAIL(krb5_unparse_name(ctx, e.principal, &k->princ));
		k->kvno = e.vno;
		k->timestamp = e.timestamp;

		/* XXXrcd: assert that we have room */
		k->enctype = KEYTABENT_ENCTYPE(e);
		k->length = KEYTABENT_CONTENT_LEN(e);
		memcpy(k->data, KEYTABENT_CONTENTS(e), k->length);
	}

	if (ret != KRB5_KT_END) {
		/* XXXrcd: do some sort of error here... */
	}

	/* XXXrcd: should this be below the done: ?? */
	K5BAIL(krb5_kt_end_seq_get(ctx, kt, &c));

done:

	/* XXXrcd: clean up memory and stuff! */

	if (kt)
		krb5_kt_close(ctx, kt);

	if (ret)
		croak("%s", croakstr);

	return first;
}

void
write_kt(krb5_context ctx, char *kt, krb5_keytab_entry *e)
{
	krb5_keytab		keytab = NULL;
	krb5_keytab_entry	old;
	krb5_error_code		ret;
	char			croakstr[2048] = "";

	if (kt)
		K5BAIL(krb5_kt_resolve(ctx, kt, &keytab));
	else
		K5BAIL(krb5_kt_default(ctx, &keytab));

	/*
	 * Because the MIT Kerberos libraries seem to just add duplicate
	 * keys, we must purge incorrect and keys while not removing the
	 * correct keys.  We do this so that we can ensure that the keytab
	 * is always in a consistent state.
	 */

	for (;;) {
		ret = krb5_kt_get_entry(ctx, keytab, e->principal, e->vno,
		    KEYTABENT_ENCTYPE(*e), &old);

		if (ret)
			break;

		if (!memcmp(KEYTABENT_CONTENTS(old), KEYTABENT_CONTENTS(*e),
		    KEYTABENT_CONTENT_LEN(old))) {
			/* we found a matching key, so nothing to do... */
			ret = 0;
			goto done;
		}

		K5BAIL(krb5_kt_remove_entry(ctx, keytab, &old));
	}

	K5BAIL(krb5_kt_add_entry(ctx, keytab, e));

done:
	if (keytab)
		krb5_kt_close(ctx, keytab);

	if (ret) {
		croak("%s", croakstr);
	}
}

char *
krb5_get_realm(krb5_context ctx)
{
	krb5_error_code	 ret;
	char		*realm;
	char		 croakstr[2048] = "";

	K5BAIL(krb5_get_default_realm(ctx, &realm));

done:
	if (ret)
		croak("%s", croakstr);

	return realm;
}

krb5_enctype *
get_as_enctypes(krb5_context ctx)
{
	krb5_error_code	 ret;
	krb5_enctype	*enctypes = NULL;
	char		 croakstr[2048] = "";

#ifdef HAVE_HEIMDAL
	K5BAIL(krb5_get_default_in_tkt_etypes(ctx, KRB5_PDU_AS_REQUEST, &enctypes));
#else
	K5BAIL(krb5_get_default_in_tkt_ktypes(ctx, &enctypes));
#endif

done:
	return enctypes;
}

char **
krb5_get_kdcs(krb5_context ctx, char *realm)
{
	krb5_error_code	  ret;
	char		 *def_realm = NULL;
	char		**hostlist = NULL;
	char		  croakstr[2048] = "";

#ifdef HAVE_HEIMDAL
	char		**hlist;
	char		 *tmp;
#endif

#ifdef HAVE_MIT
	krb5_data	  realm_data;
#endif /* HAVE_MIT */

	if (!realm || !realm[0]) {
		K5BAIL(krb5_get_default_realm(ctx, &def_realm));
		realm = def_realm;
	}

#ifdef HAVE_HEIMDAL
	K5BAIL(krb5_get_krbhst(ctx, &realm, &hostlist));

	/* XXXrcd: Heidmal includes protocol and port in the output
	 *         and so we need to strip that out.
	 */

	for (hlist=hostlist; *hlist; hlist++) {
		tmp = strrchr(*hlist, ':');
		if (tmp)
			*tmp = '\0';
		tmp = strrchr(*hlist, '/');
		if (tmp) {
			tmp = strdup(tmp+1);
			free(*hlist);
			*hlist = tmp;
		}
	}
#else
#ifdef HAVE_MIT
	realm_data.data = realm;
	realm_data.length = strlen(realm);
	K5BAIL(krb5_get_krbhst(ctx, &realm_data, &hostlist));
#endif /* HAVE_MIT */
#endif /* HAVE_HEIMDAL */

done:
	if (def_realm)
		krb5_free_default_realm(ctx, def_realm);

	if (ret) {
		/* XXX free host list? */
		return NULL;
	}
	return hostlist;
}

void
kinit_anonymous(krb5_context ctx, char *realm, char *ccname)
{
	krb5_error_code		 ret;
	krb5_get_init_creds_opt	*opt = NULL;
	krb5_init_creds_context	 ictx = NULL;
	krb5_ccache		 ccache = NULL;
	krb5_principal		 princ = NULL;
	int			 cred_allocated = 0;
	char			 croakstr[2048] = "";
#ifdef HAVE_MIT
	krb5_creds		 creds;

	memset(&creds, 0, sizeof(creds));
#endif

	if (ccname)
		K5BAIL(krb5_cc_resolve(ctx, ccname, &ccache));
	else
		K5BAIL(krb5_cc_default(ctx, &ccache));

	K5BAIL(krb5_get_init_creds_opt_alloc(ctx, &opt));

	krb5_get_init_creds_opt_set_anonymous(opt, 1);
#ifdef HAVE_HEIMDAL
	K5BAIL(krb5_make_principal(ctx, &princ, realm,
	    KRB5_WELLKNOWN_NAME, KRB5_ANON_NAME, NULL));
	krb5_principal_set_type(ctx, princ, KRB5_NT_WELLKNOWN);
	K5BAIL(krb5_get_init_creds_opt_set_pkinit(ctx, opt, princ,
	    NULL, NULL, NULL, NULL, 4, NULL, NULL, NULL));
#else
	K5BAIL(krb5_copy_principal(ctx, krb5_anonymous_principal(), &princ));
	krb5_get_init_creds_opt_set_anonymous(opt, 1);
#endif

	krb5_get_init_creds_opt_set_tkt_life(opt, 15 * 60);

	K5BAIL(krb5_init_creds_init(ctx, princ, NULL, NULL, 0, opt, &ictx));
	K5BAIL(krb5_init_creds_get(ctx, ictx));
#ifdef HAVE_HEIMDAL
	K5BAIL(krb5_init_creds_store(ctx, ictx, ccache));
#else
	K5BAIL(krb5_init_creds_get_creds(ctx, ictx, &creds));
	K5BAIL(krb5_cc_initialize(ctx, ccache, princ));
	K5BAIL(krb5_cc_store_cred(ctx, ccache, &creds));
#endif

done:
	if (ictx)
		krb5_init_creds_free(ctx, ictx);

	if (opt)
		krb5_get_init_creds_opt_free(ctx, opt);

	if (ccache)
		krb5_cc_close(ctx, ccache);

#ifdef HAVE_MIT
	krb5_free_cred_contents(ctx, &creds);
#endif

	if (princ)
		krb5_free_principal(ctx, princ);

	if (ret)
		croak("%s", croakstr);
}

struct kts {
	int		 kvno;
	krb5_keytab	 kt;
	struct kts	*next;
};

void
kinit_kt(krb5_context ctx, char *princstr, char *ktname, char *ccname)
{
	krb5_error_code		 ret;
	krb5_get_init_creds_opt	*opt = NULL;
	krb5_init_creds_context	 ictx = NULL;
	krb5_keytab_entry	 e;
	int			 e_in_use = 0;
	krb5_kt_cursor		 c;
	int			 c_in_use = 0;
	krb5_keytab		 kt = NULL;
	krb5_keytab		 tmpkt = NULL;
	krb5_ccache		 ccache = NULL;
	krb5_principal		 princ = NULL;
	struct kts		*kts = NULL;
	struct kts		*next_one = NULL;
	int			 kvno = -1;
	int			 max_kvno = -1;
	int			 min_kvno = -1;
	char			 croakstr[2048] = "";
	char			*rndktpart = NULL;
	char			 tmp[256];
#ifdef HAVE_MIT
	krb5_creds		 creds;

	memset(&creds, 0, sizeof(creds));
#endif

	/*
	 * rndktpart isn't a passwd but rather a random string we use in
	 * naming the memory keytabs to avoid collisions.  This is why we
	 * make it so long.
	 */

	rndktpart = random_passwd(ctx, 25);

	if (ktname)
		K5BAIL(krb5_kt_resolve(ctx, ktname, &kt));
        else
		K5BAIL(krb5_kt_default(ctx, &kt));

	if (ccname)
		K5BAIL(krb5_cc_resolve(ctx, ccname, &ccache));
	else
		K5BAIL(krb5_cc_default(ctx, &ccache));

	K5BAIL(krb5_parse_name(ctx, princstr, &princ));

	/*
	 * Unlike the builtin functions, we try to make quite sure that
	 * we get a TGT even if there are invalid keys in the keytab.
	 * To do this, we will try all of the keys that match the principal
	 * in reverse kvno order.  We build a set of MEMORY: keytabs from
	 * our original keytab and then try each of them to obtain creds.
	 * Heimdal's semantics are that MEMORY: keytabs are cleaned up when
	 * the last reference is closed.  We thus maintain a stack of open
	 * keytabs so that we can close them later.  At the moment, MIT
	 * emulates Heimdal's behaviour.
	 *
	 * XXXrcd: should we also deal with FILE: keytabs so that this code
	 *         will work on older MIT krb5 versions?  Maybe...
	 */

	K5BAIL(krb5_kt_start_seq_get(ctx, kt, &c));
	c_in_use = 1;

	while (!(ret = krb5_kt_next_entry(ctx, kt, &e, &c))) {
		struct kts	*this;

		if (!krb5_principal_compare(ctx, e.principal, princ)) {
			krb5_kt_free_entry(ctx, &e);
			continue;
		}

		e_in_use = 1;

		/*
		 * this_one should either be the current kt or the last one
		 * after this loop.
		 *
		 * XXXrcd: this inner loop makes our algorithm O(n^2) which
		 *         should likely be fixed at some point...  This
		 *         shouldn't prove to be an issue in most situations
		 *         as keytabs should not be allowed to grow arbitrarily
		 *         large.  That said, they probably do in the wild...
		 *         Dealing with this will involve choosing a data
		 *         structure which is a better fit for the algorithm.
		 */

		for (this = kts; this && this->next; this = this->next)
			if (this->kvno == e.vno)
				break;

		if (min_kvno == -1 || e.vno < min_kvno)
			min_kvno = e.vno;

		if (max_kvno == -1 || e.vno > max_kvno)
			max_kvno = e.vno;

		if (!this || this->kvno != e.vno) {
			next_one = malloc(sizeof(*next_one));
			if (!next_one) {
				snprintf(croakstr, sizeof(croakstr),
				    "malloc failed!");
				ret = 1;
				goto done;
			}
			snprintf(tmp, sizeof(tmp), "MEMORY:%x.%s", e.vno,
			    rndktpart);
			K5BAIL(krb5_kt_resolve(ctx, tmp, &next_one->kt));
			next_one->kvno = e.vno;
			if (this)
				this->next = next_one;
			this = next_one;
			next_one = NULL;
		}

		K5BAIL(krb5_kt_add_entry(ctx, this->kt, &e));
		krb5_kt_free_entry(ctx, &e);
		e_in_use = 0;
	}

	if (ret != KRB5_KT_END) {
		/* XXXrcd: do some sort of error here... or not?? */
	}

	if (max_kvno == -1 || min_kvno == -1) {
		snprintf(croakstr, sizeof(croakstr), "Failed to find key "
		    "for %s in keytab.", princstr);
		ret = 1;
		goto done;
	}

	K5BAIL(krb5_get_init_creds_opt_alloc(ctx, &opt));
	krb5_get_init_creds_opt_set_tkt_life(opt, 15 * 60);

	for (kvno = max_kvno; kvno >= min_kvno; kvno--) {
		snprintf(tmp, sizeof(tmp), "MEMORY:%x.%s", kvno, rndktpart);
		K5BAIL(krb5_kt_resolve(ctx, tmp, &tmpkt));
		K5BAIL(krb5_init_creds_init(ctx, princ, NULL, NULL, 0, opt,
		    &ictx));
		K5BAIL(krb5_init_creds_set_keytab(ctx, ictx, tmpkt));
		ret = krb5_init_creds_get(ctx, ictx);
		krb5_kt_close(ctx, tmpkt);
		tmpkt = NULL;
		if (!ret)
			break;

		/* We store the error message the first time as it's useful */

		if (!croakstr[0]) {
			const char	*tmp;

			tmp = krb5_get_error_message(ctx, ret);
			if (tmp) {
				snprintf(croakstr, sizeof(croakstr),
				    "%s: %s", "kinit_kt", tmp);
				krb5_free_error_message(ctx, tmp);
			} else {
				snprintf(croakstr, sizeof(croakstr),
				    "%s: unknown error", "kinit_kt");
			}
		}

		krb5_init_creds_free(ctx, ictx);
		ictx = NULL;
	}

	if (ret) {
		if (!croakstr[0])
			snprintf(croakstr, sizeof(croakstr),
			    "Failed to kinit from keytab");
		goto done;
	}

#ifdef HAVE_HEIMDAL
	K5BAIL(krb5_init_creds_store(ctx, ictx, ccache));
#else
	K5BAIL(krb5_init_creds_get_creds(ctx, ictx, &creds));
	K5BAIL(krb5_cc_initialize(ctx, ccache, princ));
	K5BAIL(krb5_cc_store_cred(ctx, ccache, &creds));
#endif

done:
	free(rndktpart);
	free(next_one);

	if (ictx)
		krb5_init_creds_free(ctx, ictx);

	if (opt)
		krb5_get_init_creds_opt_free(ctx, opt);

	if (c_in_use)
		krb5_kt_end_seq_get(ctx, kt, &c);

	if (e_in_use)
		krb5_kt_free_entry(ctx, &e);

	for (; kts;) {
		struct kts	*tmp_kts;

		tmp_kts = kts;
		kts = kts->next;
		krb5_kt_close(ctx, tmp_kts->kt);
		free(tmp_kts);
	}

	if (tmpkt)
		krb5_kt_close(ctx, tmpkt);

	if (kt)
		krb5_kt_close(ctx, kt);

	if (ccache)
		krb5_cc_close(ctx, ccache);

	if (princ)
		krb5_free_principal(ctx, princ);

#ifdef HAVE_MIT
	krb5_free_cred_contents(ctx, &creds);
#endif

	if (ret)
		croak("%s", croakstr);
}

#ifndef HAVE_HEIMDAL	/* XXXrcd: this needs to be implemented */
char **
krb5_list_pols(krb5_context ctx, kadm5_handle hndl, char *exp)
{
        kadm5_ret_t       ret;
	char		**out = NULL;
        char            **pols = NULL;
	char		  croakstr[2048] = "";
        int               count;
	int		  i;

	K5BAIL(kadm5_get_policies(hndl, exp, &pols, &count));

	/* We must null terminate the string because of our typemap. */
	out = malloc((count + 1) * sizeof(*out));
	if (!out) {
		snprintf(croakstr, sizeof(croakstr), "krb5_list_pols"
		    "(): malloc failed");
		ret = 1;
		goto done;
	}
	for (i=0; i < count; i++)
		out[i] = pols[i];
	out[i] = NULL;

done:
        /* XXXrcd: leaks like a sieve. */
	if (ret)
		croak("%s", croakstr);
        return out;
}
#else
char **
krb5_list_pols(krb5_context ctx, kadm5_handle hndl, char *exp)
{

	croak("Policies are not implemented in Heimdal");
}
#endif

char **
krb5_list_princs(krb5_context ctx, kadm5_handle hndl, char *exp)
{
        kadm5_ret_t       ret;
	char		**out = NULL;
        char            **princs = NULL;
	char		  croakstr[2048] = "";
        int               count;
	int		  i;

        K5BAIL(kadm5_get_principals(hndl, exp, &princs, &count));

	/* We must null terminate the string because of our typemap. */
	out = malloc((count + 1) * sizeof(*out));
	if (!out) {
		snprintf(croakstr, sizeof(croakstr), "krb5_list_princs"
		    "(): malloc failed");
		ret = 1;
		goto done;
	}
	for (i=0; i < count; i++)
		out[i] = princs[i];
	out[i] = NULL;

done:
        /* XXXrcd: leaks like a sieve. */
	if (ret)
		croak("%s", croakstr);
        return out;
}


krb5_keyblock
krb5_make_a_key(krb5_context ctx, krb5_enctype enctype)
{
	krb5_error_code	ret = 0;
	krb5_keyblock	key;
	char		croakstr[2048] = "";

	K5BAIL(krb5_c_make_random_key(ctx, enctype, &key));

done:
	if (ret)
		croak("%s", croakstr);
	return key;
}

void
init_store_creds(krb5_context ctx, char *ccname, krb5_creds *creds)
{
	krb5_ccache		ccache;
	krb5_error_code		ret;
	char			croakstr[2048] = "";

	if (ccname && ccname[0])
		K5BAIL(krb5_cc_resolve(ctx, ccname, &ccache));
	else
		K5BAIL(krb5_cc_default(ctx, &ccache));

	K5BAIL(krb5_cc_initialize(ctx, ccache, creds->client));
	K5BAIL(krb5_cc_store_cred(ctx, ccache, creds));

done:
	if (ret)
		croak("%s", croakstr);
}

void
print_enctypes(krb5_context ctx, krb5_enctype *etypes)
{
	krb5_error_code	 ret;
	krb5_enctype	*e;
#ifdef HAVE_HEIMDAL
	char		*str = NULL;
#else
	char		 buf[64];
#endif

	for (e=etypes; *e; e++) {
#ifdef HAVE_HEIMDAL
		ret = krb5_enctype_to_string(NULL, *e, &str);
		fprintf(stderr, "got etype: %d, %s\n", *e, str);
		free(str);
#else
		ret = krb5_enctype_to_name(*e, TRUE, buf, sizeof (buf));
		fprintf(stderr, "got etype: %d, %s\n", *e, buf);
#endif
	}
}

#ifdef HAVE_HEIMDAL

#undef warn		/* Conflict between Perl and <err.h> via <hdb.h> */
#undef vwarn		/* Conflict between Perl and <err.h> via <hdb.h> */
#ifdef HEIMDAL_INCLUDES_IN_KRB5
#include <krb5/hdb.h>
#include <krb5/hdb_err.h>
#include <krb5/der.h>
#else
#include <hdb.h>
#include <hdb_err.h>
#include <der.h>
#endif
#define warn Perl_warn	/* Conflict between Perl and <err.h> via <hdb.h> */
#define vwarn Perl_vwarn/* Conflict between Perl and <err.h> via <hdb.h> */

#undef ALLOC
#define ALLOC(X) do {					\
		((X) = calloc(1, sizeof(*(X))));	\
		if (!(X)) {				\
			ret = ENOMEM;			\
			goto done;			\
		}					\
	} while (0)

krb5_creds *
mint_ticket(krb5_context ctx, kadm5_handle hndl, char *princ, int lifetime,
	    int renew_till, krb5_enctype *enctypes)
{
	Ticket			 t;
	EncTicketPart		 et;
	unsigned char		*buf;
	size_t			 buf_size;
	size_t			 len = 0;
	krb5_principal		 client;
	krb5_principal		 krbtgt;
	krb5_timestamp		 now;
	krb5_error_code		 ret;
	krb5_crypto		 crypto;
	EncryptionKey		 skey;
	int			 skvno;
	krb5_creds		*creds;
	EncryptionKey		 tmpkey;
	kadm5_principal_ent_rec	 dprinc;
	int			 i;
	krb5_const_realm	 client_realm;
	char			 croakstr[2048] = "";

	K5BAIL(krb5_parse_name(ctx, princ, &client));

	client_realm = krb5_principal_get_realm(ctx, client);
	K5BAIL(krb5_make_principal(ctx, &krbtgt, client_realm, KRB5_TGS_NAME,
	    client_realm, NULL));

	K5BAIL(kadm5_get_principal(hndl, krbtgt, &dprinc, 
	    KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA));

	for (i=0; i < dprinc.n_key_data; i++) {
		krb5_key_data	*kd = &dprinc.key_data[i];

		/* XXXrcd: this only works on Heimdal: */

		/* XXXrcd: we should definitely search for the best
		 *         key, i.e. highest kvno and correct etype.
		 */

		skvno = kd->key_data_kvno;
		skey.keytype = kd->key_data_type[0];
		skey.keyvalue.length = kd->key_data_length[0];
		skey.keyvalue.data = malloc(skey.keyvalue.length);
		memcpy(skey.keyvalue.data, kd->key_data_contents[0],
		   skey.keyvalue.length);

		break;
	}

	memset((void *)&et, 0x0, sizeof(et));

	krb5_timeofday(ctx, &now);	/* XXXrcd: can't fail? */

	et.flags.initial = 1;
	K5BAIL(krb5_generate_random_keyblock(ctx, 17, &et.key));
	copy_PrincipalName(&client->name, &et.cname);
	copy_Realm(&client->realm, &et.crealm);
	et.endtime = now + lifetime;
	if (renew_till > 0) {
		ALLOC(et.renew_till);
		*et.renew_till = now + renew_till;
		et.flags.renewable = 1;
	}

	K5BAIL(copy_EncryptionKey(&et.key, &tmpkey));

	ASN1_MALLOC_ENCODE(EncTicketPart, buf, buf_size, &et, &len, ret);

	K5BAIL(krb5_crypto_init(ctx, &skey, skey.keytype, &crypto));
	K5BAIL(krb5_encrypt_EncryptedData(ctx, crypto, KRB5_KU_TICKET, buf,
	    len, skvno, &t.enc_part));

	free(buf);
	krb5_crypto_destroy(ctx, crypto);

	/* Fill in the rest of the ticket */

	t.tkt_vno = 5;
	copy_PrincipalName(&krbtgt->name, &t.sname);
	copy_Realm(&krbtgt->realm, &t.realm);

	ASN1_MALLOC_ENCODE(Ticket, buf, buf_size, &t, &len, ret);

	/* Okay, now we have a ticket... */

	creds = malloc(sizeof(*creds));
	memset(creds, 0x0, sizeof(*creds));

	K5BAIL(krb5_copy_principal(ctx, client, &creds->client));
	K5BAIL(krb5_copy_principal(ctx, krbtgt, &creds->server));

	creds->flags.b.initial = 1;

	creds->times.authtime = now;
	creds->times.starttime = now;
	creds->times.endtime = now + lifetime;
	if (renew_till) {
		creds->flags.b.renewable = 1;
		creds->times.renew_till = now + renew_till;
	}

	creds->ticket.length = len;
	creds->ticket.data = buf;

	ret = copy_EncryptionKey(&tmpkey, &creds->session);

done:
	if (ret)
		croak("%s", croakstr);

	return creds;
}

#else /* HAVE_HEIMDAL */

krb5_creds *
mint_ticket(krb5_context ctx, kadm5_handle hndl, char *princ, int lifetime,
	    int renew_till, krb5_enctype *enctypes)
{
	krb5_error_code		 ret;
	kadm5_principal_ent_rec	 dprinc;
	krb5_principal		 client = NULL;
	krb5_creds		*creds = NULL;
	krb5_keytab		 kt = NULL;
	krb5_keytab_entry	 kte;
	krb5_get_init_creds_opt	*gic_opt = NULL;
	size_t			 i;
	char			*rndktpart = NULL;
	char			 tmp[256];
	char			 croakstr[2048] = "";

	memset(&dprinc, 0, sizeof (dprinc));
	memset(&kte, 0, sizeof (kte));
	kte.magic = KV5M_KEYTAB_ENTRY;
	kte.timestamp = 1; /* any time will do */

	K5BAIL(krb5_parse_name(ctx, princ, &client));
	kte.principal = client;

	/* This keytab will get the decrypted keys from the KDB entry */
	rndktpart = random_passwd(ctx, 25);
	if (!rndktpart)
		BAIL(ENOMEM, "generating MEMORY keytab name");
	snprintf(tmp, sizeof(tmp), "MEMORY:%s", rndktpart);
	K5BAIL(krb5_kt_resolve(ctx, tmp, &kt));

	K5BAIL(kadm5_get_principal(hndl, client, &dprinc, 
	    KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA));

	/* Add all the keys from the KDB into the MEMORY keytab */
	for (i = 0; dprinc.n_key_data > 0 && i < dprinc.n_key_data; i++) {
		krb5_key_data	*kd = &dprinc.key_data[i];

		kte.vno = kd->key_data_kvno;

		/*
		 * We might be missing an old master key, so don't
		 * K5BAIL() here.
		 */
		ret = kadm5_decrypt_key(hndl, &dprinc, kd->key_data_type[0],
		    -1 /*salt*/, kd->key_data_kvno, &kte.key, NULL, NULL);
		if (ret)
			continue;

		K5BAIL(krb5_kt_add_entry(ctx, kt, &kte));

		krb5_free_keyblock_contents(ctx, &kte.key);
		memset(&kte.key, 0, sizeof (kte.key));
	}

	/* Now use krb5_get_init_creds_keytab() */
	K5BAIL(krb5_get_init_creds_opt_alloc(ctx, &gic_opt));
	krb5_get_init_creds_opt_set_forwardable(gic_opt, 0);
	krb5_get_init_creds_opt_set_proxiable(gic_opt, 0);

	creds = calloc(1, sizeof (*creds));
	if (!creds)
		BAIL(ENOMEM, "allocating krb5_creds");
	K5BAIL(krb5_get_init_creds_keytab(ctx, creds, client, kt, 0,
	    NULL/*krbtgt*/, gic_opt));

done:
	kte.principal = NULL;
	krb5_free_keytab_entry_contents(ctx, &kte);
	krb5_get_init_creds_opt_free(ctx, gic_opt);
	kadm5_free_principal_ent(hndl, &dprinc);
	if (kt)
		krb5_kt_close(ctx, kt);
	if (ret)
		croak("%s", croakstr);

	return creds;
}

#endif

#ifdef HAVE_HEIMDAL

#include <sys/un.h>

#include <kadm5/private.h>

krb5_error_code
init_kdb(krb5_context ctx, kadm5_handle hndl)
{
	krb5_error_code	 ret;
	HDB		*db;

	db = _kadm5_s_get_db(hndl);
	ret = db->hdb_open(ctx, db, O_RDWR | O_CREAT, 0600);
	if (ret)
		return ret;
	db->hdb_close(ctx, db);
	return 0;
}
#else
krb5_error_code
init_kdb(krb5_context ctx, kadm5_handle hndl)
{

	/*
	 * This is only used by tests, and we now have a KDB in git for
	 * this, so no need to do anything here.  We should do the same
	 * for Heimdal.
	 */
	return 0;
}
#endif

krb5_keyblock
string_to_key(krb5_context ctx, krb5_enctype enctype, const char *password,
	      krb5_principal princ)
{
	krb5_error_code		ret;
	char			croakstr[2048] = "";
	krb5_keyblock		k;

	memset(&k, 0, sizeof(k));

#ifdef HAVE_HEIMDAL
	K5BAIL(krb5_string_to_key(ctx, enctype, password, princ, &k));
#else
	krb5_data pwdata;
	pwdata.length = strlen(password);
	pwdata.data = (char *)password;
	K5BAIL(krb5_c_string_to_key(ctx, enctype, &pwdata, NULL/*no salt*/, &k));
#endif
done:
	return k; /* XXX leak */
}
