#include "sm2_private_key.h"
#include "sm2_public_key.h"

#include <gmssl/sm2.h>

typedef struct private_sm2_private_key_t private_sm2_private_key_t;

/**
 * Private data of a sm2_private_key_t object.
 */
struct private_sm2_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	sm2_private_key_t public;

	SM2_KEY ctx;

	/**
	 * reference count
	 */
	refcount_t ref;
};

static bool build_signature(private_sm2_private_key_t *this,
							chunk_t data, chunk_t *signature)
{
	*signature  = chunk_alloc(sizeof(SM2_SIGNATURE));
    SM2_SIGN_CTX *signCtx = malloc(sizeof(SM2_SIGN_CTX));
    sm2_sign_init(signCtx, &this->ctx, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
    sm2_sign_update(signCtx, data.ptr, data.len);
    sm2_sign_finish(signCtx, signature->ptr, &signature->len);
    free(signCtx);

	return TRUE;
}

METHOD(private_key_t, sign, bool,
	private_sm2_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{
	switch (scheme)
	{
		case SIGN_SM2_WITH_SM3:
			return build_signature(this, data, signature);
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(private_key_t, decrypt, bool,
	private_sm2_private_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "EC private key decryption not implemented");
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_sm2_private_key_t *this)
{
	return 32;
}

METHOD(private_key_t, get_type, key_type_t,
	private_sm2_private_key_t *this)
{
	return KEY_SM2;
}

bool store_prikey(SM2_KEY *key, chunk_t *data)
{
	*data = chunk_alloc(96);

	memcpy(data->ptr, key->public_key.x, 32);
	memcpy(data->ptr + 32, key->public_key.y, 32);
    memcpy(data->ptr + 64, key->private_key, 32);

	return TRUE;
}

bool load_prikey(SM2_KEY *key, chunk_t data)
{
    memcpy(key->public_key.x, data.ptr, 32);
    memcpy(key->public_key.y, data.ptr + 32, 32);
    memcpy(key->private_key, data.ptr + 64, 32);

    return TRUE;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_sm2_private_key_t *this)
{
	public_key_t *public;
	chunk_t key;

	store_pubkey(this->ctx.public_key, &key);

	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_SM2,
								BUILD_BLOB_ASN1_DER, key, BUILD_END);
	free(key.ptr);
	return public;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_sm2_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
    lib->encoding->get_cache(lib->encoding, type, this, fp);
	return TRUE;
}

METHOD(private_key_t, get_encoding, bool,
	private_sm2_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;

			store_prikey(&this->ctx, encoding);
			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
								NULL, encoding, CRED_PART_ECDSA_PRIV_ASN1_DER,
								asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}
			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_sm2_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_sm2_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_sm2_private_key_t *create_empty(void)
{
	private_sm2_private_key_t *this;

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.sign = _sign,
				.decrypt = _decrypt,
				.get_keysize = _get_keysize,
				.get_public_key = _get_public_key,
				.equals = private_key_equals,
				.belongs_to = private_key_belongs_to,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = private_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
	);
	return this;
}

sm2_private_key_t *sm2_private_key_gen(key_type_t type, va_list args)
{
	private_sm2_private_key_t *this;
	u_int key_size = 0;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				key_size = va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (!key_size)
	{
		return NULL;
	}
	this = create_empty();
	switch (type)
	{
		case KEY_SM2:{
			sm2_key_generate(&this->ctx);
		}break;
		default:{
			DBG1(DBG_LIB, "EC private type %d key size %d not supported", type, key_size);
			destroy(this);
			return NULL;
		}
	}
	this->type = type;
	return &this->public;
}

sm2_private_key_t *sm2_private_key_load(key_type_t type, va_list args)
{
	private_sm2_private_key_t *this;
	chunk_t par = chunk_empty, key = chunk_empty;
	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ALGID_PARAMS:
				par = va_arg(args, chunk_t);
				continue;
			case BUILD_BLOB_ASN1_DER:
				key = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	this = create_empty();

	if (par.ptr || key.ptr)
	{
		load_prikey(this->prikey, this->pubkey, key);
        this->type = type;
	    return &this->public;
	}
	destroy(this);
	return NULL;
}