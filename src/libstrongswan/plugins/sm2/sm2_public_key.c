#include "sm2_public_key.h"
#include <gmssl/sm2.h>

typedef struct private_sm2_public_key_t private_sm2_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_sm2_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	sm2_public_key_t public;

	SM2_POINT pubkey;

	/**
	 * reference counter
	 */
	refcount_t ref;
};

bool store_pubkey(SM2_POINT *pubkey, chunk_t *data)
{
	*data = chunk_alloc(64);

	memcpy(data->ptr, pubkey->x, 32);
	memcpy(data->ptr + 32, pubkey->y, 32);

	return TRUE;
}

bool load_pubkey(SM2_POINT *pubkey, chunk_t data)
{
    memcpy(pubkey->x, data.ptr, 32);
    memcpy(pubkey->y, data.ptr + 32, 32);

    return TRUE;
}

static bool verify_signature(private_sm2_public_key_t *this,
							 chunk_t hash, chunk_t signature)
{
    SM2_SIGN_CTX *signCtx = malloc(sizeof(SM2_SIGN_CTX));
    sm2_verify_init(signCtx, &this->ctx, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
    sm2_verify_update(signCtx, data.ptr, data.len);
    int rc = sm2_verify_finish(signCtx, signature->ptr, signature->len);
    free(signCtx);

	return rc ? TRUE : FALSE;
}

METHOD(public_key_t, get_type, key_type_t,
	private_sm2_public_key_t *this)
{
	return KEY_SM2;
}

METHOD(public_key_t, verify, bool,
	private_sm2_public_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
		case SIGN_SM2_WITH_SM3:
			return verify_signature(this, data, signature);
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported in EC",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(public_key_t, encrypt, bool,
	private_sm2_public_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "EC public key encryption not implemented");
    return FALSE;
}

METHOD(public_key_t, get_keysize, int,
	private_sm2_public_key_t *this)
{
	return 64;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_sm2_public_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	lib->encoding->get_cache(lib->encoding, type, this, fp);
	return TRUE;
}

METHOD(public_key_t, get_encoding, bool,
	private_sm2_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	bool success = TRUE;

	store_pubkey(&this->pubkey, encoding);

	if (type != PUBKEY_SPKI_ASN1_DER)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, type,
						NULL, encoding, CRED_PART_ECDSA_PUB_ASN1_DER,
						asn1_encoding, CRED_PART_END);
		chunk_clear(&asn1_encoding);
	}
	return success;
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_sm2_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void,
	private_sm2_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_sm2_public_key_t *create_empty()
{
	private_sm2_public_key_t *this;

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt,
				.get_keysize = _get_keysize,
				.equals = public_key_equals,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = public_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
	);
	return this;
}

sm2_public_key_t *sm2_public_key_load(key_type_t type, va_list args)
{
	private_sm2_public_key_t *this;
	chunk_t blob = chunk_empty;

	if (type != KEY_SM2)
	{
		return NULL;
	}

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!blob.len)
	{
		return NULL;
	}

	this = create_empty();
	load_pubkey(&this->pubkey, blob);

	return &this->public;
}