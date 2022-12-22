#include "sm2_dh.h"

#include <gmssl/sm2.h>

typedef struct private_sm2_dh_t private_sm2_dh_t;

/**
 * Private data of an sm2_dh_t object.
 */
struct private_sm2_dh_t {

	/**
	 * Public sm2_dh_t interface.
	 */
	sm2_dh_t public;

    /**
	 * Diffie-Hellman group number.
	 */
	key_exchange_method_t group;

	SM2_KEY ctx;
    SM2_POINT otherPubkey;

	/**
	 * TRUE if shared secret is computed
	 */
	bool computed;

    /**
	 * Shared secret
	 */
	chunk_t shared_secret;
};

METHOD(key_exchange_t, set_public_key, bool,
	private_sm2_dh_t *this, chunk_t value)
{
	if (value.len == 64)
	{
		memcpy(this->otherPubkey.x, value.ptr, 32);
        memcpy(this->otherPubkey.y, value.ptr + 32, 32);
		return TRUE;
	}
	return FALSE;
}

METHOD(key_exchange_t, get_public_key, bool,
	private_sm2_dh_t *this, chunk_t *value)
{
	*value = chunk_alloc(SM2_POINT);
    memcpy(value.ptr, this->ctx.public_key.x, 32);
    memcpy(value.ptr + 32, this->ctx.public_key.y, 32);
	return TRUE;
}

METHOD(key_exchange_t, set_private_key, bool,
	private_sm2_dh_t *this, chunk_t value)
{
    memcpy(this->ctx.private_key, value.ptr, 32);
	return TRUE;
}

bool compute_shared_key(private_sm2_dh_t *this)
{
    SM2_POINT p;
    if (!sm2_ecdh(&this->ctx, &this->otherPubkey, &p)) {
		DBG1(DBG_LIB, "ECDH shared secret computation failed");
		return FALSE;
	}
    memcpy(this->shared_secret->ptr, p.x, 32);
    memcpy(this->shared_secret->ptr + 32, p.y, 32);
	this->computed = TRUE;
    return TRUE;
}

METHOD(key_exchange_t, get_shared_secret, bool,
	private_sm2_dh_t *this, chunk_t *secret)
{
	if (!this->computed && !compute_shared_key(this))
	{
		return FALSE;
	}
	*secret = chunk_clone(this->shared_secret);
	return TRUE;
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_sm2_dh_t *this)
{
	return CURVE_SM2;
}

METHOD(key_exchange_t, destroy, void,
	private_sm2_dh_t *this)
{
	chunk_clear(&this->shared_secret);
	free(this);
}

/*
 * Described in header.
 */
sm2_dh_t *sm2_dh_create(key_exchange_method_t group)
{
	private_sm2_dh_t *this;

	if (group != CURVE_SM2)
	{
		return FALSE;
	}

	INIT(this,
		.public = {
			.ke = {
				.get_shared_secret = _get_shared_secret,
				.set_public_key = _set_public_key,
				.get_public_key = _get_public_key,
				.set_private_key = _set_private_key,
				.get_method = _get_method,
				.destroy = _destroy,
			},
		},
		.group = group,
	);

	if (!sm2_key_generate(&this->ctx))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}
