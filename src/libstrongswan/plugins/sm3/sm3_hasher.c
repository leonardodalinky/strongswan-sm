/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * Copyright (C) 1991-1992, RSA Data Security, Inc. Created 1991.
 * All rights reserved.
 *
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm.
 * Ported to fulfill hasher_t interface.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * Modified by Leonardodalinky 2022
 * 
 * 本模块用于提供 SM3 哈希算法的实现
 */

#include <string.h>

#include "sm3_hasher.h"
#include <gmssl/sm3.h>


typedef struct private_sm3_hasher_t private_sm3_hasher_t;

/**
 * Private data structure with hashing context.
 */
struct private_sm3_hasher_t {
	/**
	 * Public interface for this hasher.
	 */
	sm3_hasher_t public;

	/*
	 * State of the hasher.
	 */
	SM3_CTX ctx;
};


#if BYTE_ORDER != LITTLE_ENDIAN
#error "Only support little endian for sm3"
#endif

METHOD(hasher_t, reset, bool,
	private_sm3_hasher_t *this)
{
	sm3_init(&this->ctx);

	return TRUE;
}

METHOD(hasher_t, get_hash, bool,
	private_sm3_hasher_t *this, chunk_t chunk, uint8_t *buffer)
{
	sm3_update(&this->ctx, chunk.ptr, chunk.len);
	if (buffer != NULL)
	{
		sm3_finish(&this->ctx, buffer);
		reset(this);
	}
	return TRUE;
}

METHOD(hasher_t, allocate_hash, bool,
	private_sm3_hasher_t *this, chunk_t chunk, chunk_t *hash)
{
	sm3_update(&this->ctx, chunk.ptr, chunk.len);
	if (hash != NULL)
	{
		*hash = chunk_alloc(HASH_SIZE_SM3);
		sm3_finish(&this->ctx, hash->ptr);
		reset(this);
	}
	return TRUE;
}

METHOD(hasher_t, get_hash_size, size_t,
	private_sm3_hasher_t *this)
{
	return HASH_SIZE_SM3;
}

METHOD(hasher_t, destroy, void,
	private_sm3_hasher_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
sm3_hasher_t *sm3_hasher_create(hash_algorithm_t algo)
{
	private_sm3_hasher_t *this;

	if (algo != HASH_SM3)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.hasher_interface = {
				.get_hash = _get_hash,
				.allocate_hash = _allocate_hash,
				.get_hash_size = _get_hash_size,
				.reset = _reset,
				.destroy = _destroy,
			},
		},
	);

	/* initialize */
	reset(this);

	return &(this->public);
}
