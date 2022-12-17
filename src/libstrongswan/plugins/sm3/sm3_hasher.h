/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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
 */

/**
 * @defgroup sm3_hasher sm3_hasher
 * @{ @ingroup sm3_p
 */

#ifndef SM3_HASHER_H_
#define SM3_HASHER_H_

typedef struct sm3_hasher_t sm3_hasher_t;

#include <crypto/hashers/hasher.h>

/**
 * Implementation of hasher_t interface using the sm3 algorithm.
 */
struct sm3_hasher_t {

	/**
	 * Generic hasher_t interface for this hasher.
	 */
	hasher_t hasher_interface;
};

/**
 * Creates a new sm3_hasher_t.
 *
 * @param algo		hash algorithm, must be HASH_sm3
 * @return			sm3_hasher_t object, NULL if not supported
 */
sm3_hasher_t *sm3_hasher_create(hash_algorithm_t algo);

#endif /** SM3_HASHER_H_ @}*/
