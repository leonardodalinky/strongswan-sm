/*
 * Copyright (C) 2005-2008 Martin Willi
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
 * @defgroup sm4_crypter sm4_crypter
 * @{ @ingroup sm4_p
 */

/*
 * Created by luqichen on 2022/12/19.
 * Implementing SM4 algorithm.
 */

#ifndef SM4_CRYPTER_H_
#define SM4_CRYPTER_H_

typedef struct sm4_crypter_t sm4_crypter_t;

#include <crypto/crypters/crypter.h>

/**
 * Class implementing the SM4 encryption algorithm.
 */
struct sm4_crypter_t {

	/**
	 * Implements crypter_t interface.
	 */
	crypter_t crypter;
};

/**
 * Constructor to create sm4_crypter_t objects.
 *
 * @param algo			algorithm to implement
 * @return				sm4_crypter_t object, NULL if not supported
 */
sm4_crypter_t *sm4_crypter_create(encryption_algorithm_t algo);

#endif /** SM4_CRYPTER_H_ @}*/