/**
 * @defgroup sm2_public_key sm2_public_key
 * @{ @ingroup sm2_p
 */

#ifndef SM2_PUBLIC_KEY_H_
#define SM2_PUBLIC_KEY_H_

#include <credentials/builder.h>
#include <credentials/cred_encoding.h>
#include <credentials/keys/public_key.h>

typedef struct sm2_public_key_t sm2_public_key_t;

/**
 * public_key_t implementation of SM2 signature algorithm
 */
struct sm2_public_key_t {

	/**
	 * Implements the public_key_t interface
	 */
	public_key_t key;
};

/**
 * Load a SM2 public key.
 *
 * Accepts BUILD_SM2_* components.
 *
 * @param type		type of the key, must be KEY_SM2
 * @param args		builder_part_t argument list
 * @return 			loaded key, NULL on failure
 */
sm2_public_key_t *sm2_public_key_load(key_type_t type, va_list args);

bool store_pubkey(SM2_POINT *pubkey, chunk_t *data);

#endif /** SM2_PUBLIC_KEY_H_ @}*/
