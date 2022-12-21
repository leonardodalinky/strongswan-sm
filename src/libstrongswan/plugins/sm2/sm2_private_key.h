/**
 * @defgroup sm2_private_key sm2_private_key
 * @{ @ingroup sm2_p
 */

#ifndef SM2_PRIVATE_KEY_H_
#define SM2_PRIVATE_KEY_H_

#include <credentials/builder.h>
#include <credentials/keys/private_key.h>

typedef struct sm2_private_key_t sm2_private_key_t;

/**
 * Private_key_t implementation of SM2 signature algorithm.
 */
struct sm2_private_key_t {

	/**
	 * Implements private_key_t interface
	 */
	private_key_t key;
};

/**
 * Generate a SM2 private key.
 *
 * Accepts the BUILD_KEY_SIZE argument.
 *
 * @param type		type of the key, must be KEY_SM2
 * @param args		builder_part_t argument list
 * @return 			generated key, NULL on failure
 */
sm2_private_key_t *sm2_private_key_gen(key_type_t type, va_list args);

/**
 * Load a SM2 private key.
 *
 * Accepts BUILD_SM2_* components.
 *
 * @param type		type of the key, must be KEY_SM2
 * @param args		builder_part_t argument list
 * @return 			loaded key, NULL on failure
 */
sm2_private_key_t *sm2_private_key_load(key_type_t type, va_list args);

#endif /** SM2_PRIVATE_KEY_H_ @}*/
