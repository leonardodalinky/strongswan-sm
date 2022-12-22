/**
 * @defgroup sm2_dh sm2_dh
 * @{ @ingroup sm2_p
 */

#ifndef SM2_DH_H_
#define SM2_DH_H_

typedef struct sm2_dh_t sm2_dh_t;

#include <library.h>

/**
 * Implementation of the Diffie-Hellman algorithm via SM2.
 */
struct sm2_dh_t {

	/**
	 * Implements key_exchange_t interface.
	 */
	key_exchange_t ke;
};

/**
 * Creates a new sm2_dh_t object.
 *
 * @param group			Diffie-Hellman group number to use
 * @param ...			expects generator and prime as chunk_t if MODP_CUSTOM
 * @return				sm2_dh_t object, NULL if not supported
 */
sm2_dh_t *sm2_dh_create(key_exchange_method_t group, ...);

#endif /** SM2_DH_H_ @}*/
