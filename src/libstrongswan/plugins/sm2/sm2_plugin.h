/**
 * @defgroup sm2_p sm2
 * @ingroup plugins
 *
 * @defgroup sm2_plugin sm2_plugin
 * @{ @ingroup sm2_p
 */

#ifndef SM2_PLUGIN_H_
#define SM2_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct sm2_plugin_t sm2_plugin_t;

/**
 * Plugin implementing the SM2 post-quantum authentication algorithm
 */
struct sm2_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** SM2_PLUGIN_H_ @}*/
