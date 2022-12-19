/*
 * Copyright (C) 2008 Martin Willi
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
 * @defgroup sm4_p sm4
 * @ingroup plugins
 *
 * @defgroup sm4_plugin sm4_plugin
 * @{ @ingroup sm4_p
 */

/*
 * Created by luqichen on 2022/12/19
 * Implementing SM4 algorithm.
*/

#ifndef SM4_PLUGIN_H_
#define SM4_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct sm4_plugin_t sm4_plugin_t;

/**
 * Plugin implementing SM4 based algorithms in software.
 */
struct sm4_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** SM4_PLUGIN_H_ @}*/
